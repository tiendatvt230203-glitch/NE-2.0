#include "../../../inc/core/dataplane/dataplane_stats.h"
#include "../../../inc/core/dataplane/tcp_reorder.h"
#include "../../../inc/core/dataplane/udp_reorder.h"
#include "../../../inc/core/forwarder/forwarder.h"
#include "../../../inc/core/iface/interface.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define NE_DP_LOG_DIR  "/var/log/core"
#define NE_DP_LOG_PATH "/var/log/core/packet.log"
#define NE_DP_TRAFFIC_DIRS 2
#define NE_DP_TRAFFIC_PROTOCOLS 2
#define NE_DP_MTU_BUCKETS 6
#define NS_PER_SEC 1000000000ull

struct traffic_counter {
    atomic_uint_fast64_t packets;
    atomic_uint_fast64_t bytes;
};

struct dp_snapshot {
    uint64_t traffic_packets[NE_DP_TRAFFIC_DIRS][NE_DP_TRAFFIC_PROTOCOLS][NE_DP_MTU_BUCKETS];
    uint64_t traffic_bytes[NE_DP_TRAFFIC_DIRS][NE_DP_TRAFFIC_PROTOCOLS][NE_DP_MTU_BUCKETS];
    uint64_t rx_lan_bytes, rx_wan_bytes, tx_lan_bytes, tx_wan_bytes;
    uint64_t local_bypass, local_drop, wan_fwd, wan_drop, wan_policy_drop;
    uint64_t rx_ring_drop_lan, rx_ring_drop_wan, mid_ring_drop;
    uint64_t tx_full_lan, tx_full_wan, crypto_ring_drop;
    uint64_t tx_no_free_lan, tx_no_free_wan;
    uint64_t jumbo_rx, jumbo_tx, jumbo_drop;
    struct ne_xdp_statistics xdp_lan, xdp_wan;
    struct dp_bond_reorder_stats tcp_reorder;
    struct dp_bond_reorder_stats udp_reorder;
};

struct report_window {
    const char *name;
    uint64_t period_ns;
    uint64_t last_ns;
    struct dp_snapshot previous;
};

static int g_on = -1;
static FILE *s_log;
static pthread_mutex_t s_report_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint_fast64_t s_tick_count;

static atomic_uint_fast64_t s_rx_lan_pkts[NE_RX_LAN_SLOTS];
static atomic_uint_fast64_t s_rx_lan_bytes[NE_RX_LAN_SLOTS];
static atomic_uint_fast64_t s_rx_wan_pkts[NE_RX_WAN_SLOTS];
static atomic_uint_fast64_t s_rx_wan_bytes[NE_RX_WAN_SLOTS];
static atomic_uint_fast64_t s_rx_ring_drop_lan[NE_RX_LAN_SLOTS];
static atomic_uint_fast64_t s_rx_ring_drop_wan[NE_RX_WAN_SLOTS];
static atomic_uint_fast64_t s_local_bypass, s_local_drop, s_wan_fwd;
static atomic_uint_fast64_t s_wan_drop, s_wan_policy_drop, s_mid_ring_drop;
static atomic_uint_fast64_t s_tx_lan_pkts[NE_TX_SLOTS];
static atomic_uint_fast64_t s_tx_lan_bytes[NE_TX_SLOTS];
static atomic_uint_fast64_t s_tx_wan_pkts[NE_TX_WAN_SLOTS];
static atomic_uint_fast64_t s_tx_wan_bytes[NE_TX_WAN_SLOTS];
static atomic_uint_fast64_t s_tx_full_lan[NE_TX_SLOTS];
static atomic_uint_fast64_t s_tx_full_wan[NE_TX_WAN_SLOTS];
static atomic_uint_fast64_t s_crypto_lan_pkts[NE_CRYPTO_WORKERS];
static atomic_uint_fast64_t s_crypto_wan_pkts[NE_CRYPTO_WORKERS];
static atomic_uint_fast64_t s_crypto_ring_drop[NE_CRYPTO_WORKERS];
static struct traffic_counter
    s_traffic[NE_DP_TRAFFIC_DIRS][NE_DP_TRAFFIC_PROTOCOLS][NE_DP_MTU_BUCKETS];

static struct report_window s_windows[] = {
    { .name = "10m", .period_ns = 10ull * 60ull * NS_PER_SEC },
    { .name = "30m", .period_ns = 30ull * 60ull * NS_PER_SEC },
    { .name = "1h",  .period_ns = 60ull * 60ull * NS_PER_SEC },
    { .name = "1d",  .period_ns = 24ull * 60ull * 60ull * NS_PER_SEC },
};

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
}

static uint64_t load64(const atomic_uint_fast64_t *value)
{
    return atomic_load_explicit(value, memory_order_relaxed);
}

static uint64_t delta64(uint64_t current, uint64_t previous)
{
    return current >= previous ? current - previous : current;
}

static uint64_t sum_slots(const atomic_uint_fast64_t *slots, uint32_t count)
{
    uint64_t total = 0;
    for (uint32_t i = 0; i < count; i++)
        total += load64(&slots[i]);
    return total;
}

static int open_packet_log(void)
{
    int fd;

    if (mkdir(NE_DP_LOG_DIR, 0750) != 0 && errno != EEXIST)
        return -1;
    fd = open(NE_DP_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if (fd < 0)
        return -1;
    s_log = fdopen(fd, "a");
    if (!s_log) {
        close(fd);
        return -1;
    }
    setvbuf(s_log, NULL, _IOLBF, 0);
    return 0;
}

void ne_dp_stats_init(void)
{
    uint64_t now;
    const char *env;

    pthread_mutex_lock(&s_report_lock);
    if (g_on >= 0) {
        pthread_mutex_unlock(&s_report_lock);
        return;
    }
    env = getenv("NE_DP_STATS");
    g_on = (!env || env[0] != '0') ? 1 : 0;
    if (g_on && open_packet_log() != 0) {
        int saved_errno = errno;
        g_on = 0;
        fprintf(stderr, "[DP-STATS] cannot open %s: %s; statistics disabled\n",
                NE_DP_LOG_PATH, strerror(saved_errno));
        fflush(stderr);
    }
    now = monotonic_ns();
    for (size_t i = 0; i < sizeof(s_windows) / sizeof(s_windows[0]); i++)
        s_windows[i].last_ns = now;
    if (s_log) {
        time_t wall = time(NULL);
        struct tm local;
        char stamp[40];
        localtime_r(&wall, &local);
        strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S%z", &local);
        fprintf(s_log, "%s [PACKET-LOGGER] event=start pid=%ld "
                "windows=10m,30m,1h,1d size_metric=ipv4_packet_bytes "
                "bucket_value=packets/bytes\n",
                stamp, (long)getpid());
    }
    pthread_mutex_unlock(&s_report_lock);
}

int ne_dp_stats_on(void)
{
    if (g_on < 0)
        ne_dp_stats_init();
    return g_on;
}

#define STAT_INC(var, n) do { \
    if (ne_dp_stats_on()) \
        atomic_fetch_add_explicit(&(var), (n), memory_order_relaxed); \
} while (0)

void ne_dp_stats_rx_lan(int slot, uint32_t pkts, uint64_t bytes)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_RX_LAN_SLOTS) return;
    atomic_fetch_add_explicit(&s_rx_lan_pkts[slot], pkts, memory_order_relaxed);
    atomic_fetch_add_explicit(&s_rx_lan_bytes[slot], bytes, memory_order_relaxed);
}
void ne_dp_stats_rx_wan(int slot, uint32_t pkts, uint64_t bytes)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_RX_WAN_SLOTS) return;
    atomic_fetch_add_explicit(&s_rx_wan_pkts[slot], pkts, memory_order_relaxed);
    atomic_fetch_add_explicit(&s_rx_wan_bytes[slot], bytes, memory_order_relaxed);
}
void ne_dp_stats_rx_ring_drop_lan(int slot, uint32_t n)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_RX_LAN_SLOTS) return;
    atomic_fetch_add_explicit(&s_rx_ring_drop_lan[slot], n, memory_order_relaxed);
}
void ne_dp_stats_rx_ring_drop_wan(int slot, uint32_t n)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_RX_WAN_SLOTS) return;
    atomic_fetch_add_explicit(&s_rx_ring_drop_wan[slot], n, memory_order_relaxed);
}
void ne_dp_stats_local_bypass(uint32_t n)    { STAT_INC(s_local_bypass, n); }
void ne_dp_stats_local_drop(uint32_t n)      { STAT_INC(s_local_drop, n); }
void ne_dp_stats_wan_fwd(uint32_t n)         { STAT_INC(s_wan_fwd, n); }
void ne_dp_stats_wan_drop(uint32_t n)        { STAT_INC(s_wan_drop, n); }
void ne_dp_stats_wan_policy_drop(uint32_t n) { STAT_INC(s_wan_policy_drop, n); }
void ne_dp_stats_mid_ring_drop(uint32_t n)   { STAT_INC(s_mid_ring_drop, n); }
void ne_dp_stats_tx_lan(int slot, uint32_t pkts, uint64_t bytes)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_TX_SLOTS) return;
    atomic_fetch_add_explicit(&s_tx_lan_pkts[slot], pkts, memory_order_relaxed);
    atomic_fetch_add_explicit(&s_tx_lan_bytes[slot], bytes, memory_order_relaxed);
}
void ne_dp_stats_tx_wan(int slot, uint32_t pkts, uint64_t bytes)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_TX_WAN_SLOTS) return;
    atomic_fetch_add_explicit(&s_tx_wan_pkts[slot], pkts, memory_order_relaxed);
    atomic_fetch_add_explicit(&s_tx_wan_bytes[slot], bytes, memory_order_relaxed);
}
void ne_dp_stats_tx_full_lan(int slot, uint32_t n)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_TX_SLOTS) return;
    atomic_fetch_add_explicit(&s_tx_full_lan[slot], n, memory_order_relaxed);
}
void ne_dp_stats_tx_full_wan(int slot, uint32_t n)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_TX_WAN_SLOTS) return;
    atomic_fetch_add_explicit(&s_tx_full_wan[slot], n, memory_order_relaxed);
}
void ne_dp_stats_crypto_lan(int worker, uint32_t n)
{
    if (!ne_dp_stats_on() || worker < 0 || worker >= (int)NE_CRYPTO_WORKERS) return;
    atomic_fetch_add_explicit(&s_crypto_lan_pkts[worker], n, memory_order_relaxed);
}
void ne_dp_stats_crypto_wan(int worker, uint32_t n)
{
    if (!ne_dp_stats_on() || worker < 0 || worker >= (int)NE_CRYPTO_WORKERS) return;
    atomic_fetch_add_explicit(&s_crypto_wan_pkts[worker], n, memory_order_relaxed);
}
void ne_dp_stats_crypto_ring_drop(int worker, uint32_t n)
{
    if (!ne_dp_stats_on() || worker < 0 || worker >= (int)NE_CRYPTO_WORKERS) return;
    atomic_fetch_add_explicit(&s_crypto_ring_drop[worker], n, memory_order_relaxed);
}

static int protocol_index(uint8_t protocol)
{
    return protocol == IPPROTO_TCP ? 0 : protocol == IPPROTO_UDP ? 1 : -1;
}

static int mtu_bucket(uint32_t len)
{
    if (len <= 1500u) return 0;
    if (len <= 3000u) return 1;
    if (len <= 5000u) return 2;
    if (len <= 7000u) return 3;
    if (len <= 9000u) return 4;
    return 5;
}

void ne_dp_stats_observe_traffic(enum ne_dp_traffic_dir dir, uint8_t protocol,
                                 uint32_t ipv4_len)
{
    int pi, bucket;

    if (!ne_dp_stats_on() || dir < 0 || dir >= NE_DP_TRAFFIC_DIRS) return;
    pi = protocol_index(protocol);
    if (pi < 0) return;
    bucket = mtu_bucket(ipv4_len);
    atomic_fetch_add_explicit(&s_traffic[dir][pi][bucket].packets, 1,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&s_traffic[dir][pi][bucket].bytes, ipv4_len,
                              memory_order_relaxed);
}

static void capture_snapshot(struct forwarder *fwd, struct dp_snapshot *out)
{
    memset(out, 0, sizeof(*out));
    for (int d = 0; d < NE_DP_TRAFFIC_DIRS; d++)
        for (int p = 0; p < NE_DP_TRAFFIC_PROTOCOLS; p++)
            for (int b = 0; b < NE_DP_MTU_BUCKETS; b++) {
                out->traffic_packets[d][p][b] = load64(&s_traffic[d][p][b].packets);
                out->traffic_bytes[d][p][b] = load64(&s_traffic[d][p][b].bytes);
            }
    out->rx_lan_bytes = sum_slots(s_rx_lan_bytes, NE_RX_LAN_SLOTS);
    out->rx_wan_bytes = sum_slots(s_rx_wan_bytes, NE_RX_WAN_SLOTS);
    out->tx_lan_bytes = sum_slots(s_tx_lan_bytes, NE_TX_SLOTS);
    out->tx_wan_bytes = sum_slots(s_tx_wan_bytes, NE_TX_WAN_SLOTS);
    out->local_bypass = load64(&s_local_bypass);
    out->local_drop = load64(&s_local_drop);
    out->wan_fwd = load64(&s_wan_fwd);
    out->wan_drop = load64(&s_wan_drop);
    out->wan_policy_drop = load64(&s_wan_policy_drop);
    out->rx_ring_drop_lan = sum_slots(s_rx_ring_drop_lan, NE_RX_LAN_SLOTS);
    out->rx_ring_drop_wan = sum_slots(s_rx_ring_drop_wan, NE_RX_WAN_SLOTS);
    out->mid_ring_drop = load64(&s_mid_ring_drop);
    out->tx_full_lan = sum_slots(s_tx_full_lan, NE_TX_SLOTS);
    out->tx_full_wan = sum_slots(s_tx_full_wan, NE_TX_WAN_SLOTS);
    out->crypto_ring_drop = sum_slots(s_crypto_ring_drop, NE_CRYPTO_WORKERS);
    dp_tcp_reorder_get_stats(&out->tcp_reorder);
    dp_udp_reorder_get_stats(&out->udp_reorder);
    if (!fwd) return;
    for (int li = 0; li < fwd->local_count; li++)
        out->tx_no_free_lan += fwd->pair.locals[li].tx_no_free;
    for (int wi = 0; wi < fwd->wan_count; wi++)
        out->tx_no_free_wan += fwd->pair.wans[wi].tx_no_free;
    out->jumbo_rx = __atomic_load_n(&fwd->pair.rx_jumbo_packets, __ATOMIC_RELAXED);
    out->jumbo_tx = __atomic_load_n(&fwd->pair.tx_jumbo_packets, __ATOMIC_RELAXED);
    out->jumbo_drop = __atomic_load_n(&fwd->pair.rx_jumbo_drops, __ATOMIC_RELAXED);
    ne_xdp_read_statistics(&fwd->pair, NE_DIR_LOCAL, &out->xdp_lan);
    ne_xdp_read_statistics(&fwd->pair, NE_DIR_WAN, &out->xdp_wan);
}

static uint64_t xdp_failures(const struct ne_xdp_statistics *cur,
                             const struct ne_xdp_statistics *prev)
{
    return delta64(cur->rx_dropped, prev->rx_dropped) +
           delta64(cur->rx_invalid_descs, prev->rx_invalid_descs) +
           delta64(cur->tx_invalid_descs, prev->tx_invalid_descs) +
           delta64(cur->rx_ring_full, prev->rx_ring_full) +
           delta64(cur->rx_fill_ring_empty_descs, prev->rx_fill_ring_empty_descs);
}

static void emit_traffic(const struct dp_snapshot *cur, const struct dp_snapshot *prev,
                         int dir, int proto, double elapsed)
{
    static const char *dirs[] = { "LAN_TO_WAN", "WAN_TO_LAN" };
    static const char *protos[] = { "TCP", "UDP" };
    static const char *buckets[] = { "le1500", "1501_3000", "3001_5000",
                                     "5001_7000", "7001_9000", "gt9000" };
    uint64_t packets = 0, bytes = 0;

    for (int b = 0; b < NE_DP_MTU_BUCKETS; b++) {
        packets += delta64(cur->traffic_packets[dir][proto][b], prev->traffic_packets[dir][proto][b]);
        bytes += delta64(cur->traffic_bytes[dir][proto][b], prev->traffic_bytes[dir][proto][b]);
    }
    fprintf(s_log, " traffic dir=%s proto=%s packets=%llu bytes=%llu avg_gbps=%.3f buckets=",
            dirs[dir], protos[proto], (unsigned long long)packets,
            (unsigned long long)bytes, elapsed > 0.0 ? (double)bytes * 8.0 / elapsed / 1e9 : 0.0);
    for (int b = 0; b < NE_DP_MTU_BUCKETS; b++)
        fprintf(s_log, "%s%s:%llu/%llu", b ? "," : "", buckets[b],
                (unsigned long long)delta64(cur->traffic_packets[dir][proto][b], prev->traffic_packets[dir][proto][b]),
                (unsigned long long)delta64(cur->traffic_bytes[dir][proto][b], prev->traffic_bytes[dir][proto][b]));
    fputc('\n', s_log);
}

static void emit_report(struct forwarder *fwd, struct report_window *w,
                        const struct dp_snapshot *cur, uint64_t now)
{
    const struct dp_snapshot *p = &w->previous;
    double elapsed = (double)(now - w->last_ns) / 1e9;
    uint64_t drops, reorder_bad, xdp_bad;
    uint32_t q_lan = 0, q_wan = 0, q_to_wan = 0, q_to_lan = 0;
    time_t wall = time(NULL);
    struct tm local;
    char stamp[40];

    drops = delta64(cur->local_drop,p->local_drop)+delta64(cur->wan_drop,p->wan_drop)+
        delta64(cur->rx_ring_drop_lan,p->rx_ring_drop_lan)+delta64(cur->rx_ring_drop_wan,p->rx_ring_drop_wan)+
        delta64(cur->mid_ring_drop,p->mid_ring_drop)+delta64(cur->tx_full_lan,p->tx_full_lan)+
        delta64(cur->tx_full_wan,p->tx_full_wan)+delta64(cur->crypto_ring_drop,p->crypto_ring_drop)+
        delta64(cur->tx_no_free_lan,p->tx_no_free_lan)+delta64(cur->tx_no_free_wan,p->tx_no_free_wan)+
        delta64(cur->jumbo_drop,p->jumbo_drop);
    reorder_bad =
        delta64(cur->tcp_reorder.late,p->tcp_reorder.late)+
        delta64(cur->tcp_reorder.duplicate_dropped,p->tcp_reorder.duplicate_dropped)+
        delta64(cur->tcp_reorder.gap_skipped,p->tcp_reorder.gap_skipped)+
        delta64(cur->tcp_reorder.overflow,p->tcp_reorder.overflow)+
        delta64(cur->tcp_reorder.evicted,p->tcp_reorder.evicted)+
        delta64(cur->udp_reorder.late,p->udp_reorder.late)+
        delta64(cur->udp_reorder.duplicate_dropped,p->udp_reorder.duplicate_dropped)+
        delta64(cur->udp_reorder.gap_skipped,p->udp_reorder.gap_skipped)+
        delta64(cur->udp_reorder.overflow,p->udp_reorder.overflow)+
        delta64(cur->udp_reorder.evicted,p->udp_reorder.evicted);
    xdp_bad = xdp_failures(&cur->xdp_lan,&p->xdp_lan)+xdp_failures(&cur->xdp_wan,&p->xdp_wan);
    if (fwd) {
        for (int i=0;i<(int)NE_CRYPTO_WORKERS;i++) { q_lan+=ne_ring_count(&fwd->local_to_mid[i]); q_wan+=ne_ring_count(&fwd->wan_to_mid[i]); }
        for (int i=0;i<fwd->wan_count;i++) q_to_wan+=fwd_mid_to_wan_depth(fwd,i);
        for (int i=0;i<fwd->local_count;i++) for (int j=0;j<(int)NE_CRYPTO_WORKERS;j++) q_to_lan+=ne_ring_count(&fwd->mid_to_local[i][j]);
    }
    localtime_r(&wall,&local); strftime(stamp,sizeof(stamp),"%Y-%m-%dT%H:%M:%S%z",&local);
    fprintf(s_log,"%s [PACKET-SUMMARY] window=%s elapsed_sec=%.1f status=%s\n",stamp,w->name,elapsed,(drops||reorder_bad||xdp_bad)?"WARN":"OK");
    for(int d=0;d<NE_DP_TRAFFIC_DIRS;d++) for(int pr=0;pr<NE_DP_TRAFFIC_PROTOCOLS;pr++) emit_traffic(cur,p,d,pr,elapsed);
    fprintf(s_log," throughput rx_lan_gbps=%.3f rx_wan_gbps=%.3f tx_lan_gbps=%.3f tx_wan_gbps=%.3f\n",
        (double)delta64(cur->rx_lan_bytes,p->rx_lan_bytes)*8/elapsed/1e9,(double)delta64(cur->rx_wan_bytes,p->rx_wan_bytes)*8/elapsed/1e9,
        (double)delta64(cur->tx_lan_bytes,p->tx_lan_bytes)*8/elapsed/1e9,(double)delta64(cur->tx_wan_bytes,p->tx_wan_bytes)*8/elapsed/1e9);
    fprintf(s_log," drops local=%llu wan=%llu wan_policy=%llu rx_ring_lan=%llu rx_ring_wan=%llu mid_ring=%llu tx_full_lan=%llu tx_full_wan=%llu crypto_ring=%llu tx_no_free_lan=%llu tx_no_free_wan=%llu jumbo=%llu\n",
        (unsigned long long)delta64(cur->local_drop,p->local_drop),(unsigned long long)delta64(cur->wan_drop,p->wan_drop),(unsigned long long)delta64(cur->wan_policy_drop,p->wan_policy_drop),
        (unsigned long long)delta64(cur->rx_ring_drop_lan,p->rx_ring_drop_lan),(unsigned long long)delta64(cur->rx_ring_drop_wan,p->rx_ring_drop_wan),(unsigned long long)delta64(cur->mid_ring_drop,p->mid_ring_drop),
        (unsigned long long)delta64(cur->tx_full_lan,p->tx_full_lan),(unsigned long long)delta64(cur->tx_full_wan,p->tx_full_wan),(unsigned long long)delta64(cur->crypto_ring_drop,p->crypto_ring_drop),
        (unsigned long long)delta64(cur->tx_no_free_lan,p->tx_no_free_lan),(unsigned long long)delta64(cur->tx_no_free_wan,p->tx_no_free_wan),(unsigned long long)delta64(cur->jumbo_drop,p->jumbo_drop));
    fprintf(s_log," reorder TCP(held=%llu released=%llu late_forwarded=%llu duplicate_dropped=%llu gap_skip=%llu overflow=%llu evicted=%llu high_water=%llu) UDP(held=%llu released=%llu late_dropped=%llu duplicate_dropped=%llu gap_skip=%llu overflow=%llu evicted=%llu high_water=%llu)\n",
        (unsigned long long)delta64(cur->tcp_reorder.held,p->tcp_reorder.held),(unsigned long long)delta64(cur->tcp_reorder.released,p->tcp_reorder.released),(unsigned long long)delta64(cur->tcp_reorder.late,p->tcp_reorder.late),(unsigned long long)delta64(cur->tcp_reorder.duplicate_dropped,p->tcp_reorder.duplicate_dropped),
        (unsigned long long)delta64(cur->tcp_reorder.gap_skipped,p->tcp_reorder.gap_skipped),(unsigned long long)delta64(cur->tcp_reorder.overflow,p->tcp_reorder.overflow),(unsigned long long)delta64(cur->tcp_reorder.evicted,p->tcp_reorder.evicted),(unsigned long long)cur->tcp_reorder.high_water,
        (unsigned long long)delta64(cur->udp_reorder.held,p->udp_reorder.held),(unsigned long long)delta64(cur->udp_reorder.released,p->udp_reorder.released),(unsigned long long)delta64(cur->udp_reorder.late,p->udp_reorder.late),(unsigned long long)delta64(cur->udp_reorder.duplicate_dropped,p->udp_reorder.duplicate_dropped),
        (unsigned long long)delta64(cur->udp_reorder.gap_skipped,p->udp_reorder.gap_skipped),(unsigned long long)delta64(cur->udp_reorder.overflow,p->udp_reorder.overflow),(unsigned long long)delta64(cur->udp_reorder.evicted,p->udp_reorder.evicted),(unsigned long long)cur->udp_reorder.high_water);
    fprintf(s_log," xdp LAN(drop=%llu ring_full=%llu fill_empty=%llu rx_bad=%llu tx_bad=%llu) WAN(drop=%llu ring_full=%llu fill_empty=%llu rx_bad=%llu tx_bad=%llu)\n",
        (unsigned long long)delta64(cur->xdp_lan.rx_dropped,p->xdp_lan.rx_dropped),(unsigned long long)delta64(cur->xdp_lan.rx_ring_full,p->xdp_lan.rx_ring_full),(unsigned long long)delta64(cur->xdp_lan.rx_fill_ring_empty_descs,p->xdp_lan.rx_fill_ring_empty_descs),
        (unsigned long long)delta64(cur->xdp_lan.rx_invalid_descs,p->xdp_lan.rx_invalid_descs),(unsigned long long)delta64(cur->xdp_lan.tx_invalid_descs,p->xdp_lan.tx_invalid_descs),
        (unsigned long long)delta64(cur->xdp_wan.rx_dropped,p->xdp_wan.rx_dropped),(unsigned long long)delta64(cur->xdp_wan.rx_ring_full,p->xdp_wan.rx_ring_full),(unsigned long long)delta64(cur->xdp_wan.rx_fill_ring_empty_descs,p->xdp_wan.rx_fill_ring_empty_descs),
        (unsigned long long)delta64(cur->xdp_wan.rx_invalid_descs,p->xdp_wan.rx_invalid_descs),(unsigned long long)delta64(cur->xdp_wan.tx_invalid_descs,p->xdp_wan.tx_invalid_descs));
    fprintf(s_log," gauges queues(lan_to_crypto=%u wan_to_crypto=%u crypto_to_wan=%u crypto_to_lan=%u) pool_free=%u jumbo_free=%u jumbo(rx=%llu tx=%llu)\n [PACKET-SUMMARY-END] window=%s\n",
        q_lan,q_wan,q_to_wan,q_to_lan,fwd?ne_pool_free_count(&fwd->pair):0,fwd?ne_jumbo_free_count(&fwd->pair):0,
        (unsigned long long)delta64(cur->jumbo_rx,p->jumbo_rx),(unsigned long long)delta64(cur->jumbo_tx,p->jumbo_tx),w->name);
    fflush(s_log);
}

void ne_dp_stats_tick(struct forwarder *fwd)
{
    uint64_t count, now;
    struct dp_snapshot current;
    int captured = 0;

    if (!ne_dp_stats_on() || !s_log) return;
    count = atomic_fetch_add_explicit(&s_tick_count,1,memory_order_relaxed)+1;
    if ((count & 1023u) != 0) return;
    now = monotonic_ns();
    pthread_mutex_lock(&s_report_lock);
    for (size_t i=0;i<sizeof(s_windows)/sizeof(s_windows[0]);i++) {
        struct report_window *w=&s_windows[i];
        if (now-w->last_ns<w->period_ns) continue;
        if (!captured) { capture_snapshot(fwd,&current); captured=1; }
        emit_report(fwd,w,&current,now);
        w->previous=current;
        w->last_ns=now;
    }
    pthread_mutex_unlock(&s_report_lock);
}

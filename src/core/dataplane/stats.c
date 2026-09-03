#include "../../../inc/core/dataplane/dataplane_stats.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/dataplane/udp_reorder.h"
#include "../../../inc/core/forwarder/forwarder.h"
#include "../../../inc/core/iface/interface.h"

#include <stdatomic.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int g_on = -1;

static atomic_uint_fast64_t s_rx_lan_pkts[NE_RX_LAN_SLOTS];
static atomic_uint_fast64_t s_rx_lan_bytes[NE_RX_LAN_SLOTS];
static atomic_uint_fast64_t s_rx_wan_pkts[NE_RX_WAN_SLOTS];
static atomic_uint_fast64_t s_rx_wan_bytes[NE_RX_WAN_SLOTS];
static atomic_uint_fast64_t s_rx_ring_drop_lan[NE_RX_LAN_SLOTS];
static atomic_uint_fast64_t s_rx_ring_drop_wan[NE_RX_WAN_SLOTS];

static atomic_uint_fast64_t s_local_bypass;
static atomic_uint_fast64_t s_local_drop;
static atomic_uint_fast64_t s_wan_fwd;
static atomic_uint_fast64_t s_wan_drop;
static atomic_uint_fast64_t s_wan_policy_drop;
static atomic_uint_fast64_t s_mid_ring_drop;
static atomic_uint_fast64_t s_seq_untracked;

static atomic_uint_fast64_t s_tx_lan_pkts[NE_TX_SLOTS];
static atomic_uint_fast64_t s_tx_lan_bytes[NE_TX_SLOTS];
static atomic_uint_fast64_t s_tx_wan_pkts[NE_TX_WAN_SLOTS];
static atomic_uint_fast64_t s_tx_wan_bytes[NE_TX_WAN_SLOTS];
static atomic_uint_fast64_t s_tx_full_lan[NE_TX_SLOTS];
static atomic_uint_fast64_t s_tx_full_wan[NE_TX_WAN_SLOTS];

static atomic_uint_fast64_t s_crypto_lan_pkts[NE_CRYPTO_WORKERS];
static atomic_uint_fast64_t s_crypto_wan_pkts[NE_CRYPTO_WORKERS];
static atomic_uint_fast64_t s_crypto_ring_drop[NE_CRYPTO_WORKERS];

static uint64_t s_prev[4];
static uint64_t s_prev_crypto_lan[NE_CRYPTO_WORKERS];
static uint64_t s_prev_crypto_wan[NE_CRYPTO_WORKERS];
static uint64_t s_prev_tx_lan_bytes[NE_TX_SLOTS];
static uint64_t s_prev_tx_wan_bytes[NE_TX_SLOTS];
static struct timespec s_last_ts;
static uint32_t s_tick_count;
static struct dp_udp_reorder_flow_stats
    s_reorder_flow_snapshot[DP_REORDER_FLOW_STATS_MAX];
static struct ne_xdp_socket_stats s_prev_xdp_lan;
static struct ne_xdp_socket_stats s_prev_xdp_wan;

#define NE_DP_CRYPTO_Q_WATERMARK (NE_RING / 4u)

void ne_dp_stats_init(void)
{
    if (g_on < 0) {
        const char *env = getenv("NE_DP_STATS");
        g_on = (!env || env[0] != '0') ? 1 : 0;
        if (g_on)
            fprintf(stderr,
                    "[DP-STATS] enabled (set NE_DP_STATS=0 to disable); "
                    "FLOW loss is inferred from authenticated NE sequence gaps, "
                    "not copied from iperf3\n");
    }
    clock_gettime(CLOCK_MONOTONIC, &s_last_ts);
    memset(s_prev, 0, sizeof(s_prev));
    memset(s_prev_crypto_lan, 0, sizeof(s_prev_crypto_lan));
    memset(s_prev_crypto_wan, 0, sizeof(s_prev_crypto_wan));
    memset(s_prev_tx_lan_bytes, 0, sizeof(s_prev_tx_lan_bytes));
    memset(s_prev_tx_wan_bytes, 0, sizeof(s_prev_tx_wan_bytes));
    memset(&s_prev_xdp_lan, 0, sizeof(s_prev_xdp_lan));
    memset(&s_prev_xdp_wan, 0, sizeof(s_prev_xdp_wan));
    s_tick_count = 0;
}

int ne_dp_stats_on(void)
{
    if (g_on < 0)
        ne_dp_stats_init();
    return g_on;
}

#define STAT_INC(var, n) do { \
    if (ne_dp_stats_on()) \
        atomic_fetch_add(&(var), (n)); \
} while (0)

void ne_dp_stats_rx_lan(int slot, uint32_t pkts, uint64_t bytes)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_RX_LAN_SLOTS)
        return;
    atomic_fetch_add(&s_rx_lan_pkts[slot], pkts);
    atomic_fetch_add(&s_rx_lan_bytes[slot], bytes);
}

void ne_dp_stats_rx_wan(int slot, uint32_t pkts, uint64_t bytes)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_RX_WAN_SLOTS)
        return;
    atomic_fetch_add(&s_rx_wan_pkts[slot], pkts);
    atomic_fetch_add(&s_rx_wan_bytes[slot], bytes);
}

void ne_dp_stats_rx_ring_drop_lan(int slot, uint32_t n)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_RX_LAN_SLOTS)
        return;
    atomic_fetch_add(&s_rx_ring_drop_lan[slot], n);
}

void ne_dp_stats_rx_ring_drop_wan(int slot, uint32_t n)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_RX_WAN_SLOTS)
        return;
    atomic_fetch_add(&s_rx_ring_drop_wan[slot], n);
}

void ne_dp_stats_local_bypass(uint32_t n)  { STAT_INC(s_local_bypass, n); }
void ne_dp_stats_local_drop(uint32_t n)    { STAT_INC(s_local_drop, n); }
void ne_dp_stats_wan_fwd(uint32_t n)       { STAT_INC(s_wan_fwd, n); }
void ne_dp_stats_wan_drop(uint32_t n)      { STAT_INC(s_wan_drop, n); }
void ne_dp_stats_wan_policy_drop(uint32_t n) { STAT_INC(s_wan_policy_drop, n); }
void ne_dp_stats_mid_ring_drop(uint32_t n) { STAT_INC(s_mid_ring_drop, n); }
void ne_dp_stats_seq_untracked(uint32_t n) { STAT_INC(s_seq_untracked, n); }

void ne_dp_stats_tx_lan(int slot, uint32_t pkts, uint64_t bytes)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_TX_SLOTS)
        return;
    atomic_fetch_add(&s_tx_lan_pkts[slot], pkts);
    atomic_fetch_add(&s_tx_lan_bytes[slot], bytes);
}

void ne_dp_stats_tx_wan(int slot, uint32_t pkts, uint64_t bytes)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_TX_WAN_SLOTS)
        return;
    atomic_fetch_add(&s_tx_wan_pkts[slot], pkts);
    atomic_fetch_add(&s_tx_wan_bytes[slot], bytes);
}

void ne_dp_stats_tx_full_lan(int slot, uint32_t n)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_TX_SLOTS)
        return;
    atomic_fetch_add(&s_tx_full_lan[slot], n);
}

void ne_dp_stats_tx_full_wan(int slot, uint32_t n)
{
    if (!ne_dp_stats_on() || slot < 0 || slot >= (int)NE_TX_WAN_SLOTS)
        return;
    atomic_fetch_add(&s_tx_full_wan[slot], n);
}

void ne_dp_stats_crypto_lan(int worker, uint32_t n)
{
    if (!ne_dp_stats_on() || worker < 0 || worker >= (int)NE_CRYPTO_WORKERS)
        return;
    atomic_fetch_add(&s_crypto_lan_pkts[worker], n);
}

void ne_dp_stats_crypto_wan(int worker, uint32_t n)
{
    if (!ne_dp_stats_on() || worker < 0 || worker >= (int)NE_CRYPTO_WORKERS)
        return;
    atomic_fetch_add(&s_crypto_wan_pkts[worker], n);
}

void ne_dp_stats_crypto_ring_drop(int worker, uint32_t n)
{
    if (!ne_dp_stats_on() || worker < 0 || worker >= (int)NE_CRYPTO_WORKERS)
        return;
    atomic_fetch_add(&s_crypto_ring_drop[worker], n);
}

static uint64_t load64(const atomic_uint_fast64_t *a)
{
    return atomic_load(a);
}

static uint64_t counter_delta(uint64_t current, uint64_t previous)
{
    return current >= previous ? current - previous : current;
}

static double elapsed_sec(const struct timespec *a, const struct timespec *b)
{
    double da = (double)a->tv_sec + (double)a->tv_nsec / 1e9;
    double db = (double)b->tv_sec + (double)b->tv_nsec / 1e9;
    return db - da;
}

static void fmt_gbps(char *out, size_t outsz, uint64_t bytes, double sec)
{
    double gbps = sec > 0.0 ? ((double)bytes * 8.0 / sec) / 1e9 : 0.0;
    snprintf(out, outsz, "%.2fG", gbps);
}

static uint64_t sum_rx_lan_bytes(void)
{
    uint64_t t = 0;
    for (uint32_t i = 0; i < NE_RX_LAN_SLOTS; i++)
        t += load64(&s_rx_lan_bytes[i]);
    return t;
}

static uint64_t sum_rx_wan_bytes(void)
{
    uint64_t t = 0;
    for (uint32_t i = 0; i < NE_RX_WAN_SLOTS; i++)
        t += load64(&s_rx_wan_bytes[i]);
    return t;
}

static uint64_t sum_tx_wan_bytes(void)
{
    uint64_t t = 0;
    for (uint32_t i = 0; i < NE_TX_WAN_SLOTS; i++)
        t += load64(&s_tx_wan_bytes[i]);
    return t;
}

static uint64_t sum_tx_lan_bytes(void)
{
    uint64_t t = 0;
    for (uint32_t i = 0; i < NE_TX_SLOTS; i++)
        t += load64(&s_tx_lan_bytes[i]);
    return t;
}

static uint64_t sum_atomic(const atomic_uint_fast64_t *values, uint32_t count)
{
    uint64_t total = 0;

    for (uint32_t i = 0; i < count; i++)
        total += load64(&values[i]);
    return total;
}

void ne_dp_stats_tick(struct forwarder *fwd)
{
    struct timespec now;
    struct timespec wall_now;
    struct tm wall_tm;
    double sec;
    char wall_ts[32] = "unknown-time";
    char lan_g[16], wan_g[16], tx_wan_g[16], tx_lan_g[16];
    uint64_t cur_lan_b, cur_wan_b, cur_tx_wan_b, cur_tx_lan_b;
    uint64_t d_lan_b, d_wan_b, d_tx_wan_b, d_tx_lan_b;

    if (!ne_dp_stats_on())
        return;

    s_tick_count++;
    if ((s_tick_count & 1023u) != 0)
        return;

    clock_gettime(CLOCK_MONOTONIC, &now);
    sec = elapsed_sec(&s_last_ts, &now);
    if (sec < 4.5)
        return;
    if (clock_gettime(CLOCK_REALTIME, &wall_now) == 0 &&
        localtime_r(&wall_now.tv_sec, &wall_tm) != NULL)
        strftime(wall_ts, sizeof(wall_ts), "%Y-%m-%dT%H:%M:%S%z", &wall_tm);

    cur_lan_b = sum_rx_lan_bytes();
    cur_wan_b = sum_rx_wan_bytes();
    cur_tx_wan_b = sum_tx_wan_bytes();
    cur_tx_lan_b = sum_tx_lan_bytes();

    d_lan_b = cur_lan_b - s_prev[0];
    d_wan_b = cur_wan_b - s_prev[1];
    d_tx_wan_b = cur_tx_wan_b - s_prev[2];
    d_tx_lan_b = cur_tx_lan_b - s_prev[3];

    s_prev[0] = cur_lan_b;
    s_prev[1] = cur_wan_b;
    s_prev[2] = cur_tx_wan_b;
    s_prev[3] = cur_tx_lan_b;
    s_last_ts = now;

    fmt_gbps(lan_g, sizeof(lan_g), d_lan_b, sec);
    fmt_gbps(wan_g, sizeof(wan_g), d_wan_b, sec);
    fmt_gbps(tx_wan_g, sizeof(tx_wan_g), d_tx_wan_b, sec);
    fmt_gbps(tx_lan_g, sizeof(tx_lan_g), d_tx_lan_b, sec);

    fprintf(stderr,
            "[DP-STATS] ts=%s interval=%.1fs LAN_RX=%s WAN_RX=%s "
            "TX_WAN=%s TX_LAN=%s "
            "bypass=%llu local_drop=%llu wan_fwd=%llu wan_drop=%llu "
            "wan_policy_drop=%llu "
            "rx_ring_drop(lan=%llu wan=%llu) mid_ring_drop=%llu "
            "seq_untracked=%llu\n",
            wall_ts, sec, lan_g, wan_g, tx_wan_g, tx_lan_g,
            (unsigned long long)load64(&s_local_bypass),
            (unsigned long long)load64(&s_local_drop),
            (unsigned long long)load64(&s_wan_fwd),
            (unsigned long long)load64(&s_wan_drop),
            (unsigned long long)load64(&s_wan_policy_drop),
            (unsigned long long)sum_atomic(s_rx_ring_drop_lan, NE_RX_LAN_SLOTS),
            (unsigned long long)sum_atomic(s_rx_ring_drop_wan, NE_RX_WAN_SLOTS),
            (unsigned long long)load64(&s_mid_ring_drop),
            (unsigned long long)load64(&s_seq_untracked));

    if (fwd) {
        uint32_t lan_q = 0, wan_q = 0, mid_wan_q = 0, mid_lan_q = 0;
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            lan_q += ne_ring_count(&fwd->local_to_mid[w]);
            wan_q += ne_ring_count(&fwd->wan_to_mid[w]);
        }
        for (int wi = 0; wi < fwd->wan_count; wi++)
            mid_wan_q += fwd_mid_to_wan_depth(fwd, wi);
        for (int li = 0; li < fwd->local_count; li++) {
            for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
                mid_lan_q += ne_ring_count(&fwd->mid_to_local[li][w]);
        }
        {
            uint64_t tx_no_free_lan = 0;
            uint64_t tx_no_free_wan = 0;

            for (int li = 0; li < fwd->local_count; li++)
                tx_no_free_lan += fwd->pair.locals[li].tx_no_free;
            for (int wi = 0; wi < fwd->wan_count; wi++)
                tx_no_free_wan += fwd->pair.wans[wi].tx_no_free;
            fprintf(stderr,
                "[DP-STATS] ring_depth lan_to_mid=%u wan_to_mid=%u "
                "mid_to_wan=%u mid_to_local=%u tx_no_free(lan=%llu wan=%llu) "
                "tx_full(lan=%llu wan=%llu) pool_free=%u\n",
                lan_q, wan_q, mid_wan_q, mid_lan_q,
                (unsigned long long)tx_no_free_lan,
                (unsigned long long)tx_no_free_wan,
                (unsigned long long)sum_atomic(s_tx_full_lan, NE_TX_SLOTS),
                (unsigned long long)sum_atomic(s_tx_full_wan, NE_TX_WAN_SLOTS),
                ne_pool_free_count(&fwd->pair));
        }

        {
            struct ne_xdp_socket_stats lan = {0};
            struct ne_xdp_socket_stats wan = {0};

            ne_pair_xdp_socket_stats(&fwd->pair, &lan, &wan);
            fprintf(stderr,
                    "[XDP-STATS] kernel_drop_delta "
                    "lan(sockets=%u errors=%u rx_drop=%llu ring_full=%llu "
                    "fill_empty=%llu invalid_rx=%llu) "
                    "wan(sockets=%u errors=%u rx_drop=%llu ring_full=%llu "
                    "fill_empty=%llu invalid_rx=%llu) "
                    "tx_invalid(lan=%llu wan=%llu) tx_empty(lan=%llu wan=%llu)\n",
                    lan.sockets_queried, lan.query_errors,
                    (unsigned long long)counter_delta(
                        lan.rx_dropped, s_prev_xdp_lan.rx_dropped),
                    (unsigned long long)counter_delta(
                        lan.rx_ring_full, s_prev_xdp_lan.rx_ring_full),
                    (unsigned long long)counter_delta(
                        lan.rx_fill_ring_empty_descs,
                        s_prev_xdp_lan.rx_fill_ring_empty_descs),
                    (unsigned long long)counter_delta(
                        lan.rx_invalid_descs, s_prev_xdp_lan.rx_invalid_descs),
                    wan.sockets_queried, wan.query_errors,
                    (unsigned long long)counter_delta(
                        wan.rx_dropped, s_prev_xdp_wan.rx_dropped),
                    (unsigned long long)counter_delta(
                        wan.rx_ring_full, s_prev_xdp_wan.rx_ring_full),
                    (unsigned long long)counter_delta(
                        wan.rx_fill_ring_empty_descs,
                        s_prev_xdp_wan.rx_fill_ring_empty_descs),
                    (unsigned long long)counter_delta(
                        wan.rx_invalid_descs, s_prev_xdp_wan.rx_invalid_descs),
                    (unsigned long long)counter_delta(
                        lan.tx_invalid_descs, s_prev_xdp_lan.tx_invalid_descs),
                    (unsigned long long)counter_delta(
                        wan.tx_invalid_descs, s_prev_xdp_wan.tx_invalid_descs),
                    (unsigned long long)counter_delta(
                        lan.tx_ring_empty_descs,
                        s_prev_xdp_lan.tx_ring_empty_descs),
                    (unsigned long long)counter_delta(
                        wan.tx_ring_empty_descs,
                        s_prev_xdp_wan.tx_ring_empty_descs));
            s_prev_xdp_lan = lan;
            s_prev_xdp_wan = wan;
        }

        {
            struct dp_udp_reorder_stats reorder;
            size_t flow_count;

            dp_udp_reorder_get_stats(&reorder);
            fprintf(stderr,
                    "[DP-STATS] bond_reorder enabled=%u hold_us=%llu "
                    "held=%llu released=%llu "
                    "late_dup=%llu gap_skip=%llu overflow=%llu evicted=%llu "
                    "held_high_water=%llu\n",
                    (unsigned int)reorder.enabled,
                    (unsigned long long)reorder.hold_us,
                    (unsigned long long)reorder.held,
                    (unsigned long long)reorder.released,
                    (unsigned long long)reorder.late_or_duplicate,
                    (unsigned long long)reorder.gap_skipped,
                    (unsigned long long)reorder.overflow,
                    (unsigned long long)reorder.evicted,
                    (unsigned long long)reorder.high_water);
            fprintf(stderr,
                    "[DP-STATS] bond_reorder_proto "
                    "tcp(h=%llu r=%llu late=%llu gap=%llu ovf=%llu evict=%llu) "
                    "udp(h=%llu r=%llu late=%llu gap=%llu ovf=%llu evict=%llu)\n",
                    (unsigned long long)reorder.tcp_held,
                    (unsigned long long)reorder.tcp_released,
                    (unsigned long long)reorder.tcp_late_or_duplicate,
                    (unsigned long long)reorder.tcp_gap_skipped,
                    (unsigned long long)reorder.tcp_overflow,
                    (unsigned long long)reorder.tcp_evicted,
                    (unsigned long long)reorder.udp_held,
                    (unsigned long long)reorder.udp_released,
                    (unsigned long long)reorder.udp_late_or_duplicate,
                    (unsigned long long)reorder.udp_gap_skipped,
                    (unsigned long long)reorder.udp_overflow,
                    (unsigned long long)reorder.udp_evicted);

            flow_count = dp_udp_reorder_get_flow_stats(
                s_reorder_flow_snapshot, DP_REORDER_FLOW_STATS_MAX);
            for (size_t i = 0; i < flow_count; i++) {
                const struct dp_udp_reorder_flow_stats *flow =
                    &s_reorder_flow_snapshot[i];
                char src[INET_ADDRSTRLEN] = "?";
                char dst[INET_ADDRSTRLEN] = "?";
                uint64_t net_missing;
                uint64_t estimated_drops;
                uint64_t expected;
                double loss_pct;
                double reorder_in_pct;
                double reorder_out_pct;
                const char *proto;

                if (flow->rx_packets == 0)
                    continue;
                (void)inet_ntop(AF_INET, &flow->key.src_ip, src, sizeof(src));
                (void)inet_ntop(AF_INET, &flow->key.dst_ip, dst, sizeof(dst));
                net_missing = flow->net_missing;
                estimated_drops = net_missing + flow->buffer_drops + flow->emit_drops;
                expected = flow->rx_packets + net_missing;
                loss_pct = expected
                    ? (double)estimated_drops * 100.0 / (double)expected : 0.0;
                reorder_in_pct = (double)flow->reordered_arrivals * 100.0 /
                    (double)flow->rx_packets;
                reorder_out_pct = (double)flow->late_or_duplicate * 100.0 /
                    (double)flow->rx_packets;
                proto = flow->key.protocol == IPPROTO_TCP ? "TCP" : "UDP";
                fprintf(stderr,
                        "[FLOW-STATS] scope=peer_seq_to_local_queue "
                        "%s %s:%u -> %s:%u worker=%u epoch=%u "
                        "rx=%llu gap_raw=%llu late_or_dup=%llu recovered=%llu "
                        "net_missing=%llu "
                        "buffer_drop=%llu duplicate_drop=%llu emit_drop=%llu "
                        "loss_est=%.4f%% "
                        "reorder_in=%llu(%.4f%%) reorder_out_est=%.4f%%\n",
                        proto, src, (unsigned int)flow->key.src_port,
                        dst, (unsigned int)flow->key.dst_port,
                        (unsigned int)flow->worker_idx, flow->epoch,
                        (unsigned long long)flow->rx_packets,
                        (unsigned long long)flow->gap_skipped,
                        (unsigned long long)flow->late_or_duplicate,
                        (unsigned long long)flow->late_recovered,
                        (unsigned long long)net_missing,
                        (unsigned long long)flow->buffer_drops,
                        (unsigned long long)flow->duplicate_drops,
                        (unsigned long long)flow->emit_drops,
                        loss_pct,
                        (unsigned long long)flow->reordered_arrivals,
                        reorder_in_pct, reorder_out_pct);
            }
        }

        {
            uint64_t worker_connections[NE_CRYPTO_WORKERS];
            uint64_t tx_connections[NE_TX_SLOTS];

            dp_route_connection_counts(worker_connections, tx_connections);
            fprintf(stderr, "[DP-STATS] tx_slot_gbps");
            for (int slot = 0; slot < (int)NE_TX_SLOTS; slot++) {
                uint64_t cur_lan = load64(&s_tx_lan_bytes[slot]);
                uint64_t cur_wan = load64(&s_tx_wan_bytes[slot]);
                double lan_rate = sec > 0.0
                    ? ((double)(cur_lan - s_prev_tx_lan_bytes[slot]) * 8.0 / sec) / 1e9
                    : 0.0;
                double wan_rate = sec > 0.0
                    ? ((double)(cur_wan - s_prev_tx_wan_bytes[slot]) * 8.0 / sec) / 1e9
                    : 0.0;

                s_prev_tx_lan_bytes[slot] = cur_lan;
                s_prev_tx_wan_bytes[slot] = cur_wan;
                fprintf(stderr, " tx%d(L=%.2fG W=%.2fG)", slot, lan_rate, wan_rate);
            }
            fprintf(stderr, "\n[DP-STATS] route_connections crypto=[");
            for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
                fprintf(stderr, "%s%llu", w ? "," : "",
                        (unsigned long long)worker_connections[w]);
            fprintf(stderr, "] tx=[");
            for (int slot = 0; slot < (int)NE_TX_SLOTS; slot++)
                fprintf(stderr, "%s%llu", slot ? "," : "",
                        (unsigned long long)tx_connections[slot]);
            fprintf(stderr, "]\n");
        }

        {
            char pps_buf[256];
            char qlan_buf[128];
            char qwan_buf[128];
            char drop_buf[128];
            size_t pps_n = 0, qlan_n = 0, qwan_n = 0, drop_n = 0;
            int busy_w = 0;
            uint32_t busy_depth = 0;

            pps_buf[0] = qlan_buf[0] = qwan_buf[0] = drop_buf[0] = '\0';
            for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
                uint64_t cur_lan = load64(&s_crypto_lan_pkts[w]);
                uint64_t cur_wan = load64(&s_crypto_wan_pkts[w]);
                uint64_t d_lan = cur_lan - s_prev_crypto_lan[w];
                uint64_t d_wan = cur_wan - s_prev_crypto_wan[w];
                uint32_t w_lan = ne_ring_count(&fwd->local_to_mid[w]);
                uint32_t w_wan = ne_ring_count(&fwd->wan_to_mid[w]);
                uint32_t w_depth = w_lan + w_wan;
                unsigned long long pps = 0;

                s_prev_crypto_lan[w] = cur_lan;
                s_prev_crypto_wan[w] = cur_wan;
                if (sec > 0.0)
                    pps = (unsigned long long)(((double)(d_lan + d_wan) / sec) + 0.5);
                pps_n += (size_t)snprintf(pps_buf + pps_n, sizeof(pps_buf) - pps_n,
                                          "%sw%d:%llu", pps_n ? " " : "", w, pps);
                qlan_n += (size_t)snprintf(qlan_buf + qlan_n, sizeof(qlan_buf) - qlan_n,
                                           "%s%u", qlan_n ? "," : "", w_lan);
                qwan_n += (size_t)snprintf(qwan_buf + qwan_n, sizeof(qwan_buf) - qwan_n,
                                           "%s%u", qwan_n ? "," : "", w_wan);
                drop_n += (size_t)snprintf(drop_buf + drop_n, sizeof(drop_buf) - drop_n,
                                           "%s%llu", drop_n ? "," : "",
                                           (unsigned long long)load64(&s_crypto_ring_drop[w]));
                if (pps_n >= sizeof(pps_buf))
                    pps_n = sizeof(pps_buf) - 1;
                if (qlan_n >= sizeof(qlan_buf))
                    qlan_n = sizeof(qlan_buf) - 1;
                if (qwan_n >= sizeof(qwan_buf))
                    qwan_n = sizeof(qwan_buf) - 1;
                if (drop_n >= sizeof(drop_buf))
                    drop_n = sizeof(drop_buf) - 1;
                if (w_depth > busy_depth) {
                    busy_depth = w_depth;
                    busy_w = w;
                }
            }
            fprintf(stderr,
                    "[DP-STATS] crypto pps=[%s] q_lan=[%s] q_wan=[%s] drop=[%s]\n",
                    pps_buf, qlan_buf, qwan_buf, drop_buf);
            if (busy_depth >= NE_DP_CRYPTO_Q_WATERMARK)
                fprintf(stderr,
                        "[DP-STATS] busiest_crypto=w%d depth=%u (watermark=%u)\n",
                        busy_w, busy_depth, NE_DP_CRYPTO_Q_WATERMARK);
        }
    }
    fflush(stderr);
}

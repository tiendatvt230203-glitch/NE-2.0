#include "../../../inc/core/dataplane/dataplane_stats.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/dataplane/udp_reorder.h"
#include "../../../inc/core/forwarder/forwarder.h"
#include "../../../inc/core/iface/interface.h"

#include <stdatomic.h>
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

#define NE_DP_CRYPTO_Q_WATERMARK (NE_RING / 4u)

void ne_dp_stats_init(void)
{
    if (g_on < 0) {
        const char *env = getenv("NE_DP_STATS");
        g_on = (env && env[0] == '1') ? 1 : 0;
        if (g_on)
            fprintf(stderr, "[DP-STATS] enabled (set NE_DP_STATS=0 to disable)\n");
    }
    clock_gettime(CLOCK_MONOTONIC, &s_last_ts);
    memset(s_prev, 0, sizeof(s_prev));
    memset(s_prev_crypto_lan, 0, sizeof(s_prev_crypto_lan));
    memset(s_prev_crypto_wan, 0, sizeof(s_prev_crypto_wan));
    memset(s_prev_tx_lan_bytes, 0, sizeof(s_prev_tx_lan_bytes));
    memset(s_prev_tx_wan_bytes, 0, sizeof(s_prev_tx_wan_bytes));
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

void ne_dp_stats_tick(struct forwarder *fwd)
{
    struct timespec now;
    double sec;
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
            "[DP-STATS] %.1fs LAN_RX=%s WAN_RX=%s TX_WAN=%s TX_LAN=%s "
            "bypass=%llu local_drop=%llu wan_fwd=%llu wan_drop=%llu "
            "wan_policy_drop=%llu "
            "rx_ring_drop(lan=%llu wan=%llu) mid_ring_drop=%llu\n",
            sec, lan_g, wan_g, tx_wan_g, tx_lan_g,
            (unsigned long long)load64(&s_local_bypass),
            (unsigned long long)load64(&s_local_drop),
            (unsigned long long)load64(&s_wan_fwd),
            (unsigned long long)load64(&s_wan_drop),
            (unsigned long long)load64(&s_wan_policy_drop),
            (unsigned long long)load64(&s_rx_ring_drop_lan[0]),
            (unsigned long long)load64(&s_rx_ring_drop_wan[0]),
            (unsigned long long)load64(&s_mid_ring_drop));

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
        fprintf(stderr,
                "[DP-STATS] ring_depth lan_to_mid=%u wan_to_mid=%u "
                "mid_to_wan=%u mid_to_local=%u tx_no_free(wan0)=%llu "
                "tx_full(lan=%llu wan=%llu) pool_free=%u\n",
                lan_q, wan_q, mid_wan_q, mid_lan_q,
                fwd->wan_count > 0
                    ? (unsigned long long)fwd->pair.wans[0].tx_no_free : 0ULL,
                (unsigned long long)load64(&s_tx_full_lan[0]),
                (unsigned long long)load64(&s_tx_full_wan[0]),
                ne_pool_free_count(&fwd->pair));

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
            struct dp_udp_reorder_stats reorder;

            dp_udp_reorder_get_stats(&reorder);
            fprintf(stderr,
                    "[DP-STATS] bond_reorder held=%llu released=%llu "
                    "late_dup=%llu gap_skip=%llu overflow=%llu evicted=%llu "
                    "held_high_water=%llu\n",
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

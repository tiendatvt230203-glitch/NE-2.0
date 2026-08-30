#include "../../../inc/core/forwarder/forwarder.h"
#include "../../../inc/core/forwarder/forwarder_wan.h"
#include "../../../inc/core/forwarder/forwarder_reload.h"
#include "../../../inc/core/forwarder/forwarder_crypto_runtime.h"
#include "../../../inc/core/failover/wan_failover.h"
#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/core/dataplane/dataplane.h"
#include "../../../inc/core/dataplane/crypto_route.h"

#include "../../../inc/core/util/main_diag.h"
#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/iface/profile_iface_xdp.h"
#include "../../../inc/core/flow/mac_learn.h"
#include "../../../inc/core/flow/flow_table.h"
#include "../../../inc/core/dataplane/dataplane_stats.h"
#include "../../../inc/core/dataplane/dp_idle.h"
#include "../../../inc/crypto/pqc_handshake.h"

#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
static atomic_int running = 1;
static pthread_mutex_t runtime_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t tx_maint_tick;

static void dp_maint_tick(struct forwarder *fwd)
{
    if (!fwd)
        return;
    fwd_crypto_maybe_expire_prev_grace();
    fwd_crypto_pqc_key_lifetime_tick();
    fwd_wan_drain_tick(fwd);
    fwd_wan_weight_blend_tick();
    mac_learn_tick(fwd);
    ne_dp_stats_tick(fwd);
}
static void pin_cpu(unsigned int cpu)
{
    cpu_set_t cpuset;
    int rc;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    rc = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    if (rc != 0) {
        fprintf(stderr, "[DP-CONF] cannot pin thread to CPU%u: %s\n",
                cpu, strerror(rc));
        fflush(stderr);
    }
}

static int dataplane_uses_cpu(int cpu)
{
    for (uint32_t i = 0; i < NE_RX_LAN_SLOTS; i++)
        if ((int)NE_CPU_RX_LAN[i] == cpu)
            return 1;
    for (uint32_t i = 0; i < NE_TX_SLOTS; i++)
        if ((int)NE_CPU_TX[i] == cpu)
            return 1;
    for (uint32_t i = 0; i < NE_CRYPTO_WORKERS; i++)
        if ((int)NE_CPU_CRYPTO[i] == cpu)
            return 1;
    for (uint32_t i = 0; i < NE_RX_WAN_SLOTS; i++)
        if ((int)NE_CPU_RX_WAN[i] == cpu)
            return 1;
    return 0;
}

void forwarder_pin_cpu(void)
{
    static atomic_int logged;
    cpu_set_t allowed;

    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0)
        return;
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &allowed) || dataplane_uses_cpu(cpu))
            continue;
        pin_cpu((unsigned int)cpu);
        if (!atomic_exchange_explicit(&logged, 1, memory_order_relaxed))
            fprintf(stderr, "[DP-CONF] control/DB threads pinned to spare CPU%d\n", cpu);
        return;
    }

    /* Never force control/DB work onto RX_LAN CPU0 when every CPU is reserved. */
    if (!atomic_exchange_explicit(&logged, 1, memory_order_relaxed))
        fprintf(stderr, "[DP-CONF] no spare housekeeping CPU; control threads left unpinned\n");
}

void forwarder_runtime_lock(void)
{
    pthread_mutex_lock(&runtime_lock);
}

void forwarder_runtime_unlock(void)
{
    pthread_mutex_unlock(&runtime_lock);
}

#define DP_TX_BURST_MAX   8

static void dp_burst_refill_local(struct forwarder *fwd, int rx_slot)
{
    ne_refill_fq_local_slot(&fwd->pair, rx_slot);
}

static void dp_burst_refill_wan(struct forwarder *fwd, int rx_slot)
{
    ne_refill_fq_wan_slot(&fwd->pair, rx_slot);
}


/*
 * Crypto worker and TX slot are independent. Each TX slot has one MPSC ring
 * and exactly one TX consumer, preserving order within every sticky flow.
 */
static int tx_collect_worker_rings(struct ne_ring *out[], struct ne_ring *per_worker,
                                   int tx_slot, int nslots)
{
    if (nslots < 1)
        nslots = 1;
    if (tx_slot < 0 || tx_slot >= nslots)
        return 0;
    out[0] = &per_worker[tx_slot];
    return 1;
}

static int tx_slot_has_pending(const struct forwarder *fwd, int tx_slot)
{
    if (!fwd || tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;
    for (int li = 0; li < fwd->local_count; li++) {
        if (ne_ring_count(&fwd->mid_to_local[li][tx_slot]))
            return 1;
    }
    for (int wi = 0; wi < fwd->wan_count; wi++) {
        if (ne_ring_count(&fwd->mid_to_wan[wi][tx_slot]))
            return 1;
    }
    return 0;
}

static int forwarder_active_tx_slots(const struct forwarder *fwd)
{
    int slots = (int)NE_TX_SLOTS;
    int found = 0;

    if (!fwd)
        return 1;
    for (int li = 0; li < fwd->local_count; li++) {
        if (!fwd->pair.local_live[li])
            continue;
        found = 1;
        if (fwd->pair.locals[li].queue_count < slots)
            slots = fwd->pair.locals[li].queue_count;
    }
    for (int wi = 0; wi < fwd->wan_count; wi++) {
        if (!fwd->pair.wan_live[wi])
            continue;
        found = 1;
        if (fwd->pair.wans[wi].queue_count < slots)
            slots = fwd->pair.wans[wi].queue_count;
    }
    return found && slots > 0 ? slots : 1;
}
static int dp_burst_tx_local(struct forwarder *fwd, int local_idx, int tx_slot)
{
    struct ne_ring *rings[NE_CRYPTO_WORKERS];
    int nring;
    int total = 0;

    if (!ne_pair_local_live(&fwd->pair, local_idx))
        return 0;

    ne_dp_tx_ctx("LAN", tx_slot);

    nring = tx_collect_worker_rings(rings, fwd->mid_to_local[local_idx], tx_slot,
                                    (int)NE_TX_SLOTS);
    if (nring <= 0)
        return 0;

    for (int burst = 0; burst < DP_TX_BURST_MAX; burst++) {
        int sent = ne_tx_drain_local_all(&fwd->pair, rings, nring, local_idx, tx_slot);
        if (sent <= 0)
            break;
        total += sent;
    }
    return total;
}

static int dp_tx_wan_once(struct forwarder *fwd, int wan_idx, int tx_slot)
{
    struct ne_ring *rings[NE_CRYPTO_WORKERS];
    int nring;

    if (!ne_pair_wan_live(&fwd->pair, wan_idx))
        return 0;

    ne_dp_tx_ctx("WAN", tx_slot);

    nring = tx_collect_worker_rings(rings, fwd->mid_to_wan[wan_idx], tx_slot,
                                    (int)NE_TX_SLOTS);
    if (nring <= 0)
        return 0;

    return ne_tx_drain_wan_all(&fwd->pair, rings, nring, wan_idx, tx_slot);
}

struct dp_tx_slot_ctx {
    struct forwarder *fwd;
    int tx_slot;
    uint8_t cpu_id;
};

struct dp_rx_slot_ctx {
    struct forwarder *fwd;
    int rx_slot;
    uint8_t cpu_id;
};

static void init_iface_meta(struct fwd_iface *iface, const char *ifname)
{
    memset(iface, 0, sizeof(*iface));
    iface->ifindex = (int)if_nametoindex(ifname);
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    iface->ifname[sizeof(iface->ifname) - 1] = '\0';
}

static uint32_t resolve_runtime_frag_mtu(const struct app_config *cfg)
{
    int sockfd;
    uint32_t min_mtu = NE_MAX_MTU;
    int found = 0;

    if (!cfg)
        return CRYPTO_OPT_FRAG_MTU_DEFAULT;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return CRYPTO_OPT_FRAG_MTU_DEFAULT;

    for (int wi = 0; wi < cfg->wan_count; wi++) {
        struct ifreq ifr;
        if (!cfg->wans[wi].dataplane)
            continue;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, cfg->wans[wi].ifname, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(sockfd, SIOCGIFMTU, &ifr) != 0)
            continue;
        if (ifr.ifr_mtu >= 576 && (uint32_t)ifr.ifr_mtu <= NE_MAX_MTU &&
            (uint32_t)ifr.ifr_mtu < min_mtu)
            min_mtu = (uint32_t)ifr.ifr_mtu;
        if (ifr.ifr_mtu >= 576)
            found = 1;
    }

    close(sockfd);
    return found ? min_mtu : CRYPTO_OPT_FRAG_MTU_DEFAULT;
}

static void *local_rx_thread(void *arg)
{
    struct dp_rx_slot_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet batch[NE_BATCH_SIZE];
    struct ne_dp_idle idle = {0};

    pin_cpu(ctx->cpu_id);
    (void)flow_table_thread_init();

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        dp_burst_refill_local(fwd, ctx->rx_slot);

        int rcvd = ne_recv_local_slot(&fwd->pair, ctx->rx_slot, batch, NE_BATCH_SIZE);
        /* Multi-buffer peek can end in the middle of a packet and produce no
         * complete job. Always release consumed descriptors; RX buffers whose
         * ownership moved to a job are deliberately not returned to FQ here. */
        ne_recv_release_local_slot(&fwd->pair, ctx->rx_slot);
        if (rcvd <= 0) {
            int fds[NE_DP_POLLFD_MAX];
            int nfds;

            ne_dp_warn_rx("LAN", (int)ctx->cpu_id, 0);
            ne_kick_fq_local_slot(&fwd->pair, ctx->rx_slot);
            if (ne_dp_idle_arm(&idle, -1)) {
                nfds = ne_rx_local_fds(&fwd->pair, ctx->rx_slot, fds, NE_DP_POLLFD_MAX);
                ne_dp_idle_poll(-1, fds, nfds);
            }
            continue;
        }
        ne_dp_idle_note_work(&idle);

        {
            uint64_t rx_bytes = 0;
            for (int i = 0; i < rcvd; i++)
                rx_bytes += batch[i].len;
            ne_dp_stats_rx_lan(ctx->rx_slot, (uint32_t)rcvd, rx_bytes);
        }

        for (int i = 0; i < rcvd; i++) {
            const uint8_t *pkt = ne_packet_data(&fwd->pair, batch[i].addr);
            int li = batch[i].local_idx < fwd->local_count ? (int)batch[i].local_idx : 0;

            if (dataplane_local_needs_mid(fwd, pkt, batch[i].len, li)) {
                int tx_slot;
                int wi = dp_crypto_pick_local_worker(pkt, batch[i].len, &tx_slot);

                batch[i].tx_slot = (uint8_t)tx_slot;
                if (ne_ring_try_push(&fwd->local_to_mid[wi], &batch[i]) != 0) {
                    ne_dp_warn_rx_drop("LAN", (int)ctx->cpu_id, wi,
                                       ne_ring_count(&fwd->local_to_mid[wi]));
                    ne_dp_stats_rx_ring_drop_lan(ctx->rx_slot, 1);
                    ne_dp_stats_crypto_ring_drop(wi, 1);
                    ne_frame_free(&fwd->pair, batch[i].addr);
                } else {
                    ne_dp_idle_wake(NE_DP_WAKE_CRYPTO(wi));
                }
                continue;
            }
            /* Bypass / ARP: RX → TX slot ring. Crypto cores unused. */
            dp_out_ring_bind(dp_pick_tx_slot(pkt, batch[i].len));
            dataplane_process_local(fwd, batch[i]);
        }
    }
    flow_table_thread_cleanup();
    return NULL;
}

static void *tx_thread(void *arg)
{
    struct dp_tx_slot_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    int tx_slot = ctx->tx_slot;
    uint32_t wan_cursor = (uint32_t)tx_slot;
    struct ne_dp_idle idle = {0};

    pin_cpu(ctx->cpu_id);
    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;

        if (tx_slot == 0 && pthread_mutex_trylock(&runtime_lock) == 0) {
            (void)fwd_reload_apply_if_pending();
            if ((++tx_maint_tick & 1023u) == 0)
                dp_maint_tick(fwd);
            pthread_mutex_unlock(&runtime_lock);
        }

        /* Each CQ helper already drains its owned queues until empty. */
        ne_drain_cq_local(&fwd->pair, tx_slot);
        ne_drain_cq_wan(&fwd->pair, tx_slot);
        for (int li = 0; li < fwd->local_count; li++)
            did_work += dp_burst_tx_local(fwd, li, tx_slot);
        /* Interleave one XSK batch per WAN and rotate the first WAN each
         * round. The old loop could emit 8*32 frames on WAN0 before touching
         * WAN1, amplifying cross-path skew even after smooth scheduling. */
        for (int burst = 0; burst < DP_TX_BURST_MAX && fwd->wan_count > 0; burst++) {
            int round_work = 0;

            for (int off = 0; off < fwd->wan_count; off++) {
                int wi = (int)((wan_cursor + (uint32_t)off) %
                               (uint32_t)fwd->wan_count);

                if (fwd_wan_is_stopped(wi))
                    continue;
                round_work += dp_tx_wan_once(fwd, wi, tx_slot);
            }
            did_work += round_work;
            wan_cursor = (wan_cursor + 1u) % (uint32_t)fwd->wan_count;
            if (round_work == 0)
                break;
        }
        if (did_work)
            ne_dp_idle_note_work(&idle);
        else if (ne_dp_idle_arm(&idle, NE_DP_WAKE_TX(tx_slot))) {
            if (tx_slot_has_pending(fwd, tx_slot)) {
                ne_dp_idle_disarm(NE_DP_WAKE_TX(tx_slot));
                ne_dp_idle_note_work(&idle);
            } else {
                ne_dp_idle_poll(NE_DP_WAKE_TX(tx_slot), NULL, 0);
            }
        }
    }
    return NULL;
}

static void *wan_rx_thread(void *arg)
{
    struct dp_rx_slot_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet batch[NE_BATCH_SIZE];
    struct ne_dp_idle idle = {0};

    pin_cpu(ctx->cpu_id);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        dp_burst_refill_wan(fwd, ctx->rx_slot);

        int rcvd = ne_recv_wan_slot(&fwd->pair, ctx->rx_slot, batch, NE_BATCH_SIZE);
        ne_recv_release_wan_slot(&fwd->pair, ctx->rx_slot);
        if (rcvd <= 0) {
            int fds[NE_DP_POLLFD_MAX];
            int nfds;

            ne_dp_warn_rx("WAN", (int)ctx->cpu_id, 0);
            ne_kick_fq_wan_slot(&fwd->pair, ctx->rx_slot);
            if (ne_dp_idle_arm(&idle, -1)) {
                nfds = ne_rx_wan_fds(&fwd->pair, ctx->rx_slot, fds, NE_DP_POLLFD_MAX);
                ne_dp_idle_poll(-1, fds, nfds);
            }
            continue;
        }
        ne_dp_idle_note_work(&idle);

        {
            uint64_t rx_bytes = 0;
            for (int i = 0; i < rcvd; i++)
                rx_bytes += batch[i].len;
            ne_dp_stats_rx_wan(ctx->rx_slot, (uint32_t)rcvd, rx_bytes);
        }

        for (int i = 0; i < rcvd; i++) {
            int wi;
            const uint8_t *pkt;

            if (batch[i].wan_idx < MAX_INTERFACES && fwd_wan_is_stopped(batch[i].wan_idx)) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            pkt = ne_packet_data(&fwd->pair, batch[i].addr);
            if (dataplane_wan_needs_mid(fwd, pkt, batch[i].len)) {
                wi = dp_crypto_pick_wan_worker(fwd, pkt, batch[i].len);
                if (wi < 0 || wi >= (int)NE_CRYPTO_WORKERS) {
                    ne_dp_stats_wan_drop(1);
                    ne_frame_free(&fwd->pair, batch[i].addr);
                    continue;
                }
                if (ne_ring_try_push(&fwd->wan_to_mid[wi], &batch[i]) != 0) {
                    ne_dp_warn_rx_drop("WAN", (int)ctx->cpu_id, wi,
                                       ne_ring_count(&fwd->wan_to_mid[wi]));
                    ne_dp_stats_rx_ring_drop_wan(ctx->rx_slot, 1);
                    ne_dp_stats_crypto_ring_drop(wi, 1);
                    ne_frame_free(&fwd->pair, batch[i].addr);
                } else {
                    ne_dp_idle_wake(NE_DP_WAKE_CRYPTO(wi));
                }
                continue;
            }
            /* Bypass / ARP: RX → TX slot ring. Crypto cores unused. */
            dp_out_ring_bind(dp_pick_tx_slot(pkt, batch[i].len));
            dataplane_process_wan(fwd, batch[i]);
        }
    }
    return NULL;
}

struct crypto_worker_ctx {
    struct forwarder *fwd;
    int worker_idx;
    uint8_t cpu_id;
};

static void crypto_idle_pause(struct forwarder *fwd, struct ne_dp_idle *idle, int worker_idx)
{
    int wake_id = NE_DP_WAKE_CRYPTO(worker_idx);

    if (ne_dp_idle_arm(idle, wake_id)) {
        if (ne_ring_count(&fwd->local_to_mid[worker_idx]) ||
            ne_ring_count(&fwd->wan_to_mid[worker_idx])) {
            ne_dp_idle_disarm(wake_id);
            ne_dp_idle_note_work(idle);
            return;
        }
        ne_dp_idle_poll(wake_id, NULL, 0);
    }
}

static void *crypto_worker_thread(void *arg)
{
    struct crypto_worker_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet job;
    uint32_t gc_tick = 0;
    struct ne_dp_idle idle = {0};

    pin_cpu(ctx->cpu_id);
    dp_crypto_worker_bind(ctx->worker_idx);
    crypto_option_bind_worker_idx((uint8_t)ctx->worker_idx);
    crypto_l2_pqc_bind_pair(&fwd->pair);
    (void)flow_table_thread_init();

    /* Encrypt / decrypt / reasm only. Bypass never queues here. */
    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;
        int crypto_on = fwd->cfg && fwd->cfg->crypto_enabled;

        /* Always dequeue: ARP (fixed-key) + encrypt. Bypass is never queued. */
        if (ne_ring_try_pop(&fwd->wan_to_mid[ctx->worker_idx], &job) == 0) {
            dataplane_process_wan(fwd, job);
            ne_dp_stats_crypto_wan(ctx->worker_idx, 1);
            did_work = 1;
        }
        if (ne_ring_try_pop(&fwd->local_to_mid[ctx->worker_idx], &job) == 0) {
            dp_out_ring_bind(job.tx_slot);
            dataplane_process_local(fwd, job);
            ne_dp_stats_crypto_lan(ctx->worker_idx, 1);
            did_work = 1;
        }
        if (crypto_on && ++gc_tick >= 2048) {
            fwd_crypto_frag_gc_worker_tick(ctx->worker_idx);
            dataplane_bond_reorder_gc(fwd, ctx->worker_idx);
            gc_tick = 0;
        }

        if (did_work)
            ne_dp_idle_note_work(&idle);
        else
            crypto_idle_pause(fwd, &idle, ctx->worker_idx);
    }
    dataplane_bond_reorder_reset(fwd, ctx->worker_idx);
    flow_table_thread_cleanup();
    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg || cfg->local_count <= 0)
        return -1;
    if (forwarder_should_stop())
        return -1;
    if (config_count_dataplane_wans(cfg) <= 0) {
        fprintf(stderr,
                "[FWD] no dataplane WAN — LAN-only until a dataplane WAN is added\n");
        fflush(stderr);
    }
    if (interface_validate_mtu_topology(cfg) != 0)
        return -1;

    memset(fwd, 0, sizeof(*fwd));
    dataplane_bond_reorder_configure();
    fwd->cfg = cfg;
    fwd->local_count = cfg->local_count;
    fwd->wan_count = config_count_dataplane_wans(cfg);
    if (fwd->local_count > MAX_INTERFACES)
        fwd->local_count = MAX_INTERFACES;
    if (fwd->wan_count > MAX_INTERFACES)
        fwd->wan_count = MAX_INTERFACES;

    crypto_option_set_mtu(resolve_runtime_frag_mtu(cfg));
    fprintf(stderr, "[FRAG] runtime MTU set to %u\n", crypto_option_get_mtu());
    ne_dp_stats_init();
    ne_dp_idle_init();

    for (int i = 0; i < fwd->local_count; i++)
        init_iface_meta(&fwd->locals[i], cfg->locals[i].ifname);
    for (int di = 0; di < fwd->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            return -1;
        fwd->wan_cfg_idx[di] = ci;
        init_iface_meta(&fwd->wans[di], cfg->wans[ci].ifname);
    }

    profile_iface_xdp_prepare_init(cfg);

    if (forwarder_should_stop())
        return -1;

    if (fwd_crypto_rebuild(cfg) != 0)
        return -1;
    if (forwarder_should_stop())
        return -1;

    fwd_crypto_reset_on_init();

    pqc_handshake_start_all_profiles(cfg);

    if (ne_pair_open(&fwd->pair, cfg) != 0)
        return -1;
    if (profile_iface_xdp_attach_init(&fwd->pair, cfg) != 0) {
        forwarder_cleanup(fwd);
        return -1;
    }
    if (forwarder_should_stop()) {
        forwarder_cleanup(fwd);
        return -1;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        if (ne_ring_init(&fwd->local_to_mid[w], NE_RING, 0) != 0 ||
            ne_ring_init(&fwd->wan_to_mid[w], NE_RING, 0) != 0) {
            forwarder_cleanup(fwd);
            return -1;
        }
    }
    for (int i = 0; i < fwd->local_count; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            if (ne_ring_init(&fwd->mid_to_local[i][w], NE_RING, 0) != 0) {
                forwarder_cleanup(fwd);
                return -1;
            }
        }
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            if (ne_ring_init(&fwd->mid_to_wan[i][w], NE_RING, 0) != 0) {
                forwarder_cleanup(fwd);
                return -1;
            }
        }
    }

    fwd_wan_reset_on_init(fwd);
    // MAC_LEARN
    mac_learn_bootstrap(&fwd->mac_table);
    mac_learn_refresh_iface_macs(fwd);
    mac_learn_restore(fwd);
    // MAC_LEARN
    if (wan_failover_start(fwd) != 0) {
        fprintf(stderr, "[FWD] wan_failover_start failed\n");
        fflush(stderr);
    }
    atomic_store_explicit(&running, 1, memory_order_release);
    return 0;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    if (!fwd)
        return;
    wan_failover_stop();
    // MAC_LEARN
    mac_learn_persist(fwd);
    mac_learn_shutdown(&fwd->mac_table);
    // MAC_LEARN
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        ne_ring_destroy(&fwd->local_to_mid[w]);
        ne_ring_destroy(&fwd->wan_to_mid[w]);
    }
    for (int i = 0; i < MAX_INTERFACES; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
            ne_ring_destroy(&fwd->mid_to_wan[i][w]);
    }
    for (int i = 0; i < MAX_INTERFACES; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
            ne_ring_destroy(&fwd->mid_to_local[i][w]);
    }
    ne_pair_close(&fwd->pair, fwd->cfg);
    ne_dp_idle_shutdown();
}

static void forwarder_join_started(struct forwarder *fwd, int local_rx_started, int tx_started,
                                   int crypto_started, int wan_rx_started)
{
    atomic_store_explicit(&running, 0, memory_order_release);
    ne_dp_idle_wake_all();
    for (int w = 0; w < local_rx_started; w++)
        pthread_join(fwd->local_rx_threads[w], NULL);
    for (int w = 0; w < tx_started; w++)
        pthread_join(fwd->tx_threads[w], NULL);
    for (int w = 0; w < crypto_started; w++)
        pthread_join(fwd->crypto_threads[w], NULL);
    for (int w = 0; w < wan_rx_started; w++)
        pthread_join(fwd->wan_rx_threads[w], NULL);
}

void forwarder_run(struct forwarder *fwd)
{
    struct crypto_worker_ctx crypto_ctx[NE_CRYPTO_WORKERS];
    struct dp_tx_slot_ctx tx_ctx[NE_TX_SLOTS];
    struct dp_rx_slot_ctx local_rx_ctx[NE_RX_LAN_SLOTS];
    struct dp_rx_slot_ctx wan_rx_ctx[NE_RX_WAN_SLOTS];
    int crypto_started = 0;
    int active_tx_slots;
    int local_rx_started = 0, tx_started = 0, wan_rx_started = 0;

    if (!fwd || forwarder_should_stop())
        return;

    if (ne_cpu_map_validate() != 0)
        return;

    active_tx_slots = forwarder_active_tx_slots(fwd);
    dp_route_set_active_tx_slots((uint32_t)active_tx_slots);
    fprintf(stderr, "[DP-CONF] active TX slots=%d (configured=%u, limited by XSK queues)\n",
            active_tx_slots, (unsigned)NE_TX_SLOTS);

    {
        int lan_rx_active = ne_rx_lan_slots_for(fwd->pair.local_queue_total);

        for (int w = 0; w < lan_rx_active; w++) {
            local_rx_ctx[w].fwd = fwd;
            local_rx_ctx[w].rx_slot = w;
            local_rx_ctx[w].cpu_id = ne_cpu_rx_lan((uint32_t)w);
            if (pthread_create(&fwd->local_rx_threads[w], NULL, local_rx_thread, &local_rx_ctx[w]) != 0) {
                forwarder_join_started(fwd, local_rx_started, 0, 0, 0);
                return;
            }
            local_rx_started++;
        }
    }

    for (int w = 0; w < active_tx_slots; w++) {
        tx_ctx[w].fwd = fwd;
        tx_ctx[w].tx_slot = w;
        tx_ctx[w].cpu_id = ne_cpu_tx((uint32_t)w);
        if (pthread_create(&fwd->tx_threads[w], NULL, tx_thread, &tx_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx_started, tx_started, 0, 0);
            return;
        }
        tx_started++;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        crypto_ctx[w].fwd = fwd;
        crypto_ctx[w].worker_idx = w;
        crypto_ctx[w].cpu_id = ne_cpu_crypto((uint32_t)w);
        if (pthread_create(&fwd->crypto_threads[w], NULL, crypto_worker_thread, &crypto_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx_started, tx_started, crypto_started, 0);
            return;
        }
        crypto_started++;
    }

    {
        int wan_rx_active = ne_rx_wan_slots_for(fwd->pair.wan_queue_total);

        for (int w = 0; w < wan_rx_active; w++) {
            wan_rx_ctx[w].fwd = fwd;
            wan_rx_ctx[w].rx_slot = w;
            wan_rx_ctx[w].cpu_id = ne_cpu_rx_wan((uint32_t)w);
            if (pthread_create(&fwd->wan_rx_threads[w], NULL, wan_rx_thread, &wan_rx_ctx[w]) != 0) {
                forwarder_join_started(fwd, local_rx_started, tx_started, crypto_started,
                                       wan_rx_started);
                return;
            }
            wan_rx_started++;
        }
    }

    fwd->threads_started = 1;
    if (fwd->cfg) {
        ne_cpu_map_log();
        fwd_crypto_sync_pqc_session_keys(fwd->cfg);
        main_diag_log_dataplane_ready(fwd);
    }
    for (int w = 0; w < local_rx_started; w++)
        pthread_join(fwd->local_rx_threads[w], NULL);
    for (int w = 0; w < (int)NE_TX_SLOTS; w++)
        pthread_join(fwd->tx_threads[w], NULL);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        pthread_join(fwd->crypto_threads[w], NULL);
    for (int w = 0; w < wan_rx_started; w++)
        pthread_join(fwd->wan_rx_threads[w], NULL);
    fwd->threads_started = 0;
}

void forwarder_stop(void)
{
    atomic_store_explicit(&running, 0, memory_order_release);
    ne_dp_idle_wake_all();
}

void forwarder_clear_stop(void)
{
    atomic_store_explicit(&running, 1, memory_order_release);
}

void forwarder_shutdown_resources(void)
{
    fwd_reload_shutdown();
}

int forwarder_should_stop(void)
{
    return atomic_load_explicit(&running, memory_order_acquire) == 0;
}

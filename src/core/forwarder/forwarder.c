#include "../../../inc/core/forwarder/forwarder.h"
#include "../../../inc/crypto/l2_crypto.h"
#include "../../../inc/core/dataplane/dataplane.h"
#include "../../../inc/core/dataplane/crypto_route.h"

#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/iface/xdp_attach.h"
#include "../../../inc/core/dataplane/dp_idle.h"

#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
static atomic_int running = 1;

static uint64_t core_stats_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static uint64_t core_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void core_stats_tick(struct forwarder *fwd)
{
    static uint64_t last_ms;
    struct ne_xdp_socket_stats lan_xdp;
    struct ne_xdp_socket_stats wan_xdp;
    uint64_t tx_no_free_lan = 0, tx_no_free_wan = 0;
    uint64_t multibuf_lan = 0, multibuf_wan = 0;
    uint32_t local_to_mid = 0, wan_to_mid = 0;
    uint32_t mid_to_local = 0, mid_to_wan = 0;
    uint64_t now;

    if (!fwd || !fwd->cfg)
        return;
    now = core_stats_now_ms();
    if (!now || now - last_ms < 1000u)
        return;
    last_ms = now;

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        local_to_mid += ne_ring_count(&fwd->local_to_mid[w]);
        wan_to_mid += ne_ring_count(&fwd->wan_to_mid[w]);
        for (int i = 0; i < fwd->local_count; i++)
            mid_to_local += ne_ring_count(&fwd->mid_to_local[i][w]);
        for (int i = 0; i < fwd->wan_count; i++)
            mid_to_wan += ne_ring_count(&fwd->mid_to_wan[i][w]);
    }
    for (int i = 0; i < fwd->pair.local_count; i++) {
        tx_no_free_lan += __atomic_load_n(&fwd->pair.locals[i].tx_no_free,
                                          __ATOMIC_RELAXED);
        for (int q = 0; q < fwd->pair.locals[i].queue_count; q++)
            multibuf_lan += __atomic_load_n(
                &fwd->pair.locals[i].queues[q].rx_chain_dropped,
                __ATOMIC_RELAXED);
    }
    for (int i = 0; i < fwd->pair.wan_count; i++) {
        tx_no_free_wan += __atomic_load_n(&fwd->pair.wans[i].tx_no_free,
                                          __ATOMIC_RELAXED);
        for (int q = 0; q < fwd->pair.wans[i].queue_count; q++)
            multibuf_wan += __atomic_load_n(
                &fwd->pair.wans[i].queues[q].rx_chain_dropped,
                __ATOMIC_RELAXED);
    }
    ne_pair_xdp_socket_stats(&fwd->pair, &lan_xdp, &wan_xdp);
    fprintf(stderr,
            "[CORE-DIAG-STATS] pool=%u/%u rings=%u/%u/%u/%u "
            "tx_no_free=%llu/%llu multibuf=%llu/%llu "
            "xdp_drop=%llu/%llu invalid_rx=%llu/%llu invalid_tx=%llu/%llu\n",
            ne_pool_free_count(&fwd->pair), fwd->pair.n_frames,
            local_to_mid, wan_to_mid, mid_to_wan, mid_to_local,
            (unsigned long long)tx_no_free_wan,
            (unsigned long long)tx_no_free_lan,
            (unsigned long long)multibuf_wan,
            (unsigned long long)multibuf_lan,
            (unsigned long long)wan_xdp.rx_dropped,
            (unsigned long long)lan_xdp.rx_dropped,
            (unsigned long long)wan_xdp.rx_invalid_descs,
            (unsigned long long)lan_xdp.rx_invalid_descs,
            (unsigned long long)wan_xdp.tx_invalid_descs,
            (unsigned long long)lan_xdp.tx_invalid_descs);
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

static int dp_burst_tx_wan(struct forwarder *fwd, int wan_idx, int tx_slot)
{
    struct ne_ring *rings[NE_CRYPTO_WORKERS];
    int nring;
    int total = 0;

    if (!ne_pair_wan_live(&fwd->pair, wan_idx))
        return 0;

    ne_dp_tx_ctx("WAN", tx_slot);

    nring = tx_collect_worker_rings(rings, fwd->mid_to_wan[wan_idx], tx_slot,
                                    (int)NE_TX_SLOTS);
    if (nring <= 0)
        return 0;

    for (int burst = 0; burst < DP_TX_BURST_MAX; burst++) {
        int sent = ne_tx_drain_wan_all(&fwd->pair, rings, nring, wan_idx, tx_slot);
        if (sent <= 0)
            break;
        total += sent;
    }
    return total;
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

static void *local_rx_thread(void *arg)
{
    struct dp_rx_slot_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet batch[NE_BATCH_SIZE];
    struct ne_dp_idle idle = {0};

    pin_cpu(ctx->cpu_id);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        dp_burst_refill_local(fwd, ctx->rx_slot);

        int rcvd = ne_recv_local_slot(&fwd->pair, ctx->rx_slot, batch, NE_BATCH_SIZE);
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
                    ne_packet_free(&fwd->pair, &batch[i]);
                } else {
                    ne_dp_idle_wake(NE_DP_WAKE_CRYPTO(wi));
                }
                continue;
            }
            /* Direct handling is retained only for an explicit fast drop path. */
            dp_out_ring_bind(dp_pick_tx_slot(pkt, batch[i].len));
            dataplane_process_local(fwd, batch[i]);
        }
        ne_recv_release_local_slot(&fwd->pair, ctx->rx_slot);
    }
    return NULL;
}

static void *tx_thread(void *arg)
{
    struct dp_tx_slot_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    int tx_slot = ctx->tx_slot;
    struct ne_dp_idle idle = {0};

    pin_cpu(ctx->cpu_id);
    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;

        if (tx_slot == 0)
            core_stats_tick(fwd);

        /* Each CQ helper already drains its owned queues until empty. */
        ne_drain_cq_local(&fwd->pair, tx_slot);
        ne_drain_cq_wan(&fwd->pair, tx_slot);
        for (int li = 0; li < fwd->local_count; li++)
            did_work += dp_burst_tx_local(fwd, li, tx_slot);
        for (int wi = 0; wi < fwd->wan_count; wi++) {
            did_work += dp_burst_tx_wan(fwd, wi, tx_slot);
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

        for (int i = 0; i < rcvd; i++) {
            int wi;
            const uint8_t *pkt;

            pkt = ne_packet_data(&fwd->pair, batch[i].addr);
            if (dataplane_wan_needs_mid(fwd, pkt, batch[i].len)) {
                wi = dp_crypto_pick_wan_worker(fwd, pkt, batch[i].len);
                if (wi < 0 || wi >= (int)NE_CRYPTO_WORKERS) {
                    ne_packet_free(&fwd->pair, &batch[i]);
                    continue;
                }
                if (ne_ring_try_push(&fwd->wan_to_mid[wi], &batch[i]) != 0) {
                    ne_dp_warn_rx_drop("WAN", (int)ctx->cpu_id, wi,
                                       ne_ring_count(&fwd->wan_to_mid[wi]));
                    ne_packet_free(&fwd->pair, &batch[i]);
                } else {
                    ne_dp_idle_wake(NE_DP_WAKE_CRYPTO(wi));
                }
                continue;
            }
            /* Plaintext/unknown WAN frames reach this direct drop path. */
            dp_out_ring_bind(dp_pick_tx_slot(pkt, batch[i].len));
            dataplane_process_wan(fwd, batch[i]);
        }
        ne_recv_release_wan_slot(&fwd->pair, ctx->rx_slot);
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
    l2_crypto_bind_worker((uint8_t)ctx->worker_idx);

    /* Encrypt, decrypt and UDP reassembly only. */
    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;

        /* Always dequeue fixed-key L2 traffic. */
        if (ne_ring_try_pop(&fwd->wan_to_mid[ctx->worker_idx], &job) == 0) {
            dataplane_process_wan(fwd, job);
            did_work = 1;
        }
        if (ne_ring_try_pop(&fwd->local_to_mid[ctx->worker_idx], &job) == 0) {
            dp_out_ring_bind(job.tx_slot);
            dataplane_process_local(fwd, job);
            did_work = 1;
        }
        if (++gc_tick >= 2048) {
            l2_crypto_frag_gc(ctx->worker_idx, core_now_ns());
            gc_tick = 0;
        }

        if (did_work)
            ne_dp_idle_note_work(&idle);
        else
            crypto_idle_pause(fwd, &idle, ctx->worker_idx);
    }
    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg || cfg->local_count <= 0)
        return -1;
    if (forwarder_should_stop())
        return -1;
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    fwd->local_count = cfg->local_count;
    fwd->wan_count = cfg->wan_count;
    if (fwd->local_count > MAX_INTERFACES)
        fwd->local_count = MAX_INTERFACES;
    if (fwd->wan_count > MAX_INTERFACES)
        fwd->wan_count = MAX_INTERFACES;
    fprintf(stderr, "[CORE] debug mode: one LAN, one WAN\n");

    fprintf(stderr, "[FRAG] encrypted UDP wire MTU=%u\n", L2_CRYPTO_MTU);
    ne_dp_idle_init();

    for (int i = 0; i < fwd->local_count; i++)
        init_iface_meta(&fwd->locals[i], cfg->locals[i].ifname);
    for (int i = 0; i < fwd->wan_count; i++)
        init_iface_meta(&fwd->wans[i], cfg->wans[i].ifname);

    xdp_attach_prepare_init(cfg);

    if (forwarder_should_stop())
        return -1;

    if (packet_crypto_init(&fwd->crypto, cfg->key) != 0)
        return -1;
    if (ne_pair_open(&fwd->pair, cfg) != 0) {
        ne_dp_idle_shutdown();
        return -1;
    }
    if (xdp_attach_all(&fwd->pair, cfg) != 0) {
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

    atomic_store_explicit(&running, 1, memory_order_release);
    return 0;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    if (!fwd)
        return;
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

int forwarder_should_stop(void)
{
    return atomic_load_explicit(&running, memory_order_acquire) == 0;
}

#include "../../../inc/core/dataplane/udp_reorder.h"
#include "../../../inc/core/util/cpu_map.h"

#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define UDP_REORDER_SETS              64u
#define UDP_REORDER_WAYS              4u
#define UDP_REORDER_FLOW_CAP          (UDP_REORDER_SETS * UDP_REORDER_WAYS)
#define UDP_REORDER_WINDOW            2048u
#define UDP_REORDER_START_BACKTRACK   32u
#define UDP_REORDER_HELD_CAP          8192u
#define UDP_REORDER_GC_SLICE          16u
#define UDP_REORDER_MISSING_TRACK     256u
#define UDP_REORDER_FLOW_IDLE_NS      (60ULL * 1000000000ULL)
/* Default for low-latency bonded paths; NE_BOND_REORDER_US can override it. */
#define UDP_REORDER_DEFAULT_HOLD_NS   (2ULL * 1000000ULL)

struct udp_reorder_slot {
    struct dp_udp_reorder_item item;
    uint32_t seq;
    uint8_t valid;
};

struct udp_missing_slot {
    uint32_t seq;
    uint8_t valid;
};

struct udp_reorder_flow {
    struct dp_udp_reorder_key key;
    uint32_t epoch;
    uint32_t next_seq;
    uint64_t gap_since_ns;
    uint64_t last_seen_ns;
    uint64_t stamp;
    atomic_uint_fast64_t stat_rx_packets;
    atomic_uint_fast64_t stat_reordered_arrivals;
    atomic_uint_fast64_t stat_late_or_duplicate;
    atomic_uint_fast64_t stat_late_recovered;
    atomic_uint_fast64_t stat_gap_skipped;
    atomic_uint_fast64_t stat_net_missing;
    atomic_uint_fast64_t stat_buffer_drops;
    atomic_uint_fast64_t stat_duplicate_drops;
    atomic_uint_fast64_t stat_emit_drops;
    uint16_t held;
    uint8_t valid;
};

static struct udp_reorder_flow
    g_flows[NE_CRYPTO_WORKERS][UDP_REORDER_FLOW_CAP];
static struct udp_reorder_slot
    g_slots[NE_CRYPTO_WORKERS][UDP_REORDER_FLOW_CAP][UDP_REORDER_WINDOW];
static struct udp_missing_slot
    g_missing[NE_CRYPTO_WORKERS][UDP_REORDER_FLOW_CAP][UDP_REORDER_MISSING_TRACK];
static uint32_t g_held_by_worker[NE_CRYPTO_WORKERS];
static uint32_t g_gc_cursor[NE_CRYPTO_WORKERS];
static uint64_t g_stamp_by_worker[NE_CRYPTO_WORKERS];
static pthread_mutex_t g_flow_meta_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_hold_ns = UDP_REORDER_DEFAULT_HOLD_NS;
static int g_enabled = 1;

enum reorder_stat_proto {
    REORDER_STAT_TCP = 0,
    REORDER_STAT_UDP,
    REORDER_STAT_PROTO_COUNT,
};

static atomic_uint_fast64_t g_stat_held[REORDER_STAT_PROTO_COUNT];
static atomic_uint_fast64_t g_stat_released[REORDER_STAT_PROTO_COUNT];
static atomic_uint_fast64_t g_stat_late[REORDER_STAT_PROTO_COUNT];
static atomic_uint_fast64_t g_stat_gap[REORDER_STAT_PROTO_COUNT];
static atomic_uint_fast64_t g_stat_overflow[REORDER_STAT_PROTO_COUNT];
static atomic_uint_fast64_t g_stat_evicted[REORDER_STAT_PROTO_COUNT];
static atomic_uint_fast64_t g_stat_high_water;

static int stat_proto(uint8_t protocol)
{
    return protocol == IPPROTO_TCP ? REORDER_STAT_TCP : REORDER_STAT_UDP;
}

static int seq_delta(uint32_t seq, uint32_t base)
{
    return (int32_t)(seq - base);
}

static uint32_t key_hash(const struct dp_udp_reorder_key *key)
{
    uint32_t h = key->src_ip ^ (key->dst_ip * 0x9e3779b9u);

    h ^= ((uint32_t)key->src_port << 16) | key->dst_port;
    h ^= (uint32_t)key->protocol * 0x27d4eb2du;
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    return h ^ (h >> 16);
}

static int key_equal(const struct dp_udp_reorder_key *a,
                     const struct dp_udp_reorder_key *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->protocol == b->protocol;
}

static void item_drop(const struct dp_udp_reorder_ops *ops,
                      struct dp_udp_reorder_item *item)
{
    if (ops && ops->drop)
        ops->drop(ops->ctx, item);
}

static int item_emit(const struct dp_udp_reorder_ops *ops,
                     struct dp_udp_reorder_item *item, int was_held,
                     uint8_t protocol)
{
    int rc = (!ops || !ops->emit) ? -1 : ops->emit(ops->ctx, item);

    /* Negative means ownership was not consumed; positive means consumed but
     * dropped by the downstream queue. */
    if (rc < 0)
        item_drop(ops, item);
    if (was_held)
        atomic_fetch_add_explicit(&g_stat_released[stat_proto(protocol)], 1u,
                                  memory_order_relaxed);
    return rc;
}

static void update_high_water(uint32_t held)
{
    uint_fast64_t old = atomic_load_explicit(&g_stat_high_water,
                                             memory_order_relaxed);

    while (held > old &&
           !atomic_compare_exchange_weak_explicit(&g_stat_high_water, &old, held,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
    }
}

static void flow_record_gap(int worker_idx, uint32_t flow_idx,
                            uint32_t first_seq, uint32_t count)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    uint32_t tracked = count < UDP_REORDER_MISSING_TRACK
        ? count : UDP_REORDER_MISSING_TRACK;
    uint32_t seq = first_seq + count - tracked;

    atomic_fetch_add_explicit(&flow->stat_gap_skipped, count,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&flow->stat_net_missing, count,
                              memory_order_relaxed);
    for (uint32_t i = 0; i < tracked; i++, seq++) {
        struct udp_missing_slot *slot =
            &g_missing[worker_idx][flow_idx][seq % UDP_REORDER_MISSING_TRACK];

        slot->seq = seq;
        slot->valid = 1;
    }
}

static int flow_recover_gap(int worker_idx, uint32_t flow_idx, uint32_t seq)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    struct udp_missing_slot *slot =
        &g_missing[worker_idx][flow_idx][seq % UDP_REORDER_MISSING_TRACK];

    if (!slot->valid || slot->seq != seq)
        return 0;
    slot->valid = 0;
    if (atomic_load_explicit(&flow->stat_net_missing,
                             memory_order_relaxed) > 0)
        atomic_fetch_sub_explicit(&flow->stat_net_missing, 1u,
                                  memory_order_relaxed);
    atomic_fetch_add_explicit(&flow->stat_late_recovered, 1u,
                              memory_order_relaxed);
    return 1;
}

static void flow_drop_slots(int worker_idx, uint32_t flow_idx,
                            const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];

    for (uint32_t i = 0; i < UDP_REORDER_WINDOW; i++) {
        struct udp_reorder_slot *slot = &g_slots[worker_idx][flow_idx][i];

        if (!slot->valid)
            continue;
        item_drop(ops, &slot->item);
        memset(slot, 0, sizeof(*slot));
        if (g_held_by_worker[worker_idx] > 0)
            g_held_by_worker[worker_idx]--;
    }
    flow->held = 0;
    flow->gap_since_ns = 0;
}

static void flow_reset(int worker_idx, uint32_t flow_idx,
                       const struct dp_udp_reorder_key *key,
                       uint32_t epoch, uint32_t first_seq, uint64_t now_ns,
                       const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    uint32_t backtrack = first_seq < UDP_REORDER_START_BACKTRACK
        ? first_seq : UDP_REORDER_START_BACKTRACK;

    if (flow->valid)
        flow_drop_slots(worker_idx, flow_idx, ops);
    pthread_mutex_lock(&g_flow_meta_lock);
    memset(g_missing[worker_idx][flow_idx], 0,
           sizeof(g_missing[worker_idx][flow_idx]));
    memset(flow, 0, sizeof(*flow));
    flow->key = *key;
    flow->epoch = epoch;
    flow->next_seq = first_seq - backtrack;
    flow->gap_since_ns = backtrack ? now_ns : 0;
    flow->last_seen_ns = now_ns;
    flow->stamp = ++g_stamp_by_worker[worker_idx];
    flow->valid = 1;
    pthread_mutex_unlock(&g_flow_meta_lock);
}

static uint32_t flow_lookup(int worker_idx,
                            const struct dp_udp_reorder_key *key,
                            uint32_t epoch, uint32_t first_seq, uint64_t now_ns,
                            const struct dp_udp_reorder_ops *ops)
{
    uint32_t set = key_hash(key) & (UDP_REORDER_SETS - 1u);
    uint32_t base = set * UDP_REORDER_WAYS;
    uint32_t victim = base;

    for (uint32_t way = 0; way < UDP_REORDER_WAYS; way++) {
        uint32_t idx = base + way;
        struct udp_reorder_flow *flow = &g_flows[worker_idx][idx];

        if (flow->valid && key_equal(&flow->key, key)) {
            if (flow->epoch != epoch)
                flow_reset(worker_idx, idx, key, epoch, first_seq, now_ns, ops);
            flow->last_seen_ns = now_ns;
            flow->stamp = ++g_stamp_by_worker[worker_idx];
            return idx;
        }
        if (!flow->valid) {
            victim = idx;
            break;
        }
        if (flow->stamp < g_flows[worker_idx][victim].stamp)
            victim = idx;
    }
    if (g_flows[worker_idx][victim].valid)
        atomic_fetch_add_explicit(
            &g_stat_evicted[stat_proto(g_flows[worker_idx][victim].key.protocol)],
            1u, memory_order_relaxed);
    flow_reset(worker_idx, victim, key, epoch, first_seq, now_ns, ops);
    return victim;
}

static void flow_flush_contiguous(int worker_idx, uint32_t flow_idx,
                                  const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];

    for (;;) {
        struct udp_reorder_slot *slot =
            &g_slots[worker_idx][flow_idx][flow->next_seq % UDP_REORDER_WINDOW];

        if (!slot->valid || slot->seq != flow->next_seq)
            break;
        slot->valid = 0;
        if (flow->held > 0)
            flow->held--;
        if (g_held_by_worker[worker_idx] > 0)
            g_held_by_worker[worker_idx]--;
        flow->next_seq++;
        if (item_emit(ops, &slot->item, 1, flow->key.protocol) != 0)
            atomic_fetch_add_explicit(&flow->stat_emit_drops, 1u,
                                      memory_order_relaxed);
        memset(&slot->item, 0, sizeof(slot->item));
    }
    flow->gap_since_ns = flow->held ? flow->gap_since_ns : 0;
}

static int flow_smallest_ahead(int worker_idx, uint32_t flow_idx,
                               uint32_t *seq_out)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    int best_delta = INT32_MAX;
    uint32_t best_seq = 0;

    for (uint32_t i = 0; i < UDP_REORDER_WINDOW; i++) {
        struct udp_reorder_slot *slot = &g_slots[worker_idx][flow_idx][i];
        int delta;

        if (!slot->valid)
            continue;
        delta = seq_delta(slot->seq, flow->next_seq);
        if (delta >= 0 && delta < best_delta) {
            best_delta = delta;
            best_seq = slot->seq;
        }
    }
    if (best_delta == INT32_MAX)
        return -1;
    *seq_out = best_seq;
    return best_delta;
}

static void flow_skip_gap(int worker_idx, uint32_t flow_idx,
                          const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    uint32_t seq;
    int delta = flow_smallest_ahead(worker_idx, flow_idx, &seq);

    if (delta < 0) {
        flow->gap_since_ns = 0;
        return;
    }
    if (delta > 0) {
        uint32_t first_missing = flow->next_seq;

        flow->next_seq = seq;
        atomic_fetch_add_explicit(&g_stat_gap[stat_proto(flow->key.protocol)],
                                  (uint32_t)delta,
                                  memory_order_relaxed);
        flow_record_gap(worker_idx, flow_idx, first_missing, (uint32_t)delta);
    }
    flow_flush_contiguous(worker_idx, flow_idx, ops);
    if (flow->held)
        flow->gap_since_ns = flow->last_seen_ns;
}

static void flow_make_window_room(int worker_idx, uint32_t flow_idx,
                                  uint32_t seq,
                                  const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];

    while (flow->held && seq_delta(seq, flow->next_seq) >=
           (int)UDP_REORDER_WINDOW)
        flow_skip_gap(worker_idx, flow_idx, ops);
    if (seq_delta(seq, flow->next_seq) >= (int)UDP_REORDER_WINDOW) {
        uint32_t target = seq - (UDP_REORDER_WINDOW - 1u);
        uint32_t skipped = (uint32_t)seq_delta(target, flow->next_seq);
        uint32_t first_missing = flow->next_seq;

        flow->next_seq = target;
        atomic_fetch_add_explicit(&g_stat_gap[stat_proto(flow->key.protocol)],
                                  skipped, memory_order_relaxed);
        flow_record_gap(worker_idx, flow_idx, first_missing, skipped);
    }
}

void dp_udp_reorder_configure_from_env(void)
{
    const char *enabled = getenv("NE_BOND_REORDER");
    const char *hold_us = getenv("NE_BOND_REORDER_US");
    const char *enabled_name = "NE_BOND_REORDER";
    const char *hold_name = "NE_BOND_REORDER_US";

    /* Keep the old deployment knobs compatible. */
    if (!enabled) {
        enabled = getenv("NE_UDP_REORDER");
        enabled_name = enabled ? "NE_UDP_REORDER" : "default";
    }
    if (!hold_us) {
        hold_us = getenv("NE_UDP_REORDER_US");
        hold_name = hold_us ? "NE_UDP_REORDER_US" : "default";
    }

    /* forwarder_init() can run again after a profile reload. Recompute both
     * values from their defaults so a previous disabled/overridden profile
     * cannot leave reorder permanently disabled in this process. */
    g_enabled = !(enabled && enabled[0] == '0');
    g_hold_ns = UDP_REORDER_DEFAULT_HOLD_NS;
    if (hold_us && hold_us[0]) {
        char *end = NULL;
        unsigned long value = strtoul(hold_us, &end, 10);

        if (end != hold_us && *end == '\0') {
            if (value < 100)
                value = 100;
            if (value > 50000)
                value = 50000;
            g_hold_ns = (uint64_t)value * 1000ULL;
        }
    }

    fprintf(stderr,
            "[BOND-REORDER] enabled=%d hold_us=%llu enabled_source=%s "
            "hold_source=%s\n",
            g_enabled, (unsigned long long)(g_hold_ns / 1000ULL),
            enabled_name, hold_name);
}

uint64_t dp_udp_reorder_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void dp_udp_reorder_submit(int worker_idx,
                           const struct dp_udp_reorder_key *key,
                           uint32_t epoch, uint32_t seq,
                           struct dp_udp_reorder_item *item,
                           uint64_t now_ns,
                           const struct dp_udp_reorder_ops *ops)
{
    uint32_t flow_idx;
    struct udp_reorder_flow *flow;
    struct udp_reorder_slot *slot;
    int delta;

    if (!item || !key || worker_idx < 0 ||
        worker_idx >= (int)NE_CRYPTO_WORKERS || !g_enabled) {
        item_emit(ops, item, 0, key ? key->protocol : 0u);
        return;
    }
    flow_idx = flow_lookup(worker_idx, key, epoch, seq, now_ns, ops);
    flow = &g_flows[worker_idx][flow_idx];
    atomic_fetch_add_explicit(&flow->stat_rx_packets, 1u,
                              memory_order_relaxed);

    if (flow->held && flow->gap_since_ns &&
        now_ns - flow->gap_since_ns >= g_hold_ns)
        flow_skip_gap(worker_idx, flow_idx, ops);

    delta = seq_delta(seq, flow->next_seq);
    if (delta < 0) {
        /* A timeout may have released newer packets already. Never turn path
         * skew into transport loss: forward the late packet and let the
         * protocol endpoint decide whether it is useful or a duplicate. */
        atomic_fetch_add_explicit(&g_stat_late[stat_proto(key->protocol)], 1u,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&flow->stat_late_or_duplicate, 1u,
                                  memory_order_relaxed);
        (void)flow_recover_gap(worker_idx, flow_idx, seq);
        if (item_emit(ops, item, 0, key->protocol) != 0)
            atomic_fetch_add_explicit(&flow->stat_emit_drops, 1u,
                                      memory_order_relaxed);
        return;
    }
    if (delta == 0) {
        flow->next_seq++;
        if (item_emit(ops, item, 0, key->protocol) != 0)
            atomic_fetch_add_explicit(&flow->stat_emit_drops, 1u,
                                      memory_order_relaxed);
        flow_flush_contiguous(worker_idx, flow_idx, ops);
        return;
    }

    flow_make_window_room(worker_idx, flow_idx, seq, ops);
    delta = seq_delta(seq, flow->next_seq);
    if (delta < 0) {
        atomic_fetch_add_explicit(&g_stat_late[stat_proto(key->protocol)], 1u,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&flow->stat_late_or_duplicate, 1u,
                                  memory_order_relaxed);
        (void)flow_recover_gap(worker_idx, flow_idx, seq);
        if (item_emit(ops, item, 0, key->protocol) != 0)
            atomic_fetch_add_explicit(&flow->stat_emit_drops, 1u,
                                      memory_order_relaxed);
        return;
    }
    if (delta == 0) {
        flow->next_seq++;
        if (item_emit(ops, item, 0, key->protocol) != 0)
            atomic_fetch_add_explicit(&flow->stat_emit_drops, 1u,
                                      memory_order_relaxed);
        flow_flush_contiguous(worker_idx, flow_idx, ops);
        return;
    }
    if (g_held_by_worker[worker_idx] >= UDP_REORDER_HELD_CAP) {
        flow_skip_gap(worker_idx, flow_idx, ops);
        if (g_held_by_worker[worker_idx] >= UDP_REORDER_HELD_CAP) {
            atomic_fetch_add_explicit(&g_stat_overflow[stat_proto(key->protocol)],
                                      1u, memory_order_relaxed);
            atomic_fetch_add_explicit(&flow->stat_buffer_drops, 1u,
                                      memory_order_relaxed);
            item_drop(ops, item);
            return;
        }
    }

    slot = &g_slots[worker_idx][flow_idx][seq % UDP_REORDER_WINDOW];
    if (slot->valid) {
        if (slot->seq == seq) {
            atomic_fetch_add_explicit(&g_stat_late[stat_proto(key->protocol)], 1u,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&flow->stat_late_or_duplicate, 1u,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&flow->stat_duplicate_drops, 1u,
                                      memory_order_relaxed);
            item_drop(ops, item);
            return;
        }
        item_drop(ops, &slot->item);
        atomic_fetch_add_explicit(&g_stat_overflow[stat_proto(key->protocol)], 1u,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&flow->stat_buffer_drops, 1u,
                                  memory_order_relaxed);
    } else {
        flow->held++;
        g_held_by_worker[worker_idx]++;
    }
    slot->item = *item;
    slot->seq = seq;
    slot->valid = 1;
    if (!flow->gap_since_ns)
        flow->gap_since_ns = now_ns;
    atomic_fetch_add_explicit(&g_stat_held[stat_proto(key->protocol)], 1u,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&flow->stat_reordered_arrivals, 1u,
                              memory_order_relaxed);
    update_high_water(g_held_by_worker[worker_idx]);
}

void dp_udp_reorder_gc(int worker_idx, uint64_t now_ns,
                       const struct dp_udp_reorder_ops *ops)
{
    uint32_t cursor;

    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;
    cursor = g_gc_cursor[worker_idx];
    for (uint32_t n = 0; n < UDP_REORDER_GC_SLICE; n++) {
        uint32_t idx = (cursor + n) % UDP_REORDER_FLOW_CAP;
        struct udp_reorder_flow *flow = &g_flows[worker_idx][idx];

        if (!flow->valid)
            continue;
        if (flow->held && flow->gap_since_ns &&
            now_ns - flow->gap_since_ns >= g_hold_ns)
            flow_skip_gap(worker_idx, idx, ops);
        if (!flow->held && now_ns - flow->last_seen_ns > UDP_REORDER_FLOW_IDLE_NS) {
            pthread_mutex_lock(&g_flow_meta_lock);
            memset(g_missing[worker_idx][idx], 0,
                   sizeof(g_missing[worker_idx][idx]));
            memset(flow, 0, sizeof(*flow));
            pthread_mutex_unlock(&g_flow_meta_lock);
        }
    }
    g_gc_cursor[worker_idx] = (cursor + UDP_REORDER_GC_SLICE) %
        UDP_REORDER_FLOW_CAP;
}

void dp_udp_reorder_reset_worker(int worker_idx,
                                 const struct dp_udp_reorder_ops *ops)
{
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;
    for (uint32_t idx = 0; idx < UDP_REORDER_FLOW_CAP; idx++) {
        if (g_flows[worker_idx][idx].valid)
            flow_drop_slots(worker_idx, idx, ops);
        pthread_mutex_lock(&g_flow_meta_lock);
        memset(g_missing[worker_idx][idx], 0,
               sizeof(g_missing[worker_idx][idx]));
        memset(&g_flows[worker_idx][idx], 0,
               sizeof(g_flows[worker_idx][idx]));
        pthread_mutex_unlock(&g_flow_meta_lock);
    }
    g_held_by_worker[worker_idx] = 0;
    g_gc_cursor[worker_idx] = 0;
}

void dp_udp_reorder_get_stats(struct dp_udp_reorder_stats *out)
{
    uint64_t tcp_held, udp_held;
    uint64_t tcp_released, udp_released;
    uint64_t tcp_late, udp_late;
    uint64_t tcp_gap, udp_gap;
    uint64_t tcp_overflow, udp_overflow;
    uint64_t tcp_evicted, udp_evicted;

    if (!out)
        return;
    out->enabled = (uint8_t)g_enabled;
    out->hold_us = g_hold_ns / 1000ULL;
    tcp_held = atomic_load_explicit(&g_stat_held[REORDER_STAT_TCP], memory_order_relaxed);
    udp_held = atomic_load_explicit(&g_stat_held[REORDER_STAT_UDP], memory_order_relaxed);
    tcp_released = atomic_load_explicit(&g_stat_released[REORDER_STAT_TCP], memory_order_relaxed);
    udp_released = atomic_load_explicit(&g_stat_released[REORDER_STAT_UDP], memory_order_relaxed);
    tcp_late = atomic_load_explicit(&g_stat_late[REORDER_STAT_TCP], memory_order_relaxed);
    udp_late = atomic_load_explicit(&g_stat_late[REORDER_STAT_UDP], memory_order_relaxed);
    tcp_gap = atomic_load_explicit(&g_stat_gap[REORDER_STAT_TCP], memory_order_relaxed);
    udp_gap = atomic_load_explicit(&g_stat_gap[REORDER_STAT_UDP], memory_order_relaxed);
    tcp_overflow = atomic_load_explicit(&g_stat_overflow[REORDER_STAT_TCP], memory_order_relaxed);
    udp_overflow = atomic_load_explicit(&g_stat_overflow[REORDER_STAT_UDP], memory_order_relaxed);
    tcp_evicted = atomic_load_explicit(&g_stat_evicted[REORDER_STAT_TCP], memory_order_relaxed);
    udp_evicted = atomic_load_explicit(&g_stat_evicted[REORDER_STAT_UDP], memory_order_relaxed);
    out->held = tcp_held + udp_held;
    out->released = tcp_released + udp_released;
    out->late_or_duplicate = tcp_late + udp_late;
    out->gap_skipped = tcp_gap + udp_gap;
    out->overflow = tcp_overflow + udp_overflow;
    out->evicted = tcp_evicted + udp_evicted;
    out->high_water = atomic_load_explicit(&g_stat_high_water,
                                            memory_order_relaxed);
    out->tcp_held = tcp_held;
    out->tcp_released = tcp_released;
    out->tcp_late_or_duplicate = tcp_late;
    out->tcp_gap_skipped = tcp_gap;
    out->tcp_overflow = tcp_overflow;
    out->tcp_evicted = tcp_evicted;
    out->udp_held = udp_held;
    out->udp_released = udp_released;
    out->udp_late_or_duplicate = udp_late;
    out->udp_gap_skipped = udp_gap;
    out->udp_overflow = udp_overflow;
    out->udp_evicted = udp_evicted;
}

size_t dp_udp_reorder_get_flow_stats(struct dp_udp_reorder_flow_stats *out,
                                     size_t capacity)
{
    size_t count = 0;

    if (!out || capacity == 0)
        return 0;

    pthread_mutex_lock(&g_flow_meta_lock);
    for (int worker = 0; worker < (int)NE_CRYPTO_WORKERS; worker++) {
        for (uint32_t idx = 0; idx < UDP_REORDER_FLOW_CAP; idx++) {
            struct udp_reorder_flow *flow = &g_flows[worker][idx];
            struct dp_udp_reorder_flow_stats *dst;

            if (!flow->valid || count >= capacity)
                continue;
            dst = &out[count++];
            memset(dst, 0, sizeof(*dst));
            dst->key = flow->key;
            dst->epoch = flow->epoch;
            dst->rx_packets = atomic_load_explicit(&flow->stat_rx_packets,
                                                   memory_order_relaxed);
            dst->reordered_arrivals = atomic_load_explicit(
                &flow->stat_reordered_arrivals, memory_order_relaxed);
            dst->late_or_duplicate = atomic_load_explicit(
                &flow->stat_late_or_duplicate, memory_order_relaxed);
            dst->late_recovered = atomic_load_explicit(
                &flow->stat_late_recovered, memory_order_relaxed);
            dst->gap_skipped = atomic_load_explicit(&flow->stat_gap_skipped,
                                                    memory_order_relaxed);
            dst->net_missing = atomic_load_explicit(&flow->stat_net_missing,
                                                    memory_order_relaxed);
            dst->buffer_drops = atomic_load_explicit(&flow->stat_buffer_drops,
                                                     memory_order_relaxed);
            dst->duplicate_drops = atomic_load_explicit(
                &flow->stat_duplicate_drops, memory_order_relaxed);
            dst->emit_drops = atomic_load_explicit(&flow->stat_emit_drops,
                                                   memory_order_relaxed);
            dst->worker_idx = (uint8_t)worker;
        }
    }
    pthread_mutex_unlock(&g_flow_meta_lock);
    return count;
}

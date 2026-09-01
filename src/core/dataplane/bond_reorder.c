#define _POSIX_C_SOURCE 200809L

#include "bond_reorder_internal.h"
#include "../../../inc/core/util/cpu_map.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define REORDER_SETS              64u
#define REORDER_WAYS               4u
#define REORDER_FLOW_CAP          (REORDER_SETS * REORDER_WAYS)
#define REORDER_WINDOW            4096u
#define REORDER_START_BACKTRACK     32u
#define REORDER_HELD_CAP         32768u
#define REORDER_GC_SLICE            16u
#define REORDER_FLOW_IDLE_NS      (60ULL * 1000000000ULL)
#define REORDER_DEFAULT_HOLD_NS   (2ULL * 1000000ULL)

struct reorder_slot {
    struct dp_bond_reorder_item item;
    uint32_t seq;
    uint8_t valid;
};

struct reorder_flow {
    struct dp_bond_reorder_key key;
    uint32_t epoch;
    uint32_t next_seq;
    uint64_t gap_since_ns;
    uint64_t last_seen_ns;
    uint64_t stamp;
    uint16_t held;
    uint8_t valid;
};

struct reorder_worker {
    struct reorder_flow *flows;
    struct reorder_slot *slots;
    uint32_t held;
    uint32_t gc_cursor;
    uint64_t stamp;
};

struct reorder_engine {
    struct reorder_worker workers[NE_CRYPTO_WORKERS];
    uint64_t hold_ns;
    int enabled;
    atomic_uint_fast64_t stat_held;
    atomic_uint_fast64_t stat_released;
    atomic_uint_fast64_t stat_late;
    atomic_uint_fast64_t stat_duplicate;
    atomic_uint_fast64_t stat_gap;
    atomic_uint_fast64_t stat_overflow;
    atomic_uint_fast64_t stat_evicted;
    atomic_uint_fast64_t stat_high_water;
};

static struct reorder_engine g_engines[DP_BOND_REORDER_PROTOCOLS] = {
    [DP_BOND_REORDER_TCP] = {
        .hold_ns = REORDER_DEFAULT_HOLD_NS,
        .enabled = 1,
    },
    [DP_BOND_REORDER_UDP] = {
        .hold_ns = REORDER_DEFAULT_HOLD_NS,
        .enabled = 1,
    },
};

static int protocol_valid(enum dp_bond_reorder_protocol protocol)
{
    return protocol >= DP_BOND_REORDER_TCP &&
           protocol < DP_BOND_REORDER_PROTOCOLS;
}

static int protocol_drops_late(enum dp_bond_reorder_protocol protocol)
{
    return protocol == DP_BOND_REORDER_UDP;
}

static int seq_delta(uint32_t seq, uint32_t base)
{
    return (int32_t)(seq - base);
}

static uint32_t key_hash(const struct dp_bond_reorder_key *key)
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

static int key_equal(const struct dp_bond_reorder_key *a,
                     const struct dp_bond_reorder_key *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->protocol == b->protocol;
}

static struct reorder_slot *flow_slots(struct reorder_worker *worker,
                                       uint32_t flow_idx)
{
    return worker->slots + ((size_t)flow_idx * REORDER_WINDOW);
}

static int worker_prepare(struct reorder_worker *worker)
{
    if (worker->flows && worker->slots)
        return 0;
    if (!worker->flows)
        worker->flows = calloc(REORDER_FLOW_CAP, sizeof(*worker->flows));
    if (!worker->slots)
        worker->slots = calloc((size_t)REORDER_FLOW_CAP * REORDER_WINDOW,
                               sizeof(*worker->slots));
    if (!worker->flows || !worker->slots) {
        free(worker->flows);
        free(worker->slots);
        worker->flows = NULL;
        worker->slots = NULL;
        return -1;
    }
    return 0;
}

static void item_drop(const struct dp_bond_reorder_ops *ops,
                      struct dp_bond_reorder_item *item)
{
    if (ops && ops->drop)
        ops->drop(ops->ctx, item);
}

static void item_emit(struct reorder_engine *engine,
                      const struct dp_bond_reorder_ops *ops,
                      struct dp_bond_reorder_item *item, int was_held)
{
    if (!ops || !ops->emit || ops->emit(ops->ctx, item) != 0)
        item_drop(ops, item);
    if (was_held)
        atomic_fetch_add_explicit(&engine->stat_released, 1u,
                                  memory_order_relaxed);
}

static void item_late(enum dp_bond_reorder_protocol protocol,
                      struct reorder_engine *engine,
                      const struct dp_bond_reorder_ops *ops,
                      struct dp_bond_reorder_item *item)
{
    atomic_fetch_add_explicit(&engine->stat_late, 1u, memory_order_relaxed);
    if (protocol_drops_late(protocol))
        item_drop(ops, item);
    else
        item_emit(engine, ops, item, 0);
}

static void update_high_water(struct reorder_engine *engine, uint32_t held)
{
    uint_fast64_t old = atomic_load_explicit(&engine->stat_high_water,
                                             memory_order_relaxed);

    while (held > old &&
           !atomic_compare_exchange_weak_explicit(&engine->stat_high_water,
                                                  &old, held,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
    }
}

static void flow_drop_slots(struct reorder_worker *worker, uint32_t flow_idx,
                            const struct dp_bond_reorder_ops *ops)
{
    struct reorder_flow *flow = &worker->flows[flow_idx];
    struct reorder_slot *slots = flow_slots(worker, flow_idx);

    for (uint32_t i = 0; i < REORDER_WINDOW; i++) {
        if (!slots[i].valid)
            continue;
        item_drop(ops, &slots[i].item);
        memset(&slots[i], 0, sizeof(slots[i]));
        if (worker->held > 0)
            worker->held--;
    }
    flow->held = 0;
    flow->gap_since_ns = 0;
}

static void flow_reset(struct reorder_worker *worker, uint32_t flow_idx,
                       const struct dp_bond_reorder_key *key,
                       uint32_t epoch, uint32_t first_seq, uint64_t now_ns,
                       const struct dp_bond_reorder_ops *ops)
{
    struct reorder_flow *flow = &worker->flows[flow_idx];
    uint32_t backtrack = first_seq < REORDER_START_BACKTRACK
        ? first_seq : REORDER_START_BACKTRACK;

    if (flow->valid)
        flow_drop_slots(worker, flow_idx, ops);
    memset(flow, 0, sizeof(*flow));
    flow->key = *key;
    flow->epoch = epoch;
    flow->next_seq = first_seq - backtrack;
    flow->gap_since_ns = backtrack ? now_ns : 0;
    flow->last_seen_ns = now_ns;
    flow->stamp = ++worker->stamp;
    flow->valid = 1;
}

static uint32_t flow_lookup(struct reorder_engine *engine,
                            struct reorder_worker *worker,
                            const struct dp_bond_reorder_key *key,
                            uint32_t epoch, uint32_t first_seq, uint64_t now_ns,
                            const struct dp_bond_reorder_ops *ops)
{
    uint32_t set = key_hash(key) & (REORDER_SETS - 1u);
    uint32_t base = set * REORDER_WAYS;
    uint32_t victim = base;

    for (uint32_t way = 0; way < REORDER_WAYS; way++) {
        uint32_t idx = base + way;
        struct reorder_flow *flow = &worker->flows[idx];

        if (flow->valid && key_equal(&flow->key, key)) {
            if (flow->epoch != epoch)
                flow_reset(worker, idx, key, epoch, first_seq, now_ns, ops);
            flow->last_seen_ns = now_ns;
            flow->stamp = ++worker->stamp;
            return idx;
        }
        if (!flow->valid) {
            victim = idx;
            break;
        }
        if (flow->stamp < worker->flows[victim].stamp)
            victim = idx;
    }
    if (worker->flows[victim].valid)
        atomic_fetch_add_explicit(&engine->stat_evicted, 1u,
                                  memory_order_relaxed);
    flow_reset(worker, victim, key, epoch, first_seq, now_ns, ops);
    return victim;
}

static void flow_flush_contiguous(struct reorder_engine *engine,
                                  struct reorder_worker *worker,
                                  uint32_t flow_idx,
                                  const struct dp_bond_reorder_ops *ops)
{
    struct reorder_flow *flow = &worker->flows[flow_idx];
    struct reorder_slot *slots = flow_slots(worker, flow_idx);

    for (;;) {
        struct reorder_slot *slot = &slots[flow->next_seq % REORDER_WINDOW];

        if (!slot->valid || slot->seq != flow->next_seq)
            break;
        slot->valid = 0;
        if (flow->held > 0)
            flow->held--;
        if (worker->held > 0)
            worker->held--;
        flow->next_seq++;
        item_emit(engine, ops, &slot->item, 1);
        memset(&slot->item, 0, sizeof(slot->item));
    }
    flow->gap_since_ns = flow->held ? flow->gap_since_ns : 0;
}

static int flow_smallest_ahead(struct reorder_worker *worker, uint32_t flow_idx,
                               uint32_t *seq_out)
{
    struct reorder_flow *flow = &worker->flows[flow_idx];
    struct reorder_slot *slots = flow_slots(worker, flow_idx);
    int best_delta = INT32_MAX;
    uint32_t best_seq = 0;

    for (uint32_t i = 0; i < REORDER_WINDOW; i++) {
        int delta;

        if (!slots[i].valid)
            continue;
        delta = seq_delta(slots[i].seq, flow->next_seq);
        if (delta >= 0 && delta < best_delta) {
            best_delta = delta;
            best_seq = slots[i].seq;
        }
    }
    if (best_delta == INT32_MAX)
        return -1;
    *seq_out = best_seq;
    return best_delta;
}

static void flow_skip_gap(struct reorder_engine *engine,
                          struct reorder_worker *worker, uint32_t flow_idx,
                          const struct dp_bond_reorder_ops *ops)
{
    struct reorder_flow *flow = &worker->flows[flow_idx];
    uint32_t seq;
    int delta = flow_smallest_ahead(worker, flow_idx, &seq);

    if (delta < 0) {
        flow->gap_since_ns = 0;
        return;
    }
    if (delta > 0) {
        flow->next_seq = seq;
        atomic_fetch_add_explicit(&engine->stat_gap, (uint32_t)delta,
                                  memory_order_relaxed);
    }
    flow_flush_contiguous(engine, worker, flow_idx, ops);
    if (flow->held)
        flow->gap_since_ns = flow->last_seen_ns;
}

static void flow_make_window_room(struct reorder_engine *engine,
                                  struct reorder_worker *worker,
                                  uint32_t flow_idx, uint32_t seq,
                                  const struct dp_bond_reorder_ops *ops)
{
    struct reorder_flow *flow = &worker->flows[flow_idx];

    while (flow->held &&
           seq_delta(seq, flow->next_seq) >= (int)REORDER_WINDOW)
        flow_skip_gap(engine, worker, flow_idx, ops);
    if (seq_delta(seq, flow->next_seq) >= (int)REORDER_WINDOW) {
        uint32_t target = seq - (REORDER_WINDOW - 1u);
        uint32_t skipped = (uint32_t)seq_delta(target, flow->next_seq);

        flow->next_seq = target;
        atomic_fetch_add_explicit(&engine->stat_gap, skipped,
                                  memory_order_relaxed);
    }
}

void dp_bond_reorder_engine_configure(enum dp_bond_reorder_protocol protocol,
                                      const char *enable_env,
                                      const char *hold_env)
{
    struct reorder_engine *engine;
    const char *enabled;
    const char *hold_us;

    if (!protocol_valid(protocol))
        return;
    engine = &g_engines[protocol];
    engine->enabled = 1;
    engine->hold_ns = REORDER_DEFAULT_HOLD_NS;

    enabled = enable_env ? getenv(enable_env) : NULL;
    if (!enabled)
        enabled = getenv("NE_BOND_REORDER");

    hold_us = hold_env ? getenv(hold_env) : NULL;
    if (!hold_us)
        hold_us = getenv("NE_BOND_REORDER_US");

    if (enabled && enabled[0] == '0')
        engine->enabled = 0;
    if (hold_us && hold_us[0]) {
        char *end = NULL;
        unsigned long value = strtoul(hold_us, &end, 10);

        if (end != hold_us && *end == '\0') {
            if (value < 100)
                value = 100;
            if (value > 50000)
                value = 50000;
            engine->hold_ns = (uint64_t)value * 1000ULL;
        }
    }
}

uint64_t dp_bond_reorder_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void dp_bond_reorder_engine_submit(enum dp_bond_reorder_protocol protocol,
                                   int worker_idx,
                                   const struct dp_bond_reorder_key *key,
                                   uint32_t epoch, uint32_t seq,
                                   struct dp_bond_reorder_item *item,
                                   uint64_t now_ns,
                                   const struct dp_bond_reorder_ops *ops)
{
    struct reorder_engine *engine;
    struct reorder_worker *worker;
    struct reorder_flow *flow;
    struct reorder_slot *slot;
    uint32_t flow_idx;
    int delta;

    if (!protocol_valid(protocol) || !item || !key || worker_idx < 0 ||
        worker_idx >= (int)NE_CRYPTO_WORKERS) {
        item_drop(ops, item);
        return;
    }
    engine = &g_engines[protocol];
    if (!engine->enabled) {
        item_emit(engine, ops, item, 0);
        return;
    }
    worker = &engine->workers[worker_idx];
    if (worker_prepare(worker) != 0) {
        atomic_fetch_add_explicit(&engine->stat_overflow, 1u,
                                  memory_order_relaxed);
        if (protocol_drops_late(protocol))
            item_drop(ops, item);
        else
            item_emit(engine, ops, item, 0);
        return;
    }

    flow_idx = flow_lookup(engine, worker, key, epoch, seq, now_ns, ops);
    flow = &worker->flows[flow_idx];

    if (flow->held && flow->gap_since_ns &&
        now_ns - flow->gap_since_ns >= engine->hold_ns)
        flow_skip_gap(engine, worker, flow_idx, ops);

    delta = seq_delta(seq, flow->next_seq);
    if (delta < 0) {
        item_late(protocol, engine, ops, item);
        return;
    }
    if (delta == 0) {
        flow->next_seq++;
        item_emit(engine, ops, item, 0);
        flow_flush_contiguous(engine, worker, flow_idx, ops);
        return;
    }

    flow_make_window_room(engine, worker, flow_idx, seq, ops);
    delta = seq_delta(seq, flow->next_seq);
    if (delta < 0) {
        item_late(protocol, engine, ops, item);
        return;
    }
    if (delta == 0) {
        flow->next_seq++;
        item_emit(engine, ops, item, 0);
        flow_flush_contiguous(engine, worker, flow_idx, ops);
        return;
    }
    if (worker->held >= REORDER_HELD_CAP) {
        flow_skip_gap(engine, worker, flow_idx, ops);
        if (worker->held >= REORDER_HELD_CAP) {
            atomic_fetch_add_explicit(&engine->stat_overflow, 1u,
                                      memory_order_relaxed);
            item_drop(ops, item);
            return;
        }
    }

    slot = &flow_slots(worker, flow_idx)[seq % REORDER_WINDOW];
    if (slot->valid) {
        if (slot->seq == seq) {
            atomic_fetch_add_explicit(&engine->stat_duplicate, 1u,
                                      memory_order_relaxed);
            item_drop(ops, item);
            return;
        }
        item_drop(ops, &slot->item);
        atomic_fetch_add_explicit(&engine->stat_overflow, 1u,
                                  memory_order_relaxed);
    } else {
        flow->held++;
        worker->held++;
    }
    slot->item = *item;
    slot->seq = seq;
    slot->valid = 1;
    if (!flow->gap_since_ns)
        flow->gap_since_ns = now_ns;
    atomic_fetch_add_explicit(&engine->stat_held, 1u, memory_order_relaxed);
    update_high_water(engine, worker->held);
}

void dp_bond_reorder_engine_gc(enum dp_bond_reorder_protocol protocol,
                              int worker_idx, uint64_t now_ns,
                              const struct dp_bond_reorder_ops *ops)
{
    struct reorder_engine *engine;
    struct reorder_worker *worker;
    uint32_t cursor;

    if (!protocol_valid(protocol) || worker_idx < 0 ||
        worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;
    engine = &g_engines[protocol];
    worker = &engine->workers[worker_idx];
    if (!worker->flows || !worker->slots)
        return;

    cursor = worker->gc_cursor;
    for (uint32_t n = 0; n < REORDER_GC_SLICE; n++) {
        uint32_t idx = (cursor + n) % REORDER_FLOW_CAP;
        struct reorder_flow *flow = &worker->flows[idx];

        if (!flow->valid)
            continue;
        if (flow->held && flow->gap_since_ns &&
            now_ns - flow->gap_since_ns >= engine->hold_ns)
            flow_skip_gap(engine, worker, idx, ops);
        if (!flow->held && now_ns - flow->last_seen_ns > REORDER_FLOW_IDLE_NS)
            memset(flow, 0, sizeof(*flow));
    }
    worker->gc_cursor = (cursor + REORDER_GC_SLICE) % REORDER_FLOW_CAP;
}

void dp_bond_reorder_engine_reset(enum dp_bond_reorder_protocol protocol,
                                 int worker_idx,
                                 const struct dp_bond_reorder_ops *ops)
{
    struct reorder_worker *worker;

    if (!protocol_valid(protocol) || worker_idx < 0 ||
        worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;
    worker = &g_engines[protocol].workers[worker_idx];
    if (!worker->flows || !worker->slots)
        return;
    for (uint32_t idx = 0; idx < REORDER_FLOW_CAP; idx++) {
        if (worker->flows[idx].valid)
            flow_drop_slots(worker, idx, ops);
        memset(&worker->flows[idx], 0, sizeof(worker->flows[idx]));
    }
    worker->held = 0;
    worker->gc_cursor = 0;
}

void dp_bond_reorder_engine_stats(enum dp_bond_reorder_protocol protocol,
                                 struct dp_bond_reorder_stats *out)
{
    struct reorder_engine *engine;

    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!protocol_valid(protocol))
        return;
    engine = &g_engines[protocol];
    out->held = atomic_load_explicit(&engine->stat_held, memory_order_relaxed);
    out->released = atomic_load_explicit(&engine->stat_released, memory_order_relaxed);
    out->late = atomic_load_explicit(&engine->stat_late, memory_order_relaxed);
    out->duplicate_dropped = atomic_load_explicit(&engine->stat_duplicate,
                                                   memory_order_relaxed);
    out->gap_skipped = atomic_load_explicit(&engine->stat_gap, memory_order_relaxed);
    out->overflow = atomic_load_explicit(&engine->stat_overflow, memory_order_relaxed);
    out->evicted = atomic_load_explicit(&engine->stat_evicted, memory_order_relaxed);
    out->high_water = atomic_load_explicit(&engine->stat_high_water,
                                            memory_order_relaxed);
}

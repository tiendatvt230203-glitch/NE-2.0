#include "../../../inc/core/dataplane/udp_reorder.h"
#include "../../../inc/core/util/cpu_map.h"

#include <netinet/in.h>
#include <stdio.h>
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
#define UDP_REORDER_FLOW_IDLE_NS      (60ULL * 1000000000ULL)
/* Fixed UDP resequencing budget for the 2.5-3.5 ms bonded paths. */
#define UDP_REORDER_DEFAULT_HOLD_NS   (3ULL * 1000000ULL)

struct udp_reorder_slot {
    struct dp_udp_reorder_item item;
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
    uint16_t held;
    uint8_t valid;
};

static struct udp_reorder_flow
    g_flows[NE_CRYPTO_WORKERS][UDP_REORDER_FLOW_CAP];
static struct udp_reorder_slot
    g_slots[NE_CRYPTO_WORKERS][UDP_REORDER_FLOW_CAP][UDP_REORDER_WINDOW];
static uint32_t g_held_by_worker[NE_CRYPTO_WORKERS];
static uint32_t g_gc_cursor[NE_CRYPTO_WORKERS];
static uint64_t g_stamp_by_worker[NE_CRYPTO_WORKERS];
static uint64_t g_hold_ns = UDP_REORDER_DEFAULT_HOLD_NS;
static int g_enabled = 1;

static int seq_delta(uint32_t seq, uint32_t base)
{
    return (int32_t)(seq - base);
}

static uint32_t key_hash(const struct dp_udp_reorder_key *key)
{
    uint32_t h = key->src_ip ^ (key->dst_ip * 0x9e3779b9u);

    h ^= ((uint32_t)key->src_port << 16) | key->dst_port;
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
           a->src_port == b->src_port && a->dst_port == b->dst_port;
}

static void item_drop(const struct dp_udp_reorder_ops *ops,
                      struct dp_udp_reorder_item *item)
{
    if (ops && ops->drop)
        ops->drop(ops->ctx, item);
}

static int item_emit(const struct dp_udp_reorder_ops *ops,
                     struct dp_udp_reorder_item *item)
{
    int rc = (!ops || !ops->emit) ? -1 : ops->emit(ops->ctx, item);

    /* Negative means ownership was not consumed; positive means consumed but
     * dropped by the downstream queue. */
    if (rc < 0)
        item_drop(ops, item);
    return rc;
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

static void flow_release_all(int worker_idx, uint32_t flow_idx,
                             const struct dp_udp_reorder_ops *ops);

static void flow_reset(int worker_idx, uint32_t flow_idx,
                       const struct dp_udp_reorder_key *key,
                       uint32_t epoch, uint32_t first_seq, uint64_t now_ns,
                       const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    uint32_t backtrack = first_seq < UDP_REORDER_START_BACKTRACK
        ? first_seq : UDP_REORDER_START_BACKTRACK;

    if (flow->valid)
        flow_release_all(worker_idx, flow_idx, ops);
    memset(flow, 0, sizeof(*flow));
    flow->key = *key;
    flow->epoch = epoch;
    flow->next_seq = first_seq - backtrack;
    flow->gap_since_ns = backtrack ? now_ns : 0;
    flow->last_seen_ns = now_ns;
    flow->stamp = ++g_stamp_by_worker[worker_idx];
    flow->valid = 1;
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
    flow_reset(worker_idx, victim, key, epoch, first_seq, now_ns, ops);
    return victim;
}

static void flow_flush_contiguous(int worker_idx, uint32_t flow_idx,
                                  const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];

    for (;;) {
        struct udp_reorder_slot *slot =
            &g_slots[worker_idx][flow_idx]
                    [flow->next_seq & (UDP_REORDER_WINDOW - 1u)];

        if (!slot->valid || slot->seq != flow->next_seq)
            break;
        slot->valid = 0;
        if (flow->held > 0)
            flow->held--;
        if (g_held_by_worker[worker_idx] > 0)
            g_held_by_worker[worker_idx]--;
        flow->next_seq++;
        (void)item_emit(ops, &slot->item);
    }
    flow->gap_since_ns = flow->held ? flow->gap_since_ns : 0;
}

static int flow_smallest_ahead(int worker_idx, uint32_t flow_idx,
                               uint32_t *seq_out)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    for (uint32_t delta = 0; delta < UDP_REORDER_WINDOW; delta++) {
        uint32_t seq = flow->next_seq + delta;
        struct udp_reorder_slot *slot =
            &g_slots[worker_idx][flow_idx]
                    [seq & (UDP_REORDER_WINDOW - 1u)];

        if (slot->valid && slot->seq == seq) {
            *seq_out = seq;
            return (int)delta;
        }
    }
    return -1;
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
        flow->next_seq = seq;
    }
    flow_flush_contiguous(worker_idx, flow_idx, ops);
    if (flow->held)
        flow->gap_since_ns = flow->last_seen_ns;
}

/* Runtime pressure or an epoch/flow-table transition must not turn UDP
 * reordering into packet loss. Release everything already owned by this flow;
 * ordering may degrade briefly, but every unique packet is preserved. */
static void flow_release_all(int worker_idx, uint32_t flow_idx,
                             const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];

    while (flow->held) {
        uint16_t before = flow->held;

        flow_skip_gap(worker_idx, flow_idx, ops);
        if (flow->held < before)
            continue;

        /* Defensive recovery for inconsistent slot metadata. */
        for (uint32_t i = 0; i < UDP_REORDER_WINDOW; i++) {
            struct udp_reorder_slot *slot =
                &g_slots[worker_idx][flow_idx][i];

            if (!slot->valid)
                continue;
            (void)item_emit(ops, &slot->item);
            memset(slot, 0, sizeof(*slot));
            if (g_held_by_worker[worker_idx] > 0)
                g_held_by_worker[worker_idx]--;
        }
        flow->held = 0;
        flow->gap_since_ns = 0;
    }
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
        flow->next_seq = target;
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
        item_emit(ops, item);
        return;
    }
    flow_idx = flow_lookup(worker_idx, key, epoch, seq, now_ns, ops);
    flow = &g_flows[worker_idx][flow_idx];
    if (flow->held && flow->gap_since_ns &&
        now_ns - flow->gap_since_ns >= g_hold_ns)
        flow_skip_gap(worker_idx, flow_idx, ops);

    delta = seq_delta(seq, flow->next_seq);
    if (delta < 0) {
        /* A timeout may have released newer packets already. Never turn path
         * skew into transport loss: forward the late packet and let the
         * protocol endpoint decide whether it is useful or a duplicate. */
        (void)item_emit(ops, item);
        return;
    }
    if (delta == 0) {
        flow->next_seq++;
        (void)item_emit(ops, item);
        flow_flush_contiguous(worker_idx, flow_idx, ops);
        return;
    }

    flow_make_window_room(worker_idx, flow_idx, seq, ops);
    delta = seq_delta(seq, flow->next_seq);
    if (delta < 0) {
        (void)item_emit(ops, item);
        return;
    }
    if (delta == 0) {
        flow->next_seq++;
        (void)item_emit(ops, item);
        flow_flush_contiguous(worker_idx, flow_idx, ops);
        return;
    }
    if (g_held_by_worker[worker_idx] >= UDP_REORDER_HELD_CAP) {
        flow_release_all(worker_idx, flow_idx, ops);
        if (g_held_by_worker[worker_idx] >= UDP_REORDER_HELD_CAP) {
            if (seq_delta(seq, flow->next_seq) >= 0)
                flow->next_seq = seq + 1u;
            flow->gap_since_ns = 0;
            (void)item_emit(ops, item);
            return;
        }
        delta = seq_delta(seq, flow->next_seq);
        if (delta <= 0) {
            if (delta == 0)
                flow->next_seq++;
            (void)item_emit(ops, item);
            return;
        }
    }

    slot = &g_slots[worker_idx][flow_idx]
                   [seq & (UDP_REORDER_WINDOW - 1u)];
    if (slot->valid) {
        if (slot->seq == seq) {
            /* A true duplicate carries no new UDP datagram. */
            item_drop(ops, item);
            return;
        }
        /* A modulo collision indicates that this flow outran its window.
         * Fail open instead of replacing and dropping a unique held packet. */
        flow_release_all(worker_idx, flow_idx, ops);
        if (seq_delta(seq, flow->next_seq) >= 0)
            flow->next_seq = seq + 1u;
        flow->gap_since_ns = 0;
        (void)item_emit(ops, item);
        return;
    } else {
        flow->held++;
        g_held_by_worker[worker_idx]++;
    }
    slot->item = *item;
    slot->seq = seq;
    slot->valid = 1;
    if (!flow->gap_since_ns)
        flow->gap_since_ns = now_ns;
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
            memset(flow, 0, sizeof(*flow));
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
        memset(&g_flows[worker_idx][idx], 0,
               sizeof(g_flows[worker_idx][idx]));
    }
    g_held_by_worker[worker_idx] = 0;
    g_gc_cursor[worker_idx] = 0;
}

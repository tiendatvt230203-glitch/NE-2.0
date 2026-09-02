#include "../../../inc/core/flow/flow_table.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define FLOW_WINDOW_SETS       512u
#define FLOW_WINDOW_WAYS         4u
#define FLOW_WINDOW_BYTES   120000u

struct flow_window_state {
    struct flow_key key;
    int wans[MAX_INTERFACES];
    int64_t swrr_current[MAX_INTERFACES];
    uint64_t byte_debt[MAX_INTERFACES];
    uint64_t window_used;
    uint64_t window_target;
    uint64_t stamp;
    uint32_t hash_seed;
    uint32_t path_mtu;
    int current_wan;
    uint8_t current_pos;
    uint8_t wan_count;
    uint8_t tie_start;
    uint8_t has_current;
    uint8_t valid;
};

static _Thread_local struct flow_window_state (*g_flow_windows)[FLOW_WINDOW_WAYS];
static _Thread_local struct flow_window_state g_default_swrr;
static _Thread_local uint64_t g_flow_window_clock;

int flow_table_thread_init(void)
{
    if (g_flow_windows)
        return 0;
    g_flow_windows = calloc(FLOW_WINDOW_SETS, sizeof(*g_flow_windows));
    return g_flow_windows ? 0 : -1;
}

void flow_table_thread_cleanup(void)
{
    free(g_flow_windows);
    g_flow_windows = NULL;
    memset(&g_default_swrr, 0, sizeof(g_default_swrr));
    g_flow_window_clock = 0;
}

static void normalize_flow_5tuple(uint32_t *src_ip, uint32_t *dst_ip,
                                  uint16_t *src_port, uint16_t *dst_port)
{
    uint32_t a;
    uint32_t b;

    if (!src_ip || !dst_ip || !src_port || !dst_port)
        return;
    a = ntohl(*src_ip);
    b = ntohl(*dst_ip);
    if (a > b || (a == b && *src_port > *dst_port)) {
        uint32_t tmp_ip = *src_ip;
        uint16_t tmp_port = *src_port;

        *src_ip = *dst_ip;
        *dst_ip = tmp_ip;
        *src_port = *dst_port;
        *dst_port = tmp_port;
    }
}

static uint32_t flow_hash(uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t protocol)
{
    uint32_t hash = src_ip ^ dst_ip;

    hash ^= ((uint32_t)src_port << 16) | dst_port;
    hash ^= protocol;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    return hash ^ (hash >> 16);
}

static int flow_window_pool_same(const struct flow_window_state *state,
                                 const int *allowed_wans, int allowed_count)
{
    if (!state || !state->valid || state->wan_count != (uint8_t)allowed_count)
        return 0;
    for (int i = 0; i < allowed_count; i++) {
        if (state->wans[i] != allowed_wans[i])
            return 0;
    }
    return 1;
}

static void flow_window_reset(struct flow_window_state *state,
                              const struct flow_key *key, uint32_t hash,
                              const int *allowed_wans, int allowed_count)
{
    memset(state, 0, sizeof(*state));
    if (key)
        state->key = *key;
    for (int i = 0; i < allowed_count; i++)
        state->wans[i] = allowed_wans[i];
    state->wan_count = (uint8_t)allowed_count;
    state->hash_seed = hash;
    state->tie_start = (uint8_t)(allowed_count > 0 ? hash % (uint32_t)allowed_count : 0u);
    state->current_wan = -1;
    state->valid = 1;
}

/* Retained for packets without a parseable 5-tuple. */
static int flow_swrr_pick_default(struct flow_window_state *state,
                                  const int *allowed_wans,
                                  const int *allowed_weights,
                                  int allowed_count)
{
    int best = -1;
    int64_t best_current = INT64_MIN;
    int64_t total = 0;

    if (!state || !allowed_wans || allowed_count <= 0)
        return 0;
    if (allowed_count == 1)
        return allowed_wans[0];

    for (int i = 0; i < allowed_count; i++) {
        int weight = allowed_weights ? allowed_weights[i] : 1;

        if (weight <= 0)
            continue;
        state->swrr_current[i] += weight;
        total += weight;
    }
    if (total <= 0)
        return allowed_wans[state->tie_start++ % allowed_count];

    for (int off = 0; off < allowed_count; off++) {
        int i = (state->tie_start + off) % allowed_count;
        int weight = allowed_weights ? allowed_weights[i] : 1;

        if (weight <= 0)
            continue;
        if (best < 0 || state->swrr_current[i] > best_current) {
            best = i;
            best_current = state->swrr_current[i];
        }
    }
    if (best < 0)
        best = 0;
    state->swrr_current[best] -= total;
    state->tie_start = (uint8_t)((best + 1) % allowed_count);
    return allowed_wans[best];
}

static uint64_t flow_window_limit(const int *allowed_weights, int allowed_count,
                                  int pos, uint32_t path_mtu)
{
    uint64_t floor_sum = 0;
    uint64_t position_units;
    uint64_t remaining_units;
    uint64_t total_units;
    uint64_t total = 0;
    int weight;

    if (allowed_count <= 0 || pos < 0 || pos >= allowed_count)
        return path_mtu ? path_mtu : FLOW_WINDOW_BYTES;
    if (!path_mtu)
        path_mtu = 1500u;
    weight = allowed_weights ? allowed_weights[pos] : 1;
    if (weight <= 0)
        return 0;
    for (int i = 0; i < allowed_count; i++) {
        int w = allowed_weights ? allowed_weights[i] : 1;

        if (w > 0)
            total += (uint64_t)w;
    }
    if (!total)
        return FLOW_WINDOW_BYTES;

    /* Reserve one MTU unit per live WAN, then use largest-remainder for the
     * rest. This keeps every quota MTU-aligned and preserves cycle size. */
    total_units = (FLOW_WINDOW_BYTES / path_mtu);
    if (!total_units)
        total_units = 1;
    total_units *= (uint64_t)allowed_count;
    remaining_units = total_units - (uint64_t)allowed_count;
    position_units = 1u + (remaining_units * (uint64_t)weight) / total;
    for (int i = 0; i < allowed_count; i++) {
        int w = allowed_weights ? allowed_weights[i] : 1;

        if (w > 0)
            floor_sum += (remaining_units * (uint64_t)w) / total;
    }
    {
        uint64_t leftovers = remaining_units - floor_sum;
        uint64_t position_rem = (remaining_units * (uint64_t)weight) % total;
        uint64_t rank = 0;

        for (int i = 0; i < allowed_count; i++) {
            int w = allowed_weights ? allowed_weights[i] : 1;
            uint64_t rem;

            if (w <= 0 || i == pos)
                continue;
            rem = (remaining_units * (uint64_t)w) % total;
            if (rem > position_rem || (rem == position_rem && i < pos))
                rank++;
        }
        if (rank < leftovers)
            position_units++;
    }
    return position_units * (uint64_t)path_mtu;
}

static uint64_t flow_window_align_target(uint64_t target, uint32_t path_mtu)
{
    uint64_t units;

    if (!path_mtu)
        return target ? target : 1u;
    units = (target + (uint64_t)path_mtu / 2u) / path_mtu;
    if (!units)
        units = 1;
    return units * (uint64_t)path_mtu;
}

static int flow_window_first_pos(const struct flow_window_state *state,
                                 const int *allowed_weights, int allowed_count)
{
    uint64_t total = 0;
    uint64_t slot;
    uint64_t accumulated = 0;

    for (int i = 0; i < allowed_count; i++) {
        int weight = allowed_weights ? allowed_weights[i] : 1;

        if (weight > 0)
            total += (uint64_t)weight;
    }
    if (!total)
        return state->tie_start % allowed_count;
    slot = state->hash_seed % total;
    for (int i = 0; i < allowed_count; i++) {
        int weight = allowed_weights ? allowed_weights[i] : 1;

        if (weight <= 0)
            continue;
        accumulated += (uint64_t)weight;
        if (slot < accumulated)
            return i;
    }
    return 0;
}

static int flow_window_start(struct flow_window_state *state,
                             const int *allowed_wans,
                             const int *allowed_weights,
                             int allowed_count, int first)
{
    uint64_t base;
    int pos;

    if (!state || !allowed_wans || allowed_count <= 0)
        return 0;
    pos = first ? flow_window_first_pos(state, allowed_weights, allowed_count)
                : (state->current_pos + 1u) % allowed_count;
    state->current_pos = (uint8_t)pos;
    state->current_wan = allowed_wans[pos];
    state->window_used = 0;
    base = flow_window_limit(allowed_weights, allowed_count, pos,
                             state->path_mtu);
    state->window_target = flow_window_align_target(
        base > state->byte_debt[pos] ? base - state->byte_debt[pos] : 1u,
        state->path_mtu);
    state->has_current = 1;
    return state->current_wan;
}

static void flow_window_finish(struct flow_window_state *state,
                               const int *allowed_weights, int allowed_count)
{
    uint64_t base;
    uint64_t used;
    uint64_t debt;
    int pos;

    if (!state || !state->has_current)
        return;
    pos = state->current_pos;
    base = flow_window_limit(allowed_weights, allowed_count, pos,
                             state->path_mtu);
    used = state->window_used;
    debt = state->byte_debt[pos];
    if (used >= base) {
        uint64_t add = used - base;

        state->byte_debt[pos] = UINT64_MAX - debt < add ? UINT64_MAX : debt + add;
    } else {
        uint64_t paid = base - used;

        state->byte_debt[pos] = debt > paid ? debt - paid : 0;
    }
}

int flow_table_pick_wan_per_packet(const int *allowed_wans,
                                   const int *allowed_weights,
                                   int allowed_count)
{
    if (!allowed_wans || allowed_count <= 0)
        return 0;
    if (allowed_count > MAX_INTERFACES)
        allowed_count = MAX_INTERFACES;
    if (!flow_window_pool_same(&g_default_swrr, allowed_wans, allowed_count))
        flow_window_reset(&g_default_swrr, NULL, 0, allowed_wans, allowed_count);
    return flow_swrr_pick_default(&g_default_swrr, allowed_wans, allowed_weights,
                                  allowed_count);
}

static struct flow_window_state *flow_window_lookup(uint32_t src_ip, uint32_t dst_ip,
                                                    uint16_t src_port, uint16_t dst_port,
                                                    uint8_t protocol, uint32_t *hash_out)
{
    struct flow_key key;
    struct flow_window_state *set;
    uint32_t hash;

    normalize_flow_5tuple(&src_ip, &dst_ip, &src_port, &dst_port);
    memset(&key, 0, sizeof(key));
    key.src_ip = src_ip;
    key.dst_ip = dst_ip;
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.protocol = protocol;
    hash = flow_hash(src_ip, dst_ip, src_port, dst_port, protocol);
    if (hash_out)
        *hash_out = hash;
    if (!g_flow_windows)
        return NULL;
    set = g_flow_windows[hash & (FLOW_WINDOW_SETS - 1u)];

    for (int way = 0; way < (int)FLOW_WINDOW_WAYS; way++) {
        if (set[way].valid && memcmp(&set[way].key, &key, sizeof(key)) == 0) {
            return &set[way];
        }
    }
    return NULL;
}

int flow_table_pick_wan_per_flow_window(uint32_t src_ip, uint32_t dst_ip,
                                        uint16_t src_port, uint16_t dst_port,
                                        uint8_t protocol,
                                        const int *allowed_wans,
                                        const int *allowed_weights,
                                        int allowed_count,
                                        uint32_t path_mtu)
{
    struct flow_key key;
    struct flow_window_state *set;
    struct flow_window_state *state;
    uint32_t hash;
    int victim = 0;

    if (!allowed_wans || allowed_count <= 0)
        return 0;
    if (allowed_count > MAX_INTERFACES)
        allowed_count = MAX_INTERFACES;
    if (flow_table_thread_init() != 0)
        return flow_table_pick_wan_per_packet(allowed_wans, allowed_weights,
                                              allowed_count);

    state = flow_window_lookup(src_ip, dst_ip, src_port, dst_port, protocol, &hash);
    if (!state) {
        normalize_flow_5tuple(&src_ip, &dst_ip, &src_port, &dst_port);
        memset(&key, 0, sizeof(key));
        key.src_ip = src_ip;
        key.dst_ip = dst_ip;
        key.src_port = src_port;
        key.dst_port = dst_port;
        key.protocol = protocol;
        set = g_flow_windows[hash & (FLOW_WINDOW_SETS - 1u)];
        for (int way = 0; way < (int)FLOW_WINDOW_WAYS; way++) {
            if (!set[way].valid) {
                victim = way;
                break;
            }
            if (set[way].stamp < set[victim].stamp)
                victim = way;
        }
        state = &set[victim];
        flow_window_reset(state, &key, hash, allowed_wans, allowed_count);
    } else if (!flow_window_pool_same(state, allowed_wans, allowed_count) ||
               state->path_mtu != path_mtu) {
        struct flow_key saved_key = state->key;

        flow_window_reset(state, &saved_key, hash, allowed_wans, allowed_count);
    }
    state->path_mtu = path_mtu ? path_mtu : 1500u;
    state->stamp = ++g_flow_window_clock;
    if (!state->has_current)
        return flow_window_start(state, allowed_wans, allowed_weights,
                                 allowed_count, 1);
    if (state->window_used >= state->window_target) {
        flow_window_finish(state, allowed_weights, allowed_count);
        return flow_window_start(state, allowed_wans, allowed_weights,
                                 allowed_count, 0);
    }
    return state->current_wan;
}

void flow_table_account_per_flow_bytes(uint32_t src_ip, uint32_t dst_ip,
                                       uint16_t src_port, uint16_t dst_port,
                                       uint8_t protocol, uint64_t wire_bytes)
{
    struct flow_window_state *state;

    if (!wire_bytes)
        return;
    state = flow_window_lookup(src_ip, dst_ip, src_port, dst_port, protocol, NULL);
    if (!state || !state->has_current)
        return;
    state->window_used += wire_bytes;
    state->stamp = ++g_flow_window_clock;
}

void flow_table_rebind_per_flow_wan(uint32_t src_ip, uint32_t dst_ip,
                                    uint16_t src_port, uint16_t dst_port,
                                    uint8_t protocol, int wan_cfg,
                                    const int *allowed_weights,
                                    int allowed_count, uint32_t path_mtu)
{
    struct flow_window_state *state;

    state = flow_window_lookup(src_ip, dst_ip, src_port, dst_port, protocol, NULL);
    if (!state)
        return;
    for (int i = 0; i < state->wan_count; i++) {
        if (state->wans[i] != wan_cfg)
            continue;
        state->current_pos = (uint8_t)i;
        state->current_wan = wan_cfg;
        state->window_used = 0;
        state->path_mtu = path_mtu ? path_mtu : 1500u;
        state->window_target = flow_window_limit(allowed_weights, allowed_count,
                                                 i, state->path_mtu);
        state->has_current = 1;
        state->stamp = ++g_flow_window_clock;
        return;
    }
}

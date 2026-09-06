#include "../../../inc/core/flow/flow_table.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define FLOW_SWRR_SETS 512u
#define FLOW_SWRR_WAYS 4u

struct flow_swrr_state {
    struct flow_key key;
    int wans[MAX_INTERFACES];
    int64_t current[MAX_INTERFACES];
    uint64_t stamp;
    uint8_t wan_count;
    uint8_t tie_start;
    uint8_t valid;
};

static _Thread_local struct flow_swrr_state (*g_flow_swrr)[FLOW_SWRR_WAYS];
static _Thread_local struct flow_swrr_state g_default_swrr;
static _Thread_local uint64_t g_flow_swrr_clock;

int flow_table_thread_init(void)
{
    if (g_flow_swrr)
        return 0;
    g_flow_swrr = calloc(FLOW_SWRR_SETS, sizeof(*g_flow_swrr));
    return g_flow_swrr ? 0 : -1;
}

void flow_table_thread_cleanup(void)
{
    free(g_flow_swrr);
    g_flow_swrr = NULL;
    memset(&g_default_swrr, 0, sizeof(g_default_swrr));
    g_flow_swrr_clock = 0;
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

static int flow_swrr_pool_same(const struct flow_swrr_state *state,
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

static void flow_swrr_reset(struct flow_swrr_state *state,
                            const struct flow_key *key, uint32_t hash,
                            const int *allowed_wans, int allowed_count)
{
    memset(state, 0, sizeof(*state));
    if (key)
        state->key = *key;
    for (int i = 0; i < allowed_count; i++)
        state->wans[i] = allowed_wans[i];
    state->wan_count = (uint8_t)allowed_count;
    state->tie_start = (uint8_t)(allowed_count > 0 ? hash % (uint32_t)allowed_count : 0u);
    state->valid = 1;
}

static int flow_swrr_pick(struct flow_swrr_state *state,
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
        state->current[i] += weight;
        total += weight;
    }
    if (total <= 0)
        return allowed_wans[state->tie_start++ % allowed_count];

    for (int off = 0; off < allowed_count; off++) {
        int i = (state->tie_start + off) % allowed_count;
        int weight = allowed_weights ? allowed_weights[i] : 1;

        if (weight <= 0)
            continue;
        if (best < 0 || state->current[i] > best_current) {
            best = i;
            best_current = state->current[i];
        }
    }
    if (best < 0)
        best = 0;
    state->current[best] -= total;
    state->tie_start = (uint8_t)((best + 1) % allowed_count);
    return allowed_wans[best];
}

int flow_table_pick_wan_per_packet(const int *allowed_wans,
                                   const int *allowed_weights,
                                   int allowed_count)
{
    if (!allowed_wans || allowed_count <= 0)
        return 0;
    if (allowed_count > MAX_INTERFACES)
        allowed_count = MAX_INTERFACES;
    if (!flow_swrr_pool_same(&g_default_swrr, allowed_wans, allowed_count))
        flow_swrr_reset(&g_default_swrr, NULL, 0, allowed_wans, allowed_count);
    return flow_swrr_pick(&g_default_swrr, allowed_wans, allowed_weights, allowed_count);
}

int flow_table_pick_wan_per_flow_packet(uint32_t src_ip, uint32_t dst_ip,
                                        uint16_t src_port, uint16_t dst_port,
                                        uint8_t protocol,
                                        const int *allowed_wans,
                                        const int *allowed_weights,
                                        int allowed_count)
{
    struct flow_key key;
    struct flow_swrr_state *set;
    struct flow_swrr_state *state = NULL;
    uint32_t hash;
    int victim = 0;

    if (!allowed_wans || allowed_count <= 0)
        return 0;
    if (allowed_count > MAX_INTERFACES)
        allowed_count = MAX_INTERFACES;
    if (flow_table_thread_init() != 0)
        return flow_table_pick_wan_per_packet(allowed_wans, allowed_weights,
                                              allowed_count);

    normalize_flow_5tuple(&src_ip, &dst_ip, &src_port, &dst_port);
    memset(&key, 0, sizeof(key));
    key.src_ip = src_ip;
    key.dst_ip = dst_ip;
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.protocol = protocol;
    hash = flow_hash(src_ip, dst_ip, src_port, dst_port, protocol);
    set = g_flow_swrr[hash & (FLOW_SWRR_SETS - 1u)];

    for (int way = 0; way < (int)FLOW_SWRR_WAYS; way++) {
        if (set[way].valid && memcmp(&set[way].key, &key, sizeof(key)) == 0) {
            state = &set[way];
            break;
        }
        if (!set[way].valid) {
            victim = way;
            continue;
        }
        if (set[way].stamp < set[victim].stamp)
            victim = way;
    }
    if (!state) {
        state = &set[victim];
        flow_swrr_reset(state, &key, hash, allowed_wans, allowed_count);
    } else if (!flow_swrr_pool_same(state, allowed_wans, allowed_count)) {
        flow_swrr_reset(state, &key, hash, allowed_wans, allowed_count);
    }
    state->stamp = ++g_flow_swrr_clock;
    return flow_swrr_pick(state, allowed_wans, allowed_weights, allowed_count);
}

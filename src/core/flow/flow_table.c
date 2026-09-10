#include "../../../inc/core/flow/flow_table.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#define FLOW_TABLE_SETS 512u
#define FLOW_TABLE_WAYS 4u
#define FLOW_MTU1500_TCP_PACKET_WINDOW 4096u
#define FLOW_MTU1500_UDP_PACKET_WINDOW 16384u
#define FLOW_MTU9000_PACKET_WINDOW 1024u

#define FLOW_WINDOW_CLASS_COUNT ((int)FLOW_WAN_WINDOW_MTU9000 + 1)

struct flow_class_state {
    int selected_wan;
    uint16_t packet_count;
    uint8_t tie_start;
};

struct flow_window_state {
    struct flow_key key;
    int wans[MAX_INTERFACES];
    uint64_t stamp;
    struct flow_class_state classes[FLOW_WINDOW_CLASS_COUNT];
    uint8_t wan_count;
    uint8_t valid;
};

static _Thread_local struct flow_window_state (*g_flow_table)[FLOW_TABLE_WAYS];
static _Thread_local struct flow_window_state g_default_state;
static _Thread_local struct flow_window_state *g_pending_state;
static _Thread_local enum flow_wan_window_class g_pending_class;
static _Thread_local uint64_t g_flow_clock;

int flow_table_thread_init(void)
{
    if (g_flow_table)
        return 0;
    g_flow_table = calloc(FLOW_TABLE_SETS, sizeof(*g_flow_table));
    return g_flow_table ? 0 : -1;
}

void flow_table_thread_cleanup(void)
{
    free(g_flow_table);
    g_flow_table = NULL;
    memset(&g_default_state, 0, sizeof(g_default_state));
    g_pending_state = NULL;
    g_pending_class = FLOW_WAN_WINDOW_MTU1500_OTHER;
    g_flow_clock = 0;
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

static int flow_pool_same(const struct flow_window_state *state,
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

static void flow_state_reset(struct flow_window_state *state,
                             const struct flow_key *key, uint32_t hash,
                             const int *allowed_wans, int allowed_count)
{
    memset(state, 0, sizeof(*state));
    if (key)
        state->key = *key;
    for (int i = 0; i < allowed_count; i++)
        state->wans[i] = allowed_wans[i];
    state->wan_count = (uint8_t)allowed_count;
    for (int i = 0; i < FLOW_WINDOW_CLASS_COUNT; i++)
        state->classes[i].tie_start =
            (uint8_t)(allowed_count > 0 ? hash % (uint32_t)allowed_count : 0u);
    state->valid = 1;
}

static int flow_pick_next(uint8_t *cursor, const int *allowed_wans,
                          int allowed_count)
{
    int selected;

    if (!cursor || !allowed_wans || allowed_count <= 0)
        return 0;
    if (allowed_count == 1)
        return allowed_wans[0];

    selected = *cursor % allowed_count;
    *cursor = (uint8_t)((selected + 1) % allowed_count);
    return allowed_wans[selected];
}

static int flow_window_wan(struct flow_window_state *state,
                           enum flow_wan_window_class window_class,
                           const int *allowed_wans,
                           int allowed_count)
{
    struct flow_class_state *class_state = &state->classes[window_class];

    if (class_state->packet_count == 0)
        class_state->selected_wan = flow_pick_next(&class_state->tie_start,
                                                   allowed_wans,
                                                   allowed_count);
    return class_state->selected_wan;
}

static void flow_window_advance(struct flow_window_state *state,
                                enum flow_wan_window_class window_class,
                                uint16_t packet_window)
{
    struct flow_class_state *class_state;

    if (!state)
        return;
    class_state = &state->classes[window_class];
    class_state->packet_count++;
    if (class_state->packet_count >= packet_window)
        class_state->packet_count = 0;
}

int flow_table_pick_wan_per_packet(const int *allowed_wans, int allowed_count)
{
    if (!allowed_wans || allowed_count <= 0)
        return 0;
    if (allowed_count > MAX_INTERFACES)
        allowed_count = MAX_INTERFACES;
    if (!flow_pool_same(&g_default_state, allowed_wans, allowed_count))
        flow_state_reset(&g_default_state, NULL, 0, allowed_wans, allowed_count);
    return flow_pick_next(
        &g_default_state.classes[FLOW_WAN_WINDOW_MTU1500_OTHER].tie_start,
        allowed_wans, allowed_count);
}

int flow_table_pick_wan_per_flow_packet(uint32_t src_ip, uint32_t dst_ip,
                                        uint16_t src_port, uint16_t dst_port,
                                        uint8_t protocol,
                                        const int *allowed_wans,
                                        int allowed_count,
                                        enum flow_wan_window_class window_class)
{
    struct flow_key key;
    struct flow_window_state *set;
    struct flow_window_state *state = NULL;
    uint32_t hash;
    int victim = 0;

    if (!allowed_wans || allowed_count <= 0)
        return 0;
    if (allowed_count > MAX_INTERFACES)
        allowed_count = MAX_INTERFACES;
    if (flow_table_thread_init() != 0)
        return flow_table_pick_wan_per_packet(allowed_wans, allowed_count);

    normalize_flow_5tuple(&src_ip, &dst_ip, &src_port, &dst_port);
    memset(&key, 0, sizeof(key));
    key.src_ip = src_ip;
    key.dst_ip = dst_ip;
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.protocol = protocol;
    hash = flow_hash(src_ip, dst_ip, src_port, dst_port, protocol);
    set = g_flow_table[hash & (FLOW_TABLE_SETS - 1u)];

    for (int way = 0; way < (int)FLOW_TABLE_WAYS; way++) {
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
        flow_state_reset(state, &key, hash, allowed_wans, allowed_count);
    } else if (!flow_pool_same(state, allowed_wans, allowed_count)) {
        flow_state_reset(state, &key, hash, allowed_wans, allowed_count);
    }
    state->stamp = ++g_flow_clock;

    g_pending_state = NULL;
    g_pending_class = FLOW_WAN_WINDOW_MTU1500_OTHER;

    if (window_class == FLOW_WAN_WINDOW_MTU9000) {
        g_pending_state = state;
        g_pending_class = window_class;
        return flow_window_wan(state, window_class, allowed_wans,
                               allowed_count);
    }

    if (window_class == FLOW_WAN_WINDOW_MTU1500_TCP) {
        int selected = flow_window_wan(state, window_class, allowed_wans,
                                       allowed_count);

        flow_window_advance(state, window_class,
                            FLOW_MTU1500_TCP_PACKET_WINDOW);
        return selected;
    }

    if (window_class == FLOW_WAN_WINDOW_MTU1500_UDP) {
        g_pending_state = state;
        g_pending_class = window_class;
        return flow_window_wan(state, window_class, allowed_wans,
                               allowed_count);
    }

    return flow_pick_next(
        &state->classes[FLOW_WAN_WINDOW_MTU1500_OTHER].tie_start,
        allowed_wans, allowed_count);
}

void flow_table_packet_complete(enum flow_wan_window_class window_class,
                                int sent)
{
    struct flow_window_state *state = g_pending_state;

    g_pending_state = NULL;
    if (!sent || !state || g_pending_class != window_class)
        return;

    if (window_class == FLOW_WAN_WINDOW_MTU1500_UDP)
        flow_window_advance(state, window_class,
                            FLOW_MTU1500_UDP_PACKET_WINDOW);
    else if (window_class == FLOW_WAN_WINDOW_MTU9000)
        flow_window_advance(state, window_class,
                            FLOW_MTU9000_PACKET_WINDOW);
}

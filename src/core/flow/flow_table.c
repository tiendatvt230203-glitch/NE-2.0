#define _POSIX_C_SOURCE 199309L
#include "../../../inc/core/flow/flow_table.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>

static _Atomic uint64_t g_pkt_wrr_seq;

static inline void normalize_flow_5tuple(uint32_t *src_ip, uint32_t *dst_ip,
                                         uint16_t *src_port, uint16_t *dst_port) {
    if (!src_ip || !dst_ip || !src_port || !dst_port)
        return;

    uint32_t a = ntohl(*src_ip);
    uint32_t b = ntohl(*dst_ip);
    if (a > b || (a == b && *src_port > *dst_port)) {
        uint32_t tmp_ip = *src_ip;
        *src_ip = *dst_ip;
        *dst_ip = tmp_ip;

        uint16_t tmp_p = *src_port;
        *src_port = *dst_port;
        *dst_port = tmp_p;
    }
}

static inline void normalize_flow_ips(uint32_t *src_ip, uint32_t *dst_ip) {
    if (!src_ip || !dst_ip)
        return;

    uint32_t a = ntohl(*src_ip);
    uint32_t b = ntohl(*dst_ip);
    if (a > b) {
        uint32_t tmp = *src_ip;
        *src_ip = *dst_ip;
        *dst_ip = tmp;
    }
}

static uint32_t flow_hash(uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t protocol) {
    uint32_t hash = src_ip ^ dst_ip;
    hash ^= ((uint32_t)src_port << 16) | dst_port;
    hash ^= protocol;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);
    return hash % FLOW_TABLE_SIZE;
}

static uint32_t flow_hash_ips(uint32_t src_ip, uint32_t dst_ip) {
    uint32_t hash = src_ip ^ dst_ip;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);
    return hash % FLOW_TABLE_SIZE;
}

static uint64_t get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void flow_table_init(struct flow_table *ft, const uint32_t *wan_window_sizes, int wan_count) {
    memset(ft, 0, sizeof(*ft));
    atomic_store(&g_pkt_wrr_seq, 0);
    ft->wan_count = wan_count;
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (wan_window_sizes)
            ft->wan_window_sizes[i] = wan_window_sizes[i];
        else
            ft->wan_window_sizes[i] = 0;
    }
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        pthread_mutex_init(&ft->locks[i], NULL);
    }
}

void flow_table_cleanup(struct flow_table *ft) {
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        pthread_mutex_lock(&ft->locks[i]);
        struct flow_entry *entry = ft->buckets[i];
        while (entry) {
            struct flow_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        ft->buckets[i] = NULL;
        pthread_mutex_unlock(&ft->locks[i]);
        pthread_mutex_destroy(&ft->locks[i]);
    }
}

static int next_wan = 0;

static int get_next_wan(int wan_count) {
    if (wan_count <= 0)
        return 0;

    int wan = __sync_fetch_and_add(&next_wan, 1);
    if (wan < 0)
        wan = -wan;
    wan %= wan_count;
    return wan;
}

static int wan_allowed_pos(int wan_idx, const int *allowed_wans, int allowed_count) {
    for (int i = 0; i < allowed_count; i++) {
        if (allowed_wans[i] == wan_idx)
            return i;
    }
    return -1;
}

static int weights_sum_positive(const int *allowed_weights, int allowed_count) {
    if (!allowed_weights || allowed_count <= 0)
        return 0;
    int s = 0;
    for (int i = 0; i < allowed_count; i++) {
        if (allowed_weights[i] > 0)
            s += allowed_weights[i];
    }
    return s;
}

static int first_positive_pos(const int *allowed_weights, int allowed_count) {
    if (!allowed_weights || allowed_count <= 0)
        return 0;
    for (int i = 0; i < allowed_count; i++) {
        if (allowed_weights[i] > 0)
            return i;
    }
    return 0;
}

static int next_enabled_pos(int pos, const int *allowed_weights, int allowed_count) {
    if (allowed_count <= 0)
        return 0;
    int sumw = weights_sum_positive(allowed_weights, allowed_count);
    if (sumw <= 0 || !allowed_weights)
        return (pos + 1) % allowed_count;
    for (int step = 1; step <= allowed_count; step++) {
        int next = (pos + step) % allowed_count;
        if (allowed_weights[next] > 0)
            return next;
    }
    return first_positive_pos(allowed_weights, allowed_count);
}

static int wrr_slot_to_wan(int slot, const int *allowed_wans, const int *allowed_weights,
                           int allowed_count, int sumw) {
    if (!allowed_wans || !allowed_weights || allowed_count <= 0 || sumw <= 0)
        return allowed_wans ? allowed_wans[0] : 0;
    int s = ((slot % sumw) + sumw) % sumw;
    int acc = 0;
    for (int i = 0; i < allowed_count; i++) {
        int w = allowed_weights[i];
        if (w <= 0)
            continue;
        acc += w;
        if (s < acc)
            return allowed_wans[i];
    }
    return allowed_wans[allowed_count - 1];
}

static uint32_t profile_wan_limit(const struct flow_table *ft, int wan_idx,
                                  const int *allowed_wans, const int *allowed_weights,
                                  int allowed_count) {
    if (!ft || wan_idx < 0 || wan_idx >= ft->wan_count)
        return 0;
    uint32_t base = ft->wan_window_sizes[wan_idx];
    if (base == 0)
        return 0;
    int sumw = weights_sum_positive(allowed_weights, allowed_count);
    if (sumw <= 0 || !allowed_weights || !allowed_wans || allowed_count <= 0)
        return base / (uint32_t)(allowed_count > 0 ? allowed_count : 1);
    int pos = wan_allowed_pos(wan_idx, allowed_wans, allowed_count);
    if (pos < 0 || allowed_weights[pos] <= 0)
        return 0;
    uint64_t limit = ((uint64_t)base * (uint64_t)allowed_weights[pos]) / (uint64_t)sumw;
    return limit > 0 ? (uint32_t)limit : 1;
}

static void flow_commit_window_switch(struct flow_entry *entry,
                                      const int *allowed_wans,
                                      const int *allowed_weights,
                                      int allowed_count,
                                      uint32_t window_bytes) {
    int pos = wan_allowed_pos(entry->current_wan, allowed_wans, allowed_count);
    if (pos < 0)
        pos = 0;
    entry->wrr_slot = next_enabled_pos(pos, allowed_weights, allowed_count);
    entry->current_wan = allowed_wans[entry->wrr_slot];
    entry->byte_count = window_bytes;
    entry->drain_until_ns = 0;
}

static void flow_window_advance(struct flow_entry *entry, struct flow_table *ft,
                                uint32_t window_bytes, uint64_t now_ns,
                                const int *allowed_wans, int allowed_count,
                                const int *allowed_weights, int sumw) {
    int pos = wan_allowed_pos(entry->current_wan, allowed_wans, allowed_count);
    if (pos < 0 || (sumw > 0 && allowed_weights && allowed_weights[pos] <= 0)) {
        pos = (sumw > 0) ? first_positive_pos(allowed_weights, allowed_count) : 0;
        entry->current_wan = allowed_wans[pos];
        entry->byte_count = 0;
        entry->wrr_slot = pos;
        entry->drain_until_ns = 0;
    }

    entry->byte_count += window_bytes;

    if (entry->drain_until_ns) {
        if (now_ns >= entry->drain_until_ns)
            flow_commit_window_switch(entry, allowed_wans, allowed_weights,
                                      allowed_count, window_bytes);
        return;
    }

    {
        uint32_t cur_limit = profile_wan_limit(ft, entry->current_wan,
                                               allowed_wans, allowed_weights,
                                               allowed_count);
        if (cur_limit > 0 && entry->byte_count >= cur_limit) {
            entry->drain_until_ns = now_ns +
                (uint64_t)FLOW_WAN_SWITCH_DRAIN_MS * 1000000ULL;
        }
    }
}

int flow_table_get_wan(struct flow_table *ft,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t src_port, uint16_t dst_port,
                       uint8_t protocol, uint32_t window_bytes) {
    normalize_flow_ips(&src_ip, &dst_ip);
    uint32_t idx = flow_hash_ips(src_ip, dst_ip);
    uint64_t now = get_time_sec();
    uint64_t now_ns = get_time_ns();
    int wan_idx;

    (void)src_port;
    (void)dst_port;
    (void)protocol;

    pthread_mutex_lock(&ft->locks[idx]);

    struct flow_entry *entry = ft->buckets[idx];

    while (entry) {
        if (entry->ip_only_key &&
            entry->key.src_ip == src_ip &&
            entry->key.dst_ip == dst_ip) {

            entry->last_seen = now;
            entry->byte_count += window_bytes;

            if (entry->drain_until_ns) {
                if (now_ns >= entry->drain_until_ns) {
                    entry->current_wan = (entry->current_wan + 1) % ft->wan_count;
                    entry->byte_count = window_bytes;
                    entry->drain_until_ns = 0;
                }
            } else {
                uint32_t cur_limit = 0;
                if (entry->current_wan >= 0 && entry->current_wan < ft->wan_count)
                    cur_limit = ft->wan_window_sizes[entry->current_wan];
                if (cur_limit > 0 && entry->byte_count >= cur_limit) {
                    entry->drain_until_ns = now_ns +
                        (uint64_t)FLOW_WAN_SWITCH_DRAIN_MS * 1000000ULL;
                }
            }

            wan_idx = entry->current_wan;
            pthread_mutex_unlock(&ft->locks[idx]);
            return wan_idx;
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(struct flow_entry));
    if (!entry) {
        pthread_mutex_unlock(&ft->locks[idx]);
        return 0;
    }

    memset(entry, 0, sizeof(*entry));
    entry->key.src_ip = src_ip;
    entry->key.dst_ip = dst_ip;
    entry->key.src_port = src_port;
    entry->key.dst_port = dst_port;
    entry->key.protocol = protocol;
    entry->byte_count = window_bytes;
    entry->current_wan = get_next_wan(ft->wan_count);
    entry->wrr_slot = 0;
    entry->last_seen = now;
    entry->drain_until_ns = 0;
    entry->valid = 1;
    entry->ip_only_key = 1;
    entry->profile_wan_pool = 0;
    entry->next = ft->buckets[idx];
    ft->buckets[idx] = entry;

    wan_idx = entry->current_wan;
    pthread_mutex_unlock(&ft->locks[idx]);
    return wan_idx;
}

int flow_table_pick_wan_per_packet(const int *allowed_wans,
                                   const int *allowed_weights,
                                   int allowed_count) {
    if (!allowed_wans || allowed_count <= 0)
        return 0;
    if (allowed_count == 1)
        return allowed_wans[0];

    int sumw = weights_sum_positive(allowed_weights, allowed_count);
    uint64_t n = atomic_fetch_add(&g_pkt_wrr_seq, 1);
    if (sumw > 0 && allowed_weights)
        return wrr_slot_to_wan((int)(n % (uint64_t)sumw), allowed_wans, allowed_weights,
                               allowed_count, sumw);
    return allowed_wans[n % (uint64_t)allowed_count];
}

int flow_table_get_wan_profile(struct flow_table *ft,
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint8_t protocol, uint32_t window_bytes,
                                const int *allowed_wans, int allowed_count,
                                const int *allowed_weights) {
    if (!ft || !allowed_wans || allowed_count <= 0)
        return flow_table_get_wan(ft, src_ip, dst_ip, src_port, dst_port, protocol,
                                  window_bytes);
    if (allowed_count == 1)
        return allowed_wans[0];

    normalize_flow_5tuple(&src_ip, &dst_ip, &src_port, &dst_port);
    uint32_t idx = flow_hash(src_ip, dst_ip, src_port, dst_port, protocol);
    uint64_t now = get_time_sec();
    uint64_t now_ns = get_time_ns();
    int sumw = weights_sum_positive(allowed_weights, allowed_count);

    pthread_mutex_lock(&ft->locks[idx]);

    struct flow_entry *entry = ft->buckets[idx];

    while (entry) {
        if (!entry->ip_only_key && entry->profile_wan_pool &&
            entry->key.src_ip == src_ip &&
            entry->key.dst_ip == dst_ip &&
            entry->key.src_port == src_port &&
            entry->key.dst_port == dst_port &&
            entry->key.protocol == protocol) {

            entry->last_seen = now;
            flow_window_advance(entry, ft, window_bytes, now_ns,
                                allowed_wans, allowed_count, allowed_weights, sumw);
            {
                int wan_idx = entry->current_wan;
                pthread_mutex_unlock(&ft->locks[idx]);
                return wan_idx;
            }
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(struct flow_entry));
    if (!entry) {
        pthread_mutex_unlock(&ft->locks[idx]);
        return 0;
    }

    memset(entry, 0, sizeof(*entry));
    entry->key.src_ip = src_ip;
    entry->key.dst_ip = dst_ip;
    entry->key.src_port = src_port;
    entry->key.dst_port = dst_port;
    entry->key.protocol = protocol;
    entry->byte_count = window_bytes;
    entry->last_seen = now;
    entry->drain_until_ns = 0;
    entry->valid = 1;
    entry->ip_only_key = 0;
    entry->profile_wan_pool = 1;
    entry->next = ft->buckets[idx];

    {
        uint32_t h = flow_hash(src_ip, dst_ip, src_port, dst_port, protocol);
        if (sumw > 0 && allowed_weights) {
            entry->current_wan = wrr_slot_to_wan((int)(h % (uint32_t)sumw),
                                                 allowed_wans, allowed_weights,
                                                 allowed_count, sumw);
            entry->wrr_slot = wan_allowed_pos(entry->current_wan, allowed_wans, allowed_count);
            if (entry->wrr_slot < 0)
                entry->wrr_slot = first_positive_pos(allowed_weights, allowed_count);
        } else {
            entry->wrr_slot = (int)(h % (uint32_t)allowed_count);
            entry->current_wan = allowed_wans[entry->wrr_slot];
        }
    }

    {
        uint32_t cur_limit = profile_wan_limit(ft, entry->current_wan,
                                               allowed_wans, allowed_weights,
                                               allowed_count);
        if (cur_limit > 0 && entry->byte_count >= cur_limit) {
            entry->drain_until_ns = now_ns +
                (uint64_t)FLOW_WAN_SWITCH_DRAIN_MS * 1000000ULL;
        }
    }

    ft->buckets[idx] = entry;
    {
        int wan_idx = entry->current_wan;
        pthread_mutex_unlock(&ft->locks[idx]);
        return wan_idx;
    }
}

void flow_table_gc_slice(struct flow_table *ft, int *bucket_cursor, int buckets)
{
    uint64_t now;
    int start, i, n;

    if (!ft || !bucket_cursor || buckets <= 0)
        return;

    now = get_time_sec();
    start = *bucket_cursor;
    for (n = 0; n < buckets; n++) {
        i = (start + n) % FLOW_TABLE_SIZE;
        pthread_mutex_lock(&ft->locks[i]);

        struct flow_entry **pp = &ft->buckets[i];
        while (*pp) {
            struct flow_entry *entry = *pp;
            if (now - entry->last_seen > FLOW_TIMEOUT_SEC) {
                *pp = entry->next;
                free(entry);
            } else {
                pp = &entry->next;
            }
        }

        pthread_mutex_unlock(&ft->locks[i]);
    }
    *bucket_cursor = (start + buckets) % FLOW_TABLE_SIZE;
}

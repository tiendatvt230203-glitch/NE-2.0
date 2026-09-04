#define _POSIX_C_SOURCE 199309L
#include "../../../inc/core/flow/flow_table.h"

#include <arpa/inet.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static _Atomic uint64_t packet_rr;

static uint64_t now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

static void normalize_5tuple(struct flow_key *key)
{
    uint32_t a = ntohl(key->src_ip);
    uint32_t b = ntohl(key->dst_ip);

    if (a > b || (a == b && key->src_port > key->dst_port)) {
        uint32_t ip = key->src_ip;
        uint16_t port = key->src_port;
        key->src_ip = key->dst_ip;
        key->dst_ip = ip;
        key->src_port = key->dst_port;
        key->dst_port = port;
    }
}

static uint32_t flow_hash(const struct flow_key *key)
{
    uint32_t hash = key->src_ip ^ key->dst_ip;
    hash ^= ((uint32_t)key->src_port << 16) | key->dst_port;
    hash ^= key->protocol;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    return hash;
}

static int same_flow(const struct flow_key *a, const struct flow_key *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->protocol == b->protocol;
}

void flow_table_init(struct flow_table *ft, int wan_count)
{
    if (!ft)
        return;
    memset(ft, 0, sizeof(*ft));
    ft->wan_count = wan_count > 0 ? wan_count : 1;
    atomic_store_explicit(&packet_rr, 0, memory_order_relaxed);
    for (int i = 0; i < FLOW_TABLE_SIZE; i++)
        pthread_mutex_init(&ft->locks[i], NULL);
}

void flow_table_cleanup(struct flow_table *ft)
{
    if (!ft || ft->wan_count <= 0)
        return;
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        struct flow_entry *entry;
        pthread_mutex_lock(&ft->locks[i]);
        entry = ft->buckets[i];
        while (entry) {
            struct flow_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        ft->buckets[i] = NULL;
        pthread_mutex_unlock(&ft->locks[i]);
        pthread_mutex_destroy(&ft->locks[i]);
    }
    ft->wan_count = 0;
}

int flow_table_pick_equal_packet_wan(int wan_count)
{
    uint64_t n;

    if (wan_count <= 1)
        return 0;
    n = atomic_fetch_add_explicit(&packet_rr, 1, memory_order_relaxed);
    return (int)(n % (uint64_t)wan_count);
}

int flow_table_get_equal_wan(struct flow_table *ft,
                             uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             uint8_t protocol, uint32_t packet_bytes)
{
    struct flow_key key = {src_ip, dst_ip, src_port, dst_port, protocol};
    struct flow_entry *entry;
    uint32_t hash, bucket;
    int wan;

    if (!ft || ft->wan_count <= 1)
        return 0;
    normalize_5tuple(&key);
    hash = flow_hash(&key);
    bucket = hash % FLOW_TABLE_SIZE;
    pthread_mutex_lock(&ft->locks[bucket]);

    for (entry = ft->buckets[bucket]; entry; entry = entry->next) {
        if (!same_flow(&entry->key, &key))
            continue;
        entry->last_seen = now_sec();
        if (entry->byte_count >= FLOW_WINDOW_BYTES) {
            entry->current_wan = (entry->current_wan + 1) % ft->wan_count;
            entry->byte_count = 0;
        }
        entry->byte_count += packet_bytes;
        wan = entry->current_wan;
        pthread_mutex_unlock(&ft->locks[bucket]);
        return wan;
    }

    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        pthread_mutex_unlock(&ft->locks[bucket]);
        return flow_table_pick_equal_packet_wan(ft->wan_count);
    }
    entry->key = key;
    entry->byte_count = packet_bytes;
    entry->last_seen = now_sec();
    entry->current_wan = (int)(hash % (uint32_t)ft->wan_count);
    entry->next = ft->buckets[bucket];
    ft->buckets[bucket] = entry;
    wan = entry->current_wan;
    pthread_mutex_unlock(&ft->locks[bucket]);
    return wan;
}

void flow_table_gc_slice(struct flow_table *ft, int *bucket_cursor, int buckets)
{
    uint64_t now;
    int start;

    if (!ft || ft->wan_count <= 0 || !bucket_cursor || buckets <= 0)
        return;
    now = now_sec();
    start = *bucket_cursor;
    for (int n = 0; n < buckets; n++) {
        int i = (start + n) % FLOW_TABLE_SIZE;
        struct flow_entry **link;

        pthread_mutex_lock(&ft->locks[i]);
        link = &ft->buckets[i];
        while (*link) {
            struct flow_entry *entry = *link;
            if (now - entry->last_seen > FLOW_TIMEOUT_SEC) {
                *link = entry->next;
                free(entry);
            } else {
                link = &entry->next;
            }
        }
        pthread_mutex_unlock(&ft->locks[i]);
    }
    *bucket_cursor = (start + buckets) % FLOW_TABLE_SIZE;
}

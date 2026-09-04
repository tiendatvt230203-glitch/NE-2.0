#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <pthread.h>
#include <stdint.h>

#define FLOW_TABLE_SIZE 16384
#define FLOW_TIMEOUT_SEC 60
#define FLOW_WINDOW_BYTES 120000u

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct flow_entry {
    struct flow_key key;
    uint32_t byte_count;
    uint64_t last_seen;
    int current_wan;
    struct flow_entry *next;
};

struct flow_table {
    struct flow_entry *buckets[FLOW_TABLE_SIZE];
    pthread_mutex_t locks[FLOW_TABLE_SIZE];
    int wan_count;
};

void flow_table_init(struct flow_table *ft, int wan_count);
void flow_table_cleanup(struct flow_table *ft);
void flow_table_gc_slice(struct flow_table *ft, int *bucket_cursor, int buckets);

/* Equal-share bonding only: each 5-tuple stays on one WAN for a fixed byte
 * window, then advances to the next WAN. There are no weights or percentages. */
int flow_table_get_equal_wan(struct flow_table *ft,
                             uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             uint8_t protocol, uint32_t packet_bytes);

/* Round-robin fallback for frames without a parseable IPv4 5-tuple. */
int flow_table_pick_equal_packet_wan(int wan_count);

#endif

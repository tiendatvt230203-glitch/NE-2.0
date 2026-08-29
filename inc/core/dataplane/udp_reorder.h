#ifndef UDP_REORDER_H
#define UDP_REORDER_H

#include "core/iface/interface.h"
#include <stdint.h>

struct dp_udp_reorder_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct dp_udp_reorder_item {
    struct ne_packet packet;
    int16_t profile_pi;
    int8_t ingress_wan_dp;
};

struct dp_udp_reorder_ops {
    void *ctx;
    int (*emit)(void *ctx, struct dp_udp_reorder_item *item);
    void (*drop)(void *ctx, struct dp_udp_reorder_item *item);
};

struct dp_udp_reorder_stats {
    uint64_t held;
    uint64_t released;
    uint64_t late_or_duplicate;
    uint64_t gap_skipped;
    uint64_t overflow;
    uint64_t evicted;
    uint64_t high_water;
    uint64_t tcp_held;
    uint64_t tcp_released;
    uint64_t tcp_late_or_duplicate;
    uint64_t tcp_gap_skipped;
    uint64_t tcp_overflow;
    uint64_t tcp_evicted;
    uint64_t udp_held;
    uint64_t udp_released;
    uint64_t udp_late_or_duplicate;
    uint64_t udp_gap_skipped;
    uint64_t udp_overflow;
    uint64_t udp_evicted;
};

void dp_udp_reorder_configure_from_env(void);
uint64_t dp_udp_reorder_now_ns(void);

/* Takes ownership of item in every return path: emit, hold, or drop. */
void dp_udp_reorder_submit(int worker_idx,
                           const struct dp_udp_reorder_key *key,
                           uint32_t epoch, uint32_t seq,
                           struct dp_udp_reorder_item *item,
                           uint64_t now_ns,
                           const struct dp_udp_reorder_ops *ops);

void dp_udp_reorder_gc(int worker_idx, uint64_t now_ns,
                       const struct dp_udp_reorder_ops *ops);
void dp_udp_reorder_reset_worker(int worker_idx,
                                 const struct dp_udp_reorder_ops *ops);
void dp_udp_reorder_get_stats(struct dp_udp_reorder_stats *out);

#endif

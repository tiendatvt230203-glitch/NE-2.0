#ifndef UDP_REORDER_H
#define UDP_REORDER_H

#include "core/iface/interface.h"
#include <stddef.h>
#include <stdint.h>

/* Reorder is useful only when traffic can arrive over multiple WAN paths. */
#define UDP_REORDER_AUTO_MIN_WANS       2u
#define UDP_REORDER_DEFAULT_HOLD_NS     (3ULL * 1000000ULL)

struct dp_udp_reorder_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

struct dp_udp_reorder_item {
    struct ne_packet packet;
    uint8_t tx_slot;
};

struct dp_udp_reorder_ops {
    void *ctx;
    int (*emit)(void *ctx, struct dp_udp_reorder_item *item);
    void (*drop)(void *ctx, struct dp_udp_reorder_item *item);
};

void dp_udp_reorder_configure(uint32_t wan_count);
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

#endif
#define _POSIX_C_SOURCE 200809L

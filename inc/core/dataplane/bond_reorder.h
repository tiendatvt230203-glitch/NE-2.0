#ifndef BOND_REORDER_H
#define BOND_REORDER_H

#include "core/iface/interface.h"
#include <stdint.h>

struct dp_bond_reorder_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct dp_bond_reorder_item {
    struct ne_packet packet;
    int16_t profile_pi;
    int8_t ingress_wan_dp;
};

struct dp_bond_reorder_ops {
    void *ctx;
    int (*emit)(void *ctx, struct dp_bond_reorder_item *item);
    void (*drop)(void *ctx, struct dp_bond_reorder_item *item);
};

/* Per-protocol counters. "late" has protocol-specific semantics:
 * TCP forwards it; UDP drops it after the committed watermark. */
struct dp_bond_reorder_stats {
    uint64_t held;
    uint64_t released;
    uint64_t late;
    uint64_t duplicate_dropped;
    uint64_t gap_skipped;
    uint64_t overflow;
    uint64_t evicted;
    uint64_t high_water;
};

uint64_t dp_bond_reorder_now_ns(void);

#endif

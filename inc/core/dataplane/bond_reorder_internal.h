#ifndef BOND_REORDER_INTERNAL_H
#define BOND_REORDER_INTERNAL_H

#include "core/dataplane/bond_reorder.h"

enum dp_bond_reorder_protocol {
    DP_BOND_REORDER_TCP = 0,
    DP_BOND_REORDER_UDP,
    DP_BOND_REORDER_PROTOCOLS,
};

void dp_bond_reorder_engine_configure(enum dp_bond_reorder_protocol protocol,
                                      const char *enable_env,
                                      const char *hold_env);
void dp_bond_reorder_engine_submit(enum dp_bond_reorder_protocol protocol,
                                   int worker_idx,
                                   const struct dp_bond_reorder_key *key,
                                   uint32_t epoch, uint32_t seq,
                                   struct dp_bond_reorder_item *item,
                                   uint64_t now_ns,
                                   const struct dp_bond_reorder_ops *ops);
void dp_bond_reorder_engine_gc(enum dp_bond_reorder_protocol protocol,
                              int worker_idx, uint64_t now_ns,
                              const struct dp_bond_reorder_ops *ops);
void dp_bond_reorder_engine_reset(enum dp_bond_reorder_protocol protocol,
                                 int worker_idx,
                                 const struct dp_bond_reorder_ops *ops);
void dp_bond_reorder_engine_stats(enum dp_bond_reorder_protocol protocol,
                                 struct dp_bond_reorder_stats *out);

#endif

#ifndef TCP_REORDER_H
#define TCP_REORDER_H

#include "core/dataplane/bond_reorder.h"

void dp_tcp_reorder_configure_from_env(void);

/* Takes ownership in every path. Late TCP packets are emitted because they
 * may fill a native TCP sequence gap and avoid retransmission. */
void dp_tcp_reorder_submit(int worker_idx,
                           const struct dp_bond_reorder_key *key,
                           uint32_t epoch, uint32_t seq,
                           struct dp_bond_reorder_item *item,
                           uint64_t now_ns,
                           const struct dp_bond_reorder_ops *ops);
void dp_tcp_reorder_gc(int worker_idx, uint64_t now_ns,
                       const struct dp_bond_reorder_ops *ops);
void dp_tcp_reorder_reset_worker(int worker_idx,
                                 const struct dp_bond_reorder_ops *ops);
void dp_tcp_reorder_get_stats(struct dp_bond_reorder_stats *out);

#endif

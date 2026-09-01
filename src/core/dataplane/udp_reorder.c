#include "../../../inc/core/dataplane/udp_reorder.h"
#include "bond_reorder_internal.h"

#include <netinet/in.h>

void dp_udp_reorder_configure_from_env(void)
{
    dp_bond_reorder_engine_configure(DP_BOND_REORDER_UDP,
                                     "NE_UDP_REORDER",
                                     "NE_UDP_REORDER_US");
}

void dp_udp_reorder_submit(int worker_idx,
                           const struct dp_bond_reorder_key *key,
                           uint32_t epoch, uint32_t seq,
                           struct dp_bond_reorder_item *item,
                           uint64_t now_ns,
                           const struct dp_bond_reorder_ops *ops)
{
    if (!key || key->protocol != IPPROTO_UDP) {
        if (ops && ops->drop)
            ops->drop(ops->ctx, item);
        return;
    }
    dp_bond_reorder_engine_submit(DP_BOND_REORDER_UDP, worker_idx, key,
                                  epoch, seq, item, now_ns, ops);
}

void dp_udp_reorder_gc(int worker_idx, uint64_t now_ns,
                       const struct dp_bond_reorder_ops *ops)
{
    dp_bond_reorder_engine_gc(DP_BOND_REORDER_UDP, worker_idx, now_ns, ops);
}

void dp_udp_reorder_reset_worker(int worker_idx,
                                 const struct dp_bond_reorder_ops *ops)
{
    dp_bond_reorder_engine_reset(DP_BOND_REORDER_UDP, worker_idx, ops);
}

void dp_udp_reorder_get_stats(struct dp_bond_reorder_stats *out)
{
    dp_bond_reorder_engine_stats(DP_BOND_REORDER_UDP, out);
}

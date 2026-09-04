#include "../../../inc/core/dataplane/dataplane.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/crypto/l2_crypto.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/packet_crypto.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/dataplane/arp_bridge.h"
#include "../../../inc/core/dataplane/dp_idle.h"

#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <stdio.h>

#define SPLIT_TAIL_REFILL_BATCH 32u
static int push_to_wan(struct forwarder *fwd, struct ne_packet *job, int wan_dp)
{
    int ri = dp_out_ring_idx();

    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    return dp_ring_push(fwd, &fwd->mid_to_wan[wan_dp][ri], job);
}

static int push_split_to_wan(struct forwarder *fwd, struct ne_packet *job,
                            uint32_t l1, struct ne_packet *tail, uint32_t l2, int wan_dp)
{
    struct ne_ring *tx = &fwd->mid_to_wan[wan_dp][dp_out_ring_idx()];

    if (!fwd || !job || !tail)
        return -1;
    if (wan_dp < 0 || wan_dp >= fwd->wan_count || ne_ring_count(tx) + 2 > tx->cap) {
        ne_frame_free(&fwd->pair, tail->addr);
        return -1;
    }
    if (l1 == 0 || l2 == 0 || l1 > fwd->pair.frame_size || l2 > fwd->pair.frame_size) {
        ne_frame_free(&fwd->pair, tail->addr);
        return -1;
    }
    tail->len = l2;
    tail->dir = NE_DIR_WAN;
    tail->wan_idx = (uint8_t)wan_dp;
    job->len = l1;
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    if (ne_ring_try_push_pair(tx, job, tail) != 0) {
        ne_frame_free(&fwd->pair, tail->addr);
        return -1;
    }
    ne_dp_idle_wake_tx_worker(dp_out_ring_idx());
    return 0;
}

static int split_tail_take(struct forwarder *fwd, int worker_idx, uint64_t *addr_out)
{
    uint32_t got;

    if (!fwd || !addr_out || worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return -1;

    if (fwd->split_tail_count[worker_idx] == 0) {
        got = ne_frame_alloc_batch(&fwd->pair, fwd->split_tail_cache[worker_idx],
                                   SPLIT_TAIL_REFILL_BATCH);
        if (got == 0)
            return -1;
        fwd->split_tail_count[worker_idx] = (uint16_t)got;
    }

    fwd->split_tail_count[worker_idx]--;
    *addr_out = fwd->split_tail_cache[worker_idx][fwd->split_tail_count[worker_idx]];
    return 0;
}

static int encrypt_to_wan(struct forwarder *fwd, struct ne_packet *job,
                        int wan_dp,
                        struct packet_crypto_ctx *pctx,
                        enum l2_crypto_proto proto, int flow_ok)
{
    int worker_idx = dp_crypto_current_worker_idx();
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    struct ne_packet tail = {0};
    uint8_t *tail_buf = NULL;
    uint32_t len = job->len;
    uint32_t l1 = 0, l2 = 0;
    uint32_t bond_seq;

    (void)flow_ok;

    if (proto == L2_PROTO_UDP) {
        if (!flow_ok || dp_udp_next_tx_seq(pkt, len, &bond_seq) != 0)
            return -1;
        l2_crypto_udp_set_tx_seq(bond_seq);
    }

    if (proto == L2_PROTO_UDP && l2_crypto_need_udp_split(len)) {
        if (split_tail_take(fwd, worker_idx, &tail.addr) != 0)
            return -1;
        tail_buf = ne_packet_data(&fwd->pair, tail.addr);
        if (l2_crypto_split_udp(pctx, pkt, len, fwd->pair.frame_size, &l1,
                                tail_buf, fwd->pair.frame_size, &l2) != 0) {
            ne_frame_free(&fwd->pair, tail.addr);
            return -1;
        }
        if (push_split_to_wan(fwd, job, l1, &tail, l2, wan_dp) != 0)
            return -1;
        return 1;
    }

    if (l2_crypto_encrypt(proto, pctx, pkt, &len) != 0)
        return -1;
    job->len = len;
    return 0;
}

int dataplane_local_needs_mid(struct forwarder *fwd, const uint8_t *pkt, uint32_t len,
                              int local_idx)
{
    (void)fwd; (void)pkt; (void)len; (void)local_idx;
    return 1;
}

static int pick_equal_wan(struct forwarder *fwd, int flow_ok, uint32_t src_ip,
                          uint32_t dst_ip, uint16_t src_port, uint16_t dst_port,
                          uint8_t proto, uint32_t bytes)
{
    if (!fwd || fwd->wan_count <= 0) return -1;
    if (!flow_ok)
        return flow_table_pick_equal_packet_wan(fwd->wan_count);
    return flow_table_get_equal_wan(&fwd->wan_flows, src_ip, dst_ip,
                                    src_port, dst_port, proto, bytes);
}

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int flow_ok = dp_parse_flow(pkt, job.len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) == 0;
    int li = job.local_idx < fwd->local_count ? (int)job.local_idx : 0;
    int wan_dp;
    int enc;

    if (!fwd || !pkt)
        goto drop;

    if (dp_pkt_is_arp(pkt, job.len)) {
        /* ARP uses its dedicated encrypted bridge path. Diagnostic mode does
         * not learn or persist its source MAC. */
        if (arp_bridge_from_local(fwd, &job, li) == 0)
            return;
        goto drop;
    }

    wan_dp = pick_equal_wan(fwd, flow_ok, src_ip, dst_ip, src_port, dst_port,
                            proto, dp_flow_window_bytes(pkt, job.len, job.len));
    if (wan_dp < 0)
        goto drop;
    enc = encrypt_to_wan(fwd, &job, wan_dp, &fwd->crypto,
                        l2_crypto_classify(proto), flow_ok);
    if (enc < 0)
        goto drop;
    if (enc > 0)
        return;
    (void)push_to_wan(fwd, &job, wan_dp);
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
}

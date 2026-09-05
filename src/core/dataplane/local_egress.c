#include "../../../inc/core/dataplane/dataplane.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/crypto/l2_crypto.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/packet_crypto.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/dataplane/dp_idle.h"

#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <stdio.h>

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
        ne_packet_free(&fwd->pair, tail);
        return -1;
    }
    if (l1 == 0 || l2 == 0 || l1 > NE_JUMBO_FRAME_MAX ||
        l2 > NE_JUMBO_FRAME_MAX) {
        ne_packet_free(&fwd->pair, tail);
        return -1;
    }
    tail->len = l2;
    tail->dir = NE_DIR_WAN;
    tail->wan_idx = (uint8_t)wan_dp;
    job->len = l1;
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    if (ne_ring_try_push_pair(tx, job, tail) != 0) {
        ne_packet_free(&fwd->pair, tail);
        return -1;
    }
    ne_dp_idle_wake_tx_worker(dp_out_ring_idx());
    return 0;
}

static int encrypt_to_wan(struct forwarder *fwd, struct ne_packet *job,
                        int wan_dp,
                        struct packet_crypto_ctx *pctx,
                        enum l2_crypto_proto proto, int flow_ok)
{
    int worker_idx = dp_crypto_current_worker_idx();
    uint8_t *pkt = fwd->crypto_buf[worker_idx];
    struct ne_packet tail = {0};
    uint8_t *tail_buf = fwd->crypto_aux[worker_idx];
    uint32_t len = job->len;
    uint32_t l1 = 0, l2 = 0;
    uint32_t udp_seq;

    (void)flow_ok;

    if (proto != L2_PROTO_UDP)
        (void)crypto_tcp_clamp_mss(pkt, len, L2_CRYPTO_MTU,
                                   L2_CRYPTO_DATA_OVERHEAD);

    if (proto == L2_PROTO_UDP) {
        if (!flow_ok || dp_udp_next_tx_seq(pkt, len, &udp_seq) != 0)
            return -1;
        l2_crypto_udp_set_tx_seq(udp_seq);
    }

    if (proto == L2_PROTO_UDP && l2_crypto_need_udp_split(len)) {
        if (l2_crypto_split_udp(pctx, pkt, len, NE_JUMBO_FRAME_MAX, &l1,
                                tail_buf, NE_JUMBO_FRAME_MAX, &l2) != 0)
            return -1;
        if (ne_packet_write(&fwd->pair, job, pkt, l1) != 0 ||
            ne_packet_write(&fwd->pair, &tail, tail_buf, l2) != 0) {
            ne_packet_free(&fwd->pair, &tail);
            return -1;
        }
        if (push_split_to_wan(fwd, job, l1, &tail, l2, wan_dp) != 0)
            return -1;
        return 1;
    }

    if (l2_crypto_encrypt(proto, pctx, pkt, &len) != 0)
        return -1;
    {
        uint32_t wire_max = ETH_HEADER_SIZE + L2_CRYPTO_MTU;

        if (len > wire_max)
            return -1;
    }
    return ne_packet_write(&fwd->pair, job, pkt, len);
}

int dataplane_local_needs_mid(struct forwarder *fwd, const uint8_t *pkt, uint32_t len,
                              int local_idx)
{
    (void)fwd; (void)pkt; (void)len; (void)local_idx;
    return 1;
}

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job)
{
    int worker_idx = dp_crypto_current_worker_idx();
    uint8_t *pkt = fwd ? fwd->crypto_buf[worker_idx] : NULL;
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int flow_ok;
    int wan_dp;
    int enc;

    if (!fwd || !pkt ||
        ne_packet_linearize(&fwd->pair, &job, pkt, NE_JUMBO_FRAME_MAX) != 0)
        goto drop;

    flow_ok = dp_parse_flow(pkt, job.len, &src_ip, &dst_ip,
                            &src_port, &dst_port, &proto) == 0;

    /* Debug topology is deliberately one LAN to one WAN. */
    wan_dp = 0;
    if (fwd->wan_count != 1)
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
    ne_packet_free(&fwd->pair, &job);
}

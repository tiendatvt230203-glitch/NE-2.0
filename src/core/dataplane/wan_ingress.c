#include "../../../inc/core/dataplane/dataplane.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/dataplane/arp_bridge.h"
#include "../../../inc/core/dataplane/udp_reorder.h"
#include "../../../inc/core/util/static_config.h"
#include "../../../inc/crypto/l2_crypto.h"
#include "../../../inc/crypto/eth_parse.h"
#include <netinet/in.h>
#include <string.h>

#define UDP_MARK_LEN 4u
static const uint8_t udp_mark[UDP_MARK_LEN] = {0x5b,0x55,0x44,0x01};

static int is_udp_wire(const uint8_t *pkt, uint32_t len)
{
    int off;
    if (!crypto_eth_l2_has_marker(pkt, len)) return 0;
    off = crypto_eth_l2_frag_magic_off(pkt, len, PACKET_CRYPTO_NONCE_BYTES);
    return off >= 0 && len >= (uint32_t)off + UDP_MARK_LEN &&
           memcmp(pkt + off, udp_mark, UDP_MARK_LEN) == 0;
}

static int forward_local(struct forwarder *fwd, struct ne_packet *job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    int li;

    if (pkt[0] & 1u) {
        for (li = 1; li < fwd->local_count; li++) {
            struct ne_packet clone = *job;
            if (ne_frame_alloc(&fwd->pair, &clone.addr) != 0)
                continue;
            memcpy(ne_packet_data(&fwd->pair, clone.addr), pkt, job->len);
            clone.dir = NE_DIR_LOCAL;
            clone.local_idx = (uint8_t)li;
            (void)dp_ring_push(fwd, &fwd->mid_to_local[li][dp_out_ring_idx()], &clone);
        }
        li = 0;
    } else {
        li = static_config_local_for_dmac(fwd->cfg, pkt);
        if (li < 0)
            return -1;
    }
    job->dir = NE_DIR_LOCAL;
    job->local_idx = (uint8_t)li;
    return dp_ring_push(fwd, &fwd->mid_to_local[li][dp_out_ring_idx()], job);
}

static int reorder_emit(void *ctx, struct dp_udp_reorder_item *item)
{
    struct forwarder *fwd = ctx;
    dp_out_ring_bind(item->tx_slot);
    return forward_local(fwd, &item->packet);
}
static void reorder_drop(void *ctx, struct dp_udp_reorder_item *item)
{
    struct forwarder *fwd = ctx;
    ne_frame_free(&fwd->pair, item->packet.addr);
}
static struct dp_udp_reorder_ops reorder_ops(struct forwarder *fwd)
{
    struct dp_udp_reorder_ops o = {.ctx=fwd,.emit=reorder_emit,.drop=reorder_drop};
    return o;
}

void dataplane_bond_reorder_configure(struct forwarder *fwd)
{
    dp_udp_reorder_configure(fwd ? (uint32_t)fwd->wan_count : 0);
}
void dataplane_bond_reorder_gc(struct forwarder *fwd, int worker)
{
    struct dp_udp_reorder_ops o = reorder_ops(fwd);
    dp_udp_reorder_gc(worker, dp_udp_reorder_now_ns(), &o);
}
void dataplane_bond_reorder_reset(struct forwarder *fwd, int worker)
{
    struct dp_udp_reorder_ops o = reorder_ops(fwd);
    dp_udp_reorder_reset_worker(worker, &o);
}

int dataplane_wan_needs_mid(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    (void)fwd;
    return crypto_eth_l2_has_marker(pkt, len) ||
           crypto_eth_l2_has_arp_marker(pkt, len);
}

void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt;
    uint32_t len, out_len = 0, epoch = 0, seq = 0;
    int rr;
    if (!fwd || !(pkt = ne_packet_data(&fwd->pair, job.addr))) goto drop;
    if (crypto_eth_l2_has_arp_marker(pkt, job.len)) {
        dp_out_ring_bind(dp_pick_tx_slot(pkt, job.len));
        if (arp_bridge_from_wan(fwd, &job) == 0) return;
        goto drop;
    }
    if (!crypto_eth_l2_has_marker(pkt, job.len)) goto drop;
    len = job.len;
    l2_crypto_udp_clear_rx_meta();
    if (is_udp_wire(pkt, len)) {
        rr = l2_crypto_reassemble_udp(dp_crypto_current_worker_idx(),
             &fwd->crypto, pkt, &len, pkt, &out_len);
        if (rr == 0) { ne_frame_free(&fwd->pair, job.addr); return; }
        if (rr != 1) goto drop;
        job.len = out_len;
    } else {
        if (l2_crypto_decrypt(L2_PROTO_DATA, &fwd->crypto, pkt, &len) != 0)
            goto drop;
        job.len = len;
    }
    if (l2_crypto_udp_take_rx_meta(&epoch, &seq) == 0) {
        struct dp_udp_reorder_key key;
        struct dp_udp_reorder_item item = {.packet=job};
        struct dp_udp_reorder_ops ops = reorder_ops(fwd);
        uint8_t proto;
        if (dp_parse_flow(pkt, job.len, &key.src_ip, &key.dst_ip,
                          &key.src_port, &key.dst_port, &proto) != 0 ||
            proto != IPPROTO_UDP) goto drop;
        item.tx_slot = (uint8_t)dp_udp_pick_tx_slot(key.src_ip,key.dst_ip,
            key.src_port,key.dst_port,dp_crypto_current_worker_idx());
        dp_udp_reorder_submit(dp_crypto_current_worker_idx(), &key, epoch, seq,
                              &item, dp_udp_reorder_now_ns(), &ops);
        return;
    }
    dp_out_ring_bind(dp_flow_pick_tx_slot(pkt, job.len, dp_crypto_current_worker_idx()));
    if (forward_local(fwd, &job) == 0) return;
drop:
    ne_frame_free(&fwd->pair, job.addr);
}

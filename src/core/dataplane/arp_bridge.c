#include "../../../inc/core/dataplane/arp_bridge.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/core/util/static_config.h"
#include "../../../inc/crypto/l2_crypto.h"
#include "../../../inc/crypto/eth_parse.h"
#include <string.h>

int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job, int ingress_li)
{
    uint8_t *pkt;
    uint32_t len;
    int wan;
    if (!fwd || !job || ingress_li < 0) return -1;
    pkt = ne_packet_data(&fwd->pair, job->addr);
    len = job->len;
    if (l2_crypto_encrypt(L2_PROTO_ARP, &fwd->crypto, pkt, &len) != 0)
        return -1;
    job->len = len;
    wan = ingress_li % fwd->wan_count;
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan;
    return dp_ring_push(fwd, &fwd->mid_to_wan[wan][dp_out_ring_idx()], job);
}

static int push_local(struct forwarder *fwd, struct ne_packet *job, int li)
{
    job->dir = NE_DIR_LOCAL;
    job->local_idx = (uint8_t)li;
    return dp_ring_push(fwd, &fwd->mid_to_local[li][dp_out_ring_idx()], job);
}

int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job)
{
    uint8_t *pkt;
    uint32_t len;
    int li;
    if (!fwd || !job) return -1;
    pkt = ne_packet_data(&fwd->pair, job->addr);
    len = job->len;
    if (l2_crypto_decrypt(L2_PROTO_ARP, &fwd->crypto, pkt, &len) != 0 ||
        !crypto_pkt_is_arp(pkt, len)) return -1;
    job->len = len;
    if (!(pkt[0] & 1u)) {
        li = static_config_local_for_dmac(fwd->cfg, pkt);
        return li >= 0 ? push_local(fwd, job, li) : -1;
    }
    /* ARP broadcast is rare; clone it to every configured LAN. */
    for (li = 1; li < fwd->local_count; li++) {
        struct ne_packet clone = *job;
        if (ne_frame_alloc(&fwd->pair, &clone.addr) != 0) continue;
        memcpy(ne_packet_data(&fwd->pair, clone.addr), pkt, len);
        (void)push_local(fwd, &clone, li);
    }
    return push_local(fwd, job, 0);
}

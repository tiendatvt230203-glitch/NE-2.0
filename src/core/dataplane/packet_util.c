#include "../../../inc/core/dataplane/dataplane_util.h"

#include "../../../inc/core/dataplane/dp_idle.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/crypto/eth_parse.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>

int dp_parse_flow(void *pkt_data, uint32_t pkt_len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto)
{
    int l3_off;
    struct iphdr *ip;
    uint32_t ihl;

    if (!pkt_data || !src_ip || !dst_ip || !src_port || !dst_port || !proto)
        return -1;

    l3_off = crypto_eth_ipv4_offset(pkt_data, pkt_len);
    if (l3_off < 0)
        return -1;

    ip = (struct iphdr *)((uint8_t *)pkt_data + l3_off);
    ihl = (uint32_t)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr) || pkt_len < (uint32_t)(l3_off + ihl))
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *proto = ip->protocol;
    *src_port = 0;
    *dst_port = 0;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        uint8_t *l4 = (uint8_t *)pkt_data + l3_off + ihl;
        if (pkt_len < (uint32_t)(l4 - (uint8_t *)pkt_data + 4))
            return -1;
        uint16_t *ports = (uint16_t *)l4;
        *src_port = ntohs(ports[0]);
        *dst_port = ntohs(ports[1]);
    }
    return 0;
}

int dp_pkt_is_arp(const uint8_t *pkt, uint32_t len)
{
    uint16_t et;

    if (!pkt || len < ETH_HEADER_SIZE)
        return 0;

    et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x8100u) {
        if (len < 18u)
            return 0;
        et = ((uint16_t)pkt[16] << 8) | pkt[17];
    }
    return et == 0x0806u;
}

int dp_ring_push(struct forwarder *fwd, struct ne_ring *ring, struct ne_packet *pkt)
{
    if (pkt->len > fwd->pair.frame_size || ne_ring_try_push(ring, pkt) != 0) {
        ne_frame_free(&fwd->pair, pkt->addr);
        return -1;
    }
    ne_dp_idle_wake_tx_worker(dp_out_ring_idx());
    return 0;
}

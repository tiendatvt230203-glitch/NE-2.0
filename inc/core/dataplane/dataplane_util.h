#ifndef DATAPLANE_UTIL_H
#define DATAPLANE_UTIL_H

#include "core/forwarder/forwarder.h"

int dp_parse_flow(void *pkt, uint32_t len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto);

int dp_pkt_is_arp(const uint8_t *pkt, uint32_t len);

/* Bytes charged toward WAN window_kb quota. ARP → 0 (never counts bandwidth). */
static inline uint32_t dp_flow_window_bytes(const uint8_t *pkt, uint32_t len, uint32_t pkt_len)
{
    if (!pkt || dp_pkt_is_arp(pkt, len))
        return 0;
    return pkt_len;
}


int dp_ring_push(struct forwarder *fwd, struct ne_ring *ring, struct ne_packet *pkt);
int dp_parse_arp_ips(const uint8_t *pkt, uint32_t len, uint32_t *spa, uint32_t *tpa);
int dp_parse_arp_op(const uint8_t *pkt, uint32_t len, uint16_t *op_out);
#endif

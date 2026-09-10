#ifndef MTU1500_TCP_MSS_H
#define MTU1500_TCP_MSS_H

#include "core/forwarder/forwarder.h"

/* Returns 1 when MSS changed, 0 when unchanged/inactive, -1 on malformed TCP. */
int dp_mtu1500_tcp_clamp_mss(struct forwarder *fwd, uint8_t *pkt,
                             uint32_t pkt_len, int l3_off);

#endif

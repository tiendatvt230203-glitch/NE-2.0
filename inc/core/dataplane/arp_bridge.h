#ifndef ARP_BRIDGE_H
#define ARP_BRIDGE_H

#include "core/forwarder/forwarder.h"


void arp_bridge_reload_policies(struct app_config *cfg);

int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li,
                          char egress_ifname[IF_NAMESIZE]);
int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp,
                        char egress_ifname[IF_NAMESIZE]);

#endif

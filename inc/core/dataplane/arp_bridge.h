#ifndef ARP_BRIDGE_H
#define ARP_BRIDGE_H
#include "core/forwarder/forwarder.h"
int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job, int ingress_li);
int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job);
#endif

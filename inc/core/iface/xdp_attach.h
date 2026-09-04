#ifndef XDP_ATTACH_H
#define XDP_ATTACH_H

#include "core/util/config.h"
#include "core/forwarder/forwarder.h"

void xdp_attach_prepare_init(const struct app_config *cfg);

int xdp_attach_all(struct ne_pair *p, const struct app_config *cfg);

int xdp_attach_bind_local(struct ne_pair *p, const struct app_config *cfg, int pair_li);
int xdp_attach_bind_wan(struct ne_pair *p, const struct app_config *cfg, int dp_slot,
                               uint16_t fake_ethertype_ipv4);

void xdp_attach_detach_ifname(const char *ifname);
void xdp_attach_detach_config(const struct app_config *cfg);

#endif

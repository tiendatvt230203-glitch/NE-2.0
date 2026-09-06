#ifndef PROFILE_IFACE_XDP_H
#define PROFILE_IFACE_XDP_H

#include "core/util/config.h"
#include "core/forwarder/forwarder.h"

void profile_iface_xdp_prepare_init(const struct app_config *cfg);

int profile_iface_xdp_attach_init(struct ne_pair *p, const struct app_config *cfg);

int profile_iface_xdp_bind_local(struct ne_pair *p, const struct app_config *cfg, int pair_li);
int profile_iface_xdp_bind_wan(struct ne_pair *p, const struct app_config *cfg, int dp_slot,
                               uint16_t fake_ethertype_ipv4);

void profile_iface_xdp_detach_local(struct ne_pair *p, int pair_li);
void profile_iface_xdp_detach_wan(struct ne_pair *p, int dp_slot);
void profile_iface_xdp_detach_ifname(const char *ifname);
void profile_iface_xdp_detach_config(const struct app_config *cfg);

int profile_iface_xdp_sync_wan_live(struct forwarder *fwd, const struct app_config *new_cfg,
                                    const struct app_config *old_cfg);

#endif

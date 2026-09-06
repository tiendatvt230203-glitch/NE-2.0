#ifndef WAN_ADMIN_H
#define WAN_ADMIN_H

struct forwarder;

int wan_admin_kick(struct forwarder *fwd, const char *ifname);
int wan_admin_restore(struct forwarder *fwd, const char *ifname);

#endif

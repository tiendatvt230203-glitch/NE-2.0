#ifndef PROFILE_IFACE_LIFECYCLE_H
#define PROFILE_IFACE_LIFECYCLE_H

#include "core/util/config.h"
#include "core/forwarder/forwarder.h"

struct profile_attach_sess {
    int validate_failed;
    int lan_added[MAX_INTERFACES];
    int lan_n;
    int wan_added[MAX_INTERFACES];
    int wan_n;
};

void profile_iface_life_attach_wan_rows(struct forwarder *fwd,
                                       const struct app_config *new_cfg,
                                       int trigger_profile_id,
                                       struct profile_attach_sess *sess);
void profile_iface_life_attach_rollback(struct forwarder *fwd,
                                       struct profile_attach_sess *sess);

void profile_iface_life_reconcile_counts(struct forwarder *fwd);

#endif

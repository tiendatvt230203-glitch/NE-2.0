#ifndef WAN_FAILOVER_H
#define WAN_FAILOVER_H

struct forwarder;


#ifndef FAILOVER_ENABLE
#define FAILOVER_ENABLE 1
#endif

int wan_failover_enabled(void);
int wan_failover_start(struct forwarder *fwd);
void wan_failover_on_cfg(struct forwarder *fwd);
void wan_failover_stop(void);
int wan_failover_dp_excluded(int wan_dp);

#endif
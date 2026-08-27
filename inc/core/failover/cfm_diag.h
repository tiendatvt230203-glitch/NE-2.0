#ifndef CFM_DIAG_H
#define CFM_DIAG_H

#include <stdbool.h>
#include <stdint.h>
#include <net/if.h>

struct app_config;

#ifndef CFM_WAN_SNAP_MAX
#define CFM_WAN_SNAP_MAX 16
#endif

struct cfm_wan_snap {
    char ifname[IF_NAMESIZE];
    char bridge[IF_NAMESIZE];
    uint8_t peer_mac[6];
    int mac_learned;
    int is_up;
};

typedef enum {
    CFM_LINK_STATE_INIT = 0,
    CFM_LINK_STATE_UP = 1,
    CFM_LINK_STATE_DOWN = -1
} cfm_link_state_t;

typedef void (*cfm_link_state_cb)(int wan_dp, const char *ifname,
                                  int old_state, int new_state, void *user);

/* Packet-Parser-ne failover API — wan_dp is dataplane index (config_wan_cfg_to_dp). */
int cfm_init(const struct app_config *cfg);
/* 1 if CFM monitors wan_dp and link is DOWN; 0 if UP or not CFM-managed. */
int cfm_link_is_down(int wan_dp);
void cfm_cleanup(void);

void cfm_set_state_callback(cfm_link_state_cb cb, void *user);

/* Snapshot WAN peer MAC + UP/DOWN for unified [mac] table. */
int cfm_snapshot_wan_peers(struct cfm_wan_snap *out, int max);

int cfm_wan_status_by_name(const char *name);
void cfm_status_ipc_start(void);
int cfm_status_ipc_query(const char *name);

#endif
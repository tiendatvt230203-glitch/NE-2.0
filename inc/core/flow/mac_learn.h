#ifndef MAC_LEARN_H
#define MAC_LEARN_H

#include "core/util/config.h"
#include <pthread.h>
#include <stdint.h>

struct forwarder;

#define MAC_LEARN_MAX_ENTRIES 256
#define MAC_LEARN_HASH_BUCKETS 256

enum mac_learn_src {
    MAC_LEARN_SRC_TRAFFIC = 0, /* rejected — FDB is ARP-only */
    MAC_LEARN_SRC_ARP = 1,     /* LAN ARP SMAC only — one MAC per LAN port */
};

struct mac_learn_entry {
    uint8_t mac[MAC_LEN];
    char ifname[IF_NAMESIZE];
};

struct mac_learn_table {
    struct mac_learn_entry list[MAC_LEARN_MAX_ENTRIES];
    int count;
    int hash_head[MAC_LEARN_HASH_BUCKETS];
    int hash_next[MAC_LEARN_MAX_ENTRIES];
    /* Cached hwaddrs of configured LAN ports — never learned into FDB. */
    uint8_t iface_macs[MAX_INTERFACES][MAC_LEN];
    int iface_mac_count;
    pthread_spinlock_t lock;
};

void mac_learn_bootstrap(struct mac_learn_table *t);
void mac_learn_shutdown(struct mac_learn_table *t);
void mac_learn_persist(struct forwarder *fwd);
void mac_learn_restore(struct forwarder *fwd);
void mac_learn_tick(struct forwarder *fwd);

/* Một bảng hệ thống: LAN/WAN + bridge + mac + WAN UP/DOWN. Bảng mới nhất = đang dùng. */
void mac_learn_log_runtime_table(struct forwarder *fwd, const struct app_config *cfg,
                                 const char *event);

/*
 * L2 FDB: one client MAC per LAN ifname (replace on learn).
 * Chỉ học SMAC từ ARP Request của client cắm dây (arp_bridge_from_local).
 * ARP relay WAN→LAN được stamp — không học / không re-bridge (tránh MAC client xa).
 * WAN→LAN ARP unicast: lookup DMAC; no entry → drop (no fallback).
 */
void mac_learn_refresh_iface_macs(struct forwarder *fwd);
int mac_is_appliance_mac(struct forwarder *fwd, const uint8_t mac[MAC_LEN]);
void mac_relay_stamp(const uint8_t smac[MAC_LEN], uint32_t spa_be);
int mac_relay_recent(const uint8_t smac[MAC_LEN], uint32_t spa_be);
void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len,
               enum mac_learn_src src);
int mac_lookup(struct forwarder *fwd, const uint8_t mac[MAC_LEN]);

/* Map config local_idx -> live fwd local slot. */
int mac_fwd_local_for_cfg_idx(const struct forwarder *fwd, int cfg_li);

/* Map ingress WAN dp → live fwd local slot via bridge pair (for WAN ARP/data). */
int mac_fwd_local_for_wan_dp(struct forwarder *fwd, int profile_pi, int wan_dp);

#endif

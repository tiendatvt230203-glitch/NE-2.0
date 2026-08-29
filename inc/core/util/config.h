#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <net/if.h>

#define MAX_INTERFACES 16
#define MAC_LEN 6
#define MAX_PROFILES 32
#define MAX_PROFILE_INTERFACES 16
#define MAX_BRIDGES_PER_PROFILE MAX_PROFILE_INTERFACES
#define MAX_CRYPTO_POLICIES 128
#define POLICY_PROTO_ANY 0
#define POLICY_PROTO_TCP_UDP 254

#ifndef CRYPTO_POLICY_MATCH_IP_ONLY
#define CRYPTO_POLICY_MATCH_IP_ONLY 0
#endif

enum policy_action {
    POLICY_ACTION_BYPASS = 0,
    POLICY_ACTION_ENCRYPT_L2 = 2
};

struct crypto_policy {
    int id;
    int db_id;
    int priority;
    int action;
    uint8_t protocol;
    int src_port_from;
    int src_port_to;
    int dst_port_from;
    int dst_port_to;
    int src_any;
    int dst_any;
    int src_negate;
    int dst_negate;
    uint32_t src_net;
    uint32_t src_mask;
    uint32_t dst_net;
    uint32_t dst_mask;
};

struct bridge_pair {
    int local_idx;
    int wan_dp;
    char ifname[IF_NAMESIZE];
};

struct profile_config {
    int id;
    char name[64];
    int enabled;
    int bridge_enable;
    int bridge_count;
    struct bridge_pair bridges[MAX_BRIDGES_PER_PROFILE];
    int local_indices[MAX_PROFILE_INTERFACES];
    int local_count;
    int wan_indices[MAX_PROFILE_INTERFACES];
    int wan_bandwidth_weight[MAX_PROFILE_INTERFACES];
    int wan_count;
    int policy_indices[MAX_CRYPTO_POLICIES];
    int policy_count;
    int policy_in_any;
    char local_identity_fingerprint[16];
    char peer_fingerprint[16];
    int pqc_is_initiator;
    int has_pqc_identity;
#define PQC_PEER_PUB_MAX 8192
    char pqc_peer_pub[PQC_PEER_PUB_MAX];
};

struct local_config {
    char ifname[IF_NAMESIZE];
};

struct wan_config {
    char ifname[IF_NAMESIZE];
    uint32_t dst_ip;
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    int dataplane;
};

struct app_config {
    struct local_config locals[MAX_INTERFACES];
    int local_count;

    struct wan_config wans[MAX_INTERFACES];
    int wan_count;

    char bpf_file[256];
    char bpf_wan_file[256];

    int crypto_enabled;
    uint16_t fake_ethertype_ipv4;
    struct profile_config profiles[MAX_PROFILES];
    int profile_count;
    struct crypto_policy policies[MAX_CRYPTO_POLICIES];
    int policy_count;
};

int config_wan_profile_weight(const struct app_config *cfg, int wan_idx);
int config_wan_live(const struct app_config *cfg, int wan_idx);
int config_wan_live_in_cfg(const struct app_config *cfg, const char *ifname);
int config_count_dataplane_wans(const struct app_config *cfg);
int config_wan_cfg_to_dp(const struct app_config *cfg, int cfg_idx);
int config_wan_dp_to_cfg(const struct app_config *cfg, int dp_idx);

int parse_ip_cidr_pub(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network);
int parse_hex_bytes_pub(const char *str, uint8_t *out, int expected_len);
int config_validate(struct app_config *cfg);
int config_local_ifname_in_cfg(const struct app_config *cfg, const char *ifname);
int config_policy_db_id_taken(const struct app_config *cfg, int db_id);
const struct crypto_policy *config_select_crypto_policy(struct app_config *cfg, int profile_idx,
                                                        uint32_t src_ip, uint32_t dst_ip,
                                                        uint16_t src_port, uint16_t dst_port,
                                                        uint8_t protocol);
void config_refresh_policy_in_any(struct app_config *cfg);
int config_policy_in_ok(const struct app_config *cfg, int profile_idx,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint8_t protocol);
#endif

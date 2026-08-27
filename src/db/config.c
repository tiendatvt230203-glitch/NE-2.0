#include "../../inc/core/util/config.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include <netinet/in.h>

static uint32_t ipv4_prefix_to_mask_be(int prefix_len) {
    if (prefix_len <= 0)
        return 0;
    if (prefix_len >= 32)
        return htonl(0xFFFFFFFFu);
    return htonl(0xFFFFFFFFu << (32 - prefix_len));
}

static int ipv4_mask_be_is_contiguous(uint32_t mask_be) {
    uint32_t m = ntohl(mask_be);
    if (m == 0)
        return 1;
    uint32_t inv = ~m;
    return (inv & (inv + 1u)) == 0;
}

static int parse_ipv4_netmask_be(const char *s, uint32_t *mask_out) {
    struct in_addr a;

    if (!s || !mask_out || !s[0])
        return -1;
    if (inet_pton(AF_INET, s, &a) != 1)
        return -1;
    if (!ipv4_mask_be_is_contiguous(a.s_addr))
        return -1;
    *mask_out = a.s_addr;
    return 0;
}

static int parse_ip_cidr(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    char buf[128];
    const char *ip_part;
    const char *suffix = NULL;

    if (!str || !ip || !netmask)
        return -1;

    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        suffix = slash + 1;
        while (*suffix == ' ' || *suffix == '\t')
            suffix++;
        if (!suffix[0])
            return -1;
    }

    ip_part = buf;
    while (*ip_part == ' ' || *ip_part == '\t')
        ip_part++;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_part, &addr) != 1)
        return -1;

    *ip = addr.s_addr;

    if (suffix) {
        if (strchr(suffix, '.')) {
            if (parse_ipv4_netmask_be(suffix, netmask) != 0)
                return -1;
        } else {
            char *end = NULL;
            long plen = strtol(suffix, &end, 10);
            if (!end || *end != '\0' || plen < 0 || plen > 32)
                return -1;
            *netmask = ipv4_prefix_to_mask_be((int)plen);
        }
    } else {
        *netmask = ipv4_prefix_to_mask_be(32);
    }

    if (network)
        *network = *ip & *netmask;

    return 0;
}

static int parse_hex_bytes(const char *str, uint8_t *out, int expected_len) {
    int len = strlen(str);
    if (len != expected_len * 2)
        return -1;

    for (int i = 0; i < expected_len; i++) {
        unsigned int val;
        if (sscanf(str + i * 2, "%2x", &val) != 1)
            return -1;
        out[i] = (uint8_t)val;
    }
    return 0;
}

int config_policy_db_id_taken(const struct app_config *cfg, int db_id)
{
    if (!cfg || db_id <= 0)
        return 0;
    for (int i = 0; i < cfg->policy_count; i++) {
        if (cfg->policies[i].db_id == db_id)
            return 1;
    }
    return 0;
}

int config_local_ifname_in_cfg(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return 0;
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return 1;
    }
    return 0;
}

int config_wan_profile_weight(const struct app_config *cfg, int wan_idx)
{
    int best = 0;

    if (!cfg || wan_idx < 0 || wan_idx >= cfg->wan_count || cfg->profile_count < 1)
        return 0;

    {
        const struct profile_config *p = &cfg->profiles[0];

        for (int wi = 0; wi < p->wan_count; wi++) {
            if (p->wan_indices[wi] != wan_idx)
                continue;
            if (p->wan_bandwidth_weight[wi] > best)
                best = p->wan_bandwidth_weight[wi];
        }
    }
    return best;
}

int config_wan_live(const struct app_config *cfg, int wan_idx)
{
    if (!cfg || wan_idx < 0 || wan_idx >= cfg->wan_count)
        return 0;
    return cfg->wans[wan_idx].dataplane ? 1 : 0;
}

int config_wan_live_in_cfg(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return config_wan_live(cfg, i);
    }
    return 0;
}

int config_count_dataplane_wans(const struct app_config *cfg)
{
    int n = 0;

    if (!cfg)
        return 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (config_wan_live(cfg, i))
            n++;
    }
    return n;
}

int config_wan_cfg_to_dp(const struct app_config *cfg, int cfg_idx)
{
    if (!config_wan_live(cfg, cfg_idx))
        return -1;
    int dp = 0;
    for (int i = 0; i < cfg_idx; i++) {
        if (config_wan_live(cfg, i))
            dp++;
    }
    return dp;
}

int config_wan_dp_to_cfg(const struct app_config *cfg, int dp_idx)
{
    if (!cfg || dp_idx < 0)
        return -1;
    int seen = 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (!config_wan_live(cfg, i))
            continue;
        if (seen == dp_idx)
            return i;
        seen++;
    }
    return -1;
}

int config_validate(struct app_config *cfg) {
    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];

        if (local->ifname[0] == '\0') {
            fprintf(stderr, "LOCAL[%d]: interface not specified\n", i);
            return -1;
        }
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *wan = &cfg->wans[i];

        if (wan->ifname[0] == '\0') {
            fprintf(stderr, "WAN[%d]: interface not specified\n", i);
            return -1;
        }

        if (wan->window_size == 0) {
            fprintf(stderr, "WAN %s: window_kb not specified\n", wan->ifname);
            return -1;
        }
    }

    return 0;
}

static int cidr_match_with_negate(int any_flag, int negate,
                                    uint32_t ip, uint32_t net, uint32_t mask) {
    if (any_flag)
        return 1;
    int in_cidr = ((ip & mask) == (net & mask));
    return negate ? !in_cidr : in_cidr;
}

static int policy_port_is_any(int from, int to)
{
    if (from < 0 || to < 0)
        return 1;
    return from <= 0 && to >= 65535;
}

/* Policy khớp mọi 5-tuple (kể cả sau khi đảo src/dst chiều IN). */
static int crypto_policy_is_catchall(const struct crypto_policy *cp)
{
    if (!cp)
        return 0;
    if (!cp->src_any || !cp->dst_any)
        return 0;
    if (cp->protocol != POLICY_PROTO_ANY)
        return 0;
#if !CRYPTO_POLICY_MATCH_IP_ONLY
    if (!policy_port_is_any(cp->src_port_from, cp->src_port_to))
        return 0;
    if (!policy_port_is_any(cp->dst_port_from, cp->dst_port_to))
        return 0;
#endif
    return 1;
}

#define POL_IN_SRC_NEG  1u
#define POL_IN_DST_NEG  2u

/* 32 byte/entry, 2 entry / cache line. Field đã đảo chiều IN (packet src = policy dst). */
struct pol_in_match {
    uint32_t src_net;
    uint32_t src_mask;
    uint32_t dst_net;
    uint32_t dst_mask;
    uint16_t sport_lo;
    uint16_t sport_hi;
    uint16_t dport_lo;
    uint16_t dport_hi;
    uint8_t  proto;
    uint8_t  flags;
    uint8_t  _pad[6];
};
_Static_assert(sizeof(struct pol_in_match) == 32, "pol_in_match packing");

static struct pol_in_match s_pol_in[MAX_PROFILES][MAX_CRYPTO_POLICIES];
static int s_pol_in_n[MAX_PROFILES];

static void pol_in_port_range(int from, int to, uint16_t *lo, uint16_t *hi)
{
#if CRYPTO_POLICY_MATCH_IP_ONLY
    *lo = 0;
    *hi = 65535;
    return;
#endif
    if (from < 0 || to < 0) {
        *lo = 0;
        *hi = 65535;
        return;
    }
    if (from > 65535)
        from = 65535;
    if (to > 65535)
        to = 65535;
    if (from > to) {
        int tmp = from;
        from = to;
        to = tmp;
    }
    *lo = (uint16_t)from;
    *hi = (uint16_t)to;
}

/* Policy LAN->WAN: src=LAN, dst=WAN. Gói WAN->LAN ngược lại nên đảo lúc dựng bảng. */
static void pol_in_fill(struct pol_in_match *e, const struct crypto_policy *cp)
{
    memset(e, 0, sizeof(*e));
    if (cp->dst_any) {
        e->src_net = 0;
        e->src_mask = 0;
    } else {
        e->src_mask = cp->dst_mask;
        e->src_net = cp->dst_net & cp->dst_mask;
        if (cp->dst_negate)
            e->flags |= POL_IN_SRC_NEG;
    }
    if (cp->src_any) {
        e->dst_net = 0;
        e->dst_mask = 0;
    } else {
        e->dst_mask = cp->src_mask;
        e->dst_net = cp->src_net & cp->src_mask;
        if (cp->src_negate)
            e->flags |= POL_IN_DST_NEG;
    }
    pol_in_port_range(cp->dst_port_from, cp->dst_port_to, &e->sport_lo, &e->sport_hi);
    pol_in_port_range(cp->src_port_from, cp->src_port_to, &e->dport_lo, &e->dport_hi);
    e->proto = cp->protocol;
}

void config_refresh_policy_in_any(struct app_config *cfg)
{
    memset(s_pol_in, 0, sizeof(s_pol_in));
    memset(s_pol_in_n, 0, sizeof(s_pol_in_n));
    if (!cfg)
        return;
    if (cfg->profile_count > 0) {
        struct profile_config *p = &cfg->profiles[0];
        int skip = 0;
        int n = 0;

        for (int i = 0; i < p->policy_count; i++) {
            int poli = p->policy_indices[i];

            if (poli < 0 || poli >= cfg->policy_count)
                continue;
            if (crypto_policy_is_catchall(&cfg->policies[poli])) {
                skip = 1;
                break;
            }
        }
        p->policy_in_any = skip;
        if (!skip) {
            for (int i = 0; i < p->policy_count; i++) {
                int poli = p->policy_indices[i];

                if (poli < 0 || poli >= cfg->policy_count)
                    continue;
                if (n < MAX_CRYPTO_POLICIES)
                    pol_in_fill(&s_pol_in[0][n++], &cfg->policies[poli]);
            }
        }
        s_pol_in_n[0] = n;
        fprintf(stderr,
                "[CRYPTO-GUARD] profile %d (%s) WAN IN 5-tuple gate %s (%d compact rules)\n",
                p->id, p->name, skip ? "OFF (catch-all any/any)" : "ON", n);
    }
}

int config_policy_in_ok(const struct app_config *cfg, int profile_idx,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint8_t protocol)
{
    int n;
    const struct pol_in_match *tbl;

    if (!cfg || profile_idx < 0 || profile_idx >= cfg->profile_count ||
        profile_idx >= MAX_PROFILES)
        return 0;

    n = s_pol_in_n[profile_idx];
    tbl = s_pol_in[profile_idx];
    for (int i = 0; i < n; i++) {
        const struct pol_in_match *e = &tbl[i];
        int src_ok;
        int dst_ok;

        /* Ít loại → nhiều loại: proto (TCP/UDP/ICMP/OSPF) → IP (NAT, ít) → port (nhiều). */
        if (e->proto == POLICY_PROTO_TCP_UDP) {
            if (protocol != 6 && protocol != 17)
                continue;
        } else if (e->proto != POLICY_PROTO_ANY && e->proto != protocol) {
            continue;
        }
        src_ok = ((src_ip & e->src_mask) == e->src_net);
        dst_ok = ((dst_ip & e->dst_mask) == e->dst_net);
        if (e->flags & POL_IN_SRC_NEG)
            src_ok = !src_ok;
        if (e->flags & POL_IN_DST_NEG)
            dst_ok = !dst_ok;
        if (!src_ok || !dst_ok)
            continue;
        if (src_port < e->sport_lo || src_port > e->sport_hi)
            continue;
        if (dst_port < e->dport_lo || dst_port > e->dport_hi)
            continue;
        return 1;
    }
    return 0;
}

static int crypto_policy_match_packet(const struct crypto_policy *cp,
                                      uint32_t src_ip, uint32_t dst_ip,
                                      uint16_t src_port, uint16_t dst_port,
                                      uint8_t protocol) {

    if (cp->protocol == POLICY_PROTO_TCP_UDP) {
        if (protocol != 6 && protocol != 17)
            return 0;
    } 
    else if (cp->protocol != POLICY_PROTO_ANY && cp->protocol != protocol) {
        return 0;
    }

    if (!cidr_match_with_negate(cp->src_any, cp->src_negate, src_ip, cp->src_net, cp->src_mask))
        return 0;
    if (!cidr_match_with_negate(cp->dst_any, cp->dst_negate, dst_ip, cp->dst_net, cp->dst_mask))
        return 0;

#if !CRYPTO_POLICY_MATCH_IP_ONLY
    if (cp->src_port_from >= 0 && cp->src_port_to >= 0) {
        if ((int)src_port < cp->src_port_from || (int)src_port > cp->src_port_to)
            return 0;
    }
    if (cp->dst_port_from >= 0 && cp->dst_port_to >= 0) {
        if ((int)dst_port < cp->dst_port_from || (int)dst_port > cp->dst_port_to)
            return 0;
    }
#endif

    return 1;
}

const struct crypto_policy *config_select_crypto_policy(struct app_config *cfg, int profile_idx,
                                                        uint32_t src_ip, uint32_t dst_ip,
                                                        uint16_t src_port, uint16_t dst_port,
                                                        uint8_t protocol)
{
    if (!cfg || profile_idx < 0 || profile_idx >= cfg->profile_count)
        return NULL;

    const struct profile_config *p = &cfg->profiles[profile_idx];
    const struct crypto_policy *best = NULL;
    int best_priority = 0x7fffffff;
    int best_id = 0x7fffffff;

    for (int i = 0; i < p->policy_count; i++) {
        int pi = p->policy_indices[i];
        if (pi < 0 || pi >= cfg->policy_count)
            continue;

        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!crypto_policy_match_packet(cp, src_ip, dst_ip, src_port, dst_port, protocol))
            continue;

        if (!best ||
            cp->priority < best_priority ||
            (cp->priority == best_priority && cp->id < best_id)) {
            best = cp;
            best_priority = cp->priority;
            best_id = cp->id;
        }
    }

    return best;
}

int parse_ip_cidr_pub(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    return parse_ip_cidr(str, ip, netmask, network);
}

int parse_hex_bytes_pub(const char *str, uint8_t *out, int expected_len) {
    return parse_hex_bytes(str, out, expected_len);
}
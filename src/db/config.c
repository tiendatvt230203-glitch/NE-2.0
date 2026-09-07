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

    }

    return 0;
}

static int cidr_contains(int any_flag, uint32_t ip,
                         uint32_t net, uint32_t mask)
{
    return any_flag || ((ip & mask) == (net & mask));
}

static int policy_port_is_any(int from, int to)
{
    if (from < 0 || to < 0)
        return 1;
    return from <= 0 && to >= 65535;
}

static int crypto_policy_is_catchall(const struct crypto_policy *cp)
{
    if (!cp || !cp->src_any || !cp->dst_any ||
        cp->protocol != POLICY_PROTO_ANY)
        return 0;
#if !CRYPTO_POLICY_MATCH_IP_ONLY
    if (!policy_port_is_any(cp->src_port_from, cp->src_port_to) ||
        !policy_port_is_any(cp->dst_port_from, cp->dst_port_to))
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
    uint8_t  wire_id;
    uint8_t  _pad0;
    int16_t  next;
    uint8_t  _pad[2];
};
_Static_assert(sizeof(struct pol_in_match) == 32, "pol_in_match packing");

static struct pol_in_match s_pol_in[MAX_PROFILES][MAX_CRYPTO_POLICIES];
static int s_pol_in_n[MAX_PROFILES];
static uint8_t s_pol_in_any[MAX_PROFILES][256];
static int16_t s_pol_in_head[MAX_PROFILES][256];
static uint8_t s_pol_in_has_negate[MAX_PROFILES][256];

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
    e->next = -1;
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
    e->wire_id = (uint8_t)cp->id;
}

void config_refresh_policy_in_table(struct app_config *cfg)
{
    memset(s_pol_in, 0, sizeof(s_pol_in));
    memset(s_pol_in_n, 0, sizeof(s_pol_in_n));
    memset(s_pol_in_any, 0, sizeof(s_pol_in_any));
    memset(s_pol_in_head, 0xff, sizeof(s_pol_in_head));
    memset(s_pol_in_has_negate, 0, sizeof(s_pol_in_has_negate));
    if (!cfg)
        return;
    if (cfg->profile_count > 0) {
        struct profile_config *p = &cfg->profiles[0];
        int n = 0;

        for (int i = 0; i < p->policy_count; i++) {
            int poli = p->policy_indices[i];

            if (poli < 0 || poli >= cfg->policy_count)
                continue;
            if (cfg->policies[poli].action != POLICY_ACTION_ENCRYPT_L2)
                continue;
            if (crypto_policy_is_catchall(&cfg->policies[poli]))
                s_pol_in_any[0][(uint8_t)cfg->policies[poli].id] = 1;
            if (n < MAX_CRYPTO_POLICIES) {
                uint8_t wire_id = (uint8_t)cfg->policies[poli].id;
                struct pol_in_match *e = &s_pol_in[0][n];

                pol_in_fill(e, &cfg->policies[poli]);
                if (e->flags & (POL_IN_SRC_NEG | POL_IN_DST_NEG))
                    s_pol_in_has_negate[0][wire_id] = 1;
                e->next = s_pol_in_head[0][wire_id];
                s_pol_in_head[0][wire_id] = (int16_t)n;
                n++;
            }
        }
        s_pol_in_n[0] = n;
        fprintf(stderr,
                "[CRYPTO-GUARD] profile %d (%s) WAN IN 5-tuple gate %s (%d compact rules)\n",
                p->id, p->name, "ON (exact wire policy)", n);
    }
}

int config_policy_in_ok(const struct app_config *cfg, int profile_idx,
                        uint8_t wire_policy_id,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint8_t protocol)
{
    int n;
    const struct pol_in_match *tbl;
    int src_positive_seen = 0;
    int dst_positive_seen = 0;
    int src_positive_ok = 0;
    int dst_positive_ok = 0;
    int src_negative_ok = 1;
    int dst_negative_ok = 1;
    int sport_ok = 0;
    int dport_ok = 0;
    int proto_ok = 0;

    if (!cfg || profile_idx < 0 || profile_idx >= cfg->profile_count ||
        profile_idx >= MAX_PROFILES)
        return 0;
    if (s_pol_in_any[profile_idx][wire_policy_id])
        return 1;

    n = s_pol_in_n[profile_idx];
    tbl = s_pol_in[profile_idx];
    if (!s_pol_in_has_negate[profile_idx][wire_policy_id]) {
        for (int i = s_pol_in_head[profile_idx][wire_policy_id];
             i >= 0 && i < n; i = tbl[i].next) {
            const struct pol_in_match *e = &tbl[i];
            int entry_proto_ok;

            if (e->proto == POLICY_PROTO_TCP_UDP)
                entry_proto_ok = protocol == 6 || protocol == 17;
            else
                entry_proto_ok = e->proto == POLICY_PROTO_ANY ||
                    e->proto == protocol;
            if (entry_proto_ok &&
                ((src_ip & e->src_mask) == e->src_net) &&
                ((dst_ip & e->dst_mask) == e->dst_net) &&
                src_port >= e->sport_lo && src_port <= e->sport_hi &&
                dst_port >= e->dport_lo && dst_port <= e->dport_hi)
                return 1;
        }
        return 0;
    }
    for (int i = s_pol_in_head[profile_idx][wire_policy_id];
         i >= 0 && i < n; i = tbl[i].next) {
        const struct pol_in_match *e = &tbl[i];
        int src_in;
        int dst_in;

        if (e->proto == POLICY_PROTO_TCP_UDP) {
            proto_ok |= protocol == 6 || protocol == 17;
        } else {
            proto_ok |= e->proto == POLICY_PROTO_ANY || e->proto == protocol;
        }

        src_in = ((src_ip & e->src_mask) == e->src_net);
        dst_in = ((dst_ip & e->dst_mask) == e->dst_net);
        if (e->flags & POL_IN_SRC_NEG)
            src_negative_ok &= !src_in;
        else {
            src_positive_seen = 1;
            src_positive_ok |= src_in;
        }
        if (e->flags & POL_IN_DST_NEG)
            dst_negative_ok &= !dst_in;
        else {
            dst_positive_seen = 1;
            dst_positive_ok |= dst_in;
        }
        sport_ok |= src_port >= e->sport_lo && src_port <= e->sport_hi;
        dport_ok |= dst_port >= e->dport_lo && dst_port <= e->dport_hi;
    }
    return proto_ok &&
        (!src_positive_seen || src_positive_ok) && src_negative_ok &&
        (!dst_positive_seen || dst_positive_ok) && dst_negative_ok &&
        sport_ok && dport_ok;
}

static int policy_port_contains(int from, int to, uint16_t port)
{
#if CRYPTO_POLICY_MATCH_IP_ONLY
    (void)from;
    (void)to;
    (void)port;
    return 1;
#else
    return from < 0 || to < 0 || ((int)port >= from && (int)port <= to);
#endif
}

/* All expanded entries with one db_id form one UI policy. Address/port lists
 * are OR groups; negated address items must all be absent (AND of NOTs). */
static int crypto_policy_group_match(const struct app_config *cfg,
                                     const struct profile_config *p,
                                     int first, int *next,
                                     uint32_t src_ip, uint32_t dst_ip,
                                     uint16_t src_port, uint16_t dst_port,
                                     uint8_t protocol)
{
    int first_pi = p->policy_indices[first];
    const struct crypto_policy *base = &cfg->policies[first_pi];
    int src_positive_seen = 0;
    int dst_positive_seen = 0;
    int src_positive_ok = 0;
    int dst_positive_ok = 0;
    int src_negative_ok = 1;
    int dst_negative_ok = 1;
    int sport_ok = 0;
    int dport_ok = 0;
    int proto_ok;
    int positive_match = 0;
    int j;

    if (base->protocol == POLICY_PROTO_TCP_UDP)
        proto_ok = protocol == 6 || protocol == 17;
    else
        proto_ok = base->protocol == POLICY_PROTO_ANY ||
            base->protocol == protocol;

    for (j = first; j < p->policy_count; j++) {
        int pi = p->policy_indices[j];
        const struct crypto_policy *cp;
        int src_in;
        int dst_in;

        if (pi < 0 || pi >= cfg->policy_count)
            break;
        cp = &cfg->policies[pi];
        if (cp->db_id != base->db_id)
            break;

        if (!base->src_negate && !base->dst_negate) {
            if (!positive_match && proto_ok &&
                cidr_contains(cp->src_any, src_ip,
                              cp->src_net, cp->src_mask) &&
                cidr_contains(cp->dst_any, dst_ip,
                              cp->dst_net, cp->dst_mask) &&
                policy_port_contains(cp->src_port_from,
                                     cp->src_port_to, src_port) &&
                policy_port_contains(cp->dst_port_from,
                                     cp->dst_port_to, dst_port))
                positive_match = 1;
            continue;
        }

        src_in = cidr_contains(cp->src_any, src_ip,
                               cp->src_net, cp->src_mask);
        dst_in = cidr_contains(cp->dst_any, dst_ip,
                               cp->dst_net, cp->dst_mask);
        if (cp->src_negate)
            src_negative_ok &= !src_in;
        else {
            src_positive_seen = 1;
            src_positive_ok |= src_in;
        }
        if (cp->dst_negate)
            dst_negative_ok &= !dst_in;
        else {
            dst_positive_seen = 1;
            dst_positive_ok |= dst_in;
        }
        sport_ok |= policy_port_contains(cp->src_port_from,
                                         cp->src_port_to, src_port);
        dport_ok |= policy_port_contains(cp->dst_port_from,
                                         cp->dst_port_to, dst_port);
    }
    *next = j;
    if (!base->src_negate && !base->dst_negate)
        return positive_match;
    return proto_ok &&
        (!src_positive_seen || src_positive_ok) && src_negative_ok &&
        (!dst_positive_seen || dst_positive_ok) && dst_negative_ok &&
        sport_ok && dport_ok;
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

    for (int i = 0; i < p->policy_count;) {
        int pi = p->policy_indices[i];
        int next = i + 1;

        if (pi < 0 || pi >= cfg->policy_count) {
            i++;
            continue;
        }

        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!crypto_policy_group_match(cfg, p, i, &next,
                                       src_ip, dst_ip, src_port, dst_port,
                                       protocol)) {
            i = next;
            continue;
        }

        if (!best ||
            cp->priority < best_priority ||
            (cp->priority == best_priority && cp->id < best_id)) {
            best = cp;
            best_priority = cp->priority;
            best_id = cp->id;
        }
        i = next;
    }

    return best;
}

int parse_ip_cidr_pub(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    return parse_ip_cidr(str, ip, netmask, network);
}

int parse_hex_bytes_pub(const char *str, uint8_t *out, int expected_len) {
    return parse_hex_bytes(str, out, expected_len);
}

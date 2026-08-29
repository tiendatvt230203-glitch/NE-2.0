#include "../../../inc/core/dataplane/arp_bridge.h"
#include "../../../inc/core/util/config.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/core/forwarder/forwarder_crypto_runtime.h"
#include "../../../inc/core/forwarder/forwarder_wan.h"
#include "../../../inc/core/flow/mac_learn.h"
#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/dataplane/dp_idle.h"
#include "../../../inc/core/failover/wan_failover.h"
#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>
#include <net/if.h>

#define ARP_LOG_FAIL_INTERVAL_MS 30000ull
#define ARP_DEFAULT_WIRE_ID      250u
#define ARP_ETH_HDR_LEN          14u

/* 1 = mã hóa ARP L2-PQC (key/option riêng), độc lập bảng policy/data crypto.
 * Decrypt vẫn chạy nếu wire có ARP marker (peer vẫn encrypt). */
#ifndef ARP_ENCRYPT_ENABLE
#define ARP_ENCRYPT_ENABLE 1
#endif

static struct packet_crypto_ctx g_arp_crypto_ctx;
static int g_arp_crypto_ctx_ready;
static int g_arp_key_loaded;
static uint8_t g_arp_default_master_key[AES_MAX_KEY_SIZE];
/* Per-LAN: 1 if last successful ARP TX used failover backup WAN. */
static uint8_t g_arp_lan_on_backup[MAX_INTERFACES];

/* 32-byte ARP master key: paste 64 hex chars (0-9a-f). Both peers must match. */
static const char g_arp_hardcoded_master_key_hex[] =
    "73214a9ce15d2fb816c73b90ad44f26e580da137cb7f2495ee6318d489ba05cf";

static uint64_t arp_monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull);
}

static void arp_crypto_ctx_init(const struct app_config *cfg)
{
    (void)cfg;

    if (!g_arp_key_loaded) {
        if (parse_hex_bytes_pub(g_arp_hardcoded_master_key_hex,
                                g_arp_default_master_key, AES_MAX_KEY_SIZE) != 0) {
            fprintf(stderr,
                    "[ARP] bad key hex (need %d hex chars, got %zu): %s\n",
                    AES_MAX_KEY_SIZE * 2,
                    strlen(g_arp_hardcoded_master_key_hex),
                    g_arp_hardcoded_master_key_hex);
            return;
        }
        g_arp_key_loaded = 1;
    }
    if (g_arp_crypto_ctx_ready)
        return;
    if (packet_crypto_init(&g_arp_crypto_ctx, g_arp_default_master_key) != 0)
        return;
    g_arp_crypto_ctx.initialized = true;
    g_arp_crypto_ctx.wire_id = (uint8_t)ARP_DEFAULT_WIRE_ID;
    g_arp_crypto_ctx.policy_id = 0;
    g_arp_crypto_ctx.profile_id = 0;
    g_arp_crypto_ctx_ready = 1;
}

static int arp_log_fail_ratelimit(uint64_t *last_ms)
{
    uint64_t now = arp_monotonic_ms();

    if (!last_ms || now - *last_ms < ARP_LOG_FAIL_INTERVAL_MS)
        return 0;
    *last_ms = now;
    return 1;
}

/* Backup path: always log — không rate-limit (debug failover ARP). */
static void arp_log_backup_line(const char *fmt, ...)
{
    // va_list ap;

    // va_start(ap, fmt);
    // vfprintf(stderr, fmt, ap);
    // va_end(ap);
    // fflush(stderr);
    (void)fmt;
}

static void arp_format_ipv4_be32(uint32_t ip_be, char *buf, size_t bufsz)
{
    uint8_t b[4];

    memcpy(b, &ip_be, 4);
    snprintf(buf, bufsz, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static void arp_format_mac(const uint8_t mac[MAC_LEN], char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static const char *arp_op_tag_from_pkt(const uint8_t *pkt, uint32_t len, int bcast_hint)
{
    uint16_t op = 0;

    if (dp_parse_arp_op(pkt, len, &op) != 0)
        return bcast_hint ? "request" : "reply";
    if (op == 1)
        return "request";
    if (op == 2)
        return "reply";
    return "other";
}

static uint16_t arp_op_from_pkt(const uint8_t *pkt, uint32_t len)
{
    uint16_t op = 0;

    if (dp_parse_arp_op(pkt, len, &op) != 0)
        return 0;
    return op;
}

static const char *arp_op_name(uint16_t op)
{
    if (op == 1)
        return "request";
    if (op == 2)
        return "reply";
    return "other";
}

static int arp_eth_dmac_is_broadcast(const uint8_t *pkt, uint32_t len)
{
    static const uint8_t bcast[MAC_LEN] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    if (!pkt || len < ARP_ETH_HDR_LEN)
        return 0;
    return memcmp(pkt, bcast, MAC_LEN) == 0;
}

static const char *arp_l2_dst_type(const uint8_t *pkt, uint32_t len)
{
    if (arp_eth_dmac_is_broadcast(pkt, len))
        return "broadcast";
    return "unicast";
}

static int arp_payload_view(const uint8_t *pkt, uint32_t len, const uint8_t **arp_out)
{
    uint16_t et;
    uint32_t off = 14u;

    if (!pkt || !arp_out || len < off + 28u)
        return -1;
    et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x8100u) {
        off = 18u;
        if (len < off + 28u)
            return -1;
    }
    *arp_out = pkt + off;
    return 0;
}

static int arp_parse_tha(const uint8_t *pkt, uint32_t len, uint8_t tha_out[MAC_LEN])
{
    const uint8_t *arp = NULL;

    if (!tha_out)
        return -1;
    if (arp_payload_view(pkt, len, &arp) != 0)
        return -1;
    memcpy(tha_out, arp + 18u, MAC_LEN);
    return 0;
}

void arp_bridge_reload_policies(struct app_config *cfg)
{
    if (!cfg)
        return;
    arp_crypto_ctx_init(cfg);
    fprintf(stderr,
            "[ARP] mode=mac-fdb+flood-whohas-only | arp_encrypt=%d (policy-independent) | key=arp-default | opt=L2-PQC/ARP\n",
            ARP_ENCRYPT_ENABLE);
}

static struct ne_ring *arp_mid_to_local_ring(struct forwarder *fwd, int li)
{
    return &fwd->mid_to_local[li][dp_out_ring_idx()];
}

static struct ne_ring *arp_mid_to_wan_ring(struct forwarder *fwd, int wan_dp)
{
    return &fwd->mid_to_wan[wan_dp][dp_out_ring_idx()];
}

static int profile_pi_for_wan_dp(struct forwarder *fwd, int wan_dp)
{
    int cfg_idx;

    if (!fwd || !fwd->cfg)
        return -1;
    cfg_idx = config_wan_dp_to_cfg(fwd->cfg, wan_dp);
    if (cfg_idx < 0 || fwd->cfg->profile_count < 1)
        return -1;

    {
        const struct profile_config *p = &fwd->cfg->profiles[0];

        if (!p->enabled)
            return -1;
        for (int wi = 0; wi < p->wan_count; wi++) {
            if (p->wan_indices[wi] == cfg_idx)
                return 0;
        }
    }
    return -1;
}

/* bridges[].local_idx is cfg locals[] index — map to live fwd pair slot by ifname. */
static int resolve_wan_dp_for_fwd_local(struct forwarder *fwd,
                                        const struct profile_config *prof,
                                        int fwd_local_idx, int *wan_dp_out)
{
    const char *ifname;

    if (!fwd || !fwd->cfg || !prof || !wan_dp_out || fwd_local_idx < 0 ||
        fwd_local_idx >= fwd->local_count)
        return -1;
    ifname = fwd->locals[fwd_local_idx].ifname;
    if (!ifname[0])
        return -1;

    for (int i = 0; i < prof->bridge_count; i++) {
        int ci = prof->bridges[i].local_idx;

        if (ci < 0 || ci >= fwd->cfg->local_count)
            continue;
        if (strcmp(fwd->cfg->locals[ci].ifname, ifname) != 0)
            continue;
        *wan_dp_out = prof->bridges[i].wan_dp;
        return 0;
    }
    return -1;
}

/*
 * ARP TX usable: chỉ khi WAN còn live trên pair và không bị mark down.
 * weight=0 / WRR / data-drain KHÔNG chặn ARP — chỉ WAN down mới thôi ARP.
 */
static int arp_wan_dp_usable(struct forwarder *fwd, int wan_dp)
{
    if (!fwd || wan_dp < 0 || wan_dp >= fwd->wan_count)
        return 0;
    if (!ne_pair_wan_live(&fwd->pair, wan_dp))
        return 0;
    if (fwd_wan_is_stopped(wan_dp))
        return 0;
    if (wan_failover_dp_excluded(wan_dp))
        return 0;
    return 1;
}

/* Map profile cfg wan index → dataplane slot (không qua ok_for_new_traffic/weight). */
static int arp_dp_for_cfg_wan(struct forwarder *fwd, int cfg_wan)
{
    int n;

    if (!fwd || cfg_wan < 0)
        return -1;
    n = fwd->wan_count;
    if (n > MAX_INTERFACES)
        n = MAX_INTERFACES;
    for (int dp = 0; dp < n; dp++) {
        if (fwd->wan_cfg_idx[dp] != cfg_wan)
            continue;
        if (arp_wan_dp_usable(fwd, dp))
            return dp;
    }
    return -1;
}

/*
 * Failover: BR WAN down → pick any other UP WAN in the profile (least-loaded).
 * Weight=0 WAN vẫn được chọn cho ARP backup nếu đang UP.
 */
static int arp_pick_backup_wan_dp(struct forwarder *fwd,
                                  const struct profile_config *prof,
                                  int primary_wan_dp)
{
    int best = -1;
    uint32_t best_depth = UINT32_MAX;

    if (!fwd || !prof)
        return -1;

    for (int i = 0; i < prof->wan_count; i++) {
        int cfg_wan = prof->wan_indices[i];
        int dp;
        uint32_t depth;

        dp = arp_dp_for_cfg_wan(fwd, cfg_wan);
        if (dp < 0 || dp == primary_wan_dp)
            continue;
        if (!fwd_wan_has_tx_room(fwd, dp))
            continue;

        depth = fwd_mid_to_wan_depth(fwd, dp);
        if (depth < best_depth) {
            best_depth = depth;
            best = dp;
        }
    }
    return best;
}

/*
 * LAN→WAN ARP:
 *  1) Prefer WAN in bridges[] for that LAN (BE) ngay khi BR WAN UP (rejoin).
 *  2) If that WAN down → backup sang bất kỳ WAN đang UP (kể cả weight=0).
 * Remote side: who-has flood; unicast → dest MAC FDB.
 */
static int arp_select_egress_wan(struct forwarder *fwd,
                                 const struct profile_config *prof,
                                 int primary_wan_dp, int *used_backup)
{
    if (used_backup)
        *used_backup = 0;

    /* BR WAN up (kể cả weight=0) → luôn join về primary, không backup. */
    if (arp_wan_dp_usable(fwd, primary_wan_dp))
        return primary_wan_dp;

    {
        int backup = arp_pick_backup_wan_dp(fwd, prof, primary_wan_dp);

        if (backup < 0)
            return -1;
        if (used_backup)
            *used_backup = 1;
        return backup;
    }
}

static int arp_profile_owns_local(struct forwarder *fwd, int profile_pi, int fwd_local_idx)
{
    const struct profile_config *prof;
    const char *ifname;

    if (!fwd || !fwd->cfg || profile_pi < 0 || profile_pi >= fwd->cfg->profile_count)
        return 0;
    if (fwd_local_idx < 0 || fwd_local_idx >= fwd->local_count)
        return 0;
    if (!ne_pair_local_live(&fwd->pair, fwd_local_idx))
        return 0;

    prof = &fwd->cfg->profiles[profile_pi];
    if (!prof->enabled)
        return 0;

    ifname = fwd->locals[fwd_local_idx].ifname;
    if (!ifname[0])
        return 0;

    for (int i = 0; i < prof->local_count; i++) {
        int ci = prof->local_indices[i];

        if (ci < 0 || ci >= fwd->cfg->local_count)
            continue;
        if (strcmp(fwd->cfg->locals[ci].ifname, ifname) == 0)
            return 1;
    }
    return 0;
}

/* Push one ARP frame to a LAN TX ring (clone if not first). */
static int arp_flood_push_local(struct forwarder *fwd, struct ne_packet *job,
                                const uint8_t *pkt, int li, int wi, int *sent)
{
    struct ne_ring *ring;

    if (!fwd || !job || !pkt || li < 0 || li >= fwd->local_count || !sent)
        return -1;

    ring = &fwd->mid_to_local[li][wi];
    if (*sent == 0) {
        job->dir = NE_DIR_LOCAL;
        job->local_idx = (uint8_t)li;
        if (ne_ring_try_push(ring, job) != 0)
            return -1;
        ne_dp_idle_wake_tx_worker(wi);
        *sent = 1;
        return 0;
    }

    {
        struct ne_packet clone = {
            .len = job->len,
            .dir = NE_DIR_LOCAL,
            .local_idx = (uint8_t)li,
        };

        if (ne_frame_alloc(&fwd->pair, &clone.addr) != 0)
            return -1;
        memcpy(ne_packet_data(&fwd->pair, clone.addr), pkt, job->len);
        if (ne_ring_try_push(ring, &clone) != 0) {
            ne_frame_free(&fwd->pair, clone.addr);
            return -1;
        }
        ne_dp_idle_wake_tx_worker(wi);
    }
    return 0;
}

/*
 * Broadcast ARP WAN→LAN: flood mọi LAN trong profile.
 * Cần cho failover — who-has về backup WAN vẫn tới LAN gốc (Br0/Br1).
 */
static int arp_flood_to_profile_locals(struct forwarder *fwd, struct ne_packet *job,
                                       const uint8_t *pkt, int profile_pi,
                                       char *lans_out, size_t lans_out_sz)
{
    const struct profile_config *prof;
    int wi;
    int sent = 0;
    uint16_t sent_mask = 0;
    size_t lans_len = 0;

    if (lans_out && lans_out_sz > 0)
        lans_out[0] = '\0';

    if (!fwd || !job || !pkt || !fwd->cfg || profile_pi < 0 ||
        profile_pi >= fwd->cfg->profile_count)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    if (!prof->enabled || prof->local_count <= 0)
        return -1;

    wi = dp_out_ring_idx();

    for (int i = 0; i < prof->local_count; i++) {
        int li = mac_fwd_local_for_cfg_idx(fwd, prof->local_indices[i]);
        const char *lif;

        if (li < 0 || li >= fwd->local_count)
            continue;
        if (!arp_profile_owns_local(fwd, profile_pi, li))
            continue;
        if (li < (int)(sizeof(sent_mask) * 8) && (sent_mask & (1u << li)) != 0)
            continue;

        if (arp_flood_push_local(fwd, job, pkt, li, wi, &sent) != 0)
            continue;

        if (li < (int)(sizeof(sent_mask) * 8))
            sent_mask |= (1u << li);

        lif = fwd->locals[li].ifname[0] ? fwd->locals[li].ifname : "?";
        if (lans_out && lans_out_sz > 1) {
            int n = snprintf(lans_out + lans_len, lans_out_sz - lans_len,
                             "%s%s", lans_len ? "," : "", lif);
            if (n < 0 || (size_t)n >= lans_out_sz - lans_len)
                lans_len = lans_out_sz - 1;
            else
                lans_len += (size_t)n;
        }
    }
    return sent > 0 ? 0 : -1;
}

static const char *local_ifname(struct forwarder *fwd, int li)
{
    if (!fwd || li < 0 || li >= fwd->local_count)
        return "?";
    return fwd->locals[li].ifname;
}

static const char *wan_ifname(struct forwarder *fwd, int wan_dp)
{
    if (!fwd || wan_dp < 0 || wan_dp >= fwd->wan_count)
        return "?";
    return fwd->wans[wan_dp].ifname;
}

/* BR name for LAN (fwd local) in profile; "-" if not in a bridge pair. */
static const char *arp_br_name_for_lan(struct forwarder *fwd,
                                       const struct profile_config *prof,
                                       int fwd_local_idx)
{
    const char *ifname;

    if (!fwd || !fwd->cfg || !prof || fwd_local_idx < 0 ||
        fwd_local_idx >= fwd->local_count)
        return "-";
    ifname = fwd->locals[fwd_local_idx].ifname;
    if (!ifname[0])
        return "-";

    for (int i = 0; i < prof->bridge_count; i++) {
        int ci = prof->bridges[i].local_idx;

        if (ci < 0 || ci >= fwd->cfg->local_count)
            continue;
        if (strcmp(fwd->cfg->locals[ci].ifname, ifname) != 0)
            continue;
        if (prof->bridges[i].ifname[0])
            return prof->bridges[i].ifname;
        return "(unnamed)";
    }
    return "-";
}

/* BR name for WAN dp in profile. */
static const char *arp_br_name_for_wan(const struct profile_config *prof, int wan_dp)
{
    if (!prof || wan_dp < 0)
        return "-";
    for (int i = 0; i < prof->bridge_count; i++) {
        if (prof->bridges[i].wan_dp != wan_dp)
            continue;
        if (prof->bridges[i].ifname[0])
            return prof->bridges[i].ifname;
        return "(unnamed)";
    }
    return "-";
}

static int profile_pi_for_fwd_local(struct forwarder *fwd, int fwd_li)
{
    const char *ifname;

    if (!fwd || !fwd->cfg || fwd_li < 0 || fwd_li >= fwd->local_count)
        return -1;
    ifname = fwd->locals[fwd_li].ifname;
    if (!ifname[0] || fwd->cfg->profile_count < 1)
        return -1;

    {
        const struct profile_config *p = &fwd->cfg->profiles[0];

        if (!p->enabled)
            return -1;
        for (int i = 0; i < p->local_count; i++) {
            int ci = p->local_indices[i];

            if (ci < 0 || ci >= fwd->cfg->local_count)
                continue;
            if (strcmp(fwd->cfg->locals[ci].ifname, ifname) == 0)
                return 0;
        }
    }
    return -1;
}

/* Returns 1 if encrypted, 0 if plaintext. Never blocks ARP forwarding. */
static int arp_try_encrypt_l2_pqc(struct forwarder *fwd, struct ne_packet *job,
                                  uint8_t *pkt, int profile_idx,
                                  const char **skip_why)
{
    uint8_t scratch[NE_FRAME];
    uint32_t orig_len;
    uint32_t len;

    if (skip_why)
        *skip_why = NULL;

    if (!fwd || !fwd->cfg || !job || !pkt) {
        if (skip_why)
            *skip_why = "bad-args";
        return 0;
    }
    if (!ARP_ENCRYPT_ENABLE) {
        if (skip_why)
            *skip_why = "arp-encrypt-disabled";
        return 0;
    }
    arp_crypto_ctx_init(fwd->cfg);
    if (!g_arp_crypto_ctx_ready) {
        if (skip_why)
            *skip_why = "arp-crypto-not-ready";
        return 0;
    }

    orig_len = job->len;
    if (orig_len > NE_FRAME) {
        if (skip_why)
            *skip_why = "frame-too-big";
        return 0;
    }
    memcpy(scratch, pkt, orig_len);
    len = orig_len;

    g_arp_crypto_ctx.profile_id = profile_idx >= 0 ? profile_idx : 0;
    g_arp_crypto_ctx.policy_id = 0;
    g_arp_crypto_ctx.wire_id = (uint8_t)ARP_DEFAULT_WIRE_ID;

    if (crypto_option_encrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_ARP,
                              &g_arp_crypto_ctx, pkt, &len) != 0) {
        memcpy(pkt, scratch, orig_len);
        job->len = orig_len;
        if (skip_why)
            *skip_why = "encrypt-error";
        return 0;
    }
    job->len = len;
    return 1;
}

static int arp_try_decrypt_l2_pqc(struct forwarder *fwd, struct ne_packet *job, uint8_t *pkt)
{
    uint32_t len;
    const char *fail_why = NULL;

    if (!fwd || !job || !pkt)
        return -1;

    if (crypto_pkt_is_arp(pkt, job->len))
        return 0; /* plain ARP — bridge as-is */

    if (!crypto_eth_l2_has_arp_marker(pkt, job->len))
        return -1; /* not ARP wire */

    arp_crypto_ctx_init(fwd->cfg);
    if (!g_arp_crypto_ctx_ready) {
        fail_why = "arp-crypto-not-ready";
        goto decrypt_fail;
    }
    len = job->len;
    if (crypto_option_decrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_ARP,
                              &g_arp_crypto_ctx, pkt, &len) != 0) {
        fail_why = "decrypt-error";
        goto decrypt_fail;
    }
    if (!crypto_pkt_is_arp(pkt, len)) {
        fail_why = "not-arp-after-decrypt";
        goto decrypt_fail;
    }
    job->len = len;
    return 1;

decrypt_fail:
    {
        static uint64_t last_dec_fail_ms;

        if (arp_log_fail_ratelimit(&last_dec_fail_ms))
            fprintf(stderr, "[ARP] decrypt-fail why=%s\n",
                    fail_why ? fail_why : "unknown");
    }
    return -1;
}

int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li,
                          char egress_ifname[IF_NAMESIZE])
{
    int profile_pi;
    const struct profile_config *prof;
    int primary_wan_dp;
    int wan_dp;
    int used_backup = 0;
    struct ne_ring *ring;
    uint8_t *mut;

    if (egress_ifname)
        egress_ifname[0] = '\0';

    if (!fwd || !fwd->cfg || !job || !pkt)
        return -1;

    mut = ne_packet_data(&fwd->pair, job->addr);
    if (!mut)
        return -1;

    if (job->len >= ARP_ETH_HDR_LEN) {
        uint32_t spa = 0, tpa = 0;
        uint16_t arp_op = 0;
        const uint8_t *smac = pkt + MAC_LEN;
        int smac_li;

        if (dp_parse_arp_ips(pkt, job->len, &spa, &tpa) == 0) {
            /* WAN relay echo (request/reply): không học MAC xa, không gửi lại WAN. */
            if (mac_relay_recent(smac, spa))
                return 0;
            /* Không bridge ARP với SMAC = MAC port LAN/WAN của appliance. */
            if (mac_is_appliance_mac(fwd, smac))
                return 0;
            /* Reply: chỉ bridge từ port LAN đang giữ SMAC trong FDB. */
            if (dp_parse_arp_op(pkt, job->len, &arp_op) == 0 && arp_op == 2) {
                smac_li = mac_lookup(fwd, smac);
                if (smac_li >= 0 && smac_li != ingress_li)
                    return 0;
            }
            /* Chỉ học chiều LAN->WAN (request hoặc reply). */
            mac_learn(fwd, ingress_li, pkt, job->len, MAC_LEARN_SRC_ARP);
        }
    }

    profile_pi = profile_pi_for_fwd_local(fwd, ingress_li);
    if (profile_pi < 0) {
        static uint64_t last_no_profile_ms;

        if (arp_log_fail_ratelimit(&last_no_profile_ms))
            fprintf(stderr, "[ARP] bridge local %s fail: no profile\n",
                    local_ifname(fwd, ingress_li));
        return -1;
    }

    prof = &fwd->cfg->profiles[profile_pi];
    if (resolve_wan_dp_for_fwd_local(fwd, prof, ingress_li, &primary_wan_dp) != 0) {
        static uint64_t last_no_pair_ms;

        if (arp_log_fail_ratelimit(&last_no_pair_ms))
            fprintf(stderr,
                    "[ARP] bridge local %s fail: no BE pair (profile=%s bridges=%d)\n",
                    local_ifname(fwd, ingress_li), prof->name, prof->bridge_count);
        return -1;
    }
    if (primary_wan_dp < 0 || primary_wan_dp >= fwd->wan_count)
        return -1;

    /* BR WAN up → dùng BR; BR down → failover ARP sang WAN UP bất kỳ. */
    wan_dp = arp_select_egress_wan(fwd, prof, primary_wan_dp, &used_backup);
    if (wan_dp < 0) {
        static uint64_t last_wan_down_ms;

        if (arp_log_fail_ratelimit(&last_wan_down_ms))
            fprintf(stderr,
                    "[ARP] bridge local %s fail: br WAN %s down, no UP backup\n",
                    local_ifname(fwd, ingress_li), wan_ifname(fwd, primary_wan_dp));
        return -1;
    }

    {
        uint32_t spa = 0, tpa = 0;
        const char *skip_why = NULL;
        int encrypted;
        int is_req;
        uint16_t arp_op;
        const char *op_tag;
        const char *op_name;
        const char *l2_dst;
        uint8_t tha_mac[MAC_LEN] = {0};
        char spa_s[16], tpa_s[16], dmac_s[24], smac_s[24], tha_s[24];

        if (job->len < ARP_ETH_HDR_LEN ||
            dp_parse_arp_ips(pkt, job->len, &spa, &tpa) != 0) {
            static uint64_t last_parse_ms;

            if (arp_log_fail_ratelimit(&last_parse_ms))
                fprintf(stderr, "[ARP-TX][?] parse-fail lan=%s\n",
                        local_ifname(fwd, ingress_li));
            return -1;
        }

        /* Parse/log fields trước encrypt — mut==pkt, sau encrypt payload ARP không còn plaintext. */
        arp_op = arp_op_from_pkt(pkt, job->len);
        is_req = arp_eth_dmac_is_broadcast(pkt, job->len);
        op_tag = arp_op_tag_from_pkt(pkt, job->len, is_req);
        op_name = arp_op_name(arp_op);
        l2_dst = arp_l2_dst_type(pkt, job->len);
        if (arp_parse_tha(pkt, job->len, tha_mac) != 0)
            memset(tha_mac, 0, sizeof(tha_mac));
        arp_format_ipv4_be32(spa, spa_s, sizeof(spa_s));
        arp_format_ipv4_be32(tpa, tpa_s, sizeof(tpa_s));
        arp_format_mac(pkt, dmac_s, sizeof(dmac_s));
        arp_format_mac(pkt + MAC_LEN, smac_s, sizeof(smac_s));
        arp_format_mac(tha_mac, tha_s, sizeof(tha_s));

        encrypted = arp_try_encrypt_l2_pqc(fwd, job, mut, profile_pi, &skip_why);

        if (used_backup) {
            if (ingress_li >= 0 && ingress_li < MAX_INTERFACES)
                g_arp_lan_on_backup[ingress_li] = 1;
            arp_log_backup_line(
                "[ARP-FO][TX][%s] backup %s/%s -> %s/%s (br_wan=%s down) "
                "| op=%s(%u) l2_dst=%s spa=%s tpa=%s tha=%s smac=%s dmac=%s enc=%d%s%s\n",
                op_tag,
                local_ifname(fwd, ingress_li),
                arp_br_name_for_lan(fwd, prof, ingress_li),
                wan_ifname(fwd, wan_dp),
                arp_br_name_for_wan(prof, wan_dp),
                wan_ifname(fwd, primary_wan_dp),
                op_name, (unsigned)arp_op, l2_dst, spa_s, tpa_s, tha_s, smac_s, dmac_s,
                encrypted,
                (!encrypted && skip_why) ? " !" : "",
                (!encrypted && skip_why) ? skip_why : "");
        } else {
            /* BR WAN up lại → ARP join về WAN BR, không backup nữa. */
            if (ingress_li >= 0 && ingress_li < MAX_INTERFACES &&
                g_arp_lan_on_backup[ingress_li]) {
                g_arp_lan_on_backup[ingress_li] = 0;
                arp_log_backup_line(
                    "[ARP-FO][TX][%s] rejoin %s/%s -> %s/%s (br_wan up) "
                    "| op=%s(%u) l2_dst=%s spa=%s tpa=%s tha=%s smac=%s dmac=%s enc=%d%s%s\n",
                    op_tag,
                    local_ifname(fwd, ingress_li),
                    arp_br_name_for_lan(fwd, prof, ingress_li),
                    wan_ifname(fwd, wan_dp),
                    arp_br_name_for_wan(prof, wan_dp),
                    op_name, (unsigned)arp_op, l2_dst, spa_s, tpa_s, tha_s, smac_s, dmac_s,
                    encrypted,
                    (!encrypted && skip_why) ? " !" : "",
                    (!encrypted && skip_why) ? skip_why : "");
            } else {
                int do_log = is_req || (strcmp(op_tag, "request") == 0);

                if (!do_log) {
                    static uint64_t last_tx_reply_ms;

                    do_log = arp_log_fail_ratelimit(&last_tx_reply_ms);
                }
                if (do_log) {
                    arp_log_backup_line(
                        "[ARP-TX][%s] %s/%s -> %s/%s "
                        "| op=%s(%u) l2_dst=%s spa=%s tpa=%s tha=%s smac=%s dmac=%s enc=%d%s%s\n",
                        op_tag,
                        local_ifname(fwd, ingress_li),
                        arp_br_name_for_lan(fwd, prof, ingress_li),
                        wan_ifname(fwd, wan_dp),
                        arp_br_name_for_wan(prof, wan_dp),
                        op_name, (unsigned)arp_op, l2_dst, spa_s, tpa_s, tha_s, smac_s,
                        dmac_s, encrypted,
                        (!encrypted && skip_why) ? " !" : "",
                        (!encrypted && skip_why) ? skip_why : "");
                }
            }
        }
    }

    ring = arp_mid_to_wan_ring(fwd, wan_dp);
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    if (dp_ring_push(fwd, ring, job) != 0) {
        static uint64_t last_ring_fail_ms;

        if (arp_log_fail_ratelimit(&last_ring_fail_ms))
            fprintf(stderr, "[ARP] bridge local %s -> wan %s fail: ring push\n",
                    local_ifname(fwd, ingress_li), wan_ifname(fwd, wan_dp));
        return -1;
    }
    if (egress_ifname)
        strncpy(egress_ifname, wan_ifname(fwd, wan_dp), IF_NAMESIZE - 1);
    return 0;
}

int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp,
                        char egress_ifname[IF_NAMESIZE])
{
    int profile_pi;
    uint8_t *mut;
    int dec;
    int was_plain;
    int had_marker;
    uint32_t spa = 0, tpa = 0;
    int have_ips = 0;
    int is_bcast;
    uint16_t arp_op = 0;
    int deliver_li = -1;
    const char *op_tag;
    const char *op_name;
    const char *l2_dst;
    uint8_t tha_mac[MAC_LEN] = {0};
    char spa_s[16] = "?", tpa_s[16] = "?", dmac_s[24], smac_s[24] = "?", tha_s[24] = "?";
    char flood_lans[256] = "";
    const char *crypto_state;

    if (egress_ifname)
        egress_ifname[0] = '\0';

    if (!fwd || !fwd->cfg || !job || !pkt)
        return -1;

    mut = ne_packet_data(&fwd->pair, job->addr);
    if (!mut)
        return -1;

    was_plain = crypto_pkt_is_arp(mut, job->len);
    had_marker = crypto_eth_l2_has_arp_marker(mut, job->len);
    if (was_plain)
        have_ips = (dp_parse_arp_ips(mut, job->len, &spa, &tpa) == 0);

    dec = arp_try_decrypt_l2_pqc(fwd, job, mut);
    if (dec < 0) {
        static uint64_t last_wan_dec_fail_ms;

        if (arp_log_fail_ratelimit(&last_wan_dec_fail_ms))
            fprintf(stderr,
                    "[ARP-RX][?] drop decrypt-fail wan=%s\n",
                    wan_ifname(fwd, ingress_wan_dp));
        return -1;
    }

    if (dec == 1)
        have_ips = (dp_parse_arp_ips(mut, job->len, &spa, &tpa) == 0);

    profile_pi = profile_pi_for_wan_dp(fwd, ingress_wan_dp);
    if (profile_pi < 0) {
        static uint64_t last_no_profile_ms;

        if (arp_log_fail_ratelimit(&last_no_profile_ms))
            fprintf(stderr, "[ARP] bridge wan %s fail: no profile\n",
                    wan_ifname(fwd, ingress_wan_dp));
        return -1;
    }

    if (job->len < ARP_ETH_HDR_LEN) {
        static uint64_t last_short_ms;

        if (arp_log_fail_ratelimit(&last_short_ms))
            fprintf(stderr, "[ARP] wan %s fail: frame too short\n",
                    wan_ifname(fwd, ingress_wan_dp));
        return -1;
    }

    is_bcast = arp_eth_dmac_is_broadcast(mut, job->len);
    arp_op = arp_op_from_pkt(mut, job->len);
    op_tag = arp_op_tag_from_pkt(mut, job->len, is_bcast);
    op_name = arp_op_name(arp_op);
    l2_dst = arp_l2_dst_type(mut, job->len);
    if (arp_parse_tha(mut, job->len, tha_mac) == 0)
        arp_format_mac(tha_mac, tha_s, sizeof(tha_s));
    arp_format_mac(mut, dmac_s, sizeof(dmac_s));
    arp_format_mac(mut + MAC_LEN, smac_s, sizeof(smac_s));
    if (have_ips) {
        arp_format_ipv4_be32(spa, spa_s, sizeof(spa_s));
        arp_format_ipv4_be32(tpa, tpa_s, sizeof(tpa_s));
        mac_relay_stamp(mut + MAC_LEN, spa);
    }

    if (dec == 1)
        crypto_state = "decrypted";
    else if (was_plain)
        crypto_state = "plain";
    else if (had_marker)
        crypto_state = "decrypted";
    else
        crypto_state = "plain";

    /* Broadcast request: flood mọi LAN trong profile (failover-safe). */
    if (is_bcast) {
        const struct profile_config *prof = &fwd->cfg->profiles[profile_pi];

        if (arp_flood_to_profile_locals(fwd, job, mut, profile_pi,
                                        flood_lans, sizeof(flood_lans)) != 0) {
            static uint64_t last_flood_fail_ms;

            if (arp_log_fail_ratelimit(&last_flood_fail_ms))
                fprintf(stderr,
                        "[ARP-RX][%s] flood-fail wan=%s | op=%s(%u) l2_dst=%s spa=%s tpa=%s tha=%s\n",
                        op_tag, wan_ifname(fwd, ingress_wan_dp),
                        op_name, (unsigned)arp_op, l2_dst, spa_s, tpa_s, tha_s);
            return -1;
        }
        arp_log_backup_line(
            "[ARP-RX][%s] %s/%s -> flood[%s] "
            "| op=%s(%u) l2_dst=%s spa=%s tpa=%s tha=%s smac=%s dmac=%s %s\n",
            op_tag,
            wan_ifname(fwd, ingress_wan_dp),
            arp_br_name_for_wan(prof, ingress_wan_dp),
            flood_lans[0] ? flood_lans : "-",
            op_name, (unsigned)arp_op, l2_dst, spa_s, tpa_s, tha_s, smac_s, dmac_s,
            crypto_state);
    } else {
        /* Unicast: chỉ forward khi DMAC có trong bảng MAC → LAN. Không fallback. */
        const struct profile_config *prof = &fwd->cfg->profiles[profile_pi];

        deliver_li = mac_lookup(fwd, mut);
        if (deliver_li < 0 || !arp_profile_owns_local(fwd, profile_pi, deliver_li)) {
            static uint64_t last_no_mac_ms;

            if (arp_log_fail_ratelimit(&last_no_mac_ms))
                fprintf(stderr,
                        "[ARP-RX][%s] drop no-mac wan=%s "
                        "| op=%s(%u) l2_dst=unicast spa=%s tpa=%s smac=%s dmac=%s\n",
                        op_tag, wan_ifname(fwd, ingress_wan_dp),
                        op_name, (unsigned)arp_op, spa_s, tpa_s, smac_s, dmac_s);
            return -1;
        }

        {
            struct ne_ring *ring = arp_mid_to_local_ring(fwd, deliver_li);

            job->dir = NE_DIR_LOCAL;
            job->local_idx = (uint8_t)deliver_li;
            if (dp_ring_push(fwd, ring, job) != 0) {
                static uint64_t last_ring_fail_ms;

                if (arp_log_fail_ratelimit(&last_ring_fail_ms))
                    fprintf(stderr,
                            "[ARP-RX][%s] drop forward-fail wan=%s lan=%s "
                            "| has-mac smac=%s dmac=%s\n",
                            op_tag,
                            wan_ifname(fwd, ingress_wan_dp),
                            local_ifname(fwd, deliver_li),
                            smac_s, dmac_s);
                return -1;
            }
            {
                static uint64_t last_rx_reply_ms;

                if (arp_log_fail_ratelimit(&last_rx_reply_ms))
                    arp_log_backup_line(
                        "[ARP-RX][%s] %s/%s -> %s/%s has-mac "
                        "| op=%s(%u) l2_dst=unicast spa=%s tpa=%s tha=%s smac=%s dmac=%s %s\n",
                        op_tag,
                        wan_ifname(fwd, ingress_wan_dp),
                        arp_br_name_for_wan(prof, ingress_wan_dp),
                        local_ifname(fwd, deliver_li),
                        arp_br_name_for_lan(fwd, prof, deliver_li),
                        op_name, (unsigned)arp_op, l2_dst,
                        spa_s, tpa_s, tha_s, smac_s, dmac_s, crypto_state);
            }
        }
    }

    if (egress_ifname) {
        if (deliver_li >= 0)
            strncpy(egress_ifname, local_ifname(fwd, deliver_li), IF_NAMESIZE - 1);
        else
            strncpy(egress_ifname, "*", IF_NAMESIZE - 1);
    }
    return 0;
}

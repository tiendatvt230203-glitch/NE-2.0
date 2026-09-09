#include "../../../inc/core/dataplane/arp_bridge.h"
#include "../../../inc/core/util/config.h"
#include "../../../inc/core/util/main_diag.h"
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
#include "../../../inc/crypto/pqc_handshake.h"

#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <net/if.h>

#define ARP_DEFAULT_WIRE_ID      250u
#define ARP_ETH_HDR_LEN          14u

/* 1 = mã hóa ARP L2-PQC (key/option riêng), độc lập bảng policy/data crypto.
 * Decrypt vẫn chạy nếu wire có ARP marker (peer vẫn encrypt). */
#ifndef ARP_ENCRYPT_ENABLE
#define ARP_ENCRYPT_ENABLE 1
#endif

static struct packet_crypto_ctx g_arp_crypto_ctx;
static int g_arp_crypto_ctx_ready;
static uint8_t g_arp_default_master_key[AES_MAX_KEY_SIZE];
static pthread_once_t g_arp_crypto_once = PTHREAD_ONCE_INIT;

/* 32-byte ARP master key: paste 64 hex chars (0-9a-f). Both peers must match. */
static const char g_arp_hardcoded_master_key_hex[] =
    "73214a9ce15d2fb816c73b90ad44f26e580da137cb7f2495ee6318d489ba05cf";

static int arp_key_nonzero(const uint8_t *key, size_t len)
{
    if (!key)
        return 0;
    for (size_t i = 0; i < len; i++) {
        if (key[i] != 0)
            return 1;
    }
    return 0;
}

static void arp_crypto_ctx_init_once(void)
{
    if (parse_hex_bytes_pub(g_arp_hardcoded_master_key_hex,
                            g_arp_default_master_key, AES_MAX_KEY_SIZE) != 0)
        return;
    if (packet_crypto_init(&g_arp_crypto_ctx, g_arp_default_master_key) != 0)
        return;
    g_arp_crypto_ctx.initialized = true;
    g_arp_crypto_ctx.wire_id = (uint8_t)ARP_DEFAULT_WIRE_ID;
    g_arp_crypto_ctx.policy_id = 0;
    g_arp_crypto_ctx.profile_id = 0;
    g_arp_crypto_ctx_ready = 1;
}

static void arp_crypto_ctx_init(const struct app_config *cfg)
{
    (void)cfg;
    pthread_once(&g_arp_crypto_once, arp_crypto_ctx_init_once);
}

/* Build an immutable per-packet context. Dynamic ARP keys replace the static
 * slots only when a valid CURRENT key has completed the PQC handshake. */
static int arp_crypto_ctx_snapshot(const struct app_config *cfg, int profile_idx,
                                   struct packet_crypto_ctx *ctx,
                                   int *using_static)
{
    uint8_t keys[KEY_SLOT_COUNT][PQC_TRAFFIC_KEY_SZ];
    uint8_t key_ids[KEY_SLOT_COUNT];
    bool valid[KEY_SLOT_COUNT];
    int profile_id;
    int dynamic_ready;

    if (!cfg || !ctx || profile_idx < 0 ||
        profile_idx >= cfg->profile_count)
        return -1;

    arp_crypto_ctx_init(cfg);
    if (!g_arp_crypto_ctx_ready)
        return -1;

    *ctx = g_arp_crypto_ctx;
    profile_id = cfg->profiles[profile_idx].id;
    ctx->profile_id = profile_id;
    ctx->policy_id = 0;
    ctx->wire_id = (uint8_t)ARP_DEFAULT_WIRE_ID;
    ctx->pqc_from_handshake = false;

    dynamic_ready = sig_pqc_arp_get_keys(keys, key_ids, valid) == 0 &&
        valid[KEY_SLOT_CURRENT] &&
        arp_key_nonzero(keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ);
    if (dynamic_ready) {
        memset(ctx->keys, 0, sizeof(ctx->keys));
        for (int slot = 0; slot < KEY_SLOT_COUNT; slot++) {
            if (valid[slot])
                memcpy(ctx->keys[slot], keys[slot], PQC_TRAFFIC_KEY_SZ);
        }
    }

    if (using_static)
        *using_static = !dynamic_ready;
    main_diag_log_arp_key(profile_id, ctx->keys[KEY_SLOT_CURRENT],
                          !dynamic_ready);
    return 0;
}

static int arp_static_ctx_snapshot(const struct app_config *cfg, int profile_idx,
                                   struct packet_crypto_ctx *ctx)
{
    if (!cfg || !ctx || profile_idx < 0 ||
        profile_idx >= cfg->profile_count)
        return -1;
    arp_crypto_ctx_init(cfg);
    if (!g_arp_crypto_ctx_ready)
        return -1;
    *ctx = g_arp_crypto_ctx;
    ctx->profile_id = cfg->profiles[profile_idx].id;
    ctx->policy_id = 0;
    ctx->wire_id = (uint8_t)ARP_DEFAULT_WIRE_ID;
    ctx->pqc_from_handshake = false;
    return 0;
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

void arp_bridge_reload_policies(struct app_config *cfg)
{
    struct packet_crypto_ctx ctx;

    if (!cfg)
        return;
    if (cfg->profile_count > 0)
        (void)arp_crypto_ctx_snapshot(cfg, 0, &ctx, NULL);
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
                                 int primary_wan_dp)
{
    /* BR WAN up (kể cả weight=0) → luôn join về primary, không backup. */
    if (arp_wan_dp_usable(fwd, primary_wan_dp))
        return primary_wan_dp;

    {
        int backup = arp_pick_backup_wan_dp(fwd, prof, primary_wan_dp);

        if (backup < 0)
            return -1;
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
                                       const uint8_t *pkt, int profile_pi)
{
    const struct profile_config *prof;
    int wi;
    int sent = 0;
    uint16_t sent_mask = 0;

    if (!fwd || !job || !pkt || !fwd->cfg || profile_pi < 0 ||
        profile_pi >= fwd->cfg->profile_count)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    if (!prof->enabled || prof->local_count <= 0)
        return -1;

    wi = dp_out_ring_idx();

    for (int i = 0; i < prof->local_count; i++) {
        int li = mac_fwd_local_for_cfg_idx(fwd, prof->local_indices[i]);

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
                                  uint8_t *pkt, int profile_idx)
{
    struct packet_crypto_ctx ctx;
    uint8_t scratch[NE_FRAME];
    uint32_t orig_len;
    uint32_t len;

    if (!fwd || !fwd->cfg || !job || !pkt)
        return 0;
    if (!ARP_ENCRYPT_ENABLE)
        return 0;
    if (arp_crypto_ctx_snapshot(fwd->cfg, profile_idx, &ctx, NULL) != 0)
        return 0;

    orig_len = job->len;
    if (orig_len > NE_FRAME)
        return 0;
    memcpy(scratch, pkt, orig_len);
    len = orig_len;

    if (crypto_option_encrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_ARP,
                              &ctx, pkt, &len) != 0) {
        memcpy(pkt, scratch, orig_len);
        job->len = orig_len;
        return 0;
    }
    job->len = len;
    return 1;
}

static int arp_try_decrypt_l2_pqc(struct forwarder *fwd, struct ne_packet *job,
                                  uint8_t *pkt, int profile_idx)
{
    struct packet_crypto_ctx ctx;
    struct packet_crypto_ctx static_ctx;
    uint8_t encrypted[NE_FRAME];
    uint32_t wire_len;
    uint32_t len;
    int using_static = 1;

    if (!fwd || !job || !pkt)
        return -1;

    if (crypto_pkt_is_arp(pkt, job->len))
        return 0; /* plain ARP — bridge as-is */

    if (!crypto_eth_l2_has_arp_marker(pkt, job->len))
        return -1; /* not ARP wire */

    if (arp_crypto_ctx_snapshot(fwd->cfg, profile_idx, &ctx,
                                &using_static) != 0)
        return -1;
    wire_len = job->len;
    if (wire_len > sizeof(encrypted))
        return -1;
    memcpy(encrypted, pkt, wire_len);
    len = job->len;
    if (crypto_option_decrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_ARP,
                              &ctx, pkt, &len) != 0) {
        /* During activation/rekey, accept a peer still using the configured
         * static fallback. Encryption always prefers dynamic CURRENT. */
        if (using_static ||
            arp_static_ctx_snapshot(fwd->cfg, profile_idx, &static_ctx) != 0)
            return -1;
        memcpy(pkt, encrypted, wire_len);
        len = wire_len;
        if (crypto_option_decrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_ARP,
                                  &static_ctx, pkt, &len) != 0)
            return -1;
    }
    if (!crypto_pkt_is_arp(pkt, len))
        return -1;
    job->len = len;
    return 1;
}

int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li,
                          char egress_ifname[IF_NAMESIZE])
{
    int profile_pi;
    const struct profile_config *prof;
    int primary_wan_dp;
    int wan_dp;
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
    if (profile_pi < 0)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    if (resolve_wan_dp_for_fwd_local(fwd, prof, ingress_li,
                                     &primary_wan_dp) != 0)
        return -1;
    if (primary_wan_dp < 0 || primary_wan_dp >= fwd->wan_count)
        return -1;

    /* BR WAN up → dùng BR; BR down → failover ARP sang WAN UP bất kỳ. */
    wan_dp = arp_select_egress_wan(fwd, prof, primary_wan_dp);
    if (wan_dp < 0)
        return -1;

    {
        uint32_t spa = 0, tpa = 0;

        if (job->len < ARP_ETH_HDR_LEN ||
            dp_parse_arp_ips(pkt, job->len, &spa, &tpa) != 0)
            return -1;
        (void)arp_try_encrypt_l2_pqc(fwd, job, mut, profile_pi);
    }

    ring = arp_mid_to_wan_ring(fwd, wan_dp);
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    if (dp_ring_push(fwd, ring, job) != 0)
        return -1;
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
    uint32_t spa = 0, tpa = 0;
    int is_bcast;
    int deliver_li = -1;

    if (egress_ifname)
        egress_ifname[0] = '\0';

    if (!fwd || !fwd->cfg || !job || !pkt)
        return -1;

    mut = ne_packet_data(&fwd->pair, job->addr);
    if (!mut)
        return -1;

    profile_pi = profile_pi_for_wan_dp(fwd, ingress_wan_dp);
    if (profile_pi < 0)
        return -1;

    dec = arp_try_decrypt_l2_pqc(fwd, job, mut, profile_pi);
    if (dec < 0)
        return -1;

    if (job->len < ARP_ETH_HDR_LEN)
        return -1;

    is_bcast = arp_eth_dmac_is_broadcast(mut, job->len);
    if (dp_parse_arp_ips(mut, job->len, &spa, &tpa) == 0)
        mac_relay_stamp(mut + MAC_LEN, spa);

    /* Broadcast request: flood mọi LAN trong profile (failover-safe). */
    if (is_bcast) {
        if (arp_flood_to_profile_locals(fwd, job, mut, profile_pi) != 0)
            return -1;
    } else {
        /* Unicast: chỉ forward khi DMAC có trong bảng MAC → LAN. Không fallback. */
        deliver_li = mac_lookup(fwd, mut);
        if (deliver_li < 0 ||
            !arp_profile_owns_local(fwd, profile_pi, deliver_li))
            return -1;

        {
            struct ne_ring *ring = arp_mid_to_local_ring(fwd, deliver_li);

            job->dir = NE_DIR_LOCAL;
            job->local_idx = (uint8_t)deliver_li;
            if (dp_ring_push(fwd, ring, job) != 0)
                return -1;
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

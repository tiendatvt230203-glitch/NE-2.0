#include "../../../inc/core/dataplane/dataplane.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/core/forwarder/forwarder_crypto_runtime.h"

#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/packet_crypto.h"

#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/flow/mac_learn.h"
#include "../../../inc/core/dataplane/arp_bridge.h"
#include "../../../inc/core/dataplane/dataplane_stats.h"
#include "../../../inc/core/dataplane/tcp_reorder.h"
#include "../../../inc/core/dataplane/udp_reorder.h"

#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <stdio.h>

/* UDP bonding format. Wire after nonce:
 *   [0x5B 'U' 'D' v1][ciphertext(kind+epoch32+seq32+datagram_id32+
 *                                IPv4/fragment)||tag]
 * The four-byte marker makes this path unambiguous without copying a full
 * frame solely for rollback; sequence/kind remain authenticated ciphertext. */
#define WAN_L2_UDP_MARKER_LEN  4u
#define WAN_L2_UDP_SHIM_LEN    13u
#define WAN_L2_GCM_TAG_LEN     16u
static const uint8_t wan_l2_udp_marker[WAN_L2_UDP_MARKER_LEN] = {
    0x5Bu, 0x55u, 0x44u, 0x01u
};

static int wan_l2_is_udp_tagged(const uint8_t *pkt, uint32_t len)
{
    int mark_off;

    if (!pkt || !crypto_eth_l2_has_marker(pkt, len))
        return 0;
    mark_off = crypto_eth_l2_frag_magic_off(pkt, len, PACKET_CRYPTO_NONCE_BYTES);
    if (mark_off < 0)
        return 0;
    if (len < (uint32_t)mark_off + WAN_L2_UDP_MARKER_LEN +
        WAN_L2_UDP_SHIM_LEN + WAN_L2_GCM_TAG_LEN)
        return 0;
    return memcmp(pkt + mark_off, wan_l2_udp_marker,
                  WAN_L2_UDP_MARKER_LEN) == 0;
}

static const struct crypto_policy *fwd_policy_by_wire_id(struct forwarder *fwd, uint8_t wire_id)
{
    if (!fwd || !fwd->cfg)
        return NULL;
    for (int i = 0; i < fwd->cfg->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
        const struct crypto_policy *cp = &fwd->cfg->policies[i];
        if (cp->action == POLICY_ACTION_BYPASS)
            continue;
        if ((uint8_t)cp->id == wire_id)
            return cp;
    }
    return NULL;
}


static int wan_l2_plain_ipv4(const uint8_t *pkt, uint32_t len)
{
    return crypto_pkt_is_ipv4(pkt, len);
}

static int wan_l2_plain_ok(const uint8_t *pkt, uint32_t len)
{
    return crypto_pkt_is_ipv4(pkt, len) || crypto_pkt_is_arp(pkt, len);
}

/* Encrypted NE wire: L2 PQC marker / UDP frag — not plain bypass. */
static int wan_wire_is_encrypted(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    if (!pkt || !fwd || !fwd->cfg)
        return 0;
    if (fwd_crypto_has_l2_marker(pkt, len) || crypto_eth_l2_has_marker(pkt, len))
        return 1;
    if (wan_l2_is_udp_tagged(pkt, len))
        return 1;
    return 0;
}

static int decrypt_l2(struct forwarder *fwd, uint8_t *pkt, uint32_t *len)
{
    struct packet_crypto_ctx *ctx;
    uint8_t wire_id = 0;
    uint8_t scratch[NE_PACKET_CAPACITY];
    uint32_t orig_len;

    (void)fwd;

    if (!pkt || !len)
        return 0;
    if (!crypto_eth_l2_has_marker(pkt, *len))
        return 0;
    if (crypto_eth_l2_read_policy_id(pkt, *len, &wire_id) != 0)
        return 0;
    ctx = fwd_crypto_ctx_for_wire_id(wire_id);
    if (!ctx)
        return -1;

    orig_len = *len;
    if (orig_len > NE_PACKET_CAPACITY)
        return -1;
    memcpy(scratch, pkt, orig_len);

    if (crypto_option_decrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_TCP, ctx, pkt, len) == 0 &&
        crypto_pkt_is_ipv4(pkt, *len))
        return 0;

    memcpy(pkt, scratch, orig_len);
    *len = orig_len;
    return -1;
}

static int reassemble_l2(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                         uint8_t policy_id, uint64_t addr, int *pending)
{
    struct packet_crypto_ctx *ctx;
    int slot, rr;
    uint32_t blen = 0;

    (void)fwd;

    ctx = fwd_crypto_ctx_for_wire_id(policy_id);
    if (!ctx)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(
        fwd_crypto_profile_id_for_wire_id(policy_id));
    if (slot < 0)
        return -1;
    crypto_l2_pqc_reasm_set_addr(addr);
    rr = crypto_option_reassemble(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_UDP, slot, dp_crypto_current_worker_idx(),
                                  ctx, pkt, len, pkt, &blen);
    if (rr == 0) {
        *pending = crypto_l2_pqc_reasm_held() ? 2 : 1;
        return 0;
    }
    if (rr != 1)
        return -1;
    *len = blen;
    return 0;
}

/* The versioned four-byte marker covers both full and split UDP. */
static int wan_try_l2_pqc_udp(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                              uint64_t addr, int *pending)
{
    uint8_t wire_pol = 0;

    if (!wan_l2_is_udp_tagged(pkt, *len))
        return 0;

    if (crypto_eth_l2_read_policy_id(pkt, *len, &wire_pol) != 0)
        return 0;

    if (!fwd_policy_by_wire_id(fwd, wire_pol))
        return 0;

    if (!fwd_crypto_ctx_for_wire_id(wire_pol))
        return 0;

    if (reassemble_l2(fwd, pkt, len, wire_pol, addr, pending) != 0) {
        if (pending)
            *pending = 0;
        return -1;
    }
    return 1;
}

static int decrypt_wan(struct forwarder *fwd, struct ne_packet *job)
{
    uint8_t scratch[NE_PACKET_CAPACITY];
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t len = job->len;
    uint16_t pid = 0;
    uint8_t fidx = 0;
    int pending = 0;
    int is_l2 = 0;

    if (!fwd || !pkt || !job)
        return -1;
    /* Caller must only invoke this for encrypted wire; plain bypass never enters. */
    if (!wan_wire_is_encrypted(fwd, pkt, len))
        return 0;

    is_l2 = fwd_crypto_has_l2_marker(pkt, len) || wan_l2_is_udp_tagged(pkt, len);

    {
        int l2_fast = wan_try_l2_pqc_udp(fwd, pkt, &len, job->addr, &pending);

        if (l2_fast < 0)
            return -1;
        if (l2_fast == 1) {
            uint64_t out_addr;

            if (pending == 2)
                return 2;
            if (pending)
                return 1;
            out_addr = crypto_l2_pqc_reasm_out_addr();
            if (out_addr && out_addr != job->addr) {
                ne_frame_free(&fwd->pair, job->addr);
                job->addr = out_addr;
            }
            job->len = len;
            return 0;
        }
        if (l2_fast == 0) {
            uint32_t orig_len = len;
            uint8_t wire_pol = 0;
            int need_backup = wan_l2_is_udp_tagged(pkt, len) ||
                crypto_option_is_fragment(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_UDP,
                                          fwd->cfg, pkt, len, &pid, &fidx);
            if (need_backup && orig_len <= sizeof(scratch))
                memcpy(scratch, pkt, orig_len);
            if (decrypt_l2(fwd, pkt, &len) != 0 || !wan_l2_plain_ok(pkt, len)) {
                if (need_backup)
                    memcpy(pkt, scratch, orig_len);
                len = orig_len;
                if (crypto_option_is_fragment(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_UDP,
                                              fwd->cfg, pkt, len, &pid, &fidx)) {
                    if (crypto_eth_l2_read_policy_id(pkt, len, &wire_pol) != 0)
                        return -1;
                    if (reassemble_l2(fwd, pkt, &len, wire_pol, job->addr, &pending) != 0)
                        return -1;
                } else if (is_l2) {
                    return -1;
                }
            }
        }
    }
    if (pending == 2)
        return 2;
    if (pending)
        return 1;

    if (!fwd->cfg->crypto_enabled) {
        job->len = len;
        return 0;
    }

    {
        uint64_t out_addr = crypto_l2_pqc_reasm_out_addr();

        if (out_addr && out_addr != job->addr) {
            ne_frame_free(&fwd->pair, job->addr);
            job->addr = out_addr;
        }
    }
    job->len = len;
    return 0;
}

static int eth_dmac_is_unicast(const uint8_t *pkt)
{
    return (pkt[0] & 0x01u) == 0;
}

static int profile_pi_for_wire_policy(struct forwarder *fwd, uint8_t wire_id)
{
    int profile_id;

    if (!fwd || !fwd->cfg)
        return -1;
    profile_id = fwd_crypto_profile_id_for_wire_id(wire_id);
    if (profile_id < 0 || fwd->cfg->profile_count < 1)
        return -1;
    if (fwd->cfg->profiles[0].id == profile_id)
        return 0;
    return -1;
}

static int profile_owns_local(struct forwarder *fwd, int profile_pi, int fwd_local_idx)
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

/* Data path only (tcp/udp/icmp/ospf): never floods — FDB miss drops. */

static int wan_profile_pi_bypass(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    const struct crypto_policy *cp;

    if (!fwd || !pkt || !fwd->cfg || fwd->cfg->profile_count < 1)
        return -1;
    if (!fwd->cfg->profiles[0].enabled)
        return -1;
    if (dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                      &src_port, &dst_port, &proto) != 0)
        return -1;

    cp = config_select_crypto_policy(fwd->cfg, 0, dst_ip, src_ip,
                                     dst_port, src_port, proto);
    if (!cp || cp->action != POLICY_ACTION_BYPASS)
        return -1;
    return 0;
}

static int wan_policy_in_ok(struct forwarder *fwd, int profile_pi,
                            const uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;

    if (!fwd || !fwd->cfg || !pkt || profile_pi < 0)
        return 0;
    if (dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                      &src_port, &dst_port, &proto) != 0)
        return 0;
    return config_policy_in_ok(fwd->cfg, profile_pi,
                               src_ip, dst_ip, src_port, dst_port, proto);
}

static void wan_clamp_tcp_mss(struct forwarder *fwd, uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    const struct crypto_policy *cp;

    if (!fwd || !pkt || !fwd->cfg || fwd->cfg->profile_count < 1)
        return;
    if (!fwd->cfg->profiles[0].enabled)
        return;
    if (dp_parse_flow(pkt, len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) != 0)
        return;
    if (proto != IPPROTO_TCP)
        return;

    cp = config_select_crypto_policy(fwd->cfg, 0, src_ip, dst_ip,
                                     src_port, dst_port, proto);
    if (!cp || cp->action == POLICY_ACTION_BYPASS)
        return;
    (void)crypto_tcp_clamp_mss(pkt, len, crypto_option_get_mtu(),
                               crypto_option_wire_overhead(CRYPTO_OPT_L2_PQC));
}

static int wan_profile_pi(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    if (!fwd || !pkt || !fwd->cfg)
        return -1;
    if (fwd_crypto_has_l2_marker(pkt, len) || crypto_eth_l2_has_marker(pkt, len)) {
        uint8_t wire_pol = 0;

        if (crypto_eth_l2_read_policy_id(pkt, len, &wire_pol) != 0)
            return -1;
        return profile_pi_for_wire_policy(fwd, wire_pol);
    }
    return wan_profile_pi_bypass(fwd, pkt, len);
}

static int forward_wan_to_local(struct forwarder *fwd, struct ne_packet *job,
                                int profile_pi, int ingress_wan_dp)
{
    uint8_t *pkt;
    int li;

    if (!fwd || !job || profile_pi < 0)
        return -1;
    pkt = ne_packet_data(&fwd->pair, job->addr);
    if (!pkt || job->len < 14u)
        return -1;
    if (!eth_dmac_is_unicast(pkt))
        return -1;

    li = mac_lookup(fwd, pkt);
    if (li < 0 || !profile_owns_local(fwd, profile_pi, li)) {
        if (ingress_wan_dp >= 0)
            li = mac_fwd_local_for_wan_dp(fwd, profile_pi, ingress_wan_dp);
    }
    if (li >= 0 && profile_owns_local(fwd, profile_pi, li)) {
        job->dir = NE_DIR_LOCAL;
        job->local_idx = (uint8_t)li;
        if (dp_ring_push(fwd, &fwd->mid_to_local[li][dp_out_ring_idx()], job) != 0) {
            /* dp_ring_push already returned the UMEM frame to the pool. */
            ne_dp_stats_wan_drop(1);
            return 1;
        }
        return 0;
    }

    return -1;
}

static int bond_reorder_emit(void *ctx, struct dp_bond_reorder_item *item)
{
    struct forwarder *fwd = ctx;
    uint8_t *pkt;
    int rc;

    if (!fwd || !item)
        return -1;
    pkt = ne_packet_data(&fwd->pair, item->packet.addr);
    if (!pkt)
        return -1;
    dp_out_ring_bind(dp_flow_pick_tx_slot(pkt, item->packet.len,
                                          dp_crypto_current_worker_idx()));
    rc = forward_wan_to_local(fwd, &item->packet, item->profile_pi,
                              item->ingress_wan_dp);
    if (rc < 0)
        return -1;
    if (rc > 0)
        return 0;
    ne_dp_stats_wan_fwd(1);
    return 0;
}

static void bond_reorder_drop(void *ctx, struct dp_bond_reorder_item *item)
{
    struct forwarder *fwd = ctx;

    if (!fwd || !item)
        return;
    ne_dp_stats_wan_drop(1);
    ne_frame_free(&fwd->pair, item->packet.addr);
}

static struct dp_bond_reorder_ops bond_reorder_ops(struct forwarder *fwd)
{
    struct dp_bond_reorder_ops ops = {
        .ctx = fwd,
        .emit = bond_reorder_emit,
        .drop = bond_reorder_drop,
    };

    return ops;
}

void dataplane_bond_reorder_configure(void)
{
    dp_tcp_reorder_configure_from_env();
    dp_udp_reorder_configure_from_env();
}

void dataplane_bond_reorder_gc(struct forwarder *fwd, int worker_idx)
{
    struct dp_bond_reorder_ops ops = bond_reorder_ops(fwd);
    uint64_t now_ns = dp_bond_reorder_now_ns();

    dp_tcp_reorder_gc(worker_idx, now_ns, &ops);
    dp_udp_reorder_gc(worker_idx, now_ns, &ops);
}

void dataplane_bond_reorder_reset(struct forwarder *fwd, int worker_idx)
{
    struct dp_bond_reorder_ops ops = bond_reorder_ops(fwd);

    dp_tcp_reorder_reset_worker(worker_idx, &ops);
    dp_udp_reorder_reset_worker(worker_idx, &ops);
}

int dataplane_wan_needs_mid(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    if (!fwd || !pkt || !fwd->cfg)
        return 0;
    /* ARP (plain or NE arp-marker) stays on crypto workers. */
    if (crypto_eth_l2_has_arp_marker(pkt, len) || dp_pkt_is_arp(pkt, len))
        return 1;
    if (!fwd->cfg->crypto_enabled)
        return 0;
    return wan_wire_is_encrypted(fwd, pkt, len);
}

void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint8_t wire_buf[128];
    uint32_t wire_len;
    int dec;
    int encrypted;
    int profile_pi;
    uint32_t flow_src_ip = 0, flow_dst_ip = 0;
    uint16_t flow_src_port = 0, flow_dst_port = 0;
    uint8_t flow_proto = 0;
    int flow_ok;

    if (!fwd || !pkt)
        goto drop;

    wire_len = job.len;
    if (wire_len < 14u || wire_len > ne_packet_capacity(&fwd->pair, job.addr))
        goto drop;
    /* Only L2/policy and IPv4/L4 headers are needed after decrypt. Keeping a
     * bounded snapshot avoids a jumbo-sized stack copy on every packet. */
    {
        uint32_t snap = wire_len < sizeof(wire_buf) ? wire_len : sizeof(wire_buf);

        memcpy(wire_buf, pkt, snap);
        wire_len = snap;
    }

    if (crypto_eth_l2_has_arp_marker(pkt, job.len) || dp_pkt_is_arp(pkt, job.len)) {
        int wan_dp = job.wan_idx < fwd->wan_count ? (int)job.wan_idx : -1;
        int bridged = -1;

        dp_out_ring_bind(dp_pick_tx_slot(pkt, job.len));
        if (wan_dp >= 0)
            bridged = arp_bridge_from_wan(fwd, &job, pkt, wan_dp, NULL);

        if (bridged == 0)
            return;
        goto drop;
    }

    encrypted = wan_wire_is_encrypted(fwd, pkt, job.len);
    if (encrypted) {
        crypto_option_tcp_clear_rx_meta();
        crypto_option_udp_clear_rx_meta();
        if (!fwd->cfg->crypto_enabled)
            goto drop;
        dec = decrypt_wan(fwd, &job);
        if (dec == 1) {
            ne_frame_free(&fwd->pair, job.addr);
            return;
        }
        if (dec == 2)
            return;
        if (dec != 0)
            goto drop;
        pkt = ne_packet_data(&fwd->pair, job.addr);
        profile_pi = wan_profile_pi(fwd, wire_buf, wire_len);
        if (profile_pi < 0)
            goto drop;
        /* Any/any: không so 5-tuple từng gói. Không any mới wan_policy_in_ok. */
        if (!fwd->cfg->profiles[profile_pi].policy_in_any) {
            if (!wan_policy_in_ok(fwd, profile_pi, pkt, job.len))
                goto policy_drop;
        }
        wan_clamp_tcp_mss(fwd, pkt, job.len);
    } else {
        if (!wan_l2_plain_ipv4(pkt, job.len))
            goto drop;
        /* Bypass đã AND 5-tuple trong wan_profile_pi_bypass — không quét lại. */
        profile_pi = wan_profile_pi(fwd, wire_buf, wire_len);
        if (profile_pi < 0)
            goto drop;
    }

    flow_ok = dp_parse_flow(pkt, job.len, &flow_src_ip, &flow_dst_ip,
                            &flow_src_port, &flow_dst_port, &flow_proto) == 0;
    if (flow_ok) {
        int l3_off = crypto_eth_ipv4_offset(pkt, job.len);

        ne_dp_stats_observe_traffic(NE_DP_TRAFFIC_WAN_TO_LAN,
                                    flow_proto,
                                    l3_off >= 0 ? job.len - (uint32_t)l3_off
                                                : job.len);
    }

    if (encrypted) {
        uint32_t epoch = 0;
        uint32_t seq = 0;
        uint64_t now_ns;
        uint8_t reorder_proto = 0;

        if (crypto_option_udp_take_rx_meta(&epoch, &seq) == 0)
            reorder_proto = IPPROTO_UDP;
        else if (crypto_option_tcp_take_rx_meta(&epoch, &seq) == 0)
            reorder_proto = IPPROTO_TCP;

        if (reorder_proto != 0) {
            struct dp_bond_reorder_key key;
            struct dp_bond_reorder_item item;
            struct dp_bond_reorder_ops ops = bond_reorder_ops(fwd);
            if (!flow_ok || flow_proto != reorder_proto)
                goto drop;
            key.src_ip = flow_src_ip;
            key.dst_ip = flow_dst_ip;
            key.src_port = flow_src_port;
            key.dst_port = flow_dst_port;
            key.protocol = flow_proto;
            memset(&item, 0, sizeof(item));
            item.packet = job;
            item.profile_pi = (int16_t)profile_pi;
            item.ingress_wan_dp = job.wan_idx < fwd->wan_count
                ? (int8_t)job.wan_idx : -1;
            now_ns = dp_bond_reorder_now_ns();
            if (reorder_proto == IPPROTO_UDP)
                dp_udp_reorder_submit(dp_crypto_current_worker_idx(), &key,
                                      epoch, seq, &item, now_ns, &ops);
            else
                dp_tcp_reorder_submit(dp_crypto_current_worker_idx(), &key,
                                      epoch, seq, &item, now_ns, &ops);
            return;
        }
        dp_out_ring_bind(dp_flow_pick_tx_slot(pkt, job.len,
                                              dp_crypto_current_worker_idx()));
    } else {
        dp_out_ring_bind(dp_pick_tx_slot(pkt, job.len));
    }

    {
        int rc = forward_wan_to_local(
            fwd, &job, profile_pi,
            job.wan_idx < fwd->wan_count ? (int)job.wan_idx : -1);

        if (rc < 0)
            goto drop;
        if (rc > 0)
            return;
    }
    ne_dp_stats_wan_fwd(1);
    return;

policy_drop:
    ne_dp_stats_wan_policy_drop(1);
    ne_dp_stats_wan_drop(1);
    ne_frame_free(&fwd->pair, job.addr);
    return;

drop:
    ne_dp_stats_wan_drop(1);
    ne_frame_free(&fwd->pair, job.addr);
}

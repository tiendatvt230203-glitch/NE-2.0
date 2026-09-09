#include "../../../inc/core/dataplane/dataplane.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/core/forwarder/forwarder_wan.h"
#include "../../../inc/core/forwarder/forwarder_crypto_runtime.h"

#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/packet_crypto.h"
#include "../../../inc/crypto/pqc_handshake.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/dataplane/arp_bridge.h"
#include "../../../inc/core/dataplane/jumbo_l2.h"
#include "../../../inc/core/dataplane/dp_idle.h"
#include "../../../inc/core/flow/flow_table.h"

#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <stdio.h>

#define SPLIT_TAIL_REFILL_BATCH 32u
static int push_to_wan(struct forwarder *fwd, struct ne_packet *job, int wan_dp)
{
    int ri = dp_out_ring_idx();

    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    return dp_ring_push(fwd, &fwd->mid_to_wan[wan_dp][ri], job);
}

static void complete_packet_window_after_enqueue(uint8_t proto,
                                                 int jumbo_packet,
                                                 int enqueue_ok)
{
    if (jumbo_packet) {
        flow_table_jumbo_packet_complete(enqueue_ok);
        return;
    }
    /* TCP advances when its WAN is selected. UDP waits for TX enqueue. */
    if (proto == IPPROTO_UDP)
        flow_table_udp_packet_complete(enqueue_ok);
}

static void free_wire_fragments(struct forwarder *fwd,
                                struct ne_packet *fragments,
                                uint32_t fragment_count)
{
    for (uint32_t i = 0; i < fragment_count; i++)
        ne_frame_free(&fwd->pair, fragments[i].addr);
}

static int push_split_to_wan(struct forwarder *fwd, struct ne_packet *job,
                            uint32_t l1, struct ne_packet *tail, uint32_t l2, int wan_dp)
{
    struct ne_ring *tx = &fwd->mid_to_wan[wan_dp][dp_out_ring_idx()];

    if (!fwd || !job || !tail)
        return -1;
    if (wan_dp < 0 || wan_dp >= fwd->wan_count || ne_ring_count(tx) + 2 > tx->cap) {
        ne_frame_free(&fwd->pair, tail->addr);
        return -1;
    }
    if (l1 == 0 || l2 == 0 || l1 > fwd->pair.frame_size || l2 > fwd->pair.frame_size) {
        ne_frame_free(&fwd->pair, tail->addr);
        return -1;
    }
    tail->len = l2;
    tail->dir = NE_DIR_WAN;
    tail->wan_idx = (uint8_t)wan_dp;
    job->len = l1;
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    if (ne_ring_try_push_pair(tx, job, tail) != 0) {
        ne_frame_free(&fwd->pair, tail->addr);
        return -1;
    }
    ne_dp_idle_wake_tx_worker(dp_out_ring_idx());
    return 0;
}

static int split_tail_take(struct forwarder *fwd, int worker_idx, uint64_t *addr_out)
{
    uint32_t got;

    if (!fwd || !addr_out || worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return -1;

    if (fwd->split_tail_count[worker_idx] == 0) {
        got = ne_frame_alloc_batch(&fwd->pair, fwd->split_tail_cache[worker_idx],
                                   SPLIT_TAIL_REFILL_BATCH);
        if (got == 0)
            return -1;
        fwd->split_tail_count[worker_idx] = (uint16_t)got;
    }

    fwd->split_tail_count[worker_idx]--;
    *addr_out = fwd->split_tail_cache[worker_idx][fwd->split_tail_count[worker_idx]];
    return 0;
}

static int encrypt_to_wan(struct forwarder *fwd, struct ne_packet *job,
                        const struct crypto_policy *cp, int wan_dp,
                        struct packet_crypto_ctx *pctx,
                        crypto_proto_class pclass, int flow_ok)
{
    int worker_idx = dp_crypto_current_worker_idx();
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    struct ne_packet tail = {0};
    uint8_t *tail_buf = NULL;
    uint32_t len = job->len;
    uint32_t l1 = 0, l2 = 0;
    crypto_option_id opt_id = CRYPTO_OPT_L2_PQC;
    uint32_t udp_seq;

    (void)flow_ok;
    (void)cp;

    if (pclass == CRYPTO_PROTO_UDP) {
        if (!flow_ok || dp_udp_next_tx_seq(pkt, len, &udp_seq) != 0)
            return -1;
        crypto_option_udp_set_tx_seq(udp_seq);
    }

    if (!crypto_option_is_jumbo_mode() &&
        crypto_option_need_split(opt_id, pclass, len)) {
        if (split_tail_take(fwd, worker_idx, &tail.addr) != 0)
            return -1;
        tail_buf = ne_packet_data(&fwd->pair, tail.addr);
        if (crypto_option_split(opt_id, pclass, pctx, pkt, len, fwd->pair.frame_size, &l1,
                                tail_buf, fwd->pair.frame_size, &l2) != 0) {
            ne_frame_free(&fwd->pair, tail.addr);
            return -1;
        }
        if (push_split_to_wan(fwd, job, l1, &tail, l2, wan_dp) != 0)
            return -1;
        return 1;
    }

    if (crypto_option_encrypt(opt_id, pclass, pctx, pkt, &len) != 0) {
        return -1;
    }
    job->len = len;
    return 0;
}

static int pick_profile_policy(struct forwarder *fwd, int local_idx, int flow_ok,
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port, uint8_t proto,
                            int *profile_idx, const struct crypto_policy **cp)
{
    const struct crypto_policy *c;
    const struct profile_config *p;
    int found = 0;

    if (!fwd || !fwd->cfg || !profile_idx || !cp || fwd->cfg->profile_count < 1)
        return -1;

    p = &fwd->cfg->profiles[0];
    if (!p->enabled)
        return -1;
    for (int i = 0; i < p->local_count; i++) {
        if (p->local_indices[i] == local_idx)
            found = 1;
    }
    if (!found)
        return -1;
    c = flow_ok
        ? config_select_crypto_policy(fwd->cfg, 0, src_ip, dst_ip, src_port, dst_port, proto)
        : NULL;
    if (!c)
        return -1;
    if (c->action != POLICY_ACTION_BYPASS && c->action != POLICY_ACTION_ENCRYPT_L2)
        return -1;
    *profile_idx = 0;
    *cp = c;
    return 0;
}

int dataplane_local_needs_mid(struct forwarder *fwd, const uint8_t *pkt, uint32_t len,
                              int local_idx)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int flow_ok;
    int profile_idx;
    const struct crypto_policy *cp;

    if (!fwd || !fwd->cfg || !pkt)
        return 0;
    /* ARP uses its own fixed-key path on crypto workers — not bypass. */
    if (dp_pkt_is_arp(pkt, len))
        return 1;
    if (!fwd->cfg->crypto_enabled)
        return 0;
    flow_ok = dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip, &src_port, &dst_port,
                            &proto) == 0;
    if (pick_profile_policy(fwd, local_idx, flow_ok, src_ip, dst_ip, src_port, dst_port,
                            proto, &profile_idx, &cp) != 0)
        return 0;
    /* Unsupported legacy encryption policies must enter the crypto path and
     * be rejected there, never fall through as plaintext bypass traffic. */
    return cp && cp->action != POLICY_ACTION_BYPASS;
}

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    uint8_t tcp_flags = 0;
    int l3_off = -1;
    int flow_ok = dp_parse_flow_tcp_meta(pkt, job.len, &src_ip, &dst_ip,
                                         &src_port, &dst_port, &proto,
                                         &l3_off, &tcp_flags) == 0;
    int li = job.local_idx < fwd->local_count ? (int)job.local_idx : 0;
    int profile_idx;
    const struct crypto_policy *cp;
    int wan_dp;
    int pi;
    struct packet_crypto_ctx *pctx;
    int enc;
    int jumbo_packet = 0;

    if (!fwd || !pkt)
        goto drop;

    if (dp_pkt_is_arp(pkt, job.len)) {
        if (job.segment_count > 1)
            goto drop;
        /* ARP: bridge path only — học MAC trong arp_bridge_from_local (client local). */
        if (arp_bridge_from_local(fwd, &job, pkt, li, NULL) == 0)
            return;
        goto drop;
    }

    if (pick_profile_policy(fwd, li, flow_ok, src_ip, dst_ip, src_port, dst_port, proto,
                            &profile_idx, &cp) != 0)
        goto drop;
    jumbo_packet = crypto_option_is_jumbo_mode() &&
        dp_jumbo_packet_needs_wire_split(&job,
                                         cp->action == POLICY_ACTION_ENCRYPT_L2);
    wan_dp = fwd_wan_pick_for_local(fwd, profile_idx, flow_ok, src_ip, dst_ip,
                                    src_port, dst_port, proto, jumbo_packet);
    if (wan_dp < 0 || !fwd_wan_has_tx_room(fwd,wan_dp))
        goto drop;

    if (cp->action == POLICY_ACTION_BYPASS) {
        int sent;

        if (jumbo_packet) {
            struct ne_packet fragments[NE_PACKET_MAX_SEGMENTS];
            uint32_t fragment_count = 0;
            struct ne_ring *ring =
                &fwd->mid_to_wan[wan_dp][dp_out_ring_idx()];

            if (dp_jumbo_build_wire(fwd, &job, NULL, (uint8_t)cp->id, 0,
                                    fragments, &fragment_count) != 0)
                goto drop;
            if (dp_jumbo_push_wan_fragments(fwd, ring, fragments,
                                            fragment_count, wan_dp) != 0) {
                free_wire_fragments(fwd, fragments, fragment_count);
                goto drop;
            }
            ne_packet_free(&fwd->pair, &job);
            complete_packet_window_after_enqueue(proto, 1, 1);
            return;
        }

        sent = push_to_wan(fwd, &job, wan_dp) == 0;
        complete_packet_window_after_enqueue(proto, 0, sent);
        return;
    }
    if (!fwd->cfg->crypto_enabled)
        goto drop;

    if (!crypto_option_is_jumbo_mode() && proto == IPPROTO_TCP &&
        (tcp_flags & 0x02u)) {
        (void)crypto_tcp_clamp_mss_l3(pkt, job.len, l3_off,
                                      crypto_option_get_mtu(),
                                      crypto_option_wire_overhead(CRYPTO_OPT_L2_PQC));
    }

    pi = (int)(cp - fwd->cfg->policies);
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !fwd_crypto_policy_ready(pi))
        goto drop;
    pctx = fwd_crypto_policy_ctx(pi);
    if (!pctx)
        goto drop;
    if (jumbo_packet) {
        struct ne_packet fragments[NE_PACKET_MAX_SEGMENTS];
        uint32_t fragment_count = 0;
        struct ne_ring *ring =
            &fwd->mid_to_wan[wan_dp][dp_out_ring_idx()];

        if (dp_jumbo_build_wire(fwd, &job, pctx, (uint8_t)cp->id, 1,
                                fragments, &fragment_count) != 0)
            goto drop;
        if (dp_jumbo_push_wan_fragments(fwd, ring, fragments,
                                        fragment_count, wan_dp) != 0) {
            free_wire_fragments(fwd, fragments, fragment_count);
            goto drop;
        }
        ne_packet_free(&fwd->pair, &job);
        complete_packet_window_after_enqueue(proto, 1, 1);
        return;
    }
    if (proto == IPPROTO_TCP) {
        uint32_t len = job.len;

        /* TCP never uses the UDP splitter. Reuse the offset already parsed
         * for policy/MSS and call the exact same L2 wire encoder directly. */
        enc = crypto_l2_pqc_encrypt_tcp_l3(pctx, pkt, &len, l3_off);
        if (enc == 0)
            job.len = len;
    } else {
        enc = encrypt_to_wan(fwd, &job, cp, wan_dp, pctx,
                             crypto_proto_classify(proto), flow_ok);
    }
    if (enc < 0)
        goto drop;
    if (enc > 0) {
        complete_packet_window_after_enqueue(proto, 0, 1);
        return;
    }
    {
        int sent = push_to_wan(fwd, &job, wan_dp) == 0;

        complete_packet_window_after_enqueue(proto, 0, sent);
    }
    return;

drop:
    complete_packet_window_after_enqueue(proto, jumbo_packet, 0);
    ne_packet_free(&fwd->pair, &job);
}

#include "../../../inc/core/dataplane/dataplane.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/crypto/l2_crypto.h"
#include "../../../inc/crypto/eth_parse.h"
#include <netinet/in.h>
#include <string.h>

#define UDP_MARK_LEN 4u
static const uint8_t udp_mark[UDP_MARK_LEN] = {0x5b,0x55,0x44,0x01};

static int is_udp_wire(const uint8_t *pkt, uint32_t len)
{
    int off;
    if (!crypto_eth_l2_has_marker(pkt, len)) return 0;
    off = crypto_eth_l2_frag_magic_off(pkt, len, PACKET_CRYPTO_NONCE_BYTES);
    return off >= 0 && len >= (uint32_t)off + UDP_MARK_LEN &&
           memcmp(pkt + off, udp_mark, UDP_MARK_LEN) == 0;
}

static int forward_local(struct forwarder *fwd, struct ne_packet *job)
{
    if (!fwd || fwd->local_count != 1)
        return -1;
    job->dir = NE_DIR_LOCAL;
    job->local_idx = 0;
    return dp_ring_push(fwd, &fwd->mid_to_local[0][dp_out_ring_idx()], job);
}

int dataplane_wan_needs_mid(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    (void)fwd;
    return crypto_eth_l2_has_marker(pkt, len);
}

void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt;
    uint32_t len, out_len = 0;
    int worker_idx = dp_crypto_current_worker_idx();
    int rr;
    if (!fwd || worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        goto drop;
    pkt = fwd->crypto_buf[worker_idx];
    if (ne_packet_linearize(&fwd->pair, &job, pkt, NE_JUMBO_FRAME_MAX) != 0)
        goto drop;
    if (!crypto_eth_l2_has_marker(pkt, job.len)) goto drop;
    len = job.len;
    if (is_udp_wire(pkt, len)) {
        rr = l2_crypto_reassemble_udp(worker_idx, &fwd->crypto, pkt, &len,
                                      fwd->crypto_aux[worker_idx], &out_len);
        if (rr == 0) { ne_packet_free(&fwd->pair, &job); return; }
        if (rr != 1) goto drop;
        pkt = fwd->crypto_aux[worker_idx];
        if (ne_packet_write(&fwd->pair, &job, pkt, out_len) != 0)
            goto drop;
    } else {
        if (l2_crypto_decrypt(L2_PROTO_DATA, &fwd->crypto, pkt, &len) != 0)
            goto drop;
        if (ne_packet_write(&fwd->pair, &job, pkt, len) != 0)
            goto drop;
    }
    dp_out_ring_bind(dp_flow_pick_tx_slot(pkt, job.len, worker_idx));
    if (forward_local(fwd, &job) == 0) return;
drop:
    ne_packet_free(&fwd->pair, &job);
}

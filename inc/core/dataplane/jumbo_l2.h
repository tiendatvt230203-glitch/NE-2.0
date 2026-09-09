#ifndef JUMBO_L2_H
#define JUMBO_L2_H

#include "core/forwarder/forwarder.h"
#include "crypto/packet_crypto.h"

#define NE_L2_JUMBO_ENCRYPTED_ETHERTYPE 0x104Cu
#define NE_L2_JUMBO_BYPASS_ETHERTYPE    0x104Du

enum dp_jumbo_rx_result {
    DP_JUMBO_RX_DROP = -1,
    DP_JUMBO_RX_HELD = 0,
    DP_JUMBO_RX_COMPLETE = 1,
};

int dp_jumbo_packet_needs_wire_split(const struct ne_packet *packet,
                                     int encrypted);
int dp_jumbo_build_wire(struct forwarder *fwd,
                        const struct ne_packet *input,
                        struct packet_crypto_ctx *crypto_ctx,
                        uint8_t wire_policy_id, int encrypted,
                        struct ne_packet output[NE_PACKET_MAX_SEGMENTS],
                        uint32_t *output_count);

/* 0 = ordinary frame, 1 = bypass jumbo fragment, 2 = encrypted fragment. */
int dp_jumbo_wire_kind(const uint8_t *packet, uint32_t length);
int dp_jumbo_wire_worker(const uint8_t *packet, uint32_t length,
                         uint8_t *worker_id);
int dp_jumbo_wire_policy(const uint8_t *packet, uint32_t length,
                         uint8_t *wire_policy_id);

int dp_jumbo_receive(struct forwarder *fwd, int worker_idx,
                     struct ne_packet *wire_packet,
                     struct packet_crypto_ctx *crypto_ctx,
                     struct ne_packet *plain_packet,
                     uint8_t *wire_policy_id, int *encrypted);
void dp_jumbo_gc(struct forwarder *fwd, int worker_idx);
void dp_jumbo_reset(struct forwarder *fwd, int worker_idx);

int dp_jumbo_push_local(struct forwarder *fwd, struct ne_ring *ring,
                        const struct ne_packet *packet, int local_idx);
int dp_jumbo_push_wan_fragments(struct forwarder *fwd, struct ne_ring *ring,
                                struct ne_packet *fragments,
                                uint32_t fragment_count, int wan_idx);

#endif

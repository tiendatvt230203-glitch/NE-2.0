#ifndef CRYPTO_ROUTE_H
#define CRYPTO_ROUTE_H

#include "core/iface/interface.h"
#include <stdint.h>

struct forwarder;

int dp_crypto_pick_local_worker(const uint8_t *pkt, uint32_t len, int *tx_slot_out);

int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len);

int dp_crypto_worker_idx_for_cpu(uint8_t cpu_id);

void dp_crypto_worker_bind(int worker_idx);
int dp_crypto_current_worker_idx(void);

/* Monotonic wire sequence in one flow/direction. Called on its sticky worker. */
int dp_udp_next_tx_seq(const uint8_t *pkt, uint32_t len, uint32_t *seq_out);

/* Learn/lookup a decrypted flow and return its sticky, independently balanced TX slot. */
int dp_flow_pick_tx_slot(const uint8_t *pkt, uint32_t len, int worker_hint);
void dp_route_set_active_tx_slots(uint32_t slots);

/* Stable packet hash to TX slot for direct drop/control handling. */
int dp_pick_tx_slot(const uint8_t *pkt, uint32_t len);
void dp_out_ring_bind(int ring_idx);
int dp_out_ring_idx(void);

#endif

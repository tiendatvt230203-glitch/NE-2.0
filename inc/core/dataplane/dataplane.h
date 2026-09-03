#ifndef DATAPLANE_H
#define DATAPLANE_H

#include "core/forwarder/forwarder.h"

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job);
void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job);

/* 1 = must go through crypto mid (encrypt/decrypt). 0 = RX handles (bypass/ARP/drop). */
int dataplane_local_needs_mid(struct forwarder *fwd, const uint8_t *pkt, uint32_t len,
                              int local_idx);
int dataplane_wan_needs_mid(struct forwarder *fwd, const uint8_t *pkt, uint32_t len);

void dataplane_bond_reorder_configure(void);
void dataplane_bond_reorder_gc(struct forwarder *fwd, int worker_idx);
void dataplane_bond_reorder_reset(struct forwarder *fwd, int worker_idx);

#endif

#ifndef DATAPLANE_H
#define DATAPLANE_H

#include "core/forwarder/forwarder.h"

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job);
void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job);

/* 1 = send through crypto worker; 0 = let RX worker handle/drop directly. */
int dataplane_local_needs_mid(struct forwarder *fwd, const uint8_t *pkt, uint32_t len,
                              int local_idx);
int dataplane_wan_needs_mid(struct forwarder *fwd, const uint8_t *pkt, uint32_t len);

#endif

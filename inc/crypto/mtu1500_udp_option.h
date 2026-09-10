#ifndef MTU1500_UDP_OPTION_H
#define MTU1500_UDP_OPTION_H

#include <stdint.h>

/* Metadata belongs exclusively to the MTU-1500 UDP wire/reorder option. */
void crypto_mtu1500_udp_set_tx_seq(uint32_t seq);
int crypto_mtu1500_udp_tx_meta(uint32_t *epoch, uint32_t *seq,
                               uint32_t *datagram_id);
void crypto_mtu1500_udp_clear_rx_meta(void);
void crypto_mtu1500_udp_set_rx_meta(uint32_t epoch, uint32_t seq);
int crypto_mtu1500_udp_take_rx_meta(uint32_t *epoch, uint32_t *seq);

#endif

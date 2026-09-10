#ifndef PQC_L2_MTU1500_UDP_H
#define PQC_L2_MTU1500_UDP_H

#include "../../../../inc/crypto/crypto_option.h"

int pqc_l2_mtu1500_udp_need_split(uint32_t pkt_len);
int pqc_l2_mtu1500_udp_split(struct packet_crypto_ctx *ctx,
                             uint8_t *pkt_data, uint32_t pkt_len,
                             size_t frag0_max, uint32_t *frag0_len,
                             uint8_t *frag1, size_t frag1_max,
                             uint32_t *frag1_len);
int pqc_l2_mtu1500_udp_encrypt(struct packet_crypto_ctx *ctx,
                               uint8_t *pkt, uint32_t *pkt_len);
int pqc_l2_mtu1500_udp_decrypt(struct packet_crypto_ctx *ctx,
                               uint8_t *pkt, uint32_t *pkt_len);
int pqc_l2_mtu1500_udp_is_fragment(const struct app_config *cfg,
                                   const uint8_t *pkt_data,
                                   uint32_t pkt_len, uint16_t *pkt_id,
                                   uint8_t *frag_index);
int pqc_l2_mtu1500_udp_reassemble(int profile_slot, int worker_idx,
                                  struct packet_crypto_ctx *ctx,
                                  uint8_t *pkt_data, uint32_t *pkt_len,
                                  uint8_t *out_buf, uint32_t *out_len);
void pqc_l2_mtu1500_udp_frag_gc(int profile_slot, int worker_idx,
                                uint64_t now_ns);

#endif

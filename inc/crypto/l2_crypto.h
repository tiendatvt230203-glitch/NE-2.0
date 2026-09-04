#ifndef L2_CRYPTO_H
#define L2_CRYPTO_H

#include "packet_crypto.h"
#include <stddef.h>
#include <stdint.h>

#define L2_CRYPTO_MTU 1500u
#define L2_FRAG_TABLE_SIZE 4096
#define L2_FRAG_TIMEOUT_NS (200ULL * 1000000ULL)

enum l2_crypto_proto {
    L2_PROTO_DATA = 0,
    L2_PROTO_UDP,
    L2_PROTO_ARP,
};

enum l2_crypto_proto l2_crypto_classify(uint8_t ip_proto);
void l2_crypto_bind_worker(uint8_t worker_idx);
uint8_t l2_crypto_worker(void);

void l2_crypto_udp_set_tx_seq(uint32_t seq);
int l2_crypto_udp_tx_meta(uint32_t *epoch, uint32_t *seq,
                          uint32_t *datagram_id);
void l2_crypto_udp_clear_rx_meta(void);
void l2_crypto_udp_set_rx_meta(uint32_t epoch, uint32_t seq);
int l2_crypto_udp_take_rx_meta(uint32_t *epoch, uint32_t *seq);

int l2_crypto_need_udp_split(uint32_t packet_len);
int l2_crypto_split_udp(struct packet_crypto_ctx *ctx,
                        uint8_t *packet, uint32_t packet_len,
                        size_t first_max, uint32_t *first_len,
                        uint8_t *second, size_t second_max,
                        uint32_t *second_len);
int l2_crypto_encrypt(enum l2_crypto_proto proto,
                      struct packet_crypto_ctx *ctx,
                      uint8_t *packet, uint32_t *packet_len);
int l2_crypto_decrypt(enum l2_crypto_proto proto,
                      struct packet_crypto_ctx *ctx,
                      uint8_t *packet, uint32_t *packet_len);
int l2_crypto_reassemble_udp(int worker_idx,
                             struct packet_crypto_ctx *ctx,
                             uint8_t *packet, uint32_t *packet_len,
                             uint8_t *output, uint32_t *output_len);
void l2_crypto_frag_gc(int worker_idx, uint64_t now_ns);

#endif

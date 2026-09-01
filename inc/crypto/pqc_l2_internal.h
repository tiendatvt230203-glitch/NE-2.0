#ifndef PQC_L2_INTERNAL_H
#define PQC_L2_INTERNAL_H

#include "crypto/crypto_option.h"
#include "crypto/crypto_pqc_layer.h"
#include "crypto/eth_parse.h"
#include "core/iface/interface.h"

#define PQC_L2_MIN_ETH_PKT        (ETH_HEADER_SIZE + 8)
#define PQC_L2_FAKE_ETHERTYPE     0x104Au
#define PQC_L2_POLICY_LEN          1
#define PQC_L2_CORE_ID_LEN         1
#define PQC_L2_NONCE_SIZE          CRYPTO_PQC_NONCE_BYTES
#define PQC_L2_UNLIKELY(x)         __builtin_expect(!!(x), 0)

int pqc_l2_policy_match(const struct app_config *cfg, int action,
                        uint8_t wire_id);
int pqc_l2_policy_off(const uint8_t *packet, size_t pkt_len);
int pqc_l2_core_id_off(const uint8_t *packet, size_t pkt_len);
int pqc_l2_nonce_off(const uint8_t *packet, size_t pkt_len);
int pqc_l2_enc_start_off(const uint8_t *packet, size_t pkt_len);
int pqc_l2_marker_off(const uint8_t *packet, size_t pkt_len);
int pqc_l2_wire_prefix_len(const uint8_t *packet, size_t pkt_len);

void pqc_l2_write_wire_header_et(uint8_t *packet, int et_off, uint16_t fake,
                                 uint8_t policy_id, const uint8_t *nonce,
                                 int nonce_size);
void pqc_l2_write_wire_header(uint8_t *packet, int et_off, uint8_t policy_id,
                              const uint8_t *nonce, int nonce_size);

int pqc_l2_encrypt_ipv4_generic(struct packet_crypto_ctx *ctx,
                                uint8_t *packet, size_t pkt_len);
int pqc_l2_decrypt_ipv4_generic(struct packet_crypto_ctx *ctx,
                                uint8_t *packet, size_t pkt_len);

#endif

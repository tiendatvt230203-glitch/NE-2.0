#ifndef PACKET_CRYPTO_H
#define PACKET_CRYPTO_H
#include <stdbool.h>
#include <stdint.h>
#define AES_MAX_KEY_SIZE 32
#define AES_GCM_TAG_SIZE 16
#define ETH_HEADER_SIZE 14
#define PACKET_CRYPTO_NONCE_BYTES 12
#define CRYPTO_PQC_NONCE_BYTES PACKET_CRYPTO_NONCE_BYTES
struct packet_crypto_ctx { uint8_t key[AES_MAX_KEY_SIZE]; bool initialized; };
int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t key[AES_MAX_KEY_SIZE]);
#endif

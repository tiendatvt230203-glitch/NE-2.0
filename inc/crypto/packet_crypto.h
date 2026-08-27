#ifndef PACKET_CRYPTO_H
#define PACKET_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define AES_MAX_KEY_SIZE   32
#define AES_GCM_TAG_SIZE   16

#define ETH_HEADER_SIZE            14
#define PROTO_FLAG_IPV4            0
#define PACKET_CRYPTO_NONCE_BYTES  12
#define CRYPTO_PQC_NONCE_BYTES     PACKET_CRYPTO_NONCE_BYTES

#define KEY_SLOT_PREV         0
#define KEY_SLOT_CURRENT      1
#define KEY_SLOT_NEXT         2
#define KEY_SLOT_COUNT        3

struct packet_crypto_ctx {
    uint8_t master_key[AES_MAX_KEY_SIZE];
    uint8_t keys[KEY_SLOT_COUNT][AES_MAX_KEY_SIZE];
    bool initialized;
    int crypto_mode;
    int policy_id;   /* PQC diversify / internal; may be db_id */
    uint8_t wire_id; /* policy wire id written into packet headers */
    int profile_id;
    int aes_bits;
    /* 1 = keys come from PQC handshake (diversify/clear on !key_ready).
     * 0 = static/master-derived keys (e.g. ARP default) — never HS-refresh. */
    bool pqc_from_handshake;
};

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t master_key[AES_MAX_KEY_SIZE],
                       int aes_bits);

void packet_crypto_update_keys(struct packet_crypto_ctx *ctx);
void packet_crypto_refresh_pqc_keys(struct packet_crypto_ctx *ctx);

const uint8_t *packet_crypto_get_key(struct packet_crypto_ctx *ctx, int slot);

#endif

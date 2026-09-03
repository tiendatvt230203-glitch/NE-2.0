#include "../../../inc/crypto/packet_crypto.h"
#include "../../../inc/core/util/config.h"
#include "../../../inc/core/util/main_diag.h"

#include <openssl/hmac.h>
#include <string.h>

#include "pqc_handshake.h"

static int key_nonzero(const uint8_t *key, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (key[i])
            return 1;
    }
    return 0;
}

/* Same 32-byte slot fill ARP used with aes_bits=256 (HMAC-SHA256, epoch 0). */
static void fill_static_slots(const uint8_t master[AES_MAX_KEY_SIZE],
                              uint8_t slots[KEY_SLOT_COUNT][AES_MAX_KEY_SIZE])
{
    uint8_t epoch_buf[8];
    unsigned char hmac_out[32];
    unsigned int hmac_len;

    memset(epoch_buf, 0, sizeof(epoch_buf));
    HMAC(EVP_sha256(), master, AES_MAX_KEY_SIZE, epoch_buf, sizeof(epoch_buf),
         hmac_out, &hmac_len);
    memcpy(slots[KEY_SLOT_PREV], hmac_out, AES_MAX_KEY_SIZE);
    memcpy(slots[KEY_SLOT_CURRENT], hmac_out, AES_MAX_KEY_SIZE);
    memcpy(slots[KEY_SLOT_NEXT], hmac_out, AES_MAX_KEY_SIZE);
}

static void pqc_clear_ctx_keys(struct packet_crypto_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->pqc_from_handshake && ctx->profile_id > 0 && ctx->policy_id > 0)
        main_diag_ne_pqc_clear(ctx->profile_id, ctx->policy_id);
    memset(ctx->keys, 0, sizeof(ctx->keys));
}

static int pqc_copy_handshake_slots(struct packet_crypto_ctx *ctx)
{
    uint8_t keys[KEY_SLOT_COUNT][PQC_TRAFFIC_KEY_SZ];
    uint8_t key_ids[KEY_SLOT_COUNT];
    bool valid[KEY_SLOT_COUNT];

    if (!ctx || ctx->crypto_mode != CRYPTO_MODE_PQC || !ctx->pqc_from_handshake)
        return -1;

    if (sig_pqc_get_keys(ctx->policy_id, keys, key_ids, valid) != 0)
        return -1;

    for (int slot = 0; slot < KEY_SLOT_COUNT; slot++) {
        if (valid[slot])
            memcpy(ctx->keys[slot], keys[slot], PQC_TRAFFIC_KEY_SZ);
        else
            memset(ctx->keys[slot], 0, PQC_TRAFFIC_KEY_SZ);
    }
    return 0;
}

static void pqc_refresh_if_stale(struct packet_crypto_ctx *ctx)
{
    if (!ctx || ctx->crypto_mode != CRYPTO_MODE_PQC || !ctx->pqc_from_handshake)
        return;

    if (pqc_copy_handshake_slots(ctx) == 0)
        return;
    if (!key_nonzero(ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ))
        pqc_clear_ctx_keys(ctx);
}

const uint8_t *packet_crypto_get_key(struct packet_crypto_ctx *ctx, int slot)
{
    if (!ctx || slot < 0 || slot >= KEY_SLOT_COUNT)
        return NULL;
    return ctx->keys[slot];
}

void packet_crypto_update_keys(struct packet_crypto_ctx *ctx)
{
    pqc_refresh_if_stale(ctx);
}

void packet_crypto_refresh_pqc_keys(struct packet_crypto_ctx *ctx)
{
    if (!ctx || ctx->crypto_mode != CRYPTO_MODE_PQC || !ctx->pqc_from_handshake)
        return;
    if (pqc_copy_handshake_slots(ctx) != 0) {
        if (!key_nonzero(ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ))
            pqc_clear_ctx_keys(ctx);
        return;
    }
    if (key_nonzero(ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ))
        main_diag_log_ne_pqc_match(ctx->profile_id, ctx->policy_id,
                                   ctx->keys[KEY_SLOT_CURRENT]);
}

int packet_crypto_init(struct packet_crypto_ctx *ctx, const uint8_t master_key[AES_MAX_KEY_SIZE],
                       int aes_bits)
{
    if (!ctx || !master_key)
        return -1;
    if (aes_bits != 128 && aes_bits != 256)
        aes_bits = 128;

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->master_key, master_key, AES_MAX_KEY_SIZE);
    ctx->aes_bits = aes_bits;
    ctx->crypto_mode = CRYPTO_MODE_PQC;
    ctx->initialized = true;
    fill_static_slots(ctx->master_key, ctx->keys);
    return 0;
}

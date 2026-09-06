#include "../../../inc/crypto/packet_crypto.h"
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

/* Same 32-byte slot fill used by the static ARP L2-PQC context. */
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

static void wipe_key_bytes(uint8_t *key, size_t len)
{
    volatile uint8_t *p = key;

    while (len--)
        *p++ = 0;
}

static void pqc_clear_ctx_keys(struct packet_crypto_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->pqc_from_handshake && ctx->profile_id > 0 && ctx->policy_id > 0)
        main_diag_ne_pqc_clear(ctx->profile_id, ctx->policy_id);
    wipe_key_bytes(ctx->keys[KEY_SLOT_PREV], PQC_TRAFFIC_KEY_SZ);
    wipe_key_bytes(ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ);
    wipe_key_bytes(ctx->keys[KEY_SLOT_NEXT], PQC_TRAFFIC_KEY_SZ);
}

static int pqc_load_handshake_slots(struct packet_crypto_ctx *ctx)
{
    uint8_t slots[KEY_SLOT_COUNT][PQC_TRAFFIC_KEY_SZ];
    uint8_t key_ids[KEY_SLOT_COUNT];
    bool valid[KEY_SLOT_COUNT];
    uint8_t old_current[PQC_TRAFFIC_KEY_SZ];

    memcpy(old_current, ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ);
    if (sig_pqc_get_keys(ctx->policy_id, slots, key_ids, valid) != 0)
        return -1;

    for (int slot = 0; slot < KEY_SLOT_COUNT; slot++) {
        if (valid[slot])
            memcpy(ctx->keys[slot], slots[slot], PQC_TRAFFIC_KEY_SZ);
        else
            wipe_key_bytes(ctx->keys[slot], PQC_TRAFFIC_KEY_SZ);
    }
    if (key_nonzero(ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ) &&
        memcmp(old_current, ctx->keys[KEY_SLOT_CURRENT],
               PQC_TRAFFIC_KEY_SZ) != 0)
        main_diag_log_ne_pqc_match(ctx->profile_id, ctx->policy_id,
                                   ctx->keys[KEY_SLOT_CURRENT]);
    return 0;
}

const uint8_t *packet_crypto_get_key(struct packet_crypto_ctx *ctx, int slot)
{
    if (!ctx || slot < 0 || slot >= KEY_SLOT_COUNT)
        return NULL;
    return ctx->keys[slot];
}

void packet_crypto_refresh_pqc_keys(struct packet_crypto_ctx *ctx)
{
    if (!ctx || !ctx->pqc_from_handshake)
        return;
    if (pqc_load_handshake_slots(ctx) != 0) {
        if (!key_nonzero(ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ))
            pqc_clear_ctx_keys(ctx);
    }
}

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t master_key[AES_MAX_KEY_SIZE])
{
    if (!ctx || !master_key)
        return -1;

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->master_key, master_key, AES_MAX_KEY_SIZE);
    ctx->initialized = true;
    fill_static_slots(ctx->master_key, ctx->keys);
    return 0;
}

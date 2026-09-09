#include "../../../inc/crypto/packet_crypto.h"
#include "../../../inc/core/util/main_diag.h"

#include "scrypt.h"
#include <stdio.h>
#include <string.h>

#include "pqc_handshake.h"

static void wipe_key_bytes(uint8_t *key, size_t len);

static int key_nonzero(const uint8_t *key, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (key[i])
            return 1;
    }
    return 0;
}

#define PACKET_CRYPTO_MAX_WIRE 4096u
#define PACKET_CRYPTO_WIRE_IDS 256u

_Static_assert(PACKET_CRYPTO_NONCE_BYTES == 12,
               "Layer-2 wire format requires a 96-bit GCM nonce");
_Static_assert(AES_GCM_TAG_SIZE == 16,
               "Layer-2 wire format requires a 128-bit GCM tag");

struct packet_cipher {
    SCryptCipherCtx *ctx;
};

static __thread struct packet_cipher tls_encrypt;
static __thread struct packet_cipher tls_decrypt;
static __thread uint8_t tls_nonce_salt[8];
static __thread uint32_t tls_nonce_counter;
static __thread uint8_t tls_nonce_ready;
static __thread uint8_t tls_zero_key_logged[PACKET_CRYPTO_WIRE_IDS];

static void packet_cipher_clear(struct packet_cipher *cipher)
{
    if (!cipher)
        return;
    if (cipher->ctx)
        scrypt_CipherCtxFree(cipher->ctx);
    cipher->ctx = NULL;
}

static int packet_cipher_begin(struct packet_cipher *cipher,
                               const uint8_t *key, const uint8_t *nonce,
                               int encrypt)
{
    if (!cipher || !key || !nonce)
        return -1;
    if (!cipher->ctx) {
        cipher->ctx = scrypt_CipherCtxNew();
        if (!cipher->ctx)
            return -1;
    }
    if (scrypt_CipherInit(cipher->ctx, CIPHER_TYPE_AES_256_GCM,
                          key, AES_MAX_KEY_SIZE, nonce,
                          PACKET_CRYPTO_NONCE_BYTES,
                          encrypt ? SCRYPT_ENCRYPTION : SCRYPT_DECRYPTION) != 0)
        return -1;
    return scrypt_CipherSetTagSize(cipher->ctx, AES_GCM_TAG_SIZE) == 0 ? 0 : -1;
}

static int packet_encrypt_one(struct packet_cipher *cipher, const uint8_t *key,
                              const uint8_t *nonce, uint8_t *data,
                              int plain_len, int *wire_len)
{
    word32 out_len = 0;
    word32 final_len = 0;
    word32 tag_len = AES_GCM_TAG_SIZE;

    if (!data || plain_len <= 0 || !wire_len ||
        packet_cipher_begin(cipher, key, nonce, 1) != 0)
        return -1;
    if (scrypt_CipherUpdate(cipher->ctx, data, (word32)plain_len,
                            data, &out_len) != 0 ||
        scrypt_CipherFinal(cipher->ctx, data + out_len, &final_len) != 0 ||
        scrypt_CipherGetTag(cipher->ctx, data + out_len + final_len,
                            &tag_len) != 0 || tag_len != AES_GCM_TAG_SIZE)
        return -1;
    *wire_len = (int)(out_len + final_len + tag_len);
    return 0;
}

static int packet_decrypt_one(struct packet_cipher *cipher, const uint8_t *key,
                              const uint8_t *nonce, uint8_t *data,
                              int wire_len, int *plain_len)
{
    int cipher_len;
    word32 out_len = 0;
    word32 final_len = 0;

    if (!data || wire_len <= AES_GCM_TAG_SIZE || !plain_len)
        return -1;
    cipher_len = wire_len - AES_GCM_TAG_SIZE;
    if (packet_cipher_begin(cipher, key, nonce, 0) != 0 ||
        scrypt_CipherSetTag(cipher->ctx, data + cipher_len,
                            AES_GCM_TAG_SIZE) != 0 ||
        scrypt_CipherUpdate(cipher->ctx, data, (word32)cipher_len,
                            data, &out_len) != 0 ||
        scrypt_CipherFinal(cipher->ctx, data + out_len, &final_len) != 0)
        return -1;
    *plain_len = (int)(out_len + final_len);
    return 0;
}

int packet_crypto_generate_nonce(uint8_t nonce[PACKET_CRYPTO_NONCE_BYTES])
{
    uint32_t counter;

    if (!nonce)
        return -1;
    if (!tls_nonce_ready) {
        if (scrypt_RandomBytes(tls_nonce_salt,
                               (word32)sizeof(tls_nonce_salt)) != 0)
            return -1;
        tls_nonce_counter = 0;
        tls_nonce_ready = 1;
    }
    counter = ++tls_nonce_counter;
    if (counter == 0) {
        if (scrypt_RandomBytes(tls_nonce_salt,
                               (word32)sizeof(tls_nonce_salt)) != 0)
            return -1;
        counter = ++tls_nonce_counter;
    }
    memcpy(nonce, tls_nonce_salt, sizeof(tls_nonce_salt));
    memcpy(nonce + sizeof(tls_nonce_salt), &counter, sizeof(counter));
    return 0;
}

int packet_crypto_encrypt(struct packet_crypto_ctx *ctx,
                          const uint8_t nonce[PACKET_CRYPTO_NONCE_BYTES],
                          uint8_t *data, int plain_len, int *wire_len)
{
    const uint8_t *key;

    if (!ctx || !ctx->initialized)
        return -1;
    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key_nonzero(key, AES_MAX_KEY_SIZE)) {
        if (ctx->pqc_from_handshake && !tls_zero_key_logged[ctx->wire_id]) {
            tls_zero_key_logged[ctx->wire_id] = 1;
            fprintf(stderr,
                    "[PQC-KEY] invalid CURRENT key for profile=%d policy=%d; blocking L2 crypto\n",
                    ctx->profile_id, ctx->policy_id);
        }
        return -1;
    }
    tls_zero_key_logged[ctx->wire_id] = 0;
    return packet_encrypt_one(&tls_encrypt, key, nonce, data,
                              plain_len, wire_len);
}

static __attribute__((noinline)) int packet_decrypt_fallback(
    const uint8_t *candidates[KEY_SLOT_COUNT], int candidate_count,
    const uint8_t nonce[PACKET_CRYPTO_NONCE_BYTES],
    uint8_t *data, int wire_len, int *plain_len)
{
    uint8_t saved[PACKET_CRYPTO_MAX_WIRE];

    memcpy(saved, data, (size_t)wire_len);
    for (int i = 0; i < candidate_count; i++) {
        if (i)
            memcpy(data, saved, (size_t)wire_len);
        if (packet_decrypt_one(&tls_decrypt, candidates[i], nonce,
                               data, wire_len, plain_len) == 0)
            return 0;
    }
    return -1;
}

int packet_crypto_decrypt(struct packet_crypto_ctx *ctx,
                          const uint8_t nonce[PACKET_CRYPTO_NONCE_BYTES],
                          uint8_t *data, int wire_len, int *plain_len)
{
    static const int order[KEY_SLOT_COUNT] = {
        KEY_SLOT_CURRENT, KEY_SLOT_NEXT, KEY_SLOT_PREV
    };
    const uint8_t *candidates[KEY_SLOT_COUNT];
    int candidate_count = 0;

    if (!ctx || !ctx->initialized || !nonce || !data ||
        wire_len <= AES_GCM_TAG_SIZE ||
        wire_len > (int)PACKET_CRYPTO_MAX_WIRE)
        return -1;
    for (int oi = 0; oi < KEY_SLOT_COUNT; oi++) {
        const uint8_t *key = packet_crypto_get_key(ctx, order[oi]);
        int duplicate = 0;

        if (!key_nonzero(key, AES_MAX_KEY_SIZE))
            continue;
        for (int i = 0; i < candidate_count; i++) {
            if (memcmp(candidates[i], key, AES_MAX_KEY_SIZE) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate)
            candidates[candidate_count++] = key;
    }
    if (candidate_count == 0)
        return -1;
    if (candidate_count == 1)
        return packet_decrypt_one(&tls_decrypt, candidates[0], nonce,
                                  data, wire_len, plain_len);

    /* Only copy ciphertext while different rotation keys must be attempted. */
    return packet_decrypt_fallback(candidates, candidate_count, nonce,
                                   data, wire_len, plain_len);
}

void packet_crypto_worker_cleanup(void)
{
    packet_cipher_clear(&tls_encrypt);
    packet_cipher_clear(&tls_decrypt);
    memset(tls_zero_key_logged, 0, sizeof(tls_zero_key_logged));
    memset(tls_nonce_salt, 0, sizeof(tls_nonce_salt));
    tls_nonce_counter = 0;
    tls_nonce_ready = 0;
}

/* Same 32-byte slot fill used by the static ARP L2-PQC context. */
static int fill_static_slots(const uint8_t master[AES_MAX_KEY_SIZE],
                             uint8_t slots[KEY_SLOT_COUNT][AES_MAX_KEY_SIZE])
{
    uint8_t epoch_buf[8];
    uint8_t hmac_out[AES_MAX_KEY_SIZE];
    SCryptHmacCtx *hmac;

    memset(epoch_buf, 0, sizeof(epoch_buf));
    hmac = scrypt_HmacCtxNew();
    if (!hmac)
        return -1;
    if (scrypt_HmacInit(hmac, master, AES_MAX_KEY_SIZE,
                        DIGEST_TYPE_SHA256) != 0 ||
        scrypt_HmacUpdate(hmac, epoch_buf, sizeof(epoch_buf)) != 0 ||
        scrypt_HmacFinal(hmac, hmac_out, sizeof(hmac_out)) != 0) {
        scrypt_HmacCtxFree(hmac);
        return -1;
    }
    scrypt_HmacCtxFree(hmac);
    memcpy(slots[KEY_SLOT_PREV], hmac_out, AES_MAX_KEY_SIZE);
    memcpy(slots[KEY_SLOT_CURRENT], hmac_out, AES_MAX_KEY_SIZE);
    memcpy(slots[KEY_SLOT_NEXT], hmac_out, AES_MAX_KEY_SIZE);
    wipe_key_bytes(hmac_out, sizeof(hmac_out));
    return 0;
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
    if (fill_static_slots(ctx->master_key, ctx->keys) != 0) {
        wipe_key_bytes(ctx->master_key, sizeof(ctx->master_key));
        return -1;
    }
    ctx->initialized = true;
    return 0;
}

#ifndef CRYPTO_PQC_LAYER_H
#define CRYPTO_PQC_LAYER_H

#include "packet_crypto.h"
#include "crypto_option.h"
#include "traffic_crypto.h"
#include "pqc_handshake.h"
#include "scrypt.h"
#include <stdio.h>
#include <string.h>

typedef struct crypto_pqc_sess {
    const uint8_t *key;
    const uint8_t *aad;
    int aad_len;
} crypto_pqc_sess_t;

typedef unsigned char byte;

static const byte HARDCODED_AAD[] = {
    0x54, 0x45, 0x53, 0x54, 0x5f, 0x41, 0x41, 0x44
};

static inline int crypto_pqc_key_is_all_zero(const byte *key, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (key[i] != 0)
            return 0;
    }
    return 1;
}

static inline int crypto_pqc_sess_load(struct packet_crypto_ctx *ctx, crypto_pqc_sess_t *sess)
{
    const byte *key;
    static __thread uint8_t zero_key_logged[256];

    if (!ctx || !sess)
        return -1;
    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;
    if (crypto_pqc_key_is_all_zero(key, PQC_TRAFFIC_KEY_SZ)) {
        if (ctx->pqc_from_handshake && !zero_key_logged[ctx->wire_id]) {
            zero_key_logged[ctx->wire_id] = 1;
            fprintf(stderr,
                    "[PQC-KEY] invalid CURRENT key (all-zero) for profile=%d policy=%d; blocking PQC crypto path\n",
                    ctx->profile_id, ctx->policy_id);
        }
        return -1;
    }
    if (ctx->pqc_from_handshake)
        zero_key_logged[ctx->wire_id] = 0;
    sess->key = key;
    sess->aad = HARDCODED_AAD;
    sess->aad_len = 12;
    return 0;
}

static inline int crypto_pqc_generate_nonce(byte nonce[CRYPTO_PQC_NONCE_BYTES])
{
    return trf_pqc_generate_nonce(nonce) == TRF_PQC_OK ? 0 : -1;
}

/* One CipherCtx per worker thread; CipherInit still runs every packet. */
static inline SCryptCipherCtx *crypto_pqc_tls_cipher(int enc)
{
    static __thread SCryptCipherCtx *tls_enc;
    static __thread SCryptCipherCtx *tls_dec;
    SCryptCipherCtx **slot = enc ? &tls_enc : &tls_dec;

    if (!*slot)
        *slot = scrypt_CipherCtxNew();
    return *slot;
}

static inline int crypto_pqc_encrypt_payload(const crypto_pqc_sess_t *sess,
                                             const byte nonce[CRYPTO_PQC_NONCE_BYTES],
                                             byte *data, int len, int *out_len)
{
    SCryptCipherCtx *c;
    int rc;

    if (!sess || !sess->key || !data || len <= 0 || !out_len)
        return -1;
    c = crypto_pqc_tls_cipher(1);
    if (!c)
        return -1;
    rc = trf_encrypt_payload_gcm(c, sess->key, nonce, CRYPTO_PQC_NONCE_BYTES,
                                 sess->aad, sess->aad_len, data, len, out_len);
    return rc == TRF_PQC_OK ? 0 : -1;
}

static inline int crypto_pqc_decrypt_payload(const crypto_pqc_sess_t *sess,
                                             const byte nonce[CRYPTO_PQC_NONCE_BYTES],
                                             byte *data, int len, int *out_len)
{
    SCryptCipherCtx *c;
    int rc;

    if (!sess || !sess->key || !data || len <= 0 || !out_len)
        return -1;
    c = crypto_pqc_tls_cipher(0);
    if (!c)
        return -1;
    rc = trf_decrypt_payload_gcm(c, sess->key, nonce, CRYPTO_PQC_NONCE_BYTES,
                                 sess->aad, sess->aad_len, data, len, out_len);
    return rc == TRF_PQC_OK ? 0 : -1;
}

/* Accept the current key and the staged/grace keys during a coordinated
 * rotation. Every retry restores the ciphertext before authenticating. */
static inline int crypto_pqc_decrypt_payload_resilient(
    struct packet_crypto_ctx *ctx,
    const byte nonce[CRYPTO_PQC_NONCE_BYTES],
    byte *data, int len, int *out_len)
{
    crypto_pqc_sess_t sess;
    const byte *keys[KEY_SLOT_COUNT];
    const int order[KEY_SLOT_COUNT] = {
        KEY_SLOT_CURRENT, KEY_SLOT_NEXT, KEY_SLOT_PREV
    };
    byte saved[2048];
    int attempted = 0;

    if (!ctx || !data || len <= 0 || len > (int)sizeof(saved))
        return -1;
    memcpy(saved, data, (size_t)len);
    for (int i = 0; i < KEY_SLOT_COUNT; i++)
        keys[i] = packet_crypto_get_key(ctx, i);

    sess.aad = HARDCODED_AAD;
    sess.aad_len = 12;
    for (int oi = 0; oi < KEY_SLOT_COUNT; oi++) {
        const byte *candidate = keys[order[oi]];
        int duplicate = 0;

        if (!candidate ||
            crypto_pqc_key_is_all_zero(candidate, PQC_TRAFFIC_KEY_SZ))
            continue;
        for (int pj = 0; pj < oi; pj++) {
            const byte *prior = keys[order[pj]];
            if (prior && memcmp(prior, candidate, PQC_TRAFFIC_KEY_SZ) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate)
            continue;
        if (attempted)
            memcpy(data, saved, (size_t)len);
        sess.key = candidate;
        attempted = 1;
        if (crypto_pqc_decrypt_payload(&sess, nonce, data, len, out_len) == 0)
            return 0;
    }
    return -1;
}

#endif

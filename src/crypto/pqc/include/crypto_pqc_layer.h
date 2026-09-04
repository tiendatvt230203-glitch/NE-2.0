#ifndef CRYPTO_PQC_LAYER_H
#define CRYPTO_PQC_LAYER_H
#include "packet_crypto.h"
#include "traffic_crypto.h"
#include "scrypt.h"

typedef unsigned char byte;
typedef struct { const uint8_t *key; } crypto_pqc_sess_t;

static inline int crypto_pqc_sess_load(struct packet_crypto_ctx *ctx,
                                       crypto_pqc_sess_t *sess)
{
    if (!ctx || !ctx->initialized || !sess) return -1;
    sess->key = ctx->key;
    return 0;
}
static inline int crypto_pqc_generate_nonce(byte nonce[CRYPTO_PQC_NONCE_BYTES])
{
    return trf_pqc_generate_nonce(nonce) == TRF_PQC_OK ? 0 : -1;
}
static inline SCryptCipherCtx *crypto_pqc_tls_cipher(int enc)
{
    static __thread SCryptCipherCtx *e, *d;
    SCryptCipherCtx **p = enc ? &e : &d;
    if (!*p) *p = scrypt_CipherCtxNew();
    return *p;
}
static inline int crypto_pqc_encrypt_payload(const crypto_pqc_sess_t *s,
    const byte nonce[CRYPTO_PQC_NONCE_BYTES], byte *data, int len, int *out_len)
{
    SCryptCipherCtx *c = crypto_pqc_tls_cipher(1);
    return s && s->key && c &&
        trf_encrypt_payload_gcm(c, s->key, nonce, CRYPTO_PQC_NONCE_BYTES,
                                data, len, out_len) == TRF_PQC_OK ? 0 : -1;
}
static inline int crypto_pqc_decrypt_payload_resilient(struct packet_crypto_ctx *ctx,
    const byte nonce[CRYPTO_PQC_NONCE_BYTES], byte *data, int len, int *out_len)
{
    SCryptCipherCtx *c = crypto_pqc_tls_cipher(0);
    return ctx && ctx->initialized && c &&
        trf_decrypt_payload_gcm(c, ctx->key, nonce, CRYPTO_PQC_NONCE_BYTES,
                                data, len, out_len) == TRF_PQC_OK ? 0 : -1;
}
#endif

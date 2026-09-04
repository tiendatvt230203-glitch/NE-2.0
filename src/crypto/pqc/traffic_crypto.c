#include "traffic_crypto.h"
#include <stdint.h>
#include <string.h>

#define GCM_TAG_SIZE 16
static int initialized;
static __thread byte nonce_salt[8];
static __thread uint32_t nonce_counter;
static __thread int nonce_ready;

int trf_pqc_init_global(void)
{
    if (initialized) return TRF_PQC_OK;
    if (scrypt_Init() != 0) return TRF_PQC_ERR_INIT;
    initialized = 1;
    return TRF_PQC_OK;
}
void trf_pqc_cleanup(void)
{
    if (initialized) scrypt_Cleanup();
    initialized = 0;
}
int trf_pqc_generate_nonce(byte out[12])
{
    uint32_t n;
    if (!out || !initialized) return TRF_PQC_ERR_INIT;
    if (!nonce_ready) {
        if (scrypt_RandomBytes(nonce_salt, sizeof(nonce_salt)) != 0)
            return TRF_PQC_ERR_CRYPTO;
        nonce_ready = 1;
    }
    n = ++nonce_counter;
    memcpy(out, nonce_salt, sizeof(nonce_salt));
    memcpy(out + sizeof(nonce_salt), &n, sizeof(n));
    return TRF_PQC_OK;
}
int trf_encrypt_payload_gcm(SCryptCipherCtx *ctx, const byte *key,
    const byte *nonce, int nonce_len, byte *data, int len, int *new_len)
{
    word32 out = 0, final = 0, tag_len = GCM_TAG_SIZE;
    byte tag[GCM_TAG_SIZE];
    if (!initialized || !ctx || !key || !nonce || !data || len <= 0 || !new_len)
        return TRF_PQC_ERR_CRYPTO;
    if (scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32, nonce,
        nonce_len, SCRYPT_ENCRYPTION) != 0 ||
        scrypt_CipherSetTagSize(ctx, GCM_TAG_SIZE) != 0 ||
        scrypt_CipherUpdate(ctx, data, len, data, &out) != 0 ||
        scrypt_CipherFinal(ctx, data + out, &final) != 0 ||
        scrypt_CipherGetTag(ctx, tag, &tag_len) != 0)
        return TRF_PQC_ERR_CRYPTO;
    memcpy(data + out + final, tag, GCM_TAG_SIZE);
    *new_len = (int)(out + final + GCM_TAG_SIZE);
    return TRF_PQC_OK;
}
int trf_decrypt_payload_gcm(SCryptCipherCtx *ctx, const byte *key,
    const byte *nonce, int nonce_len, byte *data, int len, int *plain_len)
{
    word32 out = 0, final = 0;
    int cipher_len = len - GCM_TAG_SIZE;
    byte tag[GCM_TAG_SIZE];
    if (!initialized || !ctx || !key || !nonce || !data ||
        cipher_len <= 0 || !plain_len) return TRF_PQC_ERR_CRYPTO;
    memcpy(tag, data + cipher_len, GCM_TAG_SIZE);
    if (scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32, nonce,
        nonce_len, SCRYPT_DECRYPTION) != 0 ||
        scrypt_CipherSetTagSize(ctx, GCM_TAG_SIZE) != 0 ||
        scrypt_CipherSetTag(ctx, tag, GCM_TAG_SIZE) != 0 ||
        scrypt_CipherUpdate(ctx, data, cipher_len, data, &out) != 0 ||
        scrypt_CipherFinal(ctx, data + out, &final) != 0)
        return TRF_PQC_ERR_CRYPTO;
    *plain_len = (int)(out + final);
    return TRF_PQC_OK;
}

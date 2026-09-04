#ifndef TRAFFIC_CRYPTO_H
#define TRAFFIC_CRYPTO_H
#include "scrypt.h"
#define TRF_PQC_OK 0
#define TRF_PQC_ERR_INIT -1
#define TRF_PQC_ERR_CRYPTO -2
int trf_pqc_init_global(void);
void trf_pqc_cleanup(void);
int trf_pqc_generate_nonce(byte out_nonce[12]);
int trf_encrypt_payload_gcm(SCryptCipherCtx *ctx, const byte *key,
    const byte *nonce, int nonce_len, byte *data, int len, int *new_len);
int trf_decrypt_payload_gcm(SCryptCipherCtx *ctx, const byte *key,
    const byte *nonce, int nonce_len, byte *data, int len, int *plain_len);
#endif

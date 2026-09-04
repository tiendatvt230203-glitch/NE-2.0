#ifndef SCRYPT_CORE_API_H
#define SCRYPT_CORE_API_H

#include "types.h"

/* Minimal ABI surface used by the hard-coded AES-256-GCM dataplane. */
SCRYPT_API int scrypt_Init(void);
SCRYPT_API int scrypt_Cleanup(void);
SCRYPT_API int scrypt_RandomBytes(byte *out, word32 out_len);

SCRYPT_API SCryptCipherCtx *scrypt_CipherCtxNew(void);
SCRYPT_API void scrypt_CipherCtxFree(SCryptCipherCtx *ctx);
SCRYPT_API int scrypt_CipherInit(SCryptCipherCtx *ctx, SCryptCipherType type,
                                 const byte *key, word32 key_len,
                                 const byte *iv, word32 iv_len, int enc);
SCRYPT_API int scrypt_CipherUpdate(SCryptCipherCtx *ctx, const byte *input,
                                   word32 input_len, byte *output,
                                   word32 *output_len);
SCRYPT_API int scrypt_CipherFinal(SCryptCipherCtx *ctx, byte *output,
                                  word32 *output_len);
SCRYPT_API int scrypt_CipherSetTagSize(SCryptCipherCtx *ctx, word32 size);
SCRYPT_API int scrypt_CipherGetTag(SCryptCipherCtx *ctx, byte *tag,
                                   word32 *tag_len);
SCRYPT_API int scrypt_CipherSetTag(SCryptCipherCtx *ctx, const byte *tag,
                                   word32 tag_len);

#endif

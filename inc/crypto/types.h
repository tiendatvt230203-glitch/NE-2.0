#ifndef SCRYPT_CORE_TYPES_H
#define SCRYPT_CORE_TYPES_H

#define SCRYPT_API

typedef unsigned char byte;
typedef unsigned int word32;
typedef struct SCryptCipherCtx SCryptCipherCtx;

enum {
    SCRYPT_DECRYPTION = 0,
    SCRYPT_ENCRYPTION = 1,
};

enum {
    SCRYPT_CIPHER_ALG_AES = 0x01,
    SCRYPT_CIPHER_BLKSIZE_128 = 0x02 << 8,
    SCRYPT_CIPHER_KEYSIZE_256 = 0x04 << 12,
    SCRYPT_CIPHER_MODE_GCM = 0x04 << 16,
};

typedef enum {
    CIPHER_TYPE_AES_256_GCM = SCRYPT_CIPHER_ALG_AES |
                              SCRYPT_CIPHER_BLKSIZE_128 |
                              SCRYPT_CIPHER_KEYSIZE_256 |
                              SCRYPT_CIPHER_MODE_GCM,
} SCryptCipherType;

#endif

#include "../../../inc/crypto/packet_crypto.h"
#include <string.h>
int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t key[AES_MAX_KEY_SIZE])
{
    if (!ctx || !key) return -1;
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->key, key, AES_MAX_KEY_SIZE);
    ctx->initialized = true;
    return 0;
}

#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/core/iface/interface.h"

#include <netinet/in.h>

/* ===================== worker bind ===================== */

static __thread uint8_t g_worker_idx;

void crypto_option_bind_worker_idx(uint8_t worker_idx)
{
    g_worker_idx = worker_idx;
}

uint8_t crypto_option_worker_idx(void)
{
    return g_worker_idx;
}

crypto_proto_class crypto_proto_classify(uint8_t ip_proto)
{
    if (ip_proto == IPPROTO_TCP)
        return CRYPTO_PROTO_TCP;
    if (ip_proto == IPPROTO_UDP)
        return CRYPTO_PROTO_UDP;
    if (ip_proto == IPPROTO_ICMP)
        return CRYPTO_PROTO_ICMP;
    if (ip_proto == 89) /* IPPROTO_OSPF */
        return CRYPTO_PROTO_OSPF;
    return CRYPTO_PROTO_OTHER;
}

/* ===================== option router ===================== */

uint32_t crypto_option_wire_overhead(crypto_option_id id)
{
    if (id == CRYPTO_OPT_L2_PQC)
        /* policy ID + worker ID + nonce + GCM tag; EtherType is replaced. */
        return 1u + 1u + PACKET_CRYPTO_NONCE_BYTES + AES_GCM_TAG_SIZE;
    return 0u;
}

#define CALL_OPS(fn, id, proto, ...) do { \
    const struct crypto_option_ops *ops = crypto_option_ops((id), (proto)); \
    if (!ops || !ops->fn) \
        return -1; \
    return ops->fn(__VA_ARGS__); \
} while (0)

int crypto_option_encrypt(crypto_option_id id, crypto_proto_class proto,
                          struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len)
{
    CALL_OPS(encrypt, id, proto, ctx, pkt, pkt_len);
}

int crypto_option_decrypt(crypto_option_id id, crypto_proto_class proto,
                          struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len)
{
    CALL_OPS(decrypt, id, proto, ctx, pkt, pkt_len);
}

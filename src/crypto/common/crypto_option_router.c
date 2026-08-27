#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/core/iface/interface.h"

#include <netinet/in.h>
#include <stdatomic.h>

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

static atomic_uint_fast32_t g_opt_pkt_id = 0;
static atomic_uint_fast32_t g_opt_frag_mtu = CRYPTO_OPT_FRAG_MTU_DEFAULT;

uint16_t crypto_option_next_pkt_id(void)
{
    return (uint16_t)(atomic_fetch_add(&g_opt_pkt_id, 1) & 0xFFFF);
}

void crypto_option_set_mtu(uint32_t mtu)
{
    if (mtu < 512)
        mtu = 512;
    if (mtu > NE_FRAME)
        mtu = NE_FRAME;
    atomic_store(&g_opt_frag_mtu, mtu);
}

uint32_t crypto_option_get_mtu(void)
{
    uint32_t mtu = (uint32_t)atomic_load(&g_opt_frag_mtu);
    if (mtu < 512 || mtu > NE_FRAME)
        return CRYPTO_OPT_FRAG_MTU_DEFAULT;
    return mtu;
}

uint32_t crypto_option_wire_overhead(crypto_option_id id)
{
    if (id == CRYPTO_OPT_L2_PQC)
        return 30u;
    return 0u;
}

#define CALL_OPS(fn, id, proto, ...) do { \
    const struct crypto_option_ops *ops = crypto_option_ops((id), (proto)); \
    if (!ops || !ops->fn) \
        return -1; \
    return ops->fn(__VA_ARGS__); \
} while (0)

#define CALL_OPS_VOID(fn, id, proto, ...) do { \
    const struct crypto_option_ops *ops = crypto_option_ops((id), (proto)); \
    if (!ops || !ops->fn) \
        return; \
    ops->fn(__VA_ARGS__); \
} while (0)

int crypto_option_need_split(crypto_option_id id, crypto_proto_class proto, uint32_t pkt_len)
{
    const struct crypto_option_ops *ops = crypto_option_ops(id, proto);
    if (!ops || !ops->need_split)
        return 0;
    return ops->need_split(pkt_len);
}

int crypto_option_split(crypto_option_id id, crypto_proto_class proto,
                        struct packet_crypto_ctx *ctx,
                        uint8_t *pkt_data, uint32_t pkt_len,
                        size_t frag0_max, uint32_t *frag0_len,
                        uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    CALL_OPS(split, id, proto, ctx, pkt_data, pkt_len, frag0_max, frag0_len,
             frag1, frag1_max, frag1_len);
}

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

int crypto_option_is_fragment(crypto_option_id id, crypto_proto_class proto,
                              const struct app_config *cfg,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint16_t *pkt_id, uint8_t *frag_index)
{
    const struct crypto_option_ops *ops = crypto_option_ops(id, proto);
    if (!ops || !ops->is_fragment)
        return 0;
    return ops->is_fragment(cfg, pkt_data, pkt_len, pkt_id, frag_index);
}

int crypto_option_reassemble(crypto_option_id id, crypto_proto_class proto,
                             int profile_slot, int worker_idx,
                             struct packet_crypto_ctx *ctx,
                             uint8_t *pkt_data, uint32_t *pkt_len,
                             uint8_t *out_buf, uint32_t *out_len)
{
    CALL_OPS(reasm, id, proto, profile_slot, worker_idx, ctx, pkt_data, pkt_len,
             out_buf, out_len);
}

void crypto_option_frag_gc(crypto_option_id id, crypto_proto_class proto,
                           int profile_slot, int worker_idx, uint64_t now_ns)
{
    CALL_OPS_VOID(frag_gc, id, proto, profile_slot, worker_idx, now_ns);
}

void crypto_option_frag_gc_all(int profile_slot, int worker_idx, uint64_t now_ns)
{
    crypto_option_frag_gc(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_UDP,
                          profile_slot, worker_idx, now_ns);
}

#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/core/iface/interface.h"

#include <netinet/in.h>
#include <stdatomic.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

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

static atomic_uint_fast32_t g_opt_frag_mtu = CRYPTO_OPT_FRAG_MTU_DEFAULT;
static atomic_uint_fast32_t g_bond_epoch;
static __thread uint32_t g_tcp_tx_seq;
static __thread uint32_t g_tcp_rx_epoch;
static __thread uint32_t g_tcp_rx_seq;
static __thread uint8_t g_tcp_tx_valid;
static __thread uint8_t g_tcp_rx_valid;
static __thread uint32_t g_udp_tx_seq;
static __thread uint32_t g_udp_tx_datagram_id;
static __thread uint32_t g_udp_tx_datagram_clock;
static __thread uint32_t g_udp_rx_epoch;
static __thread uint32_t g_udp_rx_seq;
static __thread uint8_t g_udp_tx_valid;
static __thread uint8_t g_udp_rx_valid;

static uint32_t crypto_option_bond_epoch(void)
{
    uint32_t epoch = (uint32_t)atomic_load_explicit(&g_bond_epoch,
                                                    memory_order_acquire);

    if (epoch != 0)
        return epoch;
    if (getrandom(&epoch, sizeof(epoch), GRND_NONBLOCK) != (ssize_t)sizeof(epoch) ||
        epoch == 0) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        epoch = (uint32_t)ts.tv_nsec ^ (uint32_t)ts.tv_sec ^
            ((uint32_t)getpid() * 0x9e3779b9u);
        if (epoch == 0)
            epoch = 1u;
    }
    {
        uint_fast32_t expected = 0;

        if (!atomic_compare_exchange_strong_explicit(&g_bond_epoch, &expected, epoch,
                                                      memory_order_release,
                                                      memory_order_acquire))
            epoch = (uint32_t)expected;
    }
    return epoch;
}

void crypto_option_tcp_set_tx_seq(uint32_t seq)
{
    g_tcp_tx_seq = seq;
    g_tcp_tx_valid = 1u;
}

int crypto_option_tcp_tx_meta(uint32_t *epoch, uint32_t *seq)
{
    if (!epoch || !seq || !g_tcp_tx_valid)
        return -1;
    *epoch = crypto_option_bond_epoch();
    *seq = g_tcp_tx_seq;
    return 0;
}

void crypto_option_tcp_clear_rx_meta(void)
{
    g_tcp_rx_valid = 0u;
}

void crypto_option_tcp_set_rx_meta(uint32_t epoch, uint32_t seq)
{
    g_tcp_rx_epoch = epoch;
    g_tcp_rx_seq = seq;
    g_tcp_rx_valid = 1u;
}

int crypto_option_tcp_take_rx_meta(uint32_t *epoch, uint32_t *seq)
{
    if (!epoch || !seq || !g_tcp_rx_valid)
        return -1;
    *epoch = g_tcp_rx_epoch;
    *seq = g_tcp_rx_seq;
    g_tcp_rx_valid = 0u;
    return 0;
}

void crypto_option_udp_set_tx_seq(uint32_t seq)
{
    g_udp_tx_seq = seq;
    g_udp_tx_datagram_id = g_udp_tx_datagram_clock++;
    g_udp_tx_valid = 1u;
}

int crypto_option_udp_tx_meta(uint32_t *epoch, uint32_t *seq,
                              uint32_t *datagram_id)
{
    if (!epoch || !seq || !datagram_id || !g_udp_tx_valid)
        return -1;
    *epoch = crypto_option_bond_epoch();
    *seq = g_udp_tx_seq;
    *datagram_id = g_udp_tx_datagram_id;
    return 0;
}

void crypto_option_udp_clear_rx_meta(void)
{
    g_udp_rx_valid = 0u;
}

void crypto_option_udp_set_rx_meta(uint32_t epoch, uint32_t seq)
{
    g_udp_rx_epoch = epoch;
    g_udp_rx_seq = seq;
    g_udp_rx_valid = 1u;
}

int crypto_option_udp_take_rx_meta(uint32_t *epoch, uint32_t *seq)
{
    if (!epoch || !seq || !g_udp_rx_valid)
        return -1;
    *epoch = g_udp_rx_epoch;
    *seq = g_udp_rx_seq;
    g_udp_rx_valid = 0u;
    return 0;
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
        /* TCP bonding adds a clear marker and authenticated epoch/sequence. */
        return 42u;
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

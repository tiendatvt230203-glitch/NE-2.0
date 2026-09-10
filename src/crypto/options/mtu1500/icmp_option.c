#include "../../pqc/include/pqc_l2_mtu1500_icmp.h"

extern const struct crypto_option_ops *crypto_opt_l2_pqc_tcp_ops(void);

static int mtu1500_icmp_encrypt(struct packet_crypto_ctx *ctx,
                                uint8_t *pkt, uint32_t *pkt_len)
{
    const struct crypto_option_ops *plain = crypto_opt_l2_pqc_tcp_ops();

    return plain && plain->encrypt ? plain->encrypt(ctx, pkt, pkt_len) : -1;
}

static int mtu1500_icmp_decrypt(struct packet_crypto_ctx *ctx,
                                uint8_t *pkt, uint32_t *pkt_len)
{
    const struct crypto_option_ops *plain = crypto_opt_l2_pqc_tcp_ops();

    return plain && plain->decrypt ? plain->decrypt(ctx, pkt, pkt_len) : -1;
}

const struct crypto_option_ops *crypto_opt_l2_pqc_icmp_1500_ops(void)
{
    static const struct crypto_option_ops ops = {
        .need_split = pqc_l2_mtu1500_icmp_need_split,
        .split = pqc_l2_mtu1500_icmp_split,
        .encrypt = mtu1500_icmp_encrypt,
        .decrypt = mtu1500_icmp_decrypt,
        .is_fragment = pqc_l2_mtu1500_icmp_is_fragment,
        .reasm = pqc_l2_mtu1500_icmp_reassemble,
        .frag_gc = pqc_l2_mtu1500_icmp_frag_gc,
    };

    return &ops;
}

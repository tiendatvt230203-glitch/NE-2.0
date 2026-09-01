#include "../../../inc/crypto/pqc_l2_internal.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../options/common/opt_no_frag_ops.h"

static int ospf_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                        uint32_t *pkt_len)
{
    int n;

    if (PQC_L2_UNLIKELY(!ctx || !ctx->initialized || !pkt ||
                        !pkt_len || *pkt_len < PQC_L2_MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    n = pqc_l2_encrypt_ipv4_generic(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int ospf_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                        uint32_t *pkt_len)
{
    int n;

    if (PQC_L2_UNLIKELY(!ctx || !ctx->initialized || !pkt || !pkt_len))
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, *pkt_len))
        return 0;
    n = pqc_l2_decrypt_ipv4_generic(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

CRYPTO_OPS_PLAIN(crypto_opt_l2_pqc_ospf_ops, ospf_encrypt, ospf_decrypt)

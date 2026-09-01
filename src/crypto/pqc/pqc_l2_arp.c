#include "../../../inc/crypto/pqc_l2_internal.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../options/common/opt_no_frag_ops.h"

#include <string.h>

#define ARP_IPV4_PAYLOAD 28
#define ARP_WIRE_HDR_LEN (PQC_L2_POLICY_LEN + PQC_L2_CORE_ID_LEN + \
                          PQC_L2_NONCE_SIZE)

static int encrypt_wire(struct packet_crypto_ctx *ctx, uint8_t *packet,
                        size_t pkt_len)
{
    int arp_off = crypto_eth_arp_offset(packet, pkt_len);
    int et_off;
    int enc_start;
    int new_len = 0;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];

    if (arp_off < 0 || pkt_len < (size_t)arp_off + ARP_IPV4_PAYLOAD)
        return -1;
    et_off = arp_off - 2;
    enc_start = et_off + 2 + ARP_WIRE_HDR_LEN;
    memmove(packet + enc_start, packet + arp_off, ARP_IPV4_PAYLOAD);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0 ||
        crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    pqc_l2_write_wire_header_et(packet, et_off, NE_L2_FAKE_ETHERTYPE_ARP,
                                ctx->wire_id, nonce, PQC_L2_NONCE_SIZE);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_start,
                                   ARP_IPV4_PAYLOAD, &new_len) != 0)
        return -1;
    return enc_start + new_len;
}

static int decrypt_wire(struct packet_crypto_ctx *ctx, uint8_t *packet,
                        size_t pkt_len)
{
    crypto_pqc_sess_t pqc;
    int et_off = crypto_eth_inner_et_off(packet, pkt_len);
    int enc_start;
    int arp_off;
    int dec_len = 0;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];

    if (et_off < 0)
        return -1;
    enc_start = et_off + 2 + ARP_WIRE_HDR_LEN;
    if (pkt_len < (size_t)enc_start)
        return -1;
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    memcpy(nonce, packet + et_off + 2 + PQC_L2_POLICY_LEN +
           PQC_L2_CORE_ID_LEN, PQC_L2_NONCE_SIZE);
    if (crypto_pqc_decrypt_payload_resilient(
            ctx, nonce, packet + enc_start,
            (int)(pkt_len - (size_t)enc_start), &dec_len) != 0 ||
        dec_len < ARP_IPV4_PAYLOAD)
        return -1;
    arp_off = et_off + 2;
    crypto_eth_set_arp_et(packet, et_off);
    memmove(packet + arp_off, packet + enc_start, (size_t)dec_len);
    return arp_off + dec_len;
}

static int arp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                       uint32_t *pkt_len)
{
    int n;

    if (PQC_L2_UNLIKELY(!ctx || !ctx->initialized || !pkt || !pkt_len ||
                        *pkt_len < PQC_L2_MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_arp(pkt, *pkt_len))
        return 0;
    n = encrypt_wire(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int arp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                       uint32_t *pkt_len)
{
    int n;

    if (PQC_L2_UNLIKELY(!ctx || !ctx->initialized || !pkt || !pkt_len))
        return -1;
    if (!crypto_eth_l2_has_arp_marker(pkt, *pkt_len))
        return 0;
    n = decrypt_wire(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

CRYPTO_OPS_PLAIN(crypto_opt_l2_pqc_arp_ops, arp_encrypt, arp_decrypt)

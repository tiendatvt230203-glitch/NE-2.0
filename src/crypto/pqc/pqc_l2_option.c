#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../options/common/opt_no_frag_ops.h"

#include <string.h>

#define MIN_ETH_PKT        (ETH_HEADER_SIZE + 8)
#define unlikely(x)        __builtin_expect(!!(x), 0)
#define OPT_FAKE_ETHERTYPE 0x104Au
#define L2_POLICY_LEN      1
#define L2_CORE_ID_LEN     1
#define L2_NONCE_SIZE      CRYPTO_PQC_NONCE_BYTES

static int l2_policy_off(const uint8_t *packet, size_t pkt_len)
{
    return crypto_eth_l2_policy_off(packet, pkt_len);
}

static int l2_core_id_off(const uint8_t *packet, size_t pkt_len)
{
    int off = l2_policy_off(packet, pkt_len);
    return off < 0 ? -1 : off + L2_POLICY_LEN;
}

static int l2_nonce_off(const uint8_t *packet, size_t pkt_len)
{
    int off = l2_core_id_off(packet, pkt_len);
    return off < 0 ? -1 : off + L2_CORE_ID_LEN;
}

static int l2_enc_start_off(const uint8_t *packet, size_t pkt_len)
{
    int off = l2_nonce_off(packet, pkt_len);
    if (off < 0 || pkt_len < (size_t)(off + L2_NONCE_SIZE))
        return -1;
    return off + L2_NONCE_SIZE;
}

static void l2_write_wire_header_et(uint8_t *packet, int et_off, uint16_t fake,
                                    uint8_t policy_id, const uint8_t *nonce)
{
    packet[et_off] = (uint8_t)(fake >> 8);
    packet[et_off + 1] = (uint8_t)(fake & 0xff);
    packet[et_off + 2] = policy_id;
    packet[et_off + 3] = crypto_option_worker_idx();
    memcpy(packet + et_off + 4, nonce, L2_NONCE_SIZE);
}

static void l2_write_wire_header(uint8_t *packet, int et_off,
                                 uint8_t policy_id, const uint8_t *nonce)
{
    l2_write_wire_header_et(packet, et_off, OPT_FAKE_ETHERTYPE,
                            policy_id, nonce);
}

static int l2_restore_plain_packet(uint8_t *packet, size_t pkt_len,
                                   const uint8_t *payload, size_t payload_len)
{
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    int l3_off;

    if (et_off < 0)
        return -1;
    l3_off = et_off + 2;
    if (payload_len >= 2 && payload[0] == 0x08 && payload[1] == 0x00) {
        crypto_eth_set_ipv4_et(packet, et_off);
        memmove(packet + l3_off, payload + 2, payload_len - 2);
        return l3_off + (int)payload_len - 2;
    }
    crypto_eth_set_ipv4_et(packet, et_off);
    memmove(packet + l3_off, payload, payload_len);
    return l3_off + (int)payload_len;
}

static int l2_do_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                         size_t pkt_len, int l3_off)
{
    uint8_t nonce[CRYPTO_PQC_NONCE_BYTES];
    size_t payload_len;
    int et_off;
    int enc_start;
    int new_len = 0;

    if (l3_off < 2)
        return -1;
    et_off = l3_off - 2;
    payload_len = pkt_len - (size_t)l3_off;
    enc_start = et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE;
    if (pkt_len < (size_t)enc_start)
        return -1;
    memmove(packet + enc_start, packet + l3_off, payload_len);
    if (packet_crypto_generate_nonce(nonce) != 0)
        return -1;
    l2_write_wire_header(packet, et_off, ctx->wire_id, nonce);
    if (packet_crypto_encrypt(ctx, nonce, packet + enc_start,
                              (int)payload_len, &new_len) != 0)
        return -1;
    return enc_start + new_len;
}

static int l2_do_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                         size_t pkt_len)
{
    uint8_t nonce[CRYPTO_PQC_NONCE_BYTES];
    int nonce_off = l2_nonce_off(packet, pkt_len);
    int enc_start = l2_enc_start_off(packet, pkt_len);
    int dec_len = 0;

    if (nonce_off < 0 || enc_start < 0)
        return -1;
    memcpy(nonce, packet + nonce_off, L2_NONCE_SIZE);
    if (packet_crypto_decrypt(ctx, nonce, packet + enc_start,
                              (int)(pkt_len - (size_t)enc_start),
                              &dec_len) != 0)
        return -1;
    return l2_restore_plain_packet(packet, pkt_len, packet + enc_start,
                                   (size_t)dec_len);
}

#define ARP_ETH_IPV4_PAYLOAD 28
#define ARP_WIRE_HDR_LEN \
    (L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE)

static int l2_do_encrypt_arp(struct packet_crypto_ctx *ctx, uint8_t *packet,
                             size_t pkt_len)
{
    uint8_t nonce[CRYPTO_PQC_NONCE_BYTES];
    int arp_off = crypto_eth_arp_offset(packet, pkt_len);
    int et_off;
    int enc_start;
    int new_len = 0;

    if (arp_off < 0 || pkt_len < (size_t)arp_off + ARP_ETH_IPV4_PAYLOAD)
        return -1;
    et_off = arp_off - 2;
    enc_start = et_off + 2 + ARP_WIRE_HDR_LEN;
    memmove(packet + enc_start, packet + arp_off, ARP_ETH_IPV4_PAYLOAD);
    if (packet_crypto_generate_nonce(nonce) != 0)
        return -1;
    l2_write_wire_header_et(packet, et_off, NE_L2_FAKE_ETHERTYPE_ARP,
                            ctx->wire_id, nonce);
    if (packet_crypto_encrypt(ctx, nonce, packet + enc_start,
                              ARP_ETH_IPV4_PAYLOAD, &new_len) != 0)
        return -1;
    return enc_start + new_len;
}

static int l2_do_decrypt_arp(struct packet_crypto_ctx *ctx, uint8_t *packet,
                             size_t pkt_len)
{
    uint8_t nonce[CRYPTO_PQC_NONCE_BYTES];
    int et_off = crypto_eth_inner_et_off(packet, pkt_len);
    int enc_start;
    int arp_off;
    int dec_len = 0;

    if (et_off < 0)
        return -1;
    enc_start = et_off + 2 + ARP_WIRE_HDR_LEN;
    if (pkt_len < (size_t)enc_start)
        return -1;
    memcpy(nonce, packet + et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN,
           L2_NONCE_SIZE);
    if (packet_crypto_decrypt(ctx, nonce, packet + enc_start,
                              (int)(pkt_len - (size_t)enc_start),
                              &dec_len) != 0 || dec_len < ARP_ETH_IPV4_PAYLOAD)
        return -1;
    arp_off = et_off + 2;
    crypto_eth_set_arp_et(packet, et_off);
    memmove(packet + arp_off, packet + enc_start, (size_t)dec_len);
    return arp_off + dec_len;
}

static int l2_ip_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                         uint32_t *pkt_len)
{
    int l3_off;
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || !pkt_len ||
                 *pkt_len < MIN_ETH_PKT))
        return -1;
    l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
    if (l3_off < 0)
        return 0;
    n = l2_do_encrypt(ctx, pkt, *pkt_len, l3_off);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

int crypto_l2_pqc_encrypt_ipv4_l3(struct packet_crypto_ctx *ctx,
                                  uint8_t *pkt, uint32_t *pkt_len,
                                  int l3_off)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || !pkt_len ||
                 *pkt_len < MIN_ETH_PKT || l3_off < 0 ||
                 (uint32_t)l3_off > *pkt_len))
        return -1;
    n = l2_do_encrypt(ctx, pkt, *pkt_len, l3_off);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int l2_ip_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                         uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || !pkt_len))
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, *pkt_len))
        return 0;
    n = l2_do_decrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int l2_arp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                          uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || !pkt_len ||
                 *pkt_len < MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_arp(pkt, *pkt_len))
        return 0;
    n = l2_do_encrypt_arp(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int l2_arp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                          uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || !pkt_len))
        return -1;
    if (!crypto_eth_l2_has_arp_marker(pkt, *pkt_len))
        return 0;
    n = l2_do_decrypt_arp(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

CRYPTO_OPS_PLAIN(crypto_opt_l2_pqc_tcp_ops, l2_ip_encrypt, l2_ip_decrypt)
CRYPTO_OPS_PLAIN(crypto_opt_l2_pqc_ospf_ops, l2_ip_encrypt, l2_ip_decrypt)
CRYPTO_OPS_PLAIN(crypto_opt_l2_pqc_arp_ops, l2_arp_encrypt, l2_arp_decrypt)

#include "../../../inc/crypto/pqc_l2_internal.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../options/common/opt_no_frag_ops.h"

#include <string.h>

#define TCP_MARKER_SIZE 4u
#define TCP_SHIM_SIZE   8u

static const uint8_t tcp_marker[TCP_MARKER_SIZE] = {
    0x5Bu, 0x54u, 0x43u, 0x01u
};

static int marker_match(const uint8_t *packet, size_t pkt_len, int off)
{
    return packet && off >= 0 &&
        pkt_len >= (size_t)off + TCP_MARKER_SIZE &&
        memcmp(packet + off, tcp_marker, TCP_MARKER_SIZE) == 0;
}

static void write_shim(uint8_t *buf, uint32_t epoch, uint32_t seq)
{
    buf[0] = (uint8_t)(epoch >> 24);
    buf[1] = (uint8_t)(epoch >> 16);
    buf[2] = (uint8_t)(epoch >> 8);
    buf[3] = (uint8_t)epoch;
    buf[4] = (uint8_t)(seq >> 24);
    buf[5] = (uint8_t)(seq >> 16);
    buf[6] = (uint8_t)(seq >> 8);
    buf[7] = (uint8_t)seq;
}

static void read_shim(const uint8_t *buf, uint32_t *epoch, uint32_t *seq)
{
    *epoch = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
        ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    *seq = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
        ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
}

static int encrypt_wire(struct packet_crypto_ctx *ctx, uint8_t *packet,
                        size_t pkt_len)
{
    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    int marker_off;
    int enc_start;
    int new_len = 0;
    size_t payload_len;
    size_t plain_len;
    uint32_t epoch;
    uint32_t seq;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];

    if (l3_off < 0 || et_off < 0 ||
        crypto_option_tcp_tx_meta(&epoch, &seq) != 0)
        return -1;
    payload_len = pkt_len - (size_t)l3_off;
    marker_off = et_off + 2 + PQC_L2_POLICY_LEN + PQC_L2_CORE_ID_LEN +
        PQC_L2_NONCE_SIZE;
    enc_start = marker_off + (int)TCP_MARKER_SIZE;
    plain_len = TCP_SHIM_SIZE + payload_len;
    if ((size_t)enc_start + plain_len + AES_GCM_TAG_SIZE > NE_PACKET_CAPACITY)
        return -1;
    memmove(packet + enc_start + TCP_SHIM_SIZE, packet + l3_off, payload_len);
    write_shim(packet + enc_start, epoch, seq);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0 ||
        crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    pqc_l2_write_wire_header(packet, et_off, ctx->wire_id, nonce,
                             PQC_L2_NONCE_SIZE);
    memcpy(packet + marker_off, tcp_marker, TCP_MARKER_SIZE);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_start,
                                   (int)plain_len, &new_len) != 0)
        return -1;
    return enc_start + new_len;
}

static int decrypt_wire(struct packet_crypto_ctx *ctx, uint8_t *packet,
                        size_t pkt_len, uint32_t *epoch, uint32_t *seq)
{
    crypto_pqc_sess_t pqc;
    int marker_off = pqc_l2_marker_off(packet, pkt_len);
    int nonce_off = pqc_l2_nonce_off(packet, pkt_len);
    int enc_start;
    int l3_off;
    int dec_len = 0;
    size_t payload_len;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];

    if (!ctx || !epoch || !seq || nonce_off < 0 ||
        !marker_match(packet, pkt_len, marker_off))
        return -1;
    enc_start = marker_off + (int)TCP_MARKER_SIZE;
    if (pkt_len < (size_t)enc_start + TCP_SHIM_SIZE + AES_GCM_TAG_SIZE)
        return -1;
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    memcpy(nonce, packet + nonce_off, PQC_L2_NONCE_SIZE);
    if (crypto_pqc_decrypt_payload_resilient(
            ctx, nonce, packet + enc_start,
            (int)(pkt_len - (size_t)enc_start), &dec_len) != 0 ||
        dec_len < (int)TCP_SHIM_SIZE)
        return -1;
    read_shim(packet + enc_start, epoch, seq);
    payload_len = (size_t)dec_len - TCP_SHIM_SIZE;
    l3_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    if (l3_off < 0)
        return -1;
    l3_off += 2;
    memmove(packet + l3_off, packet + enc_start + TCP_SHIM_SIZE, payload_len);
    crypto_eth_set_ipv4_et(packet, l3_off - 2);
    return l3_off + (int)payload_len;
}

static int tcp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                       uint32_t *pkt_len)
{
    int n;

    if (PQC_L2_UNLIKELY(!ctx || !ctx->initialized || !pkt || !pkt_len ||
                        *pkt_len < PQC_L2_MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    n = encrypt_wire(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int tcp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                       uint32_t *pkt_len)
{
    uint32_t epoch;
    uint32_t seq;
    int marker_off;
    int n;

    if (PQC_L2_UNLIKELY(!ctx || !ctx->initialized || !pkt || !pkt_len))
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, *pkt_len))
        return 0;
    marker_off = pqc_l2_marker_off(pkt, *pkt_len);
    if (marker_match(pkt, *pkt_len, marker_off)) {
        n = decrypt_wire(ctx, pkt, *pkt_len, &epoch, &seq);
        if (n >= 0)
            crypto_option_tcp_set_rx_meta(epoch, seq);
    } else {
        n = pqc_l2_decrypt_ipv4_generic(ctx, pkt, *pkt_len);
    }
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

CRYPTO_OPS_PLAIN(crypto_opt_l2_pqc_tcp_ops, tcp_encrypt, tcp_decrypt)

#include "../../../inc/crypto/pqc_l2_internal.h"
#include "../../../inc/crypto/eth_parse.h"

#include <string.h>

int pqc_l2_policy_match(const struct app_config *cfg, int action,
                        uint8_t wire_id)
{
    if (!cfg)
        return 0;
    for (int i = 0; i < cfg->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
        const struct crypto_policy *cp = &cfg->policies[i];

        if (cp->action == action && (uint8_t)cp->id == wire_id)
            return 1;
    }
    return 0;
}

int pqc_l2_policy_off(const uint8_t *packet, size_t pkt_len)
{
    return crypto_eth_l2_policy_off(packet, pkt_len);
}

int pqc_l2_core_id_off(const uint8_t *packet, size_t pkt_len)
{
    int off = pqc_l2_policy_off(packet, pkt_len);

    return off < 0 ? -1 : off + PQC_L2_POLICY_LEN;
}

int pqc_l2_nonce_off(const uint8_t *packet, size_t pkt_len)
{
    int off = pqc_l2_core_id_off(packet, pkt_len);

    return off < 0 ? -1 : off + PQC_L2_CORE_ID_LEN;
}

int pqc_l2_enc_start_off(const uint8_t *packet, size_t pkt_len)
{
    int off = pqc_l2_nonce_off(packet, pkt_len);

    if (off < 0 || pkt_len < (size_t)(off + PQC_L2_NONCE_SIZE))
        return -1;
    return off + PQC_L2_NONCE_SIZE;
}

int pqc_l2_marker_off(const uint8_t *packet, size_t pkt_len)
{
    return pqc_l2_enc_start_off(packet, pkt_len);
}

int pqc_l2_wire_prefix_len(const uint8_t *packet, size_t pkt_len)
{
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);

    return et_off < 0 ? -1 : et_off + 2;
}

void pqc_l2_write_wire_header_et(uint8_t *packet, int et_off, uint16_t fake,
                                 uint8_t policy_id, const uint8_t *nonce,
                                 int nonce_size)
{
    packet[et_off] = (uint8_t)(fake >> 8);
    packet[et_off + 1] = (uint8_t)fake;
    packet[et_off + 2] = policy_id;
    packet[et_off + 3] = crypto_option_worker_idx();
    memcpy(packet + et_off + 4, nonce, (size_t)nonce_size);
}

void pqc_l2_write_wire_header(uint8_t *packet, int et_off, uint8_t policy_id,
                              const uint8_t *nonce, int nonce_size)
{
    pqc_l2_write_wire_header_et(packet, et_off, PQC_L2_FAKE_ETHERTYPE,
                                policy_id, nonce, nonce_size);
}

static int restore_plain_ipv4(uint8_t *packet, size_t pkt_len,
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

int pqc_l2_encrypt_ipv4_generic(struct packet_crypto_ctx *ctx,
                                uint8_t *packet, size_t pkt_len)
{
    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    int enc_start;
    int new_len = 0;
    size_t payload_len;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];

    if (l3_off < 0 || et_off < 0)
        return -1;
    payload_len = pkt_len - (size_t)l3_off;
    enc_start = et_off + 2 + PQC_L2_POLICY_LEN + PQC_L2_CORE_ID_LEN +
        PQC_L2_NONCE_SIZE;
    if ((size_t)enc_start + payload_len + AES_GCM_TAG_SIZE > NE_PACKET_CAPACITY)
        return -1;
    memmove(packet + enc_start, packet + l3_off, payload_len);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0 ||
        crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    pqc_l2_write_wire_header(packet, et_off, ctx->wire_id, nonce,
                             PQC_L2_NONCE_SIZE);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_start,
                                   (int)payload_len, &new_len) != 0)
        return -1;
    return enc_start + new_len;
}

int pqc_l2_decrypt_ipv4_generic(struct packet_crypto_ctx *ctx,
                                uint8_t *packet, size_t pkt_len)
{
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int enc_start = pqc_l2_enc_start_off(packet, pkt_len);
    int nonce_off = pqc_l2_nonce_off(packet, pkt_len);
    int dec_len = 0;

    if (enc_start < 0 || nonce_off < 0 ||
        crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    memcpy(nonce, packet + nonce_off, PQC_L2_NONCE_SIZE);
    if (crypto_pqc_decrypt_payload_resilient(
            ctx, nonce, packet + enc_start,
            (int)(pkt_len - (size_t)enc_start), &dec_len) != 0)
        return -1;
    return restore_plain_ipv4(packet, pkt_len, packet + enc_start,
                              (size_t)dec_len);
}

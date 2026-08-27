#define _POSIX_C_SOURCE 199309L

#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/util/cpu_map.h"
#include "crypto_pqc_layer.h"
#include "../../options/common/opt_no_frag_ops.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MIN_ETH_PKT             (ETH_HEADER_SIZE + 8)
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

/* ===================== L2 PQC ===================== */

/* wire — local to this option */
#define OPT_FAKE_ETHERTYPE  0x104Au
#define OPT_AES_BITS        256
#define OPT_NONCE_SIZE      PACKET_CRYPTO_NONCE_BYTES

struct opt_entry {
    uint16_t pkt_id;
    uint8_t  first[1600];
    uint32_t first_len;
    uint8_t  second[1600];
    uint32_t second_len;
    uint8_t  eth_hdr[ETH_L2_HDR_MAX];
    uint8_t  eth_len;
    uint64_t timestamp_ns;
    uint8_t  got_first;
    uint8_t  got_second;
};

struct opt_table {
    struct opt_entry entries[OPT_FRAG_TABLE_SIZE];
};

static struct opt_table *g_tables[MAX_PROFILES][NE_CRYPTO_WORKERS];

void crypto_l2_pqc_bind_pair(struct ne_pair *p)
{
    (void)p;
}

void crypto_l2_pqc_reasm_set_addr(uint64_t addr)
{
    (void)addr;
}

int crypto_l2_pqc_reasm_held(void)
{
    /* Copy-based frag0: never hold UMEM frames. */
    return 0;
}

uint64_t crypto_l2_pqc_reasm_out_addr(void)
{
    return 0;
}

static void opt_clear_entry(struct opt_entry *entry)
{
    memset(entry, 0, sizeof(*entry));
}

static uint64_t opt_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void opt_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index)
{
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

static void opt_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index)
{
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

static void opt_prepare_entry(struct opt_entry *entry, uint16_t pkt_id, uint64_t now)
{
    if (entry->pkt_id != pkt_id ||
        ((entry->got_first || entry->got_second) &&
         (now - entry->timestamp_ns) > OPT_FRAG_TIMEOUT_NS))
        opt_clear_entry(entry);
    entry->pkt_id = pkt_id;
    entry->timestamp_ns = now;
}

static int opt_pick_slot(struct opt_table *ft, uint16_t pkt_id, uint64_t now)
{
    const int probe = 8;
    int base = (int)(pkt_id % OPT_FRAG_TABLE_SIZE);
    int empty_idx = -1;
    int oldest_idx = -1;
    uint64_t oldest_age = 0;

    for (int i = 0; i < probe; i++) {
        int idx = (base + i) % OPT_FRAG_TABLE_SIZE;
        struct opt_entry *e = &ft->entries[idx];
        int occupied = (e->got_first || e->got_second);

        if (occupied && (now - e->timestamp_ns) > OPT_FRAG_TIMEOUT_NS) {
            opt_clear_entry(e);
            occupied = 0;
        }
        if (!occupied) {
            if (empty_idx < 0)
                empty_idx = idx;
            continue;
        }
        if (e->pkt_id == pkt_id)
            return idx;

        {
            uint64_t age = now - e->timestamp_ns;
            if (oldest_idx < 0 || age > oldest_age) {
                oldest_idx = idx;
                oldest_age = age;
            }
        }
    }
    if (empty_idx >= 0)
        return empty_idx;
    if (oldest_idx >= 0)
        return oldest_idx;
    return base;
}

static int opt_store_first(struct opt_entry *entry, uint16_t pkt_id,
                           const uint8_t *eth, uint8_t eth_len,
                           const uint8_t *data, uint32_t data_len, uint64_t now)
{
    if (data_len > sizeof(entry->first))
        return -1;
    if (eth_len == 0 || eth_len > sizeof(entry->eth_hdr))
        return -1;
    opt_prepare_entry(entry, pkt_id, now);
    entry->first_len = data_len;
    memcpy(entry->first, data, data_len);
    memcpy(entry->eth_hdr, eth, eth_len);
    entry->eth_len = eth_len;
    entry->got_first = 1;
    return 0;
}

static int opt_store_second(struct opt_entry *entry, uint16_t pkt_id,
                            const uint8_t *data, uint32_t data_len, uint64_t now)
{
    if (data_len > sizeof(entry->second))
        return -1;
    opt_prepare_entry(entry, pkt_id, now);
    entry->second_len = data_len;
    memcpy(entry->second, data, data_len);
    entry->got_second = 1;
    return 0;
}

static int opt_emit_join(struct opt_entry *entry, uint8_t *out_buf, uint32_t *out_len)
{
    int eth_len;
    int off = 0;

    if (!entry->got_first || !entry->got_second)
        return 0;
    eth_len = entry->eth_len ? (int)entry->eth_len : (int)ETH_HEADER_SIZE;
    if (entry->first_len + entry->second_len + (uint32_t)eth_len > NE_FRAME) {
        opt_clear_entry(entry);
        return -1;
    }
    memcpy(out_buf, entry->eth_hdr, (size_t)eth_len);
    off += eth_len;
    memcpy(out_buf + off, entry->first, entry->first_len);
    off += (int)entry->first_len;
    if (entry->second_len > 0) {
        memcpy(out_buf + off, entry->second, entry->second_len);
        off += (int)entry->second_len;
    }
    *out_len = (uint32_t)off;
    if (eth_len >= 2)
        crypto_eth_set_ipv4_et(out_buf, eth_len - 2);
    opt_clear_entry(entry);
    return 1;
}

static void opt_frag_gc_table(struct opt_table *ft, uint64_t now_ns)
{
    for (int i = 0; i < OPT_FRAG_TABLE_SIZE; i++) {
        struct opt_entry *e = &ft->entries[i];
        if ((e->got_first || e->got_second) &&
            (now_ns - e->timestamp_ns) > OPT_FRAG_TIMEOUT_NS)
            opt_clear_entry(e);
    }
}

static struct opt_table *opt_table(int profile_slot, int worker_idx)
{
    struct opt_table *t;

    if (profile_slot < 0 || profile_slot >= MAX_PROFILES)
        profile_slot = 0;
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        worker_idx = 0;
    t = g_tables[profile_slot][worker_idx];
    if (!t) {
        t = calloc(1, sizeof(*t));
        if (!t)
            return NULL;
        g_tables[profile_slot][worker_idx] = t;
    }
    return t;
}

static int opt_policy_match(const struct app_config *cfg, int action, int mode,
                            uint8_t wire_id)
{
    if (!cfg)
        return 0;
    for (int i = 0; i < cfg->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
        const struct crypto_policy *cp = &cfg->policies[i];
        if (!cp || cp->action != action)
            continue;
        if (cp->crypto_mode != mode)
            continue;
        if ((uint8_t)cp->id == wire_id)
            return 1;
    }
    return 0;
}

#define L2_POLICY_LEN           1
#define L2_CORE_ID_LEN          1
#define L2_FRAG_TAG_SIZE        4
#define L2_FRAG_MAGIC           0x5B
#define L2_NONCE_SIZE           CRYPTO_PQC_NONCE_BYTES
static int l2_policy_off(const uint8_t *packet, size_t pkt_len)
{
    return crypto_eth_l2_policy_off(packet, pkt_len);
}

static int l2_core_id_off(const uint8_t *packet, size_t pkt_len)
{
    int off = l2_policy_off(packet, pkt_len);
    if (off < 0)
        return -1;
    return off + L2_POLICY_LEN;
}

static int l2_nonce_off(const uint8_t *packet, size_t pkt_len)
{
    int off = l2_core_id_off(packet, pkt_len);
    if (off < 0)
        return -1;
    return off + L2_CORE_ID_LEN;
}

static int l2_enc_start_off(const uint8_t *packet, size_t pkt_len)
{
    int off = l2_nonce_off(packet, pkt_len);
    if (off < 0 || pkt_len < (size_t)(off + L2_NONCE_SIZE))
        return -1;
    return off + L2_NONCE_SIZE;
}

static int l2_frag_magic_off(const uint8_t *packet, size_t pkt_len)
{
    return l2_enc_start_off(packet, pkt_len);
}

static void l2_write_wire_header_et(uint8_t *packet, int et_off, uint16_t fake,
                                    uint8_t policy_id, const uint8_t *nonce, int nonce_size)
{
    packet[et_off] = (uint8_t)(fake >> 8);
    packet[et_off + 1] = (uint8_t)(fake & 0xFF);
    packet[et_off + 2] = policy_id;
    packet[et_off + 3] = crypto_option_worker_idx();
    memcpy(packet + et_off + 4, nonce, (size_t)nonce_size);
}

static void l2_write_wire_header(uint8_t *packet, int et_off, uint8_t policy_id,
                                 const uint8_t *nonce, int nonce_size)
{
    l2_write_wire_header_et(packet, et_off, OPT_FAKE_ETHERTYPE, policy_id, nonce, nonce_size);
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

static int l2_wire_prefix_len(const uint8_t *packet, size_t pkt_len)
{
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    if (et_off < 0)
        return -1;
    return et_off + 2;
}

#define OPT_FRAG_META_LEN       35

static int l2_do_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    size_t payload_len;

    if (l3_off < 0 || et_off < 0)
        return -1;
    payload_len = pkt_len - (size_t)l3_off;

    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    int enc_start = et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE;

    if (pkt_len < (size_t)enc_start)
        return -1;
    memmove(packet + enc_start, packet + l3_off, payload_len);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    l2_write_wire_header(packet, et_off, ctx->wire_id, nonce, L2_NONCE_SIZE);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_start, (int)payload_len, &new_len) != 0)
        return -1;
    return enc_start + new_len;

}

static int l2_do_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{

    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int dec_len = 0;
    int enc_start = l2_enc_start_off(packet, pkt_len);

    if (enc_start < 0)
        return -1;
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    memcpy(nonce, packet + l2_nonce_off(packet, pkt_len), (size_t)L2_NONCE_SIZE);
    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_start,
                                   (int)(pkt_len - (size_t)enc_start), &dec_len) != 0)
        return -1;
    return l2_restore_plain_packet(packet, pkt_len, packet + enc_start, (size_t)dec_len);

}

/*
 * ARP L2 PQC wire (overwrite ethertype only):
 *   [dst][src][0x823E][policy_id:1][core_id:1][nonce:12][ciphertext(ARP 28B)+tag:16]
 * Decrypt: see 0x823E → decrypt → write back 0x0806.
 */
#define ARP_ETH_IPV4_PAYLOAD 28
#define ARP_WIRE_HDR_LEN     (L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE) /* 14 */

static int l2_do_encrypt_arp(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int arp_off = crypto_eth_arp_offset(packet, pkt_len);
    int et_off;
    int enc_start;
    int new_len = 0;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];

    if (arp_off < 0 || pkt_len < (size_t)arp_off + ARP_ETH_IPV4_PAYLOAD)
        return -1;
    et_off = arp_off - 2;
    enc_start = et_off + 2 + ARP_WIRE_HDR_LEN;

    memmove(packet + enc_start, packet + arp_off, ARP_ETH_IPV4_PAYLOAD);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    /* Overwrite 0x0806 → 0x823E + policy_id + core_id + nonce */
    l2_write_wire_header_et(packet, et_off, NE_L2_FAKE_ETHERTYPE_ARP,
                            ctx->wire_id, nonce, L2_NONCE_SIZE);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_start,
                                   ARP_ETH_IPV4_PAYLOAD, &new_len) != 0)
        return -1;
    return enc_start + new_len;
}

static int l2_do_decrypt_arp(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int et_off;
    int enc_start;
    int arp_off;
    int dec_len = 0;

    et_off = crypto_eth_inner_et_off(packet, pkt_len);
    if (et_off < 0)
        return -1;
    enc_start = et_off + 2 + ARP_WIRE_HDR_LEN;
    if (pkt_len < (size_t)enc_start)
        return -1;
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    memcpy(nonce, packet + et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN, (size_t)L2_NONCE_SIZE);
    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_start,
                                   (int)(pkt_len - (size_t)enc_start), &dec_len) != 0)
        return -1;
    if (dec_len < ARP_ETH_IPV4_PAYLOAD)
        return -1;
    /* Restore ethertype 0x0806 and slide ARP body back. */
    arp_off = et_off + 2;
    crypto_eth_set_arp_et(packet, et_off);
    memmove(packet + arp_off, packet + enc_start, (size_t)dec_len);
    return arp_off + dec_len;
}

static int l2_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, int et_off)
{

    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    int enc_off = et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE + 1 + L2_FRAG_TAG_SIZE;
    size_t need = (size_t)enc_off + enc_plain_len + AES_GCM_TAG_SIZE;

    if (need > out_max)
        return -1;
    memcpy(out_buf, eth_hdr, (size_t)et_off);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    memmove(out_buf + enc_off, enc_plain, enc_plain_len);
    l2_write_wire_header(out_buf, et_off, ctx->wire_id, nonce, L2_NONCE_SIZE);
    out_buf[et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE] = L2_FRAG_MAGIC;
    opt_write_frag_tag(out_buf + et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE + 1,
                       pkt_id, frag_index);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, out_buf + enc_off, (int)enc_plain_len, &new_len) != 0)
        return -1;
    *out_len = (uint32_t)(enc_off + new_len);
    return 0;

}

static int l2_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len, int et_off, int l3_off)
{

    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    int enc_off = et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE + 1 + L2_FRAG_TAG_SIZE;
    size_t need = (size_t)enc_off + frag0_plain_len + AES_GCM_TAG_SIZE;

    if (need > out_max)
        return -1;
    memmove(packet + enc_off, packet + l3_off, frag0_plain_len);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    l2_write_wire_header(packet, et_off, ctx->wire_id, nonce, L2_NONCE_SIZE);
    packet[et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE] = L2_FRAG_MAGIC;
    opt_write_frag_tag(packet + et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE + 1,
                       pkt_id, 0);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off, (int)frag0_plain_len, &new_len) != 0)
        return -1;
    *out_len = (uint32_t)(enc_off + new_len);
    return 0;

}

static int l2_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index)
{

    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int dec_len = 0;
    int frag_magic_off = l2_frag_magic_off(packet, pkt_len);
    int enc_off;
    int l3_off;

    if (frag_magic_off < 0 || packet[frag_magic_off] != L2_FRAG_MAGIC)
        return -1;
    enc_off = frag_magic_off + 1 + L2_FRAG_TAG_SIZE;
    if (pkt_len < (size_t)enc_off)
        return -1;
    opt_read_frag_tag(packet + frag_magic_off + 1, out_pkt_id, out_frag_index);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    memcpy(nonce, packet + l2_nonce_off(packet, pkt_len), (size_t)L2_NONCE_SIZE);
    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)(pkt_len - (size_t)enc_off), &dec_len) != 0)
        return -1;
    l3_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    if (l3_off < 0)
        return -1;
    l3_off += 2;
    memmove(packet + l3_off, packet + enc_off, (size_t)dec_len);
    return l3_off + dec_len;

}

static int l2_split(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len,
                    size_t frag0_max, uint32_t *frag0_len,
                    uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    uint32_t frag_mtu = crypto_option_get_mtu();
    int l3_off = crypto_eth_ipv4_offset(pkt_data, pkt_len);
    const uint8_t *eth_hdr;
    const uint8_t *ip_hdr;
    int ip_hdr_len;
    uint8_t ip_proto;
    const uint8_t *ip_payload;
    uint32_t ip_payload_len;
    int transport_hdr_len = -1;
    uint32_t app_off = 0;
    uint32_t app_len;
    uint32_t frag_overhead;
    uint32_t max_plain0;
    uint32_t fixed_plain0;
    uint32_t half1;
    uint32_t half2;
    uint16_t pkt_id;
    uint32_t frag0_plain_len;
    const uint8_t *frag1_plain;

    if (l3_off < 0)
        return -1;
    eth_hdr = pkt_data;
    ip_hdr = pkt_data + l3_off;
    ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
    if ((ip_hdr[0] >> 4) != 4 || ip_hdr_len < 20 ||
        pkt_len < (uint32_t)(l3_off + ip_hdr_len))
        return -1;
    ip_proto = ip_hdr[9];
    ip_payload = pkt_data + l3_off + ip_hdr_len;
    ip_payload_len = pkt_len - (uint32_t)l3_off - (uint32_t)ip_hdr_len;
    if (ip_proto != 17)
        return -1;
    if (ip_payload_len < 8)
        return -1;
    transport_hdr_len = 8;
    app_off = 8;
    app_len = ip_payload_len - 8;
    if (app_len == 0)
        return -1;
    frag_overhead = (uint32_t)l3_off + (uint32_t)OPT_FRAG_META_LEN;
    if (frag_overhead >= frag_mtu)
        return -1;
    max_plain0 = frag_mtu - frag_overhead;
    fixed_plain0 = (uint32_t)ip_hdr_len + app_off;
    if (max_plain0 <= fixed_plain0)
        return -1;
    half1 = max_plain0 - fixed_plain0;
    if (half1 >= app_len)
        half1 = app_len - 1;
    half2 = app_len - half1;
    pkt_id = crypto_option_next_pkt_id();
    if (transport_hdr_len >= 0)
        frag0_plain_len = (uint32_t)ip_hdr_len + (uint32_t)transport_hdr_len + half1;
    else
        frag0_plain_len = (uint32_t)ip_hdr_len + half1;
    frag1_plain = (transport_hdr_len >= 0) ? ip_payload + app_off + half1 : ip_payload + half1;
    if (l2_encrypt_fragment_single(ctx, eth_hdr, frag1_plain, half2, pkt_id, 1,
                                   frag1, frag1_max, frag1_len,
                                   crypto_eth_l2_prefix_len(eth_hdr, ETH_L2_HDR_MAX)) != 0)
        return -1;
    if (l2_encrypt_fragment0_inplace(ctx, pkt_data, pkt_len, frag0_plain_len, pkt_id,
                                     frag0_max, frag0_len,
                                     crypto_eth_l2_prefix_len(pkt_data, pkt_len), l3_off) != 0)
        return -1;
    return 0;
}

static int l2_reassemble(struct opt_table *ft, const uint8_t *pkt_data, uint32_t pkt_len,
                         uint16_t pkt_id, uint8_t frag_index,
                         uint8_t *out_buf, uint32_t *out_len)
{
    int wire_eth = l2_wire_prefix_len(pkt_data, pkt_len);
    const uint8_t *inner;
    uint32_t inner_len;
    uint64_t now;
    int idx;
    struct opt_entry *entry;

    if (wire_eth < 0 || wire_eth > (int)ETH_L2_HDR_MAX)
        return -1;
    if (pkt_len < (uint32_t)wire_eth)
        return -1;
    inner = pkt_data + wire_eth;
    inner_len = pkt_len - (uint32_t)wire_eth;
    now = opt_time_ns();
    idx = opt_pick_slot(ft, pkt_id, now);
    entry = &ft->entries[idx];
    if (frag_index == 0) {
        int ip_hdr_len;
        int joined;

        if (inner_len < 20 || (inner[0] >> 4) != 4)
            return -1;
        ip_hdr_len = (inner[0] & 0x0F) * 4;
        if (ip_hdr_len < 20 || inner_len < (uint32_t)ip_hdr_len)
            return -1;
        if (opt_store_first(entry, pkt_id, pkt_data, (uint8_t)wire_eth, inner, inner_len, now) != 0)
            return -1;
        joined = opt_emit_join(entry, out_buf, out_len);
        if (joined < 0)
            return -1;
        if (joined == 0)
            return 0;
        return 1;
    }
    if (frag_index == 1) {
        int joined;

        if ((entry->got_first || entry->got_second) && entry->pkt_id == pkt_id &&
            (now - entry->timestamp_ns) > OPT_FRAG_TIMEOUT_NS)
            opt_clear_entry(entry);
        if (opt_store_second(entry, pkt_id, inner, inner_len, now) != 0)
            return -1;
        joined = opt_emit_join(entry, out_buf, out_len);
        if (joined < 0)
            return -1;
        if (joined == 0)
            return 0;
        return 1;
    }
    return -1;
}

static int l2_udp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int l3_off;
    int et_off;
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    if (!OPT_FAKE_ETHERTYPE)
        return 0;
    l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
    et_off = crypto_eth_l2_prefix_len(pkt, *pkt_len);
    if (l3_off < 0 || et_off < 0)
        return -1;
    n = l2_do_encrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int l2_udp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt))
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, *pkt_len))
        return 0;
    n = l2_do_decrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}
static int l2_udp_need_split(uint32_t pkt_len)
{
    return (pkt_len + OPT_FRAG_META_LEN) > crypto_option_get_mtu();
}

static int l2_udp_split(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len,
                           size_t frag0_max, uint32_t *frag0_len,
                           uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    return l2_split(ctx, pkt_data, pkt_len, frag0_max, frag0_len, frag1, frag1_max, frag1_len);
}

static int l2_udp_is_fragment(const struct app_config *cfg, const uint8_t *pkt_data,
                                 uint32_t pkt_len, uint16_t *pkt_id, uint8_t *frag_index)
{
    int tag_off;
    uint8_t wire_pol;

    if (!cfg || !pkt_id || !frag_index)
        return 0;
    if (!crypto_eth_l2_has_marker(pkt_data, pkt_len))
        return 0;
    tag_off = l2_frag_magic_off(pkt_data, pkt_len);
    if (tag_off < 0)
        return 0;
    if (pkt_len < (uint32_t)(tag_off + 1 + L2_FRAG_TAG_SIZE))
        return 0;
    if (pkt_data[tag_off] != L2_FRAG_MAGIC)
        return 0;
    if (crypto_eth_l2_read_policy_id(pkt_data, pkt_len, &wire_pol) != 0)
        return 0;
    if (!opt_policy_match(cfg, POLICY_ACTION_ENCRYPT_L2, CRYPTO_MODE_PQC, wire_pol))
        return 0;
    opt_read_frag_tag(pkt_data + tag_off + 1, pkt_id, frag_index);
    if (pkt_data[tag_off + 4] != 0) {
        return 0;
    }
    return (*frag_index <= 1) ? 1 : 0;
}

static int l2_udp_reasm(int profile_slot, int worker_idx, struct packet_crypto_ctx *ctx,
                           uint8_t *pkt_data, uint32_t *pkt_len,
                           uint8_t *out_buf, uint32_t *out_len)
{
    int nd;
    uint16_t opid = 0;
    uint8_t ofidx = 0;
    int rr;

    if (!ctx || !pkt_data || !pkt_len || !out_buf || !out_len)
        return -1;
    nd = l2_decrypt_fragment(ctx, pkt_data, *pkt_len, &opid, &ofidx);
    if (nd < 0)
        return -1;
    *pkt_len = (uint32_t)nd;
    struct opt_table *ft = opt_table(profile_slot, worker_idx);
    if (!ft)
        return -1;
    rr = l2_reassemble(ft, pkt_data, *pkt_len,
                     opid, ofidx, out_buf, out_len);
    if (rr == 1)
        *pkt_len = *out_len;
    return rr;
}

static void l2_udp_frag_gc(int profile_slot, int worker_idx, uint64_t now_ns)
{
    struct opt_table *ft = opt_table(profile_slot, worker_idx);
    if (ft)
        opt_frag_gc_table(ft, now_ns);
}
static int l2_tcp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int l3_off;
    int et_off;
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    if (!OPT_FAKE_ETHERTYPE)
        return 0;
    l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
    et_off = crypto_eth_l2_prefix_len(pkt, *pkt_len);
    if (l3_off < 0 || et_off < 0)
        return -1;
    n = l2_do_encrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int l2_tcp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt))
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, *pkt_len))
        return 0;
    n = l2_do_decrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}
static int l2_icmp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int l3_off;
    int et_off;
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    if (!OPT_FAKE_ETHERTYPE)
        return 0;
    l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
    et_off = crypto_eth_l2_prefix_len(pkt, *pkt_len);
    if (l3_off < 0 || et_off < 0)
        return -1;
    n = l2_do_encrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int l2_icmp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt))
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, *pkt_len))
        return 0;
    n = l2_do_decrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}
static int l2_ospf_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int l3_off;
    int et_off;
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    if (!OPT_FAKE_ETHERTYPE)
        return 0;
    l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
    et_off = crypto_eth_l2_prefix_len(pkt, *pkt_len);
    if (l3_off < 0 || et_off < 0)
        return -1;
    n = l2_do_encrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int l2_ospf_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt))
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, *pkt_len))
        return 0;
    n = l2_do_decrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}
static int l2_arp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_arp(pkt, *pkt_len))
        return 0;
    n = l2_do_encrypt_arp(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int l2_arp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt))
        return -1;
    /* 0x823E = encrypted ARP */
    if (!crypto_eth_l2_has_arp_marker(pkt, *pkt_len))
        return 0;
    n = l2_do_decrypt_arp(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

CRYPTO_OPS_PLAIN(crypto_opt_l2_pqc_tcp_ops, l2_tcp_encrypt, l2_tcp_decrypt)
CRYPTO_OPS_PLAIN(crypto_opt_l2_pqc_icmp_ops, l2_icmp_encrypt, l2_icmp_decrypt)
CRYPTO_OPS_PLAIN(crypto_opt_l2_pqc_ospf_ops, l2_ospf_encrypt, l2_ospf_decrypt)
CRYPTO_OPS_PLAIN(crypto_opt_l2_pqc_arp_ops, l2_arp_encrypt, l2_arp_decrypt)

const struct crypto_option_ops *crypto_opt_l2_pqc_udp_ops(void)
{
    static const struct crypto_option_ops ops = {
        .need_split = l2_udp_need_split,
        .split = l2_udp_split,
        .encrypt = l2_udp_encrypt,
        .decrypt = l2_udp_decrypt,
        .is_fragment = l2_udp_is_fragment,
        .reasm = l2_udp_reasm,
        .frag_gc = l2_udp_frag_gc,
    };
    return &ops;
}
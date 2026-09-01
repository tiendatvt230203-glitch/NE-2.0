#define _POSIX_C_SOURCE 199309L

#include "../../../inc/crypto/pqc_l2_internal.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/pqc_frag_layout.h"
#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/util/cpu_map.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define UDP_MARKER_SIZE 4u
#define UDP_SHIM_VERSION 1u
#define UDP_SHIM_SIZE    13u

enum udp_kind {
    UDP_KIND_FRAG0 = 0,
    UDP_KIND_FRAG1 = 1,
    UDP_KIND_FULL = 2,
};

static const uint8_t udp_marker[UDP_MARKER_SIZE] = {
    0x5Bu, 0x55u, 0x44u, 0x01u
};

struct udp_reasm_entry {
    uint32_t epoch;
    uint32_t datagram_id;
    uint32_t bond_seq;
    uint32_t first_len;
    uint32_t second_len;
    uint64_t timestamp_ns;
    uint8_t eth_hdr[ETH_L2_HDR_MAX];
    uint8_t eth_len;
    uint8_t got_first;
    uint8_t got_second;
    uint8_t first[NE_MAX_MTU];
    uint8_t second[NE_MAX_MTU];
};

struct udp_reasm_table {
    uint32_t gc_cursor;
    struct udp_reasm_entry entries[OPT_FRAG_TABLE_SIZE];
};

static struct udp_reasm_table *g_tables[MAX_PROFILES][NE_CRYPTO_WORKERS];
static struct ne_pair *g_reasm_pair;
static _Thread_local uint64_t g_reasm_input_addr;
static _Thread_local uint64_t g_reasm_output_addr;
static _Thread_local int g_reasm_input_valid;

void crypto_l2_pqc_bind_pair(struct ne_pair *pair)
{
    g_reasm_pair = pair;
}

void crypto_l2_pqc_reasm_set_addr(uint64_t addr)
{
    g_reasm_input_addr = addr;
    g_reasm_output_addr = 0;
    g_reasm_input_valid = 1;
}

int crypto_l2_pqc_reasm_held(void)
{
    return 0;
}

uint64_t crypto_l2_pqc_reasm_out_addr(void)
{
    return g_reasm_output_addr;
}

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void clear_entry(struct udp_reasm_entry *entry)
{
    entry->epoch = 0;
    entry->datagram_id = 0;
    entry->bond_seq = 0;
    entry->first_len = 0;
    entry->second_len = 0;
    entry->timestamp_ns = 0;
    entry->eth_len = 0;
    entry->got_first = 0;
    entry->got_second = 0;
}

static void prepare_entry(struct udp_reasm_entry *entry, uint32_t epoch,
                          uint32_t datagram_id, uint32_t bond_seq,
                          uint64_t now)
{
    if (entry->epoch != epoch || entry->datagram_id != datagram_id ||
        entry->bond_seq != bond_seq ||
        ((entry->got_first || entry->got_second) &&
         now - entry->timestamp_ns > OPT_FRAG_TIMEOUT_NS))
        clear_entry(entry);
    entry->epoch = epoch;
    entry->datagram_id = datagram_id;
    entry->bond_seq = bond_seq;
    entry->timestamp_ns = now;
}

static int pick_slot(struct udp_reasm_table *table, uint32_t epoch,
                     uint32_t datagram_id, uint64_t now)
{
    const int probe = 8;
    uint32_t mixed = datagram_id ^ (epoch * 0x9e3779b9u);
    int base = (int)(mixed % OPT_FRAG_TABLE_SIZE);
    int empty = -1;
    int oldest = -1;
    uint64_t oldest_age = 0;

    for (int i = 0; i < probe; i++) {
        int idx = (base + i) % OPT_FRAG_TABLE_SIZE;
        struct udp_reasm_entry *entry = &table->entries[idx];
        int occupied = entry->got_first || entry->got_second;

        if (occupied && now - entry->timestamp_ns > OPT_FRAG_TIMEOUT_NS) {
            clear_entry(entry);
            occupied = 0;
        }
        if (!occupied) {
            if (empty < 0)
                empty = idx;
            continue;
        }
        if (entry->epoch == epoch && entry->datagram_id == datagram_id)
            return idx;
        if (oldest < 0 || now - entry->timestamp_ns > oldest_age) {
            oldest = idx;
            oldest_age = now - entry->timestamp_ns;
        }
    }
    if (empty >= 0)
        return empty;
    return oldest >= 0 ? oldest : base;
}

static int store_first(struct udp_reasm_entry *entry, uint32_t epoch,
                       uint32_t datagram_id, uint32_t bond_seq,
                       const uint8_t *eth, uint8_t eth_len,
                       const uint8_t *data, uint32_t data_len, uint64_t now)
{
    if (data_len > sizeof(entry->first) || eth_len == 0 ||
        eth_len > sizeof(entry->eth_hdr))
        return -1;
    prepare_entry(entry, epoch, datagram_id, bond_seq, now);
    entry->first_len = data_len;
    memcpy(entry->first, data, data_len);
    memcpy(entry->eth_hdr, eth, eth_len);
    entry->eth_len = eth_len;
    entry->got_first = 1;
    return 0;
}

static int store_second(struct udp_reasm_entry *entry, uint32_t epoch,
                        uint32_t datagram_id, uint32_t bond_seq,
                        const uint8_t *data, uint32_t data_len, uint64_t now)
{
    if (data_len > sizeof(entry->second))
        return -1;
    prepare_entry(entry, epoch, datagram_id, bond_seq, now);
    entry->second_len = data_len;
    memcpy(entry->second, data, data_len);
    entry->got_second = 1;
    return 0;
}

static int emit_join(struct udp_reasm_entry *entry, uint8_t *out_buf,
                     uint32_t *out_len)
{
    uint8_t *joined = out_buf;
    uint32_t joined_len;
    int eth_len;
    int off;

    if (!entry->got_first || !entry->got_second)
        return 0;
    eth_len = entry->eth_len ? entry->eth_len : ETH_HEADER_SIZE;
    joined_len = (uint32_t)eth_len + entry->first_len + entry->second_len;
    if (joined_len > NE_PACKET_CAPACITY) {
        clear_entry(entry);
        return -1;
    }
    if (g_reasm_pair && g_reasm_input_valid &&
        joined_len > ne_packet_capacity(g_reasm_pair, g_reasm_input_addr)) {
        if (ne_packet_alloc(g_reasm_pair, joined_len, &g_reasm_output_addr) != 0) {
            clear_entry(entry);
            return -1;
        }
        joined = ne_packet_data(g_reasm_pair, g_reasm_output_addr);
        if (!joined) {
            ne_frame_free(g_reasm_pair, g_reasm_output_addr);
            g_reasm_output_addr = 0;
            clear_entry(entry);
            return -1;
        }
    }
    memcpy(joined, entry->eth_hdr, (size_t)eth_len);
    off = eth_len;
    memcpy(joined + off, entry->first, entry->first_len);
    off += (int)entry->first_len;
    if (entry->second_len) {
        memcpy(joined + off, entry->second, entry->second_len);
        off += (int)entry->second_len;
    }
    *out_len = (uint32_t)off;
    if (eth_len >= 2)
        crypto_eth_set_ipv4_et(joined, eth_len - 2);
    clear_entry(entry);
    return 1;
}

static struct udp_reasm_table *reasm_table(int profile_slot, int worker_idx,
                                            int create)
{
    struct udp_reasm_table *table;

    if (profile_slot < 0 || profile_slot >= MAX_PROFILES)
        profile_slot = 0;
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        worker_idx = 0;
    table = g_tables[profile_slot][worker_idx];
    if (!table && create) {
        table = calloc(1, sizeof(*table));
        if (!table)
            return NULL;
        g_tables[profile_slot][worker_idx] = table;
    }
    return table;
}

static void gc_table(struct udp_reasm_table *table, uint64_t time_ns)
{
    const uint32_t slice = 256u;
    uint32_t start = table->gc_cursor;

    for (uint32_t n = 0; n < slice; n++) {
        uint32_t idx = (start + n) % OPT_FRAG_TABLE_SIZE;
        struct udp_reasm_entry *entry = &table->entries[idx];

        if ((entry->got_first || entry->got_second) &&
            time_ns - entry->timestamp_ns > OPT_FRAG_TIMEOUT_NS)
            clear_entry(entry);
    }
    table->gc_cursor = (start + slice) % OPT_FRAG_TABLE_SIZE;
}

static void write_shim(uint8_t *buf, uint8_t kind, uint32_t epoch,
                       uint32_t seq, uint32_t datagram_id)
{
    buf[0] = (uint8_t)((UDP_SHIM_VERSION << 4) | (kind & 0x0fu));
    buf[1] = (uint8_t)(epoch >> 24);
    buf[2] = (uint8_t)(epoch >> 16);
    buf[3] = (uint8_t)(epoch >> 8);
    buf[4] = (uint8_t)epoch;
    buf[5] = (uint8_t)(seq >> 24);
    buf[6] = (uint8_t)(seq >> 16);
    buf[7] = (uint8_t)(seq >> 8);
    buf[8] = (uint8_t)seq;
    buf[9] = (uint8_t)(datagram_id >> 24);
    buf[10] = (uint8_t)(datagram_id >> 16);
    buf[11] = (uint8_t)(datagram_id >> 8);
    buf[12] = (uint8_t)datagram_id;
}

static int read_shim(const uint8_t *buf, uint8_t *kind, uint32_t *epoch,
                     uint32_t *seq, uint32_t *datagram_id)
{
    if (!buf || !kind || !epoch || !seq || !datagram_id)
        return -1;
    *kind = buf[0] & 0x0fu;
    if ((buf[0] >> 4) != UDP_SHIM_VERSION || *kind > UDP_KIND_FULL)
        return -1;
    *epoch = ((uint32_t)buf[1] << 24) | ((uint32_t)buf[2] << 16) |
        ((uint32_t)buf[3] << 8) | (uint32_t)buf[4];
    *seq = ((uint32_t)buf[5] << 24) | ((uint32_t)buf[6] << 16) |
        ((uint32_t)buf[7] << 8) | (uint32_t)buf[8];
    *datagram_id = ((uint32_t)buf[9] << 24) | ((uint32_t)buf[10] << 16) |
        ((uint32_t)buf[11] << 8) | (uint32_t)buf[12];
    return 0;
}

static int marker_match(const uint8_t *packet, size_t pkt_len, int off)
{
    return packet && off >= 0 && pkt_len >= (size_t)off + UDP_MARKER_SIZE &&
        memcmp(packet + off, udp_marker, UDP_MARKER_SIZE) == 0;
}

static void marker_write(uint8_t *packet, int off)
{
    memcpy(packet + off, udp_marker, UDP_MARKER_SIZE);
}

static int encrypt_full(struct packet_crypto_ctx *ctx, uint8_t *packet,
                        size_t pkt_len)
{
    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    int marker_off;
    int enc_start;
    int new_len = 0;
    size_t payload_len;
    size_t plain_len;
    uint32_t epoch, seq, datagram_id;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];

    if (l3_off < 0 || et_off < 0 ||
        crypto_option_udp_tx_meta(&epoch, &seq, &datagram_id) != 0)
        return -1;
    payload_len = pkt_len - (size_t)l3_off;
    marker_off = et_off + 2 + PQC_L2_POLICY_LEN + PQC_L2_CORE_ID_LEN +
        PQC_L2_NONCE_SIZE;
    enc_start = marker_off + (int)UDP_MARKER_SIZE;
    plain_len = UDP_SHIM_SIZE + payload_len;
    if ((size_t)enc_start + plain_len + AES_GCM_TAG_SIZE > NE_PACKET_CAPACITY)
        return -1;
    memmove(packet + enc_start + UDP_SHIM_SIZE, packet + l3_off, payload_len);
    write_shim(packet + enc_start, UDP_KIND_FULL, epoch, seq, datagram_id);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0 ||
        crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    pqc_l2_write_wire_header_et(packet, et_off, NE_L2_FAKE_ETHERTYPE_UDP,
                                ctx->wire_id, nonce, PQC_L2_NONCE_SIZE);
    marker_write(packet, marker_off);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_start,
                                   (int)plain_len, &new_len) != 0)
        return -1;
    return enc_start + new_len;
}

static int decrypt_wire(struct packet_crypto_ctx *ctx, uint8_t *packet,
                        size_t pkt_len, uint32_t *epoch, uint32_t *seq,
                        uint32_t *datagram_id, uint8_t *kind)
{
    crypto_pqc_sess_t pqc;
    int marker_off = pqc_l2_marker_off(packet, pkt_len);
    int nonce_off = pqc_l2_nonce_off(packet, pkt_len);
    int enc_start;
    int l3_off;
    int dec_len = 0;
    size_t payload_len;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];

    if (!ctx || !epoch || !seq || !datagram_id || !kind || nonce_off < 0 ||
        !marker_match(packet, pkt_len, marker_off))
        return -1;
    enc_start = marker_off + (int)UDP_MARKER_SIZE;
    if (pkt_len < (size_t)enc_start + UDP_SHIM_SIZE + AES_GCM_TAG_SIZE)
        return -1;
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    memcpy(nonce, packet + nonce_off, PQC_L2_NONCE_SIZE);
    if (crypto_pqc_decrypt_payload_resilient(
            ctx, nonce, packet + enc_start,
            (int)(pkt_len - (size_t)enc_start), &dec_len) != 0 ||
        dec_len < (int)UDP_SHIM_SIZE ||
        read_shim(packet + enc_start, kind, epoch, seq, datagram_id) != 0)
        return -1;
    payload_len = (size_t)dec_len - UDP_SHIM_SIZE;
    l3_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    if (l3_off < 0)
        return -1;
    l3_off += 2;
    memmove(packet + l3_off, packet + enc_start + UDP_SHIM_SIZE, payload_len);
    if (*kind == UDP_KIND_FULL)
        crypto_eth_set_ipv4_et(packet, l3_off - 2);
    return l3_off + (int)payload_len;
}

static int encrypt_fragment1(struct packet_crypto_ctx *ctx,
                             const uint8_t *eth_hdr,
                             const uint8_t *plain, uint32_t plain_len,
                             uint32_t epoch, uint32_t seq,
                             uint32_t datagram_id, uint8_t kind,
                             uint8_t *out, size_t out_max,
                             uint32_t *out_len, int et_off)
{
    int marker_off = et_off + 2 + PQC_L2_POLICY_LEN + PQC_L2_CORE_ID_LEN +
        PQC_L2_NONCE_SIZE;
    int enc_off = marker_off + (int)UDP_MARKER_SIZE;
    size_t enc_plain_len = UDP_SHIM_SIZE + plain_len;
    int new_len = 0;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];

    if ((size_t)enc_off + enc_plain_len + AES_GCM_TAG_SIZE > out_max)
        return -1;
    memcpy(out, eth_hdr, (size_t)et_off);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0 ||
        crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    memmove(out + enc_off + UDP_SHIM_SIZE, plain, plain_len);
    write_shim(out + enc_off, kind, epoch, seq, datagram_id);
    pqc_l2_write_wire_header_et(out, et_off, NE_L2_FAKE_ETHERTYPE_UDP,
                                ctx->wire_id, nonce, PQC_L2_NONCE_SIZE);
    marker_write(out, marker_off);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, out + enc_off,
                                   (int)enc_plain_len, &new_len) != 0)
        return -1;
    *out_len = (uint32_t)(enc_off + new_len);
    return 0;
}

static int encrypt_fragment0(struct packet_crypto_ctx *ctx, uint8_t *packet,
                             uint32_t plain_len, uint32_t epoch, uint32_t seq,
                             uint32_t datagram_id, size_t out_max,
                             uint32_t *out_len, int et_off, int l3_off)
{
    int marker_off = et_off + 2 + PQC_L2_POLICY_LEN + PQC_L2_CORE_ID_LEN +
        PQC_L2_NONCE_SIZE;
    int enc_off = marker_off + (int)UDP_MARKER_SIZE;
    size_t enc_plain_len = UDP_SHIM_SIZE + plain_len;
    int new_len = 0;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];

    if ((size_t)enc_off + enc_plain_len + AES_GCM_TAG_SIZE > out_max)
        return -1;
    memmove(packet + enc_off + UDP_SHIM_SIZE, packet + l3_off, plain_len);
    write_shim(packet + enc_off, UDP_KIND_FRAG0, epoch, seq, datagram_id);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0 ||
        crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    pqc_l2_write_wire_header_et(packet, et_off, NE_L2_FAKE_ETHERTYPE_UDP,
                                ctx->wire_id, nonce, PQC_L2_NONCE_SIZE);
    marker_write(packet, marker_off);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)enc_plain_len, &new_len) != 0)
        return -1;
    *out_len = (uint32_t)(enc_off + new_len);
    return 0;
}

static int udp_split(struct packet_crypto_ctx *ctx, uint8_t *packet,
                     uint32_t pkt_len, size_t frag0_max, uint32_t *frag0_len,
                     uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    uint32_t mtu = crypto_option_get_mtu();
    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    int et_off;
    const uint8_t *ip;
    const uint8_t *payload;
    const uint8_t *frag1_plain;
    int ip_hlen;
    uint32_t payload_len;
    uint32_t app_len;
    uint32_t epoch, seq, datagram_id;
    struct crypto_pqc_udp_frag_layout layout;

    if (l3_off < 0)
        return -1;
    et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    ip = packet + l3_off;
    ip_hlen = (ip[0] & 0x0fu) * 4;
    if (et_off < 0 || (ip[0] >> 4) != 4 || ip_hlen < 20 ||
        pkt_len < (uint32_t)(l3_off + ip_hlen))
        return -1;
    payload = packet + l3_off + ip_hlen;
    payload_len = pkt_len - (uint32_t)l3_off - (uint32_t)ip_hlen;
    if (ip[9] != 17 || payload_len < 8)
        return -1;
    app_len = payload_len - 8;
    if (!app_len || crypto_pqc_udp_fragment_layout(
            mtu, (uint32_t)l3_off, (uint32_t)ip_hlen, app_len, &layout) != 0 ||
        crypto_option_udp_tx_meta(&epoch, &seq, &datagram_id) != 0)
        return -1;
    frag1_plain = payload + 8 + app_len - layout.frag1_payload_len;
    if (encrypt_fragment1(ctx, packet, frag1_plain, layout.frag1_payload_len,
                          epoch, seq, datagram_id, UDP_KIND_FRAG1,
                          frag1, frag1_max, frag1_len, et_off) != 0)
        return -1;
    return encrypt_fragment0(ctx, packet, layout.frag0_plain_len,
                             epoch, seq, datagram_id, frag0_max, frag0_len,
                             et_off, l3_off);
}

static int reassemble(struct udp_reasm_table *table, const uint8_t *packet,
                      uint32_t pkt_len, uint32_t epoch, uint32_t datagram_id,
                      uint32_t bond_seq, uint8_t kind,
                      uint8_t *out, uint32_t *out_len)
{
    int wire_len = pqc_l2_wire_prefix_len(packet, pkt_len);
    const uint8_t *inner;
    uint32_t inner_len;
    uint64_t time_ns;
    struct udp_reasm_entry *entry;
    int idx;

    if (wire_len < 0 || wire_len > ETH_L2_HDR_MAX ||
        pkt_len < (uint32_t)wire_len)
        return -1;
    inner = packet + wire_len;
    inner_len = pkt_len - (uint32_t)wire_len;
    time_ns = now_ns();
    idx = pick_slot(table, epoch, datagram_id, time_ns);
    entry = &table->entries[idx];
    if (kind == UDP_KIND_FRAG0) {
        int ip_hlen;

        if (inner_len < 20 || (inner[0] >> 4) != 4)
            return -1;
        ip_hlen = (inner[0] & 0x0f) * 4;
        if (ip_hlen < 20 || inner_len < (uint32_t)ip_hlen ||
            store_first(entry, epoch, datagram_id, bond_seq, packet,
                        (uint8_t)wire_len, inner, inner_len, time_ns) != 0)
            return -1;
        return emit_join(entry, out, out_len);
    }
    if (kind == UDP_KIND_FRAG1) {
        if ((entry->got_first || entry->got_second) &&
            entry->epoch == epoch && entry->datagram_id == datagram_id &&
            time_ns - entry->timestamp_ns > OPT_FRAG_TIMEOUT_NS)
            clear_entry(entry);
        if (store_second(entry, epoch, datagram_id, bond_seq,
                         inner, inner_len, time_ns) != 0)
            return -1;
        return emit_join(entry, out, out_len);
    }
    return -1;
}

static int udp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                       uint32_t *pkt_len)
{
    int n;

    if (PQC_L2_UNLIKELY(!ctx || !ctx->initialized || !pkt || !pkt_len ||
                        *pkt_len < PQC_L2_MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    n = encrypt_full(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int udp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt,
                       uint32_t *pkt_len)
{
    uint32_t epoch, seq, datagram_id;
    uint8_t kind;
    int n;

    if (PQC_L2_UNLIKELY(!ctx || !ctx->initialized || !pkt || !pkt_len))
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, *pkt_len))
        return 0;
    n = decrypt_wire(ctx, pkt, *pkt_len, &epoch, &seq, &datagram_id, &kind);
    if (n < 0 || kind != UDP_KIND_FULL || !crypto_pkt_is_ipv4(pkt, (size_t)n))
        return -1;
    *pkt_len = (uint32_t)n;
    crypto_option_udp_set_rx_meta(epoch, seq);
    return 0;
}

static int udp_need_split(uint32_t pkt_len)
{
    return crypto_pqc_udp_needs_fragment(pkt_len, crypto_option_get_mtu());
}

static int udp_is_fragment(const struct app_config *cfg, const uint8_t *packet,
                           uint32_t pkt_len, uint16_t *pkt_id,
                           uint8_t *frag_index)
{
    int marker_off;
    uint8_t wire_policy;

    if (!cfg || !pkt_id || !frag_index ||
        !crypto_eth_l2_has_marker(packet, pkt_len))
        return 0;
    marker_off = pqc_l2_marker_off(packet, pkt_len);
    if (marker_off < 0 || pkt_len < (uint32_t)marker_off + UDP_MARKER_SIZE +
        UDP_SHIM_SIZE + AES_GCM_TAG_SIZE ||
        !marker_match(packet, pkt_len, marker_off) ||
        crypto_eth_l2_read_policy_id(packet, pkt_len, &wire_policy) != 0 ||
        !pqc_l2_policy_match(cfg, POLICY_ACTION_ENCRYPT_L2, wire_policy))
        return 0;
    *pkt_id = 0;
    *frag_index = 0;
    return 1;
}

static int udp_reasm(int profile_slot, int worker_idx,
                     struct packet_crypto_ctx *ctx, uint8_t *packet,
                     uint32_t *pkt_len, uint8_t *out, uint32_t *out_len)
{
    uint32_t epoch = 0, seq = 0, datagram_id = 0;
    uint8_t kind = 0;
    struct udp_reasm_table *table;
    int n;
    int rc;

    if (!ctx || !packet || !pkt_len || !out || !out_len)
        return -1;
    n = decrypt_wire(ctx, packet, *pkt_len, &epoch, &seq,
                     &datagram_id, &kind);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    if (kind == UDP_KIND_FULL) {
        if (!crypto_pkt_is_ipv4(packet, *pkt_len))
            return -1;
        if (out != packet)
            memcpy(out, packet, *pkt_len);
        *out_len = *pkt_len;
        crypto_option_udp_set_rx_meta(epoch, seq);
        return 1;
    }
    if (kind > UDP_KIND_FRAG1)
        return -1;
    table = reasm_table(profile_slot, worker_idx, 1);
    if (!table)
        return -1;
    rc = reassemble(table, packet, *pkt_len, epoch, datagram_id, seq,
                    kind, out, out_len);
    if (rc == 1) {
        *pkt_len = *out_len;
        crypto_option_udp_set_rx_meta(epoch, seq);
    }
    return rc;
}

static void udp_frag_gc(int profile_slot, int worker_idx, uint64_t time_ns)
{
    struct udp_reasm_table *table = reasm_table(profile_slot, worker_idx, 0);

    if (table)
        gc_table(table, time_ns);
}

const struct crypto_option_ops *crypto_opt_l2_pqc_udp_ops(void)
{
    static const struct crypto_option_ops ops = {
        .need_split = udp_need_split,
        .split = udp_split,
        .encrypt = udp_encrypt,
        .decrypt = udp_decrypt,
        .is_fragment = udp_is_fragment,
        .reasm = udp_reasm,
        .frag_gc = udp_frag_gc,
    };

    return &ops;
}

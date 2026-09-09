#define _POSIX_C_SOURCE 199309L

#include "../../../inc/core/dataplane/jumbo_l2.h"
#include "../../../inc/core/dataplane/dp_idle.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/crypto/crypto_option.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define JUMBO_ETH_LEN             14u
#define JUMBO_PREFIX_LEN          2u
#define JUMBO_NONCE_LEN           PACKET_CRYPTO_NONCE_BYTES
#define JUMBO_SHIM_LEN            16u
#define JUMBO_ENC_START           (JUMBO_ETH_LEN + JUMBO_PREFIX_LEN + JUMBO_NONCE_LEN)
#define JUMBO_ENC_PAYLOAD_OFF     (JUMBO_ENC_START + JUMBO_SHIM_LEN)
#define JUMBO_BYPASS_SHIM_OFF     (JUMBO_ETH_LEN + JUMBO_PREFIX_LEN)
#define JUMBO_BYPASS_PAYLOAD_OFF  (JUMBO_BYPASS_SHIM_OFF + JUMBO_SHIM_LEN)
#define JUMBO_WIRE_MAX            4060u
#define JUMBO_ORIGINAL_MAX        (CRYPTO_OPT_FRAG_MTU_MAX + JUMBO_ETH_LEN)
#define JUMBO_REASM_SLOTS         4096u
#define JUMBO_REASM_TIMEOUT_NS    (200ULL * 1000000ULL)

static const uint8_t jumbo_magic[3] = { 0x4au, 0x4du, 0x42u }; /* JMB */
static atomic_uint_fast32_t jumbo_packet_clock = ATOMIC_VAR_INIT(1u);

_Static_assert(JUMBO_WIRE_MAX <= NE_FRAME,
               "jumbo wire fragment must fit one UMEM frame");
_Static_assert(JUMBO_WIRE_MAX > JUMBO_ENC_PAYLOAD_OFF + AES_GCM_TAG_SIZE,
               "jumbo encrypted wire header leaves no payload room");

struct jumbo_reasm_entry {
    uint64_t timestamp_ns;
    uint64_t addr[NE_PACKET_MAX_SEGMENTS];
    uint32_t length[NE_PACKET_MAX_SEGMENTS];
    uint16_t offset[NE_PACKET_MAX_SEGMENTS];
    uint32_t packet_id;
    uint16_t total_len;
    uint8_t source_mac[6];
    uint8_t got_mask;
    uint8_t fragment_count;
    uint8_t wire_policy_id;
    uint8_t encrypted;
    uint8_t valid;
};

struct jumbo_reasm_table {
    uint32_t gc_cursor;
    struct jumbo_reasm_entry entries[JUMBO_REASM_SLOTS];
};

static struct jumbo_reasm_table *jumbo_tables[NE_CRYPTO_WORKERS];

static uint64_t jumbo_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | p[3];
}

static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint32_t packet_segment_count(const struct ne_packet *packet)
{
    uint32_t count = packet ? packet->segment_count : 0;

    if (count == 0)
        count = 1;
    return count <= NE_PACKET_MAX_SEGMENTS ? count : 0;
}

static uint64_t packet_segment_addr(const struct ne_packet *packet, uint32_t index)
{
    return index == 0 ? packet->addr : packet->continuation_addr[index - 1u];
}

static uint32_t packet_segment_len(const struct ne_packet *packet, uint32_t index)
{
    return index == 0 ? packet->len : packet->continuation_len[index - 1u];
}

static uint32_t packet_total_len(const struct ne_packet *packet)
{
    uint32_t count = packet_segment_count(packet);
    uint32_t total = 0;

    if (!count)
        return 0;
    for (uint32_t i = 0; i < count; i++)
        total += packet_segment_len(packet, i);
    return total;
}

static int packet_copy_out(struct forwarder *fwd,
                           const struct ne_packet *packet,
                           uint32_t offset, uint8_t *dst, uint32_t length)
{
    uint32_t count = packet_segment_count(packet);

    if (!fwd || !packet || !dst || !count)
        return -1;
    for (uint32_t i = 0; i < count && length; i++) {
        uint32_t seg_len = packet_segment_len(packet, i);
        uint8_t *seg = ne_packet_data(&fwd->pair,
                                      packet_segment_addr(packet, i));
        uint32_t take;

        if (!seg || seg_len > fwd->pair.frame_size)
            return -1;
        if (offset >= seg_len) {
            offset -= seg_len;
            continue;
        }
        take = seg_len - offset;
        if (take > length)
            take = length;
        memcpy(dst, seg + offset, take);
        dst += take;
        length -= take;
        offset = 0;
    }
    return length == 0 ? 0 : -1;
}

static void jumbo_write_shim(uint8_t *shim, uint32_t packet_id,
                             uint16_t total_len, uint16_t offset,
                             uint16_t payload_len, uint8_t index,
                             uint8_t count)
{
    memcpy(shim, jumbo_magic, sizeof(jumbo_magic));
    shim[3] = 1u;
    write_be32(shim + 4, packet_id);
    write_be16(shim + 8, total_len);
    write_be16(shim + 10, offset);
    write_be16(shim + 12, payload_len);
    shim[14] = index;
    shim[15] = count;
}

static int jumbo_read_shim(const uint8_t *shim, uint32_t available,
                           uint32_t *packet_id, uint16_t *total_len,
                           uint16_t *offset, uint16_t *payload_len,
                           uint8_t *index, uint8_t *count)
{
    if (!shim || available < JUMBO_SHIM_LEN ||
        memcmp(shim, jumbo_magic, sizeof(jumbo_magic)) != 0 || shim[3] != 1u)
        return -1;
    *packet_id = read_be32(shim + 4);
    *total_len = read_be16(shim + 8);
    *offset = read_be16(shim + 10);
    *payload_len = read_be16(shim + 12);
    *index = shim[14];
    *count = shim[15];
    if (*total_len < JUMBO_ETH_LEN || *total_len > JUMBO_ORIGINAL_MAX ||
        *count < 2 || *count > NE_PACKET_MAX_SEGMENTS || *index >= *count ||
        *payload_len == 0 || (uint32_t)*offset + *payload_len > *total_len)
        return -1;
    return 0;
}

int dp_jumbo_packet_needs_wire_split(const struct ne_packet *packet,
                                     int encrypted)
{
    uint32_t count = packet_segment_count(packet);
    uint32_t total = packet_total_len(packet);

    if (count > 1)
        return 1;
    /* A single-buffer bypass packet is transmitted unchanged. Only encrypted
     * packets whose normal L2-PQC expansion no longer fits need jumbo wire
     * fragmentation despite arriving in one descriptor. */
    return encrypted && total &&
        total + JUMBO_PREFIX_LEN + JUMBO_NONCE_LEN + AES_GCM_TAG_SIZE >
            NE_FRAME;
}

static void free_output(struct forwarder *fwd, struct ne_packet *output,
                        uint32_t count)
{
    for (uint32_t i = 0; i < count; i++)
        ne_frame_free(&fwd->pair, output[i].addr);
}

int dp_jumbo_build_wire(struct forwarder *fwd,
                        const struct ne_packet *input,
                        struct packet_crypto_ctx *crypto_ctx,
                        uint8_t wire_policy_id, int encrypted,
                        struct ne_packet output[NE_PACKET_MAX_SEGMENTS],
                        uint32_t *output_count)
{
    uint32_t total_len;
    uint32_t payload_max;
    uint32_t count;
    uint32_t packet_id;
    uint32_t offset = 0;
    uint8_t worker = crypto_option_worker_idx();

    if (!fwd || !input || !output || !output_count ||
        (encrypted && (!crypto_ctx || !crypto_ctx->initialized)))
        return -1;
    memset(output, 0, sizeof(*output) * NE_PACKET_MAX_SEGMENTS);
    *output_count = 0;
    total_len = packet_total_len(input);
    if (total_len < JUMBO_ETH_LEN || total_len > JUMBO_ORIGINAL_MAX)
        return -1;
    payload_max = encrypted
        ? JUMBO_WIRE_MAX - JUMBO_ENC_PAYLOAD_OFF - AES_GCM_TAG_SIZE
        : JUMBO_WIRE_MAX - JUMBO_BYPASS_PAYLOAD_OFF;
    count = (total_len + payload_max - 1u) / payload_max;
    if (count < 2 || count > NE_PACKET_MAX_SEGMENTS)
        return -1;
    packet_id = (uint32_t)atomic_fetch_add_explicit(&jumbo_packet_clock, 1u,
                                                     memory_order_relaxed);

    for (uint32_t i = 0; i < count; i++) {
        uint32_t payload_len = total_len - offset;
        uint8_t *wire;

        if (payload_len > payload_max)
            payload_len = payload_max;
        if (ne_frame_alloc(&fwd->pair, &output[i].addr) != 0) {
            free_output(fwd, output, i);
            return -1;
        }
        wire = ne_packet_data(&fwd->pair, output[i].addr);
        if (!wire || packet_copy_out(fwd, input, 0, wire, 12u) != 0) {
            free_output(fwd, output, i + 1u);
            return -1;
        }
        write_be16(wire + 12, encrypted ? NE_L2_JUMBO_ENCRYPTED_ETHERTYPE
                                        : NE_L2_JUMBO_BYPASS_ETHERTYPE);
        wire[14] = wire_policy_id;
        wire[15] = worker;

        if (encrypted) {
            uint8_t nonce[JUMBO_NONCE_LEN];
            int encrypted_len = 0;

            if (packet_crypto_generate_nonce(nonce) != 0) {
                free_output(fwd, output, i + 1u);
                return -1;
            }
            memcpy(wire + 16, nonce, sizeof(nonce));
            jumbo_write_shim(wire + JUMBO_ENC_START, packet_id,
                             (uint16_t)total_len, (uint16_t)offset,
                             (uint16_t)payload_len, (uint8_t)i,
                             (uint8_t)count);
            if (packet_copy_out(fwd, input, offset,
                                wire + JUMBO_ENC_PAYLOAD_OFF,
                                payload_len) != 0 ||
                packet_crypto_encrypt(crypto_ctx, nonce,
                    wire + JUMBO_ENC_START,
                    (int)(JUMBO_SHIM_LEN + payload_len),
                    &encrypted_len) != 0) {
                free_output(fwd, output, i + 1u);
                return -1;
            }
            output[i].len = JUMBO_ENC_START + (uint32_t)encrypted_len;
        } else {
            jumbo_write_shim(wire + JUMBO_BYPASS_SHIM_OFF, packet_id,
                             (uint16_t)total_len, (uint16_t)offset,
                             (uint16_t)payload_len, (uint8_t)i,
                             (uint8_t)count);
            if (packet_copy_out(fwd, input, offset,
                                wire + JUMBO_BYPASS_PAYLOAD_OFF,
                                payload_len) != 0) {
                free_output(fwd, output, i + 1u);
                return -1;
            }
            output[i].len = JUMBO_BYPASS_PAYLOAD_OFF + payload_len;
        }
        output[i].segment_count = 1;
        output[i].total_len = output[i].len;
        offset += payload_len;
    }
    *output_count = count;
    return 0;
}

int dp_jumbo_wire_kind(const uint8_t *packet, uint32_t length)
{
    uint16_t ethertype;

    if (!packet || length < JUMBO_BYPASS_PAYLOAD_OFF ||
        length > JUMBO_WIRE_MAX)
        return 0;
    ethertype = read_be16(packet + 12);
    if (ethertype == NE_L2_JUMBO_BYPASS_ETHERTYPE)
        return 1;
    if (ethertype == NE_L2_JUMBO_ENCRYPTED_ETHERTYPE &&
        length >= JUMBO_ENC_PAYLOAD_OFF + AES_GCM_TAG_SIZE)
        return 2;
    return 0;
}

int dp_jumbo_wire_worker(const uint8_t *packet, uint32_t length,
                         uint8_t *worker_id)
{
    if (!worker_id || dp_jumbo_wire_kind(packet, length) == 0)
        return -1;
    *worker_id = packet[15];
    return 0;
}

int dp_jumbo_wire_policy(const uint8_t *packet, uint32_t length,
                         uint8_t *wire_policy_id)
{
    if (!wire_policy_id || dp_jumbo_wire_kind(packet, length) == 0)
        return -1;
    *wire_policy_id = packet[14];
    return 0;
}

static uint32_t jumbo_hash(uint32_t packet_id, const uint8_t source_mac[6],
                           uint8_t policy, uint8_t encrypted)
{
    uint32_t hash = packet_id ^ ((uint32_t)policy << 24) ^ encrypted;

    for (int i = 0; i < 6; i++)
        hash = (hash * 33u) ^ source_mac[i];
    hash ^= hash >> 16;
    return hash;
}

static int entry_same(const struct jumbo_reasm_entry *entry,
                      uint32_t packet_id, const uint8_t source_mac[6],
                      uint8_t policy, uint8_t encrypted)
{
    return entry->valid && entry->packet_id == packet_id &&
        entry->wire_policy_id == policy && entry->encrypted == encrypted &&
        memcmp(entry->source_mac, source_mac, 6) == 0;
}

static void entry_release(struct forwarder *fwd,
                          struct jumbo_reasm_entry *entry)
{
    if (fwd && entry && entry->valid) {
        for (uint32_t i = 0; i < entry->fragment_count; i++) {
            if (entry->got_mask & (1u << i))
                ne_frame_free(&fwd->pair, entry->addr[i]);
        }
    }
    if (entry)
        memset(entry, 0, sizeof(*entry));
}

static struct jumbo_reasm_entry *entry_find(struct forwarder *fwd,
    struct jumbo_reasm_table *table, uint32_t packet_id,
    const uint8_t source_mac[6], uint8_t policy, uint8_t encrypted,
    uint64_t now)
{
    uint32_t base = jumbo_hash(packet_id, source_mac, policy, encrypted) &
        (JUMBO_REASM_SLOTS - 1u);
    struct jumbo_reasm_entry *victim = NULL;

    for (uint32_t i = 0; i < 8u; i++) {
        struct jumbo_reasm_entry *entry =
            &table->entries[(base + i) & (JUMBO_REASM_SLOTS - 1u)];

        if (entry_same(entry, packet_id, source_mac, policy, encrypted))
            return entry;
        if (!entry->valid)
            return entry;
        if (!victim || entry->timestamp_ns < victim->timestamp_ns)
            victim = entry;
    }
    entry_release(fwd, victim);
    (void)now;
    return victim;
}

int dp_jumbo_receive(struct forwarder *fwd, int worker_idx,
                     struct ne_packet *wire_packet,
                     struct packet_crypto_ctx *crypto_ctx,
                     struct ne_packet *plain_packet,
                     uint8_t *wire_policy_id, int *encrypted)
{
    struct jumbo_reasm_table *table;
    struct jumbo_reasm_entry *entry;
    uint8_t *wire;
    uint8_t *shim;
    uint8_t *payload;
    uint32_t packet_id;
    uint16_t total_len, offset, payload_len;
    uint8_t index, count;
    uint8_t policy;
    int kind;
    int plain_len = 0;
    uint64_t now = jumbo_now_ns();

    if (!fwd || !wire_packet || !plain_packet || !wire_policy_id ||
        !encrypted || worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return DP_JUMBO_RX_DROP;
    wire = ne_packet_data(&fwd->pair, wire_packet->addr);
    kind = dp_jumbo_wire_kind(wire, wire_packet->len);
    if (!kind || dp_jumbo_wire_policy(wire, wire_packet->len, &policy) != 0)
        return DP_JUMBO_RX_DROP;

    if (kind == 2) {
        uint8_t nonce[JUMBO_NONCE_LEN];

        if (!crypto_ctx || !crypto_ctx->initialized)
            return DP_JUMBO_RX_DROP;
        memcpy(nonce, wire + 16, sizeof(nonce));
        if (packet_crypto_decrypt(crypto_ctx, nonce, wire + JUMBO_ENC_START,
                                  (int)(wire_packet->len - JUMBO_ENC_START),
                                  &plain_len) != 0 ||
            plain_len < (int)JUMBO_SHIM_LEN)
            return DP_JUMBO_RX_DROP;
        shim = wire + JUMBO_ENC_START;
        payload = shim + JUMBO_SHIM_LEN;
        if (jumbo_read_shim(shim, (uint32_t)plain_len, &packet_id,
                            &total_len, &offset, &payload_len,
                            &index, &count) != 0 ||
            payload_len != (uint16_t)(plain_len - (int)JUMBO_SHIM_LEN))
            return DP_JUMBO_RX_DROP;
    } else {
        shim = wire + JUMBO_BYPASS_SHIM_OFF;
        payload = wire + JUMBO_BYPASS_PAYLOAD_OFF;
        if (jumbo_read_shim(shim,
                            wire_packet->len - JUMBO_BYPASS_SHIM_OFF,
                            &packet_id, &total_len, &offset, &payload_len,
                            &index, &count) != 0 ||
            payload_len != wire_packet->len - JUMBO_BYPASS_PAYLOAD_OFF)
            return DP_JUMBO_RX_DROP;
    }

    table = jumbo_tables[worker_idx];
    if (!table) {
        table = calloc(1, sizeof(*table));
        if (!table)
            return DP_JUMBO_RX_DROP;
        jumbo_tables[worker_idx] = table;
    }
    entry = entry_find(fwd, table, packet_id, wire + 6, policy,
                       (uint8_t)(kind == 2), now);
    if (!entry)
        return DP_JUMBO_RX_DROP;
    if (!entry->valid) {
        entry->valid = 1;
        entry->packet_id = packet_id;
        entry->total_len = total_len;
        entry->fragment_count = count;
        entry->wire_policy_id = policy;
        entry->encrypted = (uint8_t)(kind == 2);
        memcpy(entry->source_mac, wire + 6, 6);
    } else if (entry->total_len != total_len ||
               entry->fragment_count != count) {
        entry_release(fwd, entry);
        return DP_JUMBO_RX_DROP;
    }
    if (entry->got_mask & (1u << index))
        return DP_JUMBO_RX_DROP;

    memmove(wire, payload, payload_len);
    entry->addr[index] = wire_packet->addr;
    entry->length[index] = payload_len;
    entry->offset[index] = offset;
    entry->got_mask |= (uint8_t)(1u << index);
    entry->timestamp_ns = now;

    if (entry->got_mask != (uint8_t)((1u << count) - 1u))
        return DP_JUMBO_RX_HELD;

    {
        uint32_t expected_offset = 0;

        memset(plain_packet, 0, sizeof(*plain_packet));
        for (uint32_t i = 0; i < count; i++) {
            if (entry->offset[i] != expected_offset) {
                entry->got_mask &= (uint8_t)~(1u << index);
                entry->addr[index] = 0;
                entry_release(fwd, entry);
                return DP_JUMBO_RX_DROP;
            }
            if (i == 0) {
                plain_packet->addr = entry->addr[i];
                plain_packet->len = entry->length[i];
            } else {
                plain_packet->continuation_addr[i - 1u] = entry->addr[i];
                plain_packet->continuation_len[i - 1u] = entry->length[i];
            }
            expected_offset += entry->length[i];
        }
        if (expected_offset != entry->total_len) {
            entry->got_mask &= (uint8_t)~(1u << index);
            entry->addr[index] = 0;
            entry_release(fwd, entry);
            return DP_JUMBO_RX_DROP;
        }
        plain_packet->segment_count = count;
        plain_packet->total_len = entry->total_len;
        plain_packet->wan_idx = wire_packet->wan_idx;
        *wire_policy_id = policy;
        *encrypted = entry->encrypted;
        memset(entry, 0, sizeof(*entry));
    }
    return DP_JUMBO_RX_COMPLETE;
}

void dp_jumbo_gc(struct forwarder *fwd, int worker_idx)
{
    struct jumbo_reasm_table *table;
    uint64_t now;

    if (!fwd || worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;
    table = jumbo_tables[worker_idx];
    if (!table)
        return;
    now = jumbo_now_ns();
    for (uint32_t n = 0; n < 64u; n++) {
        struct jumbo_reasm_entry *entry =
            &table->entries[table->gc_cursor++ & (JUMBO_REASM_SLOTS - 1u)];

        if (entry->valid && now - entry->timestamp_ns > JUMBO_REASM_TIMEOUT_NS)
            entry_release(fwd, entry);
    }
}

void dp_jumbo_reset(struct forwarder *fwd, int worker_idx)
{
    struct jumbo_reasm_table *table;

    if (!fwd || worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;
    table = jumbo_tables[worker_idx];
    if (!table)
        return;
    for (uint32_t i = 0; i < JUMBO_REASM_SLOTS; i++)
        entry_release(fwd, &table->entries[i]);
    free(table);
    jumbo_tables[worker_idx] = NULL;
}

int dp_jumbo_push_local(struct forwarder *fwd, struct ne_ring *ring,
                        const struct ne_packet *packet, int local_idx)
{
    struct ne_packet descriptors[NE_PACKET_MAX_SEGMENTS];
    uint32_t count = packet_segment_count(packet);

    if (!fwd || !ring || !packet || count < 2)
        return -1;
    memset(descriptors, 0, sizeof(descriptors));
    for (uint32_t i = 0; i < count; i++) {
        descriptors[i].addr = packet_segment_addr(packet, i);
        descriptors[i].len = packet_segment_len(packet, i);
        descriptors[i].total_len = descriptors[i].len;
        descriptors[i].segment_count = 1;
        descriptors[i].xdp_options = i + 1u < count ? XDP_PKT_CONTD : 0;
        descriptors[i].dir = NE_DIR_LOCAL;
        descriptors[i].local_idx = (uint8_t)local_idx;
    }
    if (ne_ring_try_push_batch_atomic(ring, descriptors, count) != 0)
        return -1;
    ne_dp_idle_wake_tx_worker(dp_out_ring_idx());
    return 0;
}

int dp_jumbo_push_wan_fragments(struct forwarder *fwd, struct ne_ring *ring,
                                struct ne_packet *fragments,
                                uint32_t fragment_count, int wan_idx)
{
    if (!fwd || !ring || !fragments || fragment_count < 2 ||
        fragment_count > NE_PACKET_MAX_SEGMENTS)
        return -1;
    for (uint32_t i = 0; i < fragment_count; i++) {
        fragments[i].dir = NE_DIR_WAN;
        fragments[i].wan_idx = (uint8_t)wan_idx;
    }
    if (ne_ring_try_push_batch_atomic(ring, fragments, fragment_count) != 0)
        return -1;
    ne_dp_idle_wake_tx_worker(dp_out_ring_idx());
    return 0;
}

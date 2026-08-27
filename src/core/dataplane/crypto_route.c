#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/core/forwarder/forwarder_crypto_runtime.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/crypto_option.h"

#include <arpa/inet.h>
#include <stdatomic.h>
#include <stddef.h>

static __thread int tls_crypto_worker_idx = -1;
static __thread int tls_out_ring_idx;
static uint32_t dp_active_tx_slots(void);

static uint32_t dp_flow_hash_mix(uint32_t src_ip, uint32_t dst_ip,
                                 uint16_t src_port, uint16_t dst_port,
                                 uint8_t protocol)
{
    uint32_t hash = src_ip ^ dst_ip;

    hash ^= ((uint32_t)src_port << 16) | dst_port;
    hash ^= protocol;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);
    return hash;
}

static inline int dp_hash_to_n(uint32_t hash, uint32_t n)
{
    if (n == 0u)
        return 0;
    if ((n & (n - 1u)) == 0u)
        return (int)(hash & (n - 1u));
    return (int)(hash % n);
}

static uint32_t dp_pkt_flow_hash(const uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;

    if (!pkt || len < 14)
        return 0;

    if (dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                      &src_port, &dst_port, &proto) != 0) {
        uint32_t hash = len;
        for (uint32_t i = 0; i < 14 && i < len; i++)
            hash = hash * 31u + pkt[i];
        return dp_flow_hash_mix(hash, hash >> 16, (uint16_t)len, 0, 0);
    }
    return dp_flow_hash_mix(ntohl(src_ip), ntohl(dst_ip), src_port, dst_port, proto);
}

void dp_out_ring_bind(int ring_idx)
{
    if (ring_idx < 0 || ring_idx >= (int)dp_active_tx_slots())
        ring_idx = 0;
    tls_out_ring_idx = ring_idx;
}

int dp_out_ring_idx(void)
{
    return tls_out_ring_idx;
}

void dp_crypto_worker_bind(int worker_idx)
{
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        worker_idx = 0;
    tls_crypto_worker_idx = worker_idx;
    tls_out_ring_idx = worker_idx % (int)dp_active_tx_slots();
}

int dp_crypto_current_worker_idx(void)
{
    return tls_crypto_worker_idx;
}

int dp_crypto_worker_idx_for_cpu(uint8_t cpu_id)
{
    for (int i = 0; i < (int)NE_CRYPTO_WORKERS; i++) {
        if (NE_CPU_CRYPTO[i] == cpu_id)
            return i;
    }
    return -1;
}

#define DP_ROUTE_SET_COUNT 8192u
#define DP_ROUTE_WAYS      8u

struct dp_route_key {
    uint32_t ip_a;
    uint32_t ip_b;
    uint16_t port_a;
    uint16_t port_b;
    uint8_t protocol;
};

struct dp_route_entry {
    struct dp_route_key key;
    uint8_t worker_idx;
    uint8_t tx_slot;
    atomic_uchar valid;
};

struct dp_flow_route {
    int worker_idx;
    int tx_slot;
};

static struct dp_route_entry g_route_table[DP_ROUTE_SET_COUNT][DP_ROUTE_WAYS];
static atomic_uchar g_route_insert_lock;
static atomic_uint_fast64_t g_worker_connection_count[NE_CRYPTO_WORKERS];
static atomic_uint_fast64_t g_tx_connection_count[NE_TX_SLOTS];
static atomic_uint g_worker_rr;
static atomic_uint g_tx_rr;
static atomic_uint g_active_tx_slots = ATOMIC_VAR_INIT(NE_TX_SLOTS);

static uint32_t dp_active_tx_slots(void)
{
    uint32_t slots = atomic_load_explicit(&g_active_tx_slots, memory_order_relaxed);

    return slots > 0 && slots <= NE_TX_SLOTS ? slots : 1u;
}

void dp_route_set_active_tx_slots(uint32_t slots)
{
    if (slots == 0)
        slots = 1;
    if (slots > NE_TX_SLOTS)
        slots = NE_TX_SLOTS;
    atomic_store_explicit(&g_active_tx_slots, slots, memory_order_release);
}
static int dp_route_key_parse(const uint8_t *pkt, uint32_t len, struct dp_route_key *key)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t protocol = 0;
    uint32_t ip_a, ip_b;
    uint16_t port_a, port_b;

    if (!key || dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                              &src_port, &dst_port, &protocol) != 0)
        return -1;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return -1;

    ip_a = ntohl(src_ip);
    ip_b = ntohl(dst_ip);
    port_a = src_port;
    port_b = dst_port;
    if (ip_a > ip_b || (ip_a == ip_b && port_a > port_b)) {
        uint32_t ip_tmp = ip_a;
        uint16_t port_tmp = port_a;

        ip_a = ip_b;
        ip_b = ip_tmp;
        port_a = port_b;
        port_b = port_tmp;
    }

    key->ip_a = ip_a;
    key->ip_b = ip_b;
    key->port_a = port_a;
    key->port_b = port_b;
    key->protocol = protocol;
    return 0;
}

static uint32_t dp_route_key_hash(const struct dp_route_key *key)
{
    return dp_flow_hash_mix(key->ip_a, key->ip_b, key->port_a, key->port_b,
                            key->protocol);
}

static int dp_route_key_equal(const struct dp_route_key *a, const struct dp_route_key *b)
{
    return a->ip_a == b->ip_a && a->ip_b == b->ip_b &&
           a->port_a == b->port_a && a->port_b == b->port_b &&
           a->protocol == b->protocol;
}

static void dp_route_insert_lock(void)
{
    while (atomic_exchange_explicit(&g_route_insert_lock, 1, memory_order_acquire)) {
#if defined(__x86_64__) || defined(__i386__)
        __builtin_ia32_pause();
#else
        __asm__ __volatile__("" ::: "memory");
#endif
    }
}

static void dp_route_insert_unlock(void)
{
    atomic_store_explicit(&g_route_insert_lock, 0, memory_order_release);
}

static int dp_route_least_loaded(atomic_uint_fast64_t counts[], int count,
                                 atomic_uint *cursor)
{
    uint32_t start = atomic_fetch_add_explicit(cursor, 1u, memory_order_relaxed);
    uint64_t best_count = UINT64_MAX;
    int best = 0;

    for (int off = 0; off < count; off++) {
        int idx = (int)((start + (uint32_t)off) % (uint32_t)count);
        uint64_t load = atomic_load_explicit(&counts[idx], memory_order_relaxed);

        if (load < best_count) {
            best_count = load;
            best = idx;
        }
    }
    return best;
}

static struct dp_flow_route dp_flow_route_get(const uint8_t *pkt, uint32_t len,
                                               int worker_hint)
{
    struct dp_flow_route route;
    struct dp_route_key key;
    struct dp_route_entry *set;
    uint32_t hash = dp_pkt_flow_hash(pkt, len);
    int empty = -1;

    route.worker_idx = dp_hash_to_n(hash, NE_CRYPTO_WORKERS);
    route.tx_slot = dp_hash_to_n(hash, dp_active_tx_slots());
    if (dp_route_key_parse(pkt, len, &key) != 0)
        return route;

    hash = dp_route_key_hash(&key);
    route.worker_idx = dp_hash_to_n(hash, NE_CRYPTO_WORKERS);
    route.tx_slot = dp_hash_to_n(hash, dp_active_tx_slots());
    set = g_route_table[hash & (DP_ROUTE_SET_COUNT - 1u)];

    for (int way = 0; way < (int)DP_ROUTE_WAYS; way++) {
        if (!atomic_load_explicit(&set[way].valid, memory_order_acquire))
            continue;
        if (dp_route_key_equal(&set[way].key, &key)) {
            route.worker_idx = set[way].worker_idx;
            route.tx_slot = set[way].tx_slot;
            return route;
        }
    }

    /* Only a flow's first packet serializes; established-flow lookup is lock-free. */
    dp_route_insert_lock();
    for (int way = 0; way < (int)DP_ROUTE_WAYS; way++) {
        if (!atomic_load_explicit(&set[way].valid, memory_order_acquire)) {
            if (empty < 0)
                empty = way;
            continue;
        }
        if (dp_route_key_equal(&set[way].key, &key)) {
            route.worker_idx = set[way].worker_idx;
            route.tx_slot = set[way].tx_slot;
            dp_route_insert_unlock();
            return route;
        }
    }

    /*
     * Never evict a live immutable entry: remapping an established TCP flow can
     * reorder packets. A saturated hash set falls back to canonical hashing.
     */
    if (empty < 0) {
        dp_route_insert_unlock();
        return route;
    }

    if (worker_hint >= 0 && worker_hint < (int)NE_CRYPTO_WORKERS)
        route.worker_idx = worker_hint;
    else
        route.worker_idx = dp_route_least_loaded(g_worker_connection_count,
                                                 (int)NE_CRYPTO_WORKERS,
                                                 &g_worker_rr);
    route.tx_slot = dp_route_least_loaded(g_tx_connection_count,
                                          (int)dp_active_tx_slots(), &g_tx_rr);

    set[empty].key = key;
    set[empty].worker_idx = (uint8_t)route.worker_idx;
    set[empty].tx_slot = (uint8_t)route.tx_slot;
    atomic_fetch_add_explicit(&g_worker_connection_count[route.worker_idx], 1u,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&g_tx_connection_count[route.tx_slot], 1u,
                              memory_order_relaxed);
    atomic_store_explicit(&set[empty].valid, 1, memory_order_release);
    dp_route_insert_unlock();
    return route;
}

int dp_pick_tx_slot(const uint8_t *pkt, uint32_t len)
{
    struct dp_route_key key;

    if (dp_route_key_parse(pkt, len, &key) == 0)
        return dp_hash_to_n(dp_route_key_hash(&key), dp_active_tx_slots());
    return dp_hash_to_n(dp_pkt_flow_hash(pkt, len), dp_active_tx_slots());
}

int dp_crypto_pick_local_worker(const uint8_t *pkt, uint32_t len, int *tx_slot_out)
{
    struct dp_flow_route route = dp_flow_route_get(pkt, len, -1);

    if (tx_slot_out)
        *tx_slot_out = route.tx_slot;
    return route.worker_idx;
}

int dp_flow_pick_tx_slot(const uint8_t *pkt, uint32_t len, int worker_hint)
{
    return dp_flow_route_get(pkt, len, worker_hint).tx_slot;
}

int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint8_t wire_id = 0;
    int wi;

    if (!fwd || !pkt)
        return 0;

    if (crypto_eth_l2_has_arp_marker(pkt, len) || dp_pkt_is_arp(pkt, len))
        return dp_crypto_pick_local_worker(pkt, len, NULL);

    /* Encrypt data only. Bypass never calls this. */
    if (!fwd->cfg || !fwd->cfg->crypto_enabled || !fwd_crypto_has_l2_marker(pkt, len))
        return -1;

    if (crypto_eth_l2_read_worker_idx(pkt, len, &wire_id) != 0)
        return -1;
    if (wire_id < NE_CRYPTO_WORKERS)
        return (int)wire_id;
    wi = dp_crypto_worker_idx_for_cpu(wire_id);
    if (wi < 0)
        return -1;
    return wi;
}

void dp_route_connection_counts(uint64_t worker_counts[NE_CRYPTO_WORKERS],
                                uint64_t tx_counts[NE_TX_SLOTS])
{
    for (uint32_t i = 0; worker_counts && i < NE_CRYPTO_WORKERS; i++)
        worker_counts[i] = atomic_load_explicit(&g_worker_connection_count[i],
                                                 memory_order_relaxed);
    for (uint32_t i = 0; tx_counts && i < NE_TX_SLOTS; i++)
        tx_counts[i] = atomic_load_explicit(&g_tx_connection_count[i], memory_order_relaxed);
}

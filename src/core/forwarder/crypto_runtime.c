#define _POSIX_C_SOURCE 199309L
#include "../../../inc/core/util/main_diag.h"
#include "../../../inc/core/forwarder/forwarder_crypto_runtime.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/dataplane/arp_bridge.h"

#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/traffic_crypto.h"
#include "../../../inc/crypto/pqc_handshake.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static struct packet_crypto_ctx policy_crypto_ctx[MAX_CRYPTO_POLICIES];
static struct packet_crypto_ctx worker_policy_crypto_ctx[NE_CRYPTO_WORKERS][MAX_CRYPTO_POLICIES];
static int policy_crypto_ready[MAX_CRYPTO_POLICIES];
static struct packet_crypto_ctx worker_prev_policy_crypto_ctx[NE_CRYPTO_WORKERS][MAX_CRYPTO_POLICIES];
static pthread_mutex_t policy_crypto_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint policy_crypto_generation = ATOMIC_VAR_INIT(1u);
static __thread unsigned int tls_policy_crypto_generation;
static __thread int tls_policy_crypto_worker = -1;
static int policy_index_by_wire_id[256];
static int policy_profile_id_by_wire_id[256];
static struct crypto_policy active_policies[MAX_CRYPTO_POLICIES];
static int active_policy_count;
static struct packet_crypto_ctx prev_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
static int prev_policy_crypto_ready[MAX_CRYPTO_POLICIES];
static int prev_policy_index_by_wire_id[256];
static int prev_policy_profile_id_by_wire_id[256];
static struct crypto_policy prev_active_policies[MAX_CRYPTO_POLICIES];

static void policy_crypto_publish_unlock(void)
{
    atomic_fetch_add_explicit(&policy_crypto_generation, 1u, memory_order_release);
    pthread_mutex_unlock(&policy_crypto_lock);
}

/*
 * Crypto workers use private immutable packet contexts. Handshake/reload only
 * bumps the generation after updating the master copy, so the steady-state
 * packet path pays one atomic load and never takes g_key_mutex.
 */
static void policy_crypto_sync_worker(int worker_idx)
{
    unsigned int generation;

    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;

    generation = atomic_load_explicit(&policy_crypto_generation, memory_order_acquire);
    if (tls_policy_crypto_worker == worker_idx &&
        tls_policy_crypto_generation == generation)
        return;

    pthread_mutex_lock(&policy_crypto_lock);
    memcpy(worker_policy_crypto_ctx[worker_idx], policy_crypto_ctx,
           sizeof(worker_policy_crypto_ctx[worker_idx]));
    memcpy(worker_prev_policy_crypto_ctx[worker_idx], prev_policy_crypto_ctx,
           sizeof(worker_prev_policy_crypto_ctx[worker_idx]));
    generation = atomic_load_explicit(&policy_crypto_generation, memory_order_relaxed);
    pthread_mutex_unlock(&policy_crypto_lock);

    tls_policy_crypto_worker = worker_idx;
    tls_policy_crypto_generation = generation;
}

static struct packet_crypto_ctx *policy_crypto_ctx_for_worker(int policy_index, int previous)
{
    int worker_idx = dp_crypto_current_worker_idx();

    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return previous ? &prev_policy_crypto_ctx[policy_index]
                        : &policy_crypto_ctx[policy_index];

    policy_crypto_sync_worker(worker_idx);
    return previous ? &worker_prev_policy_crypto_ctx[worker_idx][policy_index]
                    : &worker_policy_crypto_ctx[worker_idx][policy_index];
}
static int prev_active_policy_count;
static int prev_grace_active;
static uint64_t prev_grace_until_ms;
static struct flow_table profile_flow_tables[MAX_PROFILES];
static int profile_flow_table_ready[MAX_PROFILES];
static int profile_flow_profile_id[MAX_PROFILES];

int fwd_crypto_profile_slot_for_id(int profile_id)
{
    if (profile_flow_table_ready[0] && profile_flow_profile_id[0] == profile_id)
        return 0;
    return -1;
}

static int profile_slot_alloc(int profile_id)
{
    if (profile_flow_table_ready[0] && profile_flow_profile_id[0] == profile_id)
        return 0;
    if (!profile_flow_table_ready[0]) {
        profile_flow_profile_id[0] = profile_id;
        return 0;
    }
    /* Replace the single live slot when the active profile id changes. */
    profile_flow_profile_id[0] = profile_id;
    return 0;
}

int fwd_crypto_ensure_profile_slots(struct app_config *cfg)
{
    int profile_id;
    int slot;

    if (!cfg || cfg->profile_count < 1)
        return -1;
    profile_id = cfg->profiles[0].id;
    slot = profile_slot_alloc(profile_id);
    if (slot < 0)
        return -1;
    if (!profile_flow_table_ready[slot]) {
        uint32_t windows[MAX_INTERFACES];
        memset(windows, 0, sizeof(windows));
        for (int wi = 0; wi < cfg->wan_count && wi < MAX_INTERFACES; wi++)
            windows[wi] = cfg->wans[wi].window_size;
        flow_table_init(&profile_flow_tables[slot], windows, cfg->wan_count);
        profile_flow_table_ready[slot] = 1;
    }
    return 0;
}

void fwd_crypto_sync_flow_table_windows(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return;

    for (int s = 0; s < 1; s++) {
        const struct profile_config *p = NULL;
        struct flow_table *ft;

        if (!profile_flow_table_ready[s])
            continue;
        ft = &profile_flow_tables[s];
        if (fwd->cfg->profile_count > 0 &&
            fwd->cfg->profiles[0].id == profile_flow_profile_id[s])
            p = &fwd->cfg->profiles[0];
        if (!p)
            continue;
        for (int i = 0; i < p->wan_count; i++) {
            int wi = p->wan_indices[i];
            if (wi >= 0 && wi < MAX_INTERFACES)
                ft->wan_window_sizes[wi] = fwd->cfg->wans[wi].window_size;
        }
    }
}

void fwd_crypto_cleanup_stale_profile_slots(const struct app_config *cfg)
{
    if (!cfg || prev_grace_active)
        return;
    for (int s = 0; s < 1; s++) {
        if (!profile_flow_table_ready[s])
            continue;
        int pid = profile_flow_profile_id[s];
        int still_active = (cfg->profile_count > 0 && cfg->profiles[0].id == pid);
        if (still_active)
            continue;
        flow_table_cleanup(&profile_flow_tables[s]);
        profile_flow_table_ready[s] = 0;
        profile_flow_profile_id[s] = 0;
    }
}

void fwd_crypto_maybe_expire_prev_grace(void)
{
    if (!prev_grace_active)
        return;
    if (monotonic_ms() >= prev_grace_until_ms)
        prev_grace_active = 0;
}

void fwd_crypto_clear_grace(void)
{
    prev_grace_active = 0;
}

void fwd_crypto_snapshot_active_to_prev(void)
{
    pthread_mutex_lock(&policy_crypto_lock);
    memcpy(prev_policy_crypto_ctx, policy_crypto_ctx, sizeof(prev_policy_crypto_ctx));
    memcpy(prev_policy_crypto_ready, policy_crypto_ready, sizeof(prev_policy_crypto_ready));
    memcpy(prev_policy_index_by_wire_id, policy_index_by_wire_id, sizeof(prev_policy_index_by_wire_id));
    memcpy(prev_policy_profile_id_by_wire_id, policy_profile_id_by_wire_id,
           sizeof(prev_policy_profile_id_by_wire_id));
    memcpy(prev_active_policies, active_policies, sizeof(prev_active_policies));
    prev_active_policy_count = active_policy_count;
    prev_grace_active = (prev_active_policy_count > 0) ? 1 : 0;
    prev_grace_until_ms = monotonic_ms() + FWD_CRYPTO_PROFILE_RELOAD_GRACE_MS;
    policy_crypto_publish_unlock();
}
static int crypto_policy_is_encrypt(const struct crypto_policy *cp)
{
    return cp && cp->action != POLICY_ACTION_BYPASS;
}

static void crypto_runtime_reset_indexes(void)
{
    for (int id = 0; id < 256; id++)
        policy_index_by_wire_id[id] = -1;
}

void forwarder_pre_diversify_pqc_keys(int profile_id)
{
    pthread_mutex_lock(&policy_crypto_lock);
    for (int i = 0; i < active_policy_count; i++) {
        if (!policy_crypto_ready[i])
            continue;
        if (policy_crypto_ctx[i].crypto_mode != CRYPTO_MODE_PQC)
            continue;
        if (policy_crypto_ctx[i].profile_id != profile_id)
            continue;
        packet_crypto_refresh_pqc_keys(&policy_crypto_ctx[i]);
    }
    policy_crypto_publish_unlock();
}

void fwd_crypto_sync_pqc_session_keys(const struct app_config *cfg)
{
    if (!cfg || !cfg->crypto_enabled || cfg->profile_count < 1)
        return;

    pthread_mutex_lock(&policy_crypto_lock);
    {
        const struct profile_config *prof = &cfg->profiles[0];

        for (int j = 0; j < prof->policy_count; j++) {
            int pi = prof->policy_indices[j];
            const struct crypto_policy *cp;
            int ctx_i = -1;

            if (pi < 0 || pi >= cfg->policy_count)
                continue;
            cp = &cfg->policies[pi];
            if (!crypto_policy_is_encrypt(cp))
                continue;

            for (int i = 0; i < active_policy_count; i++) {
                if (active_policies[i].db_id == cp->db_id) {
                    ctx_i = i;
                    break;
                }
            }
            if (ctx_i < 0 || !policy_crypto_ready[ctx_i])
                continue;

            policy_crypto_ctx[ctx_i].profile_id = prof->id;
            policy_crypto_ctx[ctx_i].policy_id = cp->db_id;
            policy_crypto_ctx[ctx_i].wire_id = (uint8_t)cp->id;

            /* HS not ready (UI đổi key / re-handshake fail) → wipe stale session key now. */
            packet_crypto_refresh_pqc_keys(&policy_crypto_ctx[ctx_i]);
        }
    }
    policy_crypto_publish_unlock();
}

int fwd_crypto_rebuild(struct app_config *cfg)
{
    struct packet_crypto_ctx old_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
    int old_policy_crypto_ready[MAX_CRYPTO_POLICIES];
    int old_policy_index_by_wire_id[256];
    int old_active_policy_count;

    pthread_mutex_lock(&policy_crypto_lock);
    old_active_policy_count = active_policy_count;
    memcpy(old_policy_crypto_ctx, policy_crypto_ctx, sizeof(old_policy_crypto_ctx));
    memcpy(old_policy_crypto_ready, policy_crypto_ready, sizeof(old_policy_crypto_ready));
    memcpy(old_policy_index_by_wire_id, policy_index_by_wire_id, sizeof(old_policy_index_by_wire_id));

    memset(policy_crypto_ready, 0, sizeof(policy_crypto_ready));
    memset(active_policies, 0, sizeof(active_policies));
    active_policy_count = 0;
    crypto_runtime_reset_indexes();
    memset(policy_profile_id_by_wire_id, -1, sizeof(policy_profile_id_by_wire_id));
    /* Drop key rows from deleted/previous profiles before rebuilding. */
    main_diag_ne_pqc_clear_all();
    
    if (cfg) {
        config_refresh_policy_in_any(cfg);
    }

    if (!cfg || !cfg->crypto_enabled) {
        policy_crypto_publish_unlock();
        arp_bridge_reload_policies(cfg);
        return 0;
    }

    if (cfg->fake_ethertype_ipv4 == 0)
        cfg->fake_ethertype_ipv4 = (uint16_t)NE_L2_FAKE_ETHERTYPE;

    active_policy_count = cfg->policy_count;
    if (active_policy_count > MAX_CRYPTO_POLICIES)
        active_policy_count = MAX_CRYPTO_POLICIES;

    for (int i = 0; i < active_policy_count; i++) {
        const struct crypto_policy *cp = &cfg->policies[i];
        active_policies[i] = *cp;
        if (!crypto_policy_is_encrypt(cp))
            continue;
        if (cp->id >= 0 && cp->id <= 255)
            policy_index_by_wire_id[(uint8_t)cp->id] = i;

        int reused = 0;
        if (cp->id >= 0 && cp->id <= 255) {
            int old_i = old_policy_index_by_wire_id[(uint8_t)cp->id];
            if (old_i >= 0 && old_i < old_active_policy_count && old_policy_crypto_ready[old_i]) {
                policy_crypto_ctx[i] = old_policy_crypto_ctx[old_i];
                policy_crypto_ready[i] = 1;
                reused = 1;
                policy_crypto_ctx[i].pqc_from_handshake = true;
                packet_crypto_refresh_pqc_keys(&policy_crypto_ctx[i]);
            }
        }
        if (reused)
            continue;

        memset(&policy_crypto_ctx[i], 0, sizeof(policy_crypto_ctx[i]));
        policy_crypto_ctx[i].initialized = true;
        policy_crypto_ctx[i].crypto_mode = CRYPTO_MODE_PQC;
        policy_crypto_ctx[i].policy_id = cp->db_id;
        policy_crypto_ctx[i].wire_id = (uint8_t)cp->id;
        policy_crypto_ctx[i].pqc_from_handshake = true;
        policy_crypto_ready[i] = 1;
        /* Only populate keys when handshake key_ready; else keep all-zero (block TX/RX). */
        packet_crypto_refresh_pqc_keys(&policy_crypto_ctx[i]);
    }

    if (cfg->profile_count > 0) {
        const struct profile_config *p = &cfg->profiles[0];
        for (int j = 0; j < p->policy_count && j < MAX_CRYPTO_POLICIES; j++) {
            int pi = p->policy_indices[j];
            if (pi < 0 || pi >= cfg->policy_count)
                continue;
            const struct crypto_policy *cp = &cfg->policies[pi];
            if (!crypto_policy_is_encrypt(cp))
                continue;
            if (cp->id >= 0 && cp->id <= 255)
                policy_profile_id_by_wire_id[(uint8_t)cp->id] = p->id;
            if (policy_crypto_ready[pi]) {
                policy_crypto_ctx[pi].profile_id = p->id;
                policy_crypto_ctx[pi].policy_id = cp->db_id;
            }
        }
    }

    policy_crypto_publish_unlock();
    arp_bridge_reload_policies(cfg);
    return 0;
}

struct packet_crypto_ctx *fwd_crypto_ctx_for_wire_id(uint8_t wire_id)
{
    fwd_crypto_maybe_expire_prev_grace();
    int pi = policy_index_by_wire_id[wire_id];
    if (pi >= 0 && pi < active_policy_count && policy_crypto_ready[pi])
        return policy_crypto_ctx_for_worker(pi, 0);
    if (prev_grace_active) {
        int ppi = prev_policy_index_by_wire_id[wire_id];
        if (ppi >= 0 && ppi < prev_active_policy_count && prev_policy_crypto_ready[ppi])
            return policy_crypto_ctx_for_worker(ppi, 1);
    }
    return NULL;
}

int fwd_crypto_profile_id_for_wire_id(uint8_t wire_id)
{
    fwd_crypto_maybe_expire_prev_grace();
    int pid = policy_profile_id_by_wire_id[wire_id];
    if (pid > 0)
        return pid;
    if (prev_grace_active) {
        int old_pid = prev_policy_profile_id_by_wire_id[wire_id];
        if (old_pid > 0)
            return old_pid;
    }
    return -1;
}

int fwd_crypto_flow_table_ready(int slot)
{
    if (slot < 0 || slot >= MAX_PROFILES)
        return 0;
    return profile_flow_table_ready[slot];
}

struct flow_table *fwd_crypto_flow_table(int slot)
{
    if (slot < 0 || slot >= MAX_PROFILES)
        return NULL;
    return &profile_flow_tables[slot];
}

#define FLOW_GC_BUCKETS_PER_TICK 256

static int profile_flow_gc_cursor[MAX_PROFILES];

void fwd_crypto_frag_gc_worker_tick(int worker_idx)
{
    struct timespec ts;
    uint64_t now_ns;

    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    if (profile_flow_table_ready[0]) {
        if (worker_idx == 0)
            flow_table_gc_slice(&profile_flow_tables[0], &profile_flow_gc_cursor[0],
                                FLOW_GC_BUCKETS_PER_TICK);
        crypto_option_frag_gc_all(0, worker_idx, now_ns);
    }
}

int fwd_crypto_policy_ready(int policy_index)
{
    return policy_index >= 0 && policy_index < MAX_CRYPTO_POLICIES && policy_crypto_ready[policy_index];
}

struct packet_crypto_ctx *fwd_crypto_policy_ctx(int policy_index)
{
    if (!fwd_crypto_policy_ready(policy_index))
        return NULL;
    return policy_crypto_ctx_for_worker(policy_index, 0);
}

int fwd_crypto_has_l2_marker(const uint8_t *pkt, uint32_t pkt_len)
{
    uint8_t wire_pol = 0;

    if (!pkt || !crypto_eth_l2_has_marker(pkt, pkt_len))
        return 0;
    if (crypto_eth_l2_read_policy_id(pkt, pkt_len, &wire_pol) != 0)
        return 0;
    return policy_index_by_wire_id[wire_pol] >= 0;
}

void fwd_crypto_reset_on_init(void)
{
    prev_active_policy_count = 0;
    prev_grace_active = 0;
    prev_grace_until_ms = 0;
    memset(prev_policy_crypto_ready, 0, sizeof(prev_policy_crypto_ready));
    memset(prev_policy_index_by_wire_id, -1, sizeof(prev_policy_index_by_wire_id));
    memset(prev_policy_profile_id_by_wire_id, -1, sizeof(prev_policy_profile_id_by_wire_id));
    memset(prev_active_policies, 0, sizeof(prev_active_policies));
    memset(profile_flow_table_ready, 0, sizeof(profile_flow_table_ready));
    memset(profile_flow_profile_id, 0, sizeof(profile_flow_profile_id));
}

void fwd_crypto_cleanup_all_profile_slots(void)
{
    for (int i = 0; i < MAX_PROFILES; i++) {
        if (!profile_flow_table_ready[i])
            continue;
        flow_table_cleanup(&profile_flow_tables[i]);
        profile_flow_table_ready[i] = 0;
        profile_flow_profile_id[i] = 0;
    }
}
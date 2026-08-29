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

static int crypto_policy_is_encrypt(const struct crypto_policy *cp);

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

#define NE_PQC_KEY_LIFETIME_MS (30ULL * 24ULL * 60ULL * 60ULL * 1000ULL)

static int ne_key_nonzero(const uint8_t *key, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (key[i])
            return 1;
    }
    return 0;
}

static void ne_wipe_key(uint8_t *key, size_t len)
{
    volatile uint8_t *p = key;

    while (len--)
        *p++ = 0;
}

/* policy_crypto_lock must be held. Clock starts when CURRENT is stored in RAM. */
static void ne_pqc_start_lifetime_clock(struct packet_crypto_ctx *ctx, uint64_t now)
{
    memcpy(ctx->pqc_timed_key, ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ);
    ctx->pqc_key_in_use_ms = now;
    ctx->pqc_rekey_sent = false;
    fprintf(stderr,
            "[NE-PQC] Policy %d session key stored in RAM; lifetime clock started.\n",
            ctx->policy_id);
}

static void ne_pqc_on_key_material(struct packet_crypto_ctx *ctx)
{
    if (!ctx || !ctx->pqc_from_handshake)
        return;
    if (!ne_key_nonzero(ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ)) {
        ctx->pqc_key_in_use_ms = 0;
        ctx->pqc_rekey_sent = false;
        ne_wipe_key(ctx->pqc_timed_key, PQC_TRAFFIC_KEY_SZ);
        return;
    }
    if (memcmp(ctx->keys[KEY_SLOT_CURRENT], ctx->pqc_timed_key,
               PQC_TRAFFIC_KEY_SZ) == 0)
        return;

    ne_pqc_start_lifetime_clock(ctx, monotonic_ms());
}

/* UDP reassembly is keyed by the single active dataplane profile. */
int fwd_crypto_profile_slot_for_id(int profile_id)
{
    return profile_id > 0 ? 0 : -1;
}

void fwd_crypto_maybe_expire_prev_grace(void)
{
    if (!prev_grace_active)
        return;
    if (monotonic_ms() >= prev_grace_until_ms)
        prev_grace_active = 0;
}

void fwd_crypto_discard_pqc_prev_key(int policy_id)
{
    int discarded = 0;

    pthread_mutex_lock(&policy_crypto_lock);
    for (int i = 0; i < active_policy_count; i++) {
        if (!policy_crypto_ready[i] ||
            policy_crypto_ctx[i].policy_id != policy_id)
            continue;
        if (ne_key_nonzero(policy_crypto_ctx[i].keys[KEY_SLOT_PREV],
                           PQC_TRAFFIC_KEY_SZ)) {
            ne_wipe_key(policy_crypto_ctx[i].keys[KEY_SLOT_PREV],
                        PQC_TRAFFIC_KEY_SZ);
            atomic_fetch_add_explicit(&policy_crypto_generation, 1u,
                                      memory_order_release);
            discarded = 1;
        }
        break;
    }
    pthread_mutex_unlock(&policy_crypto_lock);

    if (discarded)
        sig_pqc_discard_prev_key(policy_id);
}

void fwd_crypto_pqc_key_lifetime_tick(void)
{
    uint64_t now = monotonic_ms();
    int request_ids[MAX_CRYPTO_POLICIES];
    uint64_t request_started[MAX_CRYPTO_POLICIES];
    int nreq = 0;

    pthread_mutex_lock(&policy_crypto_lock);
    for (int i = 0; i < active_policy_count; i++) {
        uint64_t started;

        if (!policy_crypto_ready[i] || !policy_crypto_ctx[i].pqc_from_handshake)
            continue;
        started = policy_crypto_ctx[i].pqc_key_in_use_ms;
        if (started == 0) {
            if (!ne_key_nonzero(policy_crypto_ctx[i].keys[KEY_SLOT_CURRENT],
                                PQC_TRAFFIC_KEY_SZ))
                continue;
            ne_pqc_start_lifetime_clock(&policy_crypto_ctx[i], now);
            continue;
        }
        if (now < started || now - started < NE_PQC_KEY_LIFETIME_MS)
            continue;
        if (policy_crypto_ctx[i].pqc_rekey_sent)
            continue;
        policy_crypto_ctx[i].pqc_rekey_sent = true;
        request_ids[nreq++] = policy_crypto_ctx[i].policy_id;
        request_started[nreq - 1] = started;
        fprintf(stderr,
                "[NE-PQC] Policy %d session key lifetime expired; requesting PQC handshake for a new key.\n",
                policy_crypto_ctx[i].policy_id);
    }
    pthread_mutex_unlock(&policy_crypto_lock);

    for (int k = 0; k < nreq; k++) {
        if (sig_pqc_request_new_session(request_ids[k]) == 0)
            continue;
        /* Binding may be transiently unavailable during reload/handshake.
         * Re-arm only if this is still the same expired key generation. */
        pthread_mutex_lock(&policy_crypto_lock);
        for (int i = 0; i < active_policy_count; i++) {
            if (policy_crypto_ready[i] &&
                policy_crypto_ctx[i].policy_id == request_ids[k] &&
                policy_crypto_ctx[i].pqc_key_in_use_ms == request_started[k]) {
                policy_crypto_ctx[i].pqc_rekey_sent = false;
                break;
            }
        }
        pthread_mutex_unlock(&policy_crypto_lock);
    }
}

int fwd_crypto_format_pqc_key_times(char *out, size_t out_max, int policy_id)
{
    uint64_t now;
    int found = -1;
    int has_key;
    uint64_t started;
    uint64_t rem_ms;
    uint64_t days;
    uint64_t hours;
    uint64_t mins;

    if (!out || out_max == 0)
        return -1;
    out[0] = '\0';
    if (policy_id <= 0) {
        snprintf(out, out_max, "không tồn tại policy này\n");
        return 0;
    }

    pthread_mutex_lock(&policy_crypto_lock);
    for (int i = 0; i < active_policy_count; i++) {
        if (active_policies[i].db_id == policy_id ||
            policy_crypto_ctx[i].policy_id == policy_id) {
            found = i;
            break;
        }
    }
    if (found < 0) {
        pthread_mutex_unlock(&policy_crypto_lock);
        snprintf(out, out_max, "không tồn tại policy này\n");
        return 0;
    }
    if (!crypto_policy_is_encrypt(&active_policies[found])) {
        pthread_mutex_unlock(&policy_crypto_lock);
        snprintf(out, out_max, "NO-ENCRYPT\n");
        return 0;
    }

    has_key = policy_crypto_ready[found] &&
              policy_crypto_ctx[found].pqc_from_handshake &&
              ne_key_nonzero(policy_crypto_ctx[found].keys[KEY_SLOT_CURRENT],
                             PQC_TRAFFIC_KEY_SZ);
    started = has_key ? policy_crypto_ctx[found].pqc_key_in_use_ms : 0;
    pthread_mutex_unlock(&policy_crypto_lock);
    now = monotonic_ms();

    if (!has_key)
        rem_ms = 0;
    else if (started == 0)
        rem_ms = NE_PQC_KEY_LIFETIME_MS;
    else if (now >= started && now - started >= NE_PQC_KEY_LIFETIME_MS)
        rem_ms = 0;
    else
        rem_ms = NE_PQC_KEY_LIFETIME_MS - (now > started ? now - started : 0);
    /* Round up to the displayed minute so a freshly started key shows the
     * full 30 days instead of 29 days 23 hours 59 minutes. */
    rem_ms = ((rem_ms + 59999ULL) / 60000ULL) * 60000ULL;
    days = rem_ms / (24ULL * 60ULL * 60ULL * 1000ULL);
    hours = (rem_ms / (60ULL * 60ULL * 1000ULL)) % 24ULL;
    mins = (rem_ms / (60ULL * 1000ULL)) % 60ULL;
    snprintf(out, out_max, "%llu day%s %llu hour%s %llu minute%s\n",
             (unsigned long long)days, days == 1 ? "" : "s",
             (unsigned long long)hours, hours == 1 ? "" : "s",
             (unsigned long long)mins, mins == 1 ? "" : "s");
    return 0;
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
    return cp && cp->action == POLICY_ACTION_ENCRYPT_L2;
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
        if (policy_crypto_ctx[i].profile_id != profile_id)
            continue;
        packet_crypto_refresh_pqc_keys(&policy_crypto_ctx[i]);
        ne_pqc_on_key_material(&policy_crypto_ctx[i]);
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
            ne_pqc_on_key_material(&policy_crypto_ctx[ctx_i]);
        }
    }
    policy_crypto_publish_unlock();
}

int fwd_crypto_rebuild(struct app_config *cfg)
{
    struct packet_crypto_ctx old_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
    int old_policy_crypto_ready[MAX_CRYPTO_POLICIES];
    struct crypto_policy old_policies[MAX_CRYPTO_POLICIES];
    int old_active_policy_count;

    pthread_mutex_lock(&policy_crypto_lock);
    old_active_policy_count = active_policy_count;
    memcpy(old_policy_crypto_ctx, policy_crypto_ctx, sizeof(old_policy_crypto_ctx));
    memcpy(old_policy_crypto_ready, policy_crypto_ready, sizeof(old_policy_crypto_ready));
    memcpy(old_policies, active_policies, sizeof(old_policies));

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
        if (!crypto_policy_is_encrypt(cp)) {
            if (cp->action != POLICY_ACTION_BYPASS)
                fprintf(stderr,
                        "[CRYPTO] Policy %d ignored: only L2 PQC and Bypass are supported.\n",
                        cp->db_id);
            continue;
        }
        if (cp->id >= 0 && cp->id <= 255)
            policy_index_by_wire_id[(uint8_t)cp->id] = i;

        int reused = 0;
        {
            int old_i = -1;
            for (int oi = 0; oi < old_active_policy_count; oi++) {
                if (old_policy_crypto_ready[oi] &&
                    old_policies[oi].db_id == cp->db_id) {
                    old_i = oi;
                    break;
                }
            }
            if (old_i >= 0) {
                policy_crypto_ctx[i] = old_policy_crypto_ctx[old_i];
                policy_crypto_ready[i] = 1;
                reused = 1;
                policy_crypto_ctx[i].pqc_from_handshake = true;
                policy_crypto_ctx[i].wire_id = (uint8_t)cp->id;
                policy_crypto_ctx[i].policy_id = cp->db_id;
                packet_crypto_refresh_pqc_keys(&policy_crypto_ctx[i]);
                ne_pqc_on_key_material(&policy_crypto_ctx[i]);
            }
        }
        if (reused)
            continue;

        memset(&policy_crypto_ctx[i], 0, sizeof(policy_crypto_ctx[i]));
        policy_crypto_ctx[i].initialized = true;
        policy_crypto_ctx[i].policy_id = cp->db_id;
        policy_crypto_ctx[i].wire_id = (uint8_t)cp->id;
        policy_crypto_ctx[i].pqc_from_handshake = true;
        policy_crypto_ready[i] = 1;
        /* Only populate keys when handshake key_ready; else keep all-zero (block TX/RX). */
        packet_crypto_refresh_pqc_keys(&policy_crypto_ctx[i]);
        ne_pqc_on_key_material(&policy_crypto_ctx[i]);
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

void fwd_crypto_frag_gc_worker_tick(int worker_idx)
{
    struct timespec ts;
    uint64_t now_ns;

    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    crypto_option_frag_gc_all(0, worker_idx, now_ns);
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
}

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "../../../inc/core/util/config.h"
#include "../../../inc/core/forwarder/forwarder.h"
#include "../../../inc/core/forwarder/forwarder_crypto_runtime.h"
#include "../../../inc/core/flow/mac_learn.h"
#include "../../../inc/crypto/packet_crypto.h"
#include "../../../inc/crypto/pqc_handshake.h"

#define DIAG_KEY_PREFIX_LEN 9
#define NE_PQC_TBL_SLOTS    64

typedef struct {
    int profile_id;
    int policy_id;
    uint8_t key_prefix[4];
    int valid;
} ne_pqc_tbl_row_t;

static ne_pqc_tbl_row_t ne_pqc_tbl[NE_PQC_TBL_SLOTS];
static pthread_mutex_t ne_pqc_tbl_lock = PTHREAD_MUTEX_INITIALIZER;

static int key_prefix_nonzero(const uint8_t *key, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (key[i])
            return 1;
    }
    return 0;
}

static void print_system_table(const struct app_config *cfg, const char *event)
{
    mac_learn_log_runtime_table(NULL, cfg, event);
}

static void key_prefix_hex(char *out, size_t outsz, const uint8_t *key)
{
    snprintf(out, outsz, "%02X%02X%02X%02X", key[0], key[1], key[2], key[3]);
}

static void ne_pqc_tbl_hline(void)
{
    fprintf(stderr,
            "+----------+----------+----------+----------+\n");
}

/* Caller holds ne_pqc_tbl_lock. Only MATCH rows (HS ok + NE==PQC). */
static void ne_pqc_tbl_print_locked(const char *event)
{
    int printed = 0;

    fprintf(stderr, "\n  [ne-key] processing: %s\n", event ? event : "update");
    ne_pqc_tbl_hline();
    fprintf(stderr,
            "| %-8s | %-8s | %-8s | %-8s |\n",
            "profile", "policy", "ne", "pqc_hs");
    ne_pqc_tbl_hline();

    for (int i = 0; i < NE_PQC_TBL_SLOTS; i++) {
        char px[DIAG_KEY_PREFIX_LEN];

        if (!ne_pqc_tbl[i].valid)
            continue;
        key_prefix_hex(px, sizeof(px), ne_pqc_tbl[i].key_prefix);
        /* ne == pqc_hs by construction — same prefix both columns for peer compare */
        fprintf(stderr,
                "| %-8d | %-8d | %-8s | %-8s |\n",
                ne_pqc_tbl[i].profile_id,
                ne_pqc_tbl[i].policy_id,
                px, px);
        printed++;
    }

    if (!printed)
        fprintf(stderr,
                "| %-8s | %-8s | %-8s | %-8s |\n",
                "-", "-", "-", "-");
    ne_pqc_tbl_hline();
    fflush(stderr);
}

/*
 * Upsert MATCH row and reprint table (like MAC table updates).
 * Only when diversify ok (peers share PQC) and local NE == PQC.
 * Only the running profile stays in the table — drop other profiles.
 */
void main_diag_log_ne_pqc_match(int profile_id, int policy_id,
                                const uint8_t ne_key[32])
{
    uint8_t hs_keys[KEY_SLOT_COUNT][PQC_TRAFFIC_KEY_SZ];
    uint8_t key_ids[KEY_SLOT_COUNT];
    bool key_slots_valid[KEY_SLOT_COUNT];
    int slot = -1;
    int changed = 0;

    if (!ne_key || !key_prefix_nonzero(ne_key, 4))
        return;
    if (profile_id <= 0 || policy_id <= 0)
        return;
    if (sig_pqc_get_keys(policy_id, hs_keys, key_ids, key_slots_valid) != 0 ||
        !key_slots_valid[KEY_SLOT_CURRENT])
        return;
    if (memcmp(ne_key, hs_keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ) != 0)
        return;

    pthread_mutex_lock(&ne_pqc_tbl_lock);

    for (int i = 0; i < NE_PQC_TBL_SLOTS; i++) {
        if (!ne_pqc_tbl[i].valid)
            continue;
        if (ne_pqc_tbl[i].profile_id != profile_id) {
            ne_pqc_tbl[i].valid = 0;
            changed = 1;
            continue;
        }
        if (ne_pqc_tbl[i].policy_id == policy_id)
            slot = i;
    }
    if (slot < 0) {
        for (int i = 0; i < NE_PQC_TBL_SLOTS; i++) {
            if (!ne_pqc_tbl[i].valid) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0)
        slot = (profile_id ^ policy_id) % NE_PQC_TBL_SLOTS;

    if (!ne_pqc_tbl[slot].valid ||
        ne_pqc_tbl[slot].profile_id != profile_id ||
        ne_pqc_tbl[slot].policy_id != policy_id ||
        memcmp(ne_pqc_tbl[slot].key_prefix, ne_key, 4) != 0)
        changed = 1;

    ne_pqc_tbl[slot].profile_id = profile_id;
    ne_pqc_tbl[slot].policy_id = policy_id;
    memcpy(ne_pqc_tbl[slot].key_prefix, ne_key, 4);
    ne_pqc_tbl[slot].valid = 1;

    if (changed)
        ne_pqc_tbl_print_locked("match");

    pthread_mutex_unlock(&ne_pqc_tbl_lock);
}

void main_diag_ne_pqc_clear(int profile_id, int policy_id)
{
    int removed = 0;

    if (profile_id <= 0 || policy_id <= 0)
        return;

    pthread_mutex_lock(&ne_pqc_tbl_lock);
    for (int i = 0; i < NE_PQC_TBL_SLOTS; i++) {
        if (!ne_pqc_tbl[i].valid)
            continue;
        if (ne_pqc_tbl[i].profile_id == profile_id &&
            ne_pqc_tbl[i].policy_id == policy_id) {
            ne_pqc_tbl[i].valid = 0;
            removed = 1;
        }
    }
    if (removed)
        ne_pqc_tbl_print_locked("clear");
    pthread_mutex_unlock(&ne_pqc_tbl_lock);
}

void main_diag_ne_pqc_clear_all(void)
{
    int removed = 0;

    pthread_mutex_lock(&ne_pqc_tbl_lock);
    for (int i = 0; i < NE_PQC_TBL_SLOTS; i++) {
        if (!ne_pqc_tbl[i].valid)
            continue;
        ne_pqc_tbl[i].valid = 0;
        removed = 1;
    }
    if (removed)
        ne_pqc_tbl_print_locked("clear");
    pthread_mutex_unlock(&ne_pqc_tbl_lock);
}

void main_diag_log_no_update(int trigger_profile_id, const struct app_config *cfg) {
    if (!cfg)
        return;

    fprintf(stderr,
            "\n[DB] profile %d — no update (DB same as running, reload skipped)\n",
            trigger_profile_id);
    fprintf(stderr, "  unchanged: LAN=%d WAN=%d policies=%d\n",
            cfg->local_count, cfg->wan_count, cfg->policy_count);
    print_system_table(cfg, "db-no-update");
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_db_apply(const struct app_config *cfg, int trigger_profile_id,
                            const struct app_config *prev_cfg) {
    if (!cfg)
        return;

    fprintf(stderr, "\n[DB] profile %d — loaded from Postgres", trigger_profile_id);
    if (prev_cfg) {
        fprintf(stderr, " | delta LAN %d->%d WAN %d->%d policies %d->%d",
                prev_cfg->local_count, cfg->local_count,
                prev_cfg->wan_count, cfg->wan_count,
                prev_cfg->policy_count, cfg->policy_count);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "| profiles: %-3d | policies: %-3d |\n",
            cfg->profile_count, cfg->policy_count);
    print_system_table(cfg, "db-load");
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_db_policy_apply(const struct app_config *cfg, int trigger_profile_id,
                                   const struct app_config *prev_cfg) {
    if (!cfg)
        return;

    fprintf(stderr,
            "\n[DB] profile %d — policy update from Postgres\n",
            trigger_profile_id);
    if (prev_cfg) {
        fprintf(stderr, "  policies %d -> %d (LAN/WAN ifaces unchanged)\n",
                prev_cfg->policy_count, cfg->policy_count);
    }
    fprintf(stderr, "| profiles: %-3d | policies: %-3d |\n",
            cfg->profile_count, cfg->policy_count);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_config_summary(struct app_config *cfg, int trigger_profile_id,
                                  int is_reload, int policy_only) {
    if (!cfg)
        return;

    fprintf(stderr, "\n");
    if (is_reload) {
        fprintf(stderr, "+-- RELOAD profile %d (dataplane up, decrypt grace 3s) --+\n",
                trigger_profile_id);
    } else {
        fprintf(stderr, "+-- CONFIG profile %d --+\n", trigger_profile_id);
    }
    fprintf(stderr, "| profiles: %-3d | policies: %-3d |\n",
            cfg->profile_count, cfg->policy_count);
    if (!policy_only)
        print_system_table(cfg, is_reload ? "reload" : "config");
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_dataplane_ready(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return;

    fprintf(stderr, "+-- DATAPLANE ready --+\n");
    fprintf(stderr,
            "| mode: single-profile (1 UMEM/process; multi-profile UMEM later) |\n");
    mac_learn_refresh_iface_macs(fwd);
    mac_learn_log_runtime_table(fwd, fwd->cfg, "dataplane-ready");
    fprintf(stderr, "\n");
    fflush(stderr);
}

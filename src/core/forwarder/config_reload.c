#include "../../../inc/core/forwarder/forwarder_reload.h"
#include "../../../inc/core/forwarder/forwarder.h"
#include "../../../inc/core/forwarder/forwarder_wan.h"
#include "../../../inc/core/forwarder/forwarder_crypto_runtime.h"
#include "../../../inc/core/iface/profile_iface_xdp.h"
#include "../../../inc/core/failover/wan_failover.h"
#include "../../../inc/core/flow/mac_learn.h"
#include "pqc_handshake.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

static atomic_int reload_pending;
static atomic_int reload_done;
static struct forwarder *reload_fwd;
static struct app_config *reload_cfg;
static int reload_rc;
static pthread_mutex_t reload_wait_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reload_wait_cv = PTHREAD_COND_INITIALIZER;

static int wait_dataplane_workers(struct forwarder *fwd)
{
    for (int i = 0; i < 500; i++) {
        if (fwd && fwd->threads_started)
            return 0;
        if (forwarder_should_stop())
            return -1;
        usleep(10000);
    }
    fprintf(stderr, "[RELOAD] dataplane workers not ready yet (still starting)\n");
    return -1;
}

int forwarder_same_topology(const struct app_config *a, const struct app_config *b)
{
    if (!a || !b)
        return 0;
    if (a->local_count != b->local_count || a->wan_count != b->wan_count)
        return 0;
    if (a->local_count <= 0 || a->wan_count <= 0)
        return 0;

    for (int i = 0; i < a->local_count; i++) {
        int found = 0;
        for (int j = 0; j < b->local_count; j++) {
            if (strcmp(a->locals[i].ifname, b->locals[j].ifname) == 0) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }
    for (int i = 0; i < a->wan_count; i++) {
        int found = 0;
        for (int j = 0; j < b->wan_count; j++) {
            if (strcmp(a->wans[i].ifname, b->wans[j].ifname) == 0) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }
    return 1;
}

static int forwarder_reload_config_impl(struct forwarder *fwd, struct app_config *cfg)
{
    if (forwarder_should_stop())
        return -1;
    const struct app_config *old_cfg = fwd->cfg;

    fwd_wan_configure_live_drains(fwd, old_cfg, cfg);
    if (profile_iface_xdp_sync_wan_live(fwd, cfg, old_cfg) != 0)
        return -1;

    fwd->cfg = cfg;
    fwd_wan_weight_blend_begin(old_cfg, cfg, fwd_crypto_profile_slot_for_id);
    if (cfg->crypto_enabled) {
        pqc_handshake_start_all_profiles(cfg);
    }
    if (fwd_crypto_ensure_profile_slots(cfg) != 0) {
        fprintf(stderr, "[RELOAD] fwd_crypto_ensure_profile_slots failed\n");
        return -1;
    }
    if (forwarder_should_stop()) {
        fprintf(stderr, "[RELOAD] aborted before crypto rebuild (stop requested)\n");
        return -1;
    }
    fwd_crypto_snapshot_active_to_prev();
    int rc = fwd_crypto_rebuild(cfg);
    if (rc != 0)
        fprintf(stderr, "[RELOAD] fwd_crypto_rebuild failed\n");
    if (forwarder_should_stop())
        return -1;
    if (rc != 0)
        fwd_crypto_clear_grace();
    fwd_crypto_sync_flow_table_windows(fwd);
    fwd_crypto_cleanup_stale_profile_slots(cfg);
    wan_failover_on_cfg(fwd);
    /* Re-merge FDB from mac_lan.log after iface/settings hot reload. */
    mac_learn_restore(fwd);
    return forwarder_should_stop() ? -1 : rc;
}

static int forwarder_queue_reload(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg)
        return -1;
    if (forwarder_should_stop())
        return -1;
    if (wait_dataplane_workers(fwd) != 0)
        return -1;

    pthread_mutex_lock(&reload_wait_mtx);
    if (atomic_load_explicit(&reload_pending, memory_order_acquire) &&
        !atomic_load_explicit(&reload_done, memory_order_acquire)) {
        pthread_mutex_unlock(&reload_wait_mtx);
        fprintf(stderr,
                "[RELOAD] busy — another reload already in flight "
                "(single pending slot; serialize profile edits and retry)\n");
        fflush(stderr);
        return -1;
    }

    reload_fwd = fwd;
    reload_cfg = cfg;
    reload_rc = -1;
    atomic_store_explicit(&reload_done, 0, memory_order_release);
    atomic_store_explicit(&reload_pending, 1, memory_order_release);

    struct timespec deadline;
    int have_deadline = 0;
    if (clock_gettime(CLOCK_REALTIME, &deadline) == 0) {
        deadline.tv_sec += 60;
        have_deadline = 1;
    }

    while (!atomic_load_explicit(&reload_done, memory_order_acquire) &&
           !forwarder_should_stop()) {
        struct timespec ts;
        if (have_deadline) {
            ts = deadline;
        } else if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            pthread_cond_wait(&reload_wait_cv, &reload_wait_mtx);
            continue;
        } else {
            ts.tv_nsec += 200000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
        }
        int wr = pthread_cond_timedwait(&reload_wait_cv, &reload_wait_mtx, &ts);
        if (have_deadline && wr == ETIMEDOUT) {
            fprintf(stderr,
                    "[RELOAD] timed out waiting for mid core (60s) — cancel pending reload "
                    "(dataplane unchanged; retry -id notify)\n");
            fflush(stderr);
            atomic_store_explicit(&reload_pending, 0, memory_order_release);
            break;
        }
    }

    int rc = reload_rc;
    int finished = atomic_load_explicit(&reload_done, memory_order_acquire);
    pthread_mutex_unlock(&reload_wait_mtx);

    if (forwarder_should_stop())
        return -1;
    if (!finished) {
        fprintf(stderr, "[RELOAD] mid core did not finish reload (timeout/busy)\n");
        fflush(stderr);
        return -1;
    }
    if (rc != 0)
        fprintf(stderr, "[RELOAD] apply on mid core failed (rc=%d)\n", rc);
    return rc;
}

int forwarder_reload_config(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg)
        return -1;
    if (forwarder_should_stop())
        return -1;
    if (!forwarder_same_topology(fwd->cfg, cfg)) {
        fprintf(stderr,
                "[RELOAD] LAN/WAN set changed (add/remove interface) — hot reload not possible\n");
        return -1;
    }
    return forwarder_queue_reload(fwd, cfg);
}

int fwd_reload_apply_if_pending(void)
{
    if (!atomic_load_explicit(&reload_pending, memory_order_acquire))
        return 0;
    struct forwarder *fwd = reload_fwd;
    struct app_config *cfg = reload_cfg;
    if (!fwd || !cfg)
        return 0;
    reload_rc = forwarder_reload_config_impl(fwd, cfg);
    atomic_store_explicit(&reload_pending, 0, memory_order_release);
    atomic_store_explicit(&reload_done, 1, memory_order_release);
    pthread_mutex_lock(&reload_wait_mtx);
    pthread_cond_broadcast(&reload_wait_cv);
    pthread_mutex_unlock(&reload_wait_mtx);
    return 1;
}

void fwd_reload_shutdown(void)
{
    atomic_store_explicit(&reload_pending, 0, memory_order_release);
    atomic_store_explicit(&reload_done, 1, memory_order_release);
    pthread_mutex_lock(&reload_wait_mtx);
    reload_rc = -1;
    pthread_cond_broadcast(&reload_wait_cv);
    pthread_mutex_unlock(&reload_wait_mtx);
}

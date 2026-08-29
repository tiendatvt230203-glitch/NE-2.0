#include "../../../inc/core/forwarder/forwarder_wan.h"
#include "../../../inc/core/iface/profile_iface_xdp.h"
#include "../../../inc/core/failover/wan_failover.h"

#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/flow/flow_table.h"

#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define WAN_DRAIN_GRACE_MS (FORWARDER_WAN_DRAIN_SEC * 1000u)

typedef struct {
    int active;
    int legacy_cfg_wan;
    int seed_weight;
    char ifname[IF_NAMESIZE];
    uint64_t start_ms;
    uint64_t until_ms;
} wan_drain_slot;

typedef struct {
    int active;
    int profile_id;
    int n;
    int wan_cfg[MAX_PROFILE_INTERFACES];
    int old_w[MAX_PROFILE_INTERFACES];
    int new_w[MAX_PROFILE_INTERFACES];
    uint64_t start_ms;
    uint64_t until_ms;
} wan_weight_blend;

typedef struct {
    int active;
    int cfg_wan;
    int target_w;
    uint64_t start_ms;
    uint64_t until_ms;
} wan_join_ramp;

static wan_drain_slot wan_drains[MAX_INTERFACES];
static int wan_active_dp_count;
static uint8_t wan_stopped[MAX_INTERFACES];
static uint8_t wan_admin_hold[MAX_INTERFACES];
static wan_weight_blend wan_weight_blends[MAX_PROFILES];
static wan_join_ramp wan_joins[MAX_INTERFACES];

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static int wan_seed_weight_from_cfg(const struct app_config *cfg, int cfg_wan)
{
    int best = 1;
    const struct profile_config *p;

    if (!cfg || cfg->profile_count < 1)
        return best;
    p = &cfg->profiles[0];
    for (int wi = 0; wi < p->wan_count; wi++) {
        if (p->wan_indices[wi] != cfg_wan)
            continue;
        if (p->wan_bandwidth_weight[wi] > best)
            best = p->wan_bandwidth_weight[wi];
    }
    return best;
}

static int wan_drain_taper_pct(int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES || !wan_drains[dp].active)
        return 0;
    uint64_t now = monotonic_ms();
    if (now >= wan_drains[dp].until_ms)
        return 0;
    uint64_t left = wan_drains[dp].until_ms - now;
    if (WAN_DRAIN_GRACE_MS == 0)
        return 0;
    return (int)((left * 100ULL) / WAN_DRAIN_GRACE_MS);
}

int fwd_wan_dp_ok_for_new_traffic(int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES || wan_stopped[dp])
        return 0;
    if (wan_admin_hold[dp])
        return 0;
    if (wan_drains[dp].active)
        return 0;
    if (wan_failover_dp_excluded(dp))
        return 0;
    return dp < wan_active_dp_count;
}

int fwd_wan_is_stopped(int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES)
        return 1;
    return wan_stopped[dp] != 0 || wan_admin_hold[dp] != 0;
}

void fwd_wan_mark_stopped(int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES)
        return;
    wan_stopped[dp] = 1;
}

void fwd_wan_mark_live(int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES)
        return;
    wan_stopped[dp] = 0;
}

void fwd_wan_admin_hold_set(int dp, int held)
{
    if (dp < 0 || dp >= MAX_INTERFACES)
        return;
    wan_admin_hold[dp] = held ? 1 : 0;
}

int fwd_wan_admin_is_held(int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES)
        return 1;
    return wan_admin_hold[dp] != 0;
}

void fwd_wan_refresh_active(struct forwarder *fwd)
{
    wan_active_dp_count = fwd ? fwd->wan_count : 0;
}

int fwd_wan_ifname_dataplane_in_cfg(const struct app_config *cfg, const char *ifname)
{
    return config_wan_live_in_cfg(cfg, ifname);
}

uint32_t fwd_wan_flush_queue(struct forwarder *fwd, int wan_idx)
{
    struct ne_packet pkt;
    uint32_t dropped = 0;
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return 0;
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        while (ne_ring_try_pop(&fwd->mid_to_wan[wan_idx][w], &pkt) == 0) {
            ne_frame_free(&fwd->pair, pkt.addr);
            dropped++;
        }
    }
    return dropped;
}

int fwd_wan_has_tx_room(struct forwarder *fwd, int wan_idx)
{
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return 0;
    int wi = dp_out_ring_idx();
    struct ne_ring *r = &fwd->mid_to_wan[wan_idx][wi];
    return ne_ring_count(r) + NE_BATCH_SIZE < r->cap;
}

static void wan_drain_finish_slot(struct forwarder *fwd, int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES || !wan_drains[dp].active)
        return;

    uint32_t dropped = fwd_wan_flush_queue(fwd, dp);
    profile_iface_xdp_detach_wan(&fwd->pair, dp);
    wan_stopped[dp] = 1;
    wan_drains[dp].active = 0;
    fprintf(stderr,
            "[WAN-DRAIN] %s stopped (queue flushed %u pkts, XDP detached)\n",
            wan_drains[dp].ifname, dropped);
    fflush(stderr);
}

void fwd_wan_drain_tick(struct forwarder *fwd)
{
    if (!fwd)
        return;
    uint64_t now = monotonic_ms();
    int n = fwd->wan_count;
    if (n > MAX_INTERFACES)
        n = MAX_INTERFACES;
    for (int dp = 0; dp < n; dp++) {
        if (!wan_drains[dp].active)
            continue;
        int taper = wan_drain_taper_pct(dp);
        if (taper > 0)
            continue;
        if (now < wan_drains[dp].until_ms)
            continue;
        wan_drain_finish_slot(fwd, dp);
    }
}

void fwd_wan_reset_on_init(struct forwarder *fwd)
{
    wan_active_dp_count = fwd ? fwd->wan_count : 0;
    memset(wan_drains, 0, sizeof(wan_drains));
    memset(wan_stopped, 0, sizeof(wan_stopped));
    memset(wan_admin_hold, 0, sizeof(wan_admin_hold));
    memset(wan_joins, 0, sizeof(wan_joins));
}

void fwd_wan_configure_live_drains(struct forwarder *fwd,
                                   const struct app_config *old,
                                   const struct app_config *cfg)
{
    if (!fwd || !old || !cfg)
        return;

    int dp_n = fwd->wan_count;
    if (dp_n > MAX_INTERFACES)
        dp_n = MAX_INTERFACES;

    for (int dp = 0; dp < dp_n; dp++) {
        int ci = fwd->wan_cfg_idx[dp];

        if (ci < 0 || ci >= old->wan_count)
            continue;
        if (!config_wan_live(old, ci) || config_wan_live(cfg, ci))
            continue;
        if (wan_drains[dp].active || wan_stopped[dp])
            continue;

        wan_drains[dp].active = 1;
        wan_drains[dp].legacy_cfg_wan = ci;
        wan_drains[dp].seed_weight = wan_seed_weight_from_cfg(old, ci);
        snprintf(wan_drains[dp].ifname, sizeof(wan_drains[dp].ifname), "%s",
                 old->wans[ci].ifname);
        wan_drains[dp].start_ms = monotonic_ms();
        wan_drains[dp].until_ms = wan_drains[dp].start_ms + WAN_DRAIN_GRACE_MS;
        fprintf(stderr,
                "[WAN-DRAIN] %s weight=0 — taper %us (bandwidth removed, no new flows)\n",
                wan_drains[dp].ifname, (unsigned)(WAN_DRAIN_GRACE_MS / 1000u));
    }
    fflush(stderr);
}

static int wan_weight_blend_progress(const wan_weight_blend *b)
{
    if (!b || !b->active)
        return 100;
    uint64_t now = monotonic_ms();
    if (now >= b->until_ms)
        return 100;
    uint64_t elapsed = now - b->start_ms;
    uint64_t total = b->until_ms - b->start_ms;
    if (total == 0)
        return 100;
    return (int)((elapsed * 100ULL) / total);
}

static int profile_wan_weight_blended(const struct profile_config *p, int cfg_wan,
                                      int nominal_weight)
{
    if (!p || nominal_weight <= 0)
        return nominal_weight;

    {
        const wan_weight_blend *b = &wan_weight_blends[0];
        int pos;
        int blend;
        int w;

        if (!b->active || b->profile_id != p->id)
            return nominal_weight;
        pos = -1;
        for (int i = 0; i < b->n; i++) {
            if (b->wan_cfg[i] == cfg_wan) {
                pos = i;
                break;
            }
        }
        if (pos < 0)
            return nominal_weight;

        blend = wan_weight_blend_progress(b);
        w = (b->old_w[pos] * (100 - blend) + b->new_w[pos] * blend) / 100;
        return w > 0 ? w : 1;
    }
}

void fwd_wan_weight_blend_tick(void)
{
    if (wan_weight_blends[0].active &&
        wan_weight_blend_progress(&wan_weight_blends[0]) >= 100)
        wan_weight_blends[0].active = 0;
    fwd_wan_join_ramp_tick();
}

static int wan_join_ramp_pct(int cfg_wan)
{
    uint64_t now;
    int i;

    if (cfg_wan < 0)
        return -1;
    now = monotonic_ms();
    for (i = 0; i < MAX_INTERFACES; i++) {
        uint64_t total;
        uint64_t elapsed;

        if (!wan_joins[i].active || wan_joins[i].cfg_wan != cfg_wan)
            continue;
        if (now >= wan_joins[i].until_ms)
            return 100;
        total = wan_joins[i].until_ms - wan_joins[i].start_ms;
        if (total == 0)
            return 100;
        elapsed = now - wan_joins[i].start_ms;
        return (int)((elapsed * 100ULL) / total);
    }
    return -1;
}

void fwd_wan_join_ramp_begin(int cfg_wan, int target_weight)
{
    int slot = -1;
    int i;

    if (cfg_wan < 0)
        return;
    for (i = 0; i < MAX_INTERFACES; i++) {
        if (wan_joins[i].active && wan_joins[i].cfg_wan == cfg_wan) {
            slot = i;
            break;
        }
        if (slot < 0 && !wan_joins[i].active)
            slot = i;
    }
    if (slot < 0)
        return;
    wan_joins[slot].active = 1;
    wan_joins[slot].cfg_wan = cfg_wan;
    wan_joins[slot].target_w = target_weight > 0 ? target_weight : 1;
    wan_joins[slot].start_ms = monotonic_ms();
    wan_joins[slot].until_ms = wan_joins[slot].start_ms + WAN_DRAIN_GRACE_MS;
    fprintf(stderr, "[WAN-ADMIN] join ramp cfg_wan=%d weight 0→%d over %us\n",
            cfg_wan, wan_joins[slot].target_w,
            (unsigned)(WAN_DRAIN_GRACE_MS / 1000u));
    fflush(stderr);
}

void fwd_wan_join_ramp_tick(void)
{
    uint64_t now = monotonic_ms();
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (!wan_joins[i].active)
            continue;
        if (now >= wan_joins[i].until_ms)
            wan_joins[i].active = 0;
    }
}

void fwd_wan_weight_blend_begin(const struct app_config *old, const struct app_config *new,
                                int (*profile_slot_for_id)(int profile_id))
{
    if (!old || !new)
        return;

    wan_weight_blends[0].active = 0;

    if (old->profile_count < 1 || new->profile_count < 1) {
        fflush(stderr);
        return;
    }

    {
        const struct profile_config *np = &new->profiles[0];
        const struct profile_config *op = &old->profiles[0];
        int changed = 0;
        int slot;
        wan_weight_blend *b;

        (void)profile_slot_for_id;
        if (op->id != np->id || op->wan_count != np->wan_count) {
            fflush(stderr);
            return;
        }
        for (int i = 0; i < np->wan_count; i++) {
            if (op->wan_indices[i] != np->wan_indices[i] ||
                op->wan_bandwidth_weight[i] != np->wan_bandwidth_weight[i]) {
                changed = 1;
                break;
            }
        }
        if (!changed) {
            fflush(stderr);
            return;
        }

        slot = 0;
        b = &wan_weight_blends[slot];
        b->active = 1;
        b->profile_id = np->id;
        b->n = np->wan_count;
        b->start_ms = monotonic_ms();
        b->until_ms = b->start_ms + WAN_DRAIN_GRACE_MS;
        for (int i = 0; i < np->wan_count && i < MAX_PROFILE_INTERFACES; i++) {
            b->wan_cfg[i] = np->wan_indices[i];
            b->old_w[i] = op->wan_bandwidth_weight[i];
            b->new_w[i] = np->wan_bandwidth_weight[i];
        }
        fprintf(stderr,
                "[WAN-BALANCE] profile %d — WAN weights blend %us (old→new, flows migrate gradually)\n",
                np->id, (unsigned)(WAN_DRAIN_GRACE_MS / 1000u));
    }
    fflush(stderr);
}

int fwd_wan_live_dp_for_cfg(struct forwarder *fwd, int cfg_wan)
{
    int n;

    if (!fwd || cfg_wan < 0)
        return -1;
    n = fwd->wan_count;
    if (fwd->pair.wan_count > n)
        n = fwd->pair.wan_count;
    if (n > MAX_INTERFACES)
        n = MAX_INTERFACES;
    for (int dp = 0; dp < n; dp++) {
        if (fwd->wan_cfg_idx[dp] != cfg_wan)
            continue;
        if (!fwd_wan_dp_ok_for_new_traffic(dp))
            return -1;
        return dp;
    }
    return -1;
}

int fwd_wan_build_profile_pool(struct forwarder *fwd, const struct profile_config *p,
                               int *allowed_wans, int *allowed_weights, int max_n)
{
    int live_cfg[MAX_PROFILE_INTERFACES];
    int live_w[MAX_PROFILE_INTERFACES];
    int live_n = 0;
    int dead_weight = 0;
    int n = 0;

    if (!fwd || !p || !allowed_wans || !allowed_weights || max_n <= 0)
        return 0;

    for (int i = 0; i < p->wan_count && live_n < MAX_PROFILE_INTERFACES; i++) {
        int wi = p->wan_indices[i];
        int base = profile_wan_weight_blended(p, wi, p->wan_bandwidth_weight[i]);
        int dp;
        int ramp;

        /*
         * weight=0: XDP vẫn gắn, ARP bridge vẫn TX — nhưng không vào WRR data
         * (tcp/udp/icmp/ospf). Không redistribute dead_weight (cố ý 0).
         */
        if (base <= 0)
            continue;

        dp = fwd_wan_live_dp_for_cfg(fwd, wi);
        if (dp < 0) {
            dead_weight += base;
            continue;
        }

        ramp = wan_join_ramp_pct(wi);
        if (ramp == 0) {
            dead_weight += base;
            continue;
        }

        live_cfg[live_n] = wi;
        live_w[live_n] = base;
        if (ramp > 0 && ramp < 100) {
            live_w[live_n] = (live_w[live_n] * ramp) / 100;
            if (live_w[live_n] <= 0)
                live_w[live_n] = 1;
        }
        live_n++;
    }

    if (live_n > 0 && dead_weight > 0) {
        int share = dead_weight / live_n;
        int rem = dead_weight % live_n;

        for (int i = 0; i < live_n; i++)
            live_w[i] += share + (i < rem ? 1 : 0);
    }

    for (int i = 0; i < live_n && n < max_n; i++) {
        allowed_wans[n] = live_cfg[i];
        allowed_weights[n] = live_w[i];
        n++;
    }

    {
        int wan_n = fwd->wan_count;
        if (wan_n > MAX_INTERFACES)
            wan_n = MAX_INTERFACES;
        for (int dp = 0; dp < wan_n && n < max_n; dp++) {
            int taper;
            if (!wan_drains[dp].active || wan_stopped[dp])
                continue;
            taper = wan_drain_taper_pct(dp);
            if (taper <= 0)
                continue;
            allowed_wans[n] = wan_drains[dp].legacy_cfg_wan;
            allowed_weights[n] = (wan_drains[dp].seed_weight * taper) / 100;
            if (allowed_weights[n] <= 0)
                allowed_weights[n] = 1;
            n++;
        }
    }
    return n;
}

int fwd_wan_dp_for_legacy_cfg(struct forwarder *fwd, int legacy_cfg_wan)
{
    int n = fwd->wan_count;
    if (n > MAX_INTERFACES)
        n = MAX_INTERFACES;
    for (int dp = 0; dp < n; dp++) {
        if (!wan_drains[dp].active || wan_stopped[dp])
            continue;
        if (wan_drains[dp].legacy_cfg_wan != legacy_cfg_wan)
            continue;
        if (wan_drain_taper_pct(dp) <= 0)
            continue;
        return dp;
    }
    (void)fwd;
    return -1;
}

static int pick_least_loaded_wan(struct forwarder *fwd, int profile_idx, int selected)
{
    if (fwd_wan_has_tx_room(fwd, selected))
        return selected;

    int best = -1;
    uint32_t best_depth = UINT32_MAX;
    int profile_pool = 0;

    if (profile_idx >= 0 && profile_idx < fwd->cfg->profile_count) {
        struct profile_config *p = &fwd->cfg->profiles[profile_idx];

        profile_pool = p->wan_count > 0;
        for (int i = 0; i < p->wan_count; i++) {
            /* weight=0: ARP-only — never pick for data fallback. */
            if (p->wan_bandwidth_weight[i] <= 0)
                continue;
            int dp = fwd_wan_live_dp_for_cfg(fwd, p->wan_indices[i]);
            if (dp < 0 || !fwd_wan_has_tx_room(fwd, dp))
                continue;
            uint32_t d = fwd_mid_to_wan_depth(fwd, dp);
            if (d < best_depth) {
                best_depth = d;
                best = dp;
            }
        }
        if (best >= 0)
            return best;
    }

    if (profile_pool)
        return selected;

    for (int wi = 0; wi < fwd->wan_count; wi++) {
        if (!fwd_wan_dp_ok_for_new_traffic(wi) || !fwd_wan_has_tx_room(fwd, wi))
            continue;
        uint32_t d = fwd_mid_to_wan_depth(fwd, wi);
        if (d < best_depth) {
            best_depth = d;
            best = wi;
        }
    }
    return best >= 0 ? best : selected;
}

int fwd_wan_pick_for_local(struct forwarder *fwd, int profile_idx, int flow_ok,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint8_t proto)
{
    if (!fwd || fwd->wan_count <= 0)
        return -1;
    if (profile_idx < 0 || profile_idx >= fwd->cfg->profile_count)
        return pick_least_loaded_wan(fwd, profile_idx, 0);

    struct profile_config *p = &fwd->cfg->profiles[profile_idx];
    int allowed_wans[MAX_INTERFACES];
    int allowed_weights[MAX_INTERFACES];
    int pool_n = fwd_wan_build_profile_pool(fwd, p, allowed_wans, allowed_weights,
                                            MAX_INTERFACES);
    if (pool_n <= 0)
        return pick_least_loaded_wan(fwd, profile_idx, 0);

    int wan_cfg = flow_ok
        ? flow_table_pick_wan_per_flow_packet(src_ip, dst_ip, src_port, dst_port, proto,
                                              allowed_wans, allowed_weights, pool_n)
        : flow_table_pick_wan_per_packet(allowed_wans, allowed_weights, pool_n);
    if (wan_cfg < 0)
        return pick_least_loaded_wan(fwd, profile_idx, 0);

    int dp = fwd_wan_live_dp_for_cfg(fwd, wan_cfg);
    if (dp < 0)
        dp = fwd_wan_dp_for_legacy_cfg(fwd, wan_cfg);
    if (dp < 0 || dp >= fwd->wan_count || !fwd_wan_dp_ok_for_new_traffic(dp))
        return pick_least_loaded_wan(fwd, profile_idx, 0);

    /* Do not drop only because the scheduled WAN ring is full while another
     * eligible WAN still has room.  The smooth state advances as if selected,
     * so the configured long-term ratio converges after the transient. */
    return pick_least_loaded_wan(fwd, profile_idx, dp);
}

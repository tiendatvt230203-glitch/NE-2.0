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
    char ifname[IF_NAMESIZE];
    uint64_t until_ms;
} wan_drain_slot;

static wan_drain_slot wan_drains[MAX_INTERFACES];
static int wan_active_dp_count;
static uint8_t wan_stopped[MAX_INTERFACES];
static uint8_t wan_admin_hold[MAX_INTERFACES];

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
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
        snprintf(wan_drains[dp].ifname, sizeof(wan_drains[dp].ifname), "%s",
                 old->wans[ci].ifname);
        wan_drains[dp].until_ms = monotonic_ms() + WAN_DRAIN_GRACE_MS;
        fprintf(stderr,
                "[WAN-DRAIN] %s removed from data pool — drain %us (no new traffic)\n",
                wan_drains[dp].ifname, (unsigned)(WAN_DRAIN_GRACE_MS / 1000u));
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
                               int *allowed_wans, int max_n)
{
    int n = 0;

    if (!fwd || !p || !allowed_wans || max_n <= 0)
        return 0;

    for (int i = 0; i < p->wan_count && n < max_n; i++) {
        int wi = p->wan_indices[i];

        /*
         * Weight 0 disables data on this WAN. Every positive value means the
         * same share; with two live WANs the data pool is always 50/50.
         * ARP remains independent from this data scheduling decision.
         */
        if (p->wan_bandwidth_weight[i] <= 0)
            continue;
        if (fwd_wan_live_dp_for_cfg(fwd, wi) < 0)
            continue;
        allowed_wans[n] = wi;
        n++;
    }
    return n;
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
                           uint8_t proto,
                           enum flow_wan_window_class window_class)
{
    int strict_window = window_class == FLOW_WAN_WINDOW_MTU9000;

    if (!fwd || fwd->wan_count <= 0)
        return -1;
    /* MTU9000 scheduling must always be attached to a parsed connection key.
     * Falling back to the global scheduler would mix unrelated connections
     * and break the 1024-original-packet window. */
    if (strict_window && !flow_ok)
        return -1;
    if (profile_idx < 0 || profile_idx >= fwd->cfg->profile_count)
        return strict_window ? -1 : pick_least_loaded_wan(fwd, profile_idx, 0);

    struct profile_config *p = &fwd->cfg->profiles[profile_idx];
    int allowed_wans[MAX_INTERFACES];
    int pool_n = fwd_wan_build_profile_pool(fwd, p, allowed_wans, MAX_INTERFACES);
    if (pool_n <= 0)
        return strict_window ? -1 : pick_least_loaded_wan(fwd, profile_idx, 0);

    int wan_cfg = flow_ok
        ? flow_table_pick_wan_per_flow_packet(src_ip, dst_ip, src_port, dst_port, proto,
                                              allowed_wans, pool_n, window_class)
        : flow_table_pick_wan_per_packet(allowed_wans, pool_n);
    if (wan_cfg < 0)
        return strict_window ? -1 : pick_least_loaded_wan(fwd, profile_idx, 0);

    int dp = fwd_wan_live_dp_for_cfg(fwd, wan_cfg);
    if (dp < 0 || dp >= fwd->wan_count || !fwd_wan_dp_ok_for_new_traffic(dp))
        return strict_window ? -1 : pick_least_loaded_wan(fwd, profile_idx, 0);

    /* Every original MTU9000 packet, including all of its wire fragments,
     * stays on the selected WAN for the full per-connection window. */
    if (strict_window)
        return dp;

    /* If the equal-share WAN ring is temporarily full, use another eligible
     * WAN with room so a transient queue spike does not force a data drop. */
    return pick_least_loaded_wan(fwd, profile_idx, dp);
}

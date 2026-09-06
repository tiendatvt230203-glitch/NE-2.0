#include "../../../inc/core/iface/profile_iface_lifecycle.h"

#include "../../../inc/core/forwarder/forwarder_wan.h"
#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/iface/profile_iface_xdp.h"

#include <net/if.h>
#include <stdio.h>
#include <string.h>

static int fwd_ensure_mid_wan_rings(struct forwarder *fwd, int di)
{
    if (!fwd || di < 0 || di >= MAX_INTERFACES)
        return -1;
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        if (fwd->mid_to_wan[di][w].cap != 0)
            continue;
        if (ne_ring_init(&fwd->mid_to_wan[di][w], NE_RING, 1) != 0) {
            fprintf(stderr,
                    "[PROFILE-LIFE] mid_to_wan ring init failed slot %d worker %d\n",
                    di, w);
            return -1;
        }
    }
    return 0;
}

static const struct profile_config *profile_by_id(const struct app_config *cfg, int profile_id)
{
    if (!cfg || profile_id <= 0 || cfg->profile_count < 1)
        return NULL;
    if (cfg->profiles[0].id == profile_id)
        return &cfg->profiles[0];
    return NULL;
}

static int pair_wan_dp_slot_live(const struct forwarder *fwd, const char *ifname)
{
    if (!fwd || !ifname)
        return -1;
    for (int di = 0; di < fwd->pair.wan_count; di++) {
        if (!ne_pair_wan_live(&fwd->pair, di))
            continue;
        if (strcmp(fwd->pair.wans[di].ifname, ifname) == 0)
            return di;
    }
    return -1;
}

static int fwd_alloc_wan_slot(struct forwarder *fwd)
{
    int n;

    if (!fwd)
        return -1;
    n = fwd->pair.wan_count;
    for (int i = 0; i < n; i++) {
        if (!ne_pair_wan_live(&fwd->pair, i))
            return i;
    }
    if (n < MAX_INTERFACES)
        return n;
    return -1;
}

static void init_fwd_wan_meta(struct forwarder *fwd, int di,
                              const struct app_config *cfg, int cfg_wan_idx)
{
    memset(&fwd->wans[di], 0, sizeof(fwd->wans[di]));
    fwd->wans[di].ifindex = (int)if_nametoindex(cfg->wans[cfg_wan_idx].ifname);
    strncpy(fwd->wans[di].ifname, cfg->wans[cfg_wan_idx].ifname,
            sizeof(fwd->wans[di].ifname) - 1);
}

void profile_iface_life_reconcile_counts(struct forwarder *fwd)
{
    int max_li = 0;
    int max_di = 0;

    if (!fwd)
        return;
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (ne_pair_local_live(&fwd->pair, i) && i + 1 > max_li)
            max_li = i + 1;
        if (ne_pair_wan_live(&fwd->pair, i) && i + 1 > max_di)
            max_di = i + 1;
    }
    fwd->local_count = max_li;
    fwd->pair.local_count = max_li;
    fwd->wan_count = max_di;
    fwd->pair.wan_count = max_di;
}

void profile_iface_life_attach_rollback(struct forwarder *fwd,
                                       struct profile_attach_sess *sess)
{
    if (!fwd || !sess)
        return;
    for (int i = sess->lan_n - 1; i >= 0; i--)
        ne_pair_unplumb_local(&fwd->pair, sess->lan_added[i]);
    for (int i = sess->wan_n - 1; i >= 0; i--) {
        ne_pair_unplumb_wan_dp(&fwd->pair, sess->wan_added[i]);
        fwd->wan_cfg_idx[sess->wan_added[i]] = -1;
        fwd_wan_mark_stopped(sess->wan_added[i]);
    }
    sess->lan_n = 0;
    sess->wan_n = 0;
    profile_iface_life_reconcile_counts(fwd);
}

void profile_iface_life_attach_wan_rows(struct forwarder *fwd,
                                       const struct app_config *new_cfg,
                                       int trigger_profile_id,
                                       struct profile_attach_sess *sess)
{
    const struct profile_config *prof = profile_by_id(new_cfg, trigger_profile_id);

    if (!prof || !sess || !fwd || !new_cfg)
        return;

    for (int pi = 0; pi < prof->wan_count; pi++) {
        int ci = prof->wan_indices[pi];
        const char *ifname;
        int di;

        if (sess->validate_failed)
            break;
        if (ci < 0 || ci >= new_cfg->wan_count)
            continue;
        if (!config_wan_live(new_cfg, ci)) {
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip WAN %s (not_dataplane)\n",
                    trigger_profile_id, new_cfg->wans[ci].ifname);
            continue;
        }
        ifname = new_cfg->wans[ci].ifname;
        if (if_nametoindex(ifname) == 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (interface not found)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        if (pair_wan_dp_slot_live(fwd, ifname) >= 0) {
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip WAN %s (already_live)\n",
                    trigger_profile_id, ifname);
            continue;
        }

        di = fwd_alloc_wan_slot(fwd);
        if (di < 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (MAX_INTERFACES)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        fprintf(stderr, "[PROFILE-LIFE] profile %d ADD WAN %s (dp slot %d)\n",
                trigger_profile_id, ifname, di);
        fflush(stderr);
        if (fwd_ensure_mid_wan_rings(fwd, di) != 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (egress ring init failed)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        if (ne_pair_plumb_wan_dp(&fwd->pair, new_cfg, ci, di) != 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (plumb/XSK failed)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        if (profile_iface_xdp_bind_wan(&fwd->pair, new_cfg, di,
                                       new_cfg->fake_ethertype_ipv4) != 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (xdp attach/xsk map failed)\n",
                    trigger_profile_id, ifname);
            ne_pair_unplumb_wan_dp(&fwd->pair, di);
            sess->validate_failed = 1;
            continue;
        }
        fwd->pair.xdp_wan_on[di] = 1;
        init_fwd_wan_meta(fwd, di, new_cfg, ci);
        fwd->wan_cfg_idx[di] = ci;
        fwd_wan_mark_live(di);
        fwd->wan_count = fwd->pair.wan_count;
        sess->wan_added[sess->wan_n++] = di;
    }
}

#include "../../../inc/core/iface/profile_iface_xdp.h"
#include "../../../inc/core/iface/profile_iface_lifecycle.h"

#include "../../../inc/core/iface/interface.h"
#include "../../../inc/crypto/eth_parse.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void profile_xdp_stop_log(const char *step, const char *ifname)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        fprintf(stderr, "[STOP] xdp %s", step);
        if (ifname && ifname[0])
            fprintf(stderr, " %s", ifname);
        fprintf(stderr, "\n");
        fflush(stderr);
        return;
    }
    fprintf(stderr, "[STOP] %ld.%03ld xdp %s",
            (long)ts.tv_sec, ts.tv_nsec / 1000000L, step);
    if (ifname && ifname[0])
        fprintf(stderr, " %s", ifname);
    fprintf(stderr, "\n");
    fflush(stderr);
}

static int profile_iface_ifname_safe(const char *ifname)
{
    if (!ifname || !ifname[0])
        return 0;
    for (const char *p = ifname; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.')
            return 0;
    }
    return 1;
}

static void profile_iface_xdp_link_off(const char *ifname)
{
    char cmd[160];
    int rc;

    if (!profile_iface_ifname_safe(ifname))
        return;

    profile_xdp_stop_log("detach begin", ifname);
    /* ip link only — bpf_xdp_detach can block forever when no prog
     * is attached (post-crash scrub) or after bpf_object__close already ran. */
    snprintf(cmd, sizeof(cmd), "/sbin/ip link set dev %s xdp off >/dev/null 2>&1",
             ifname);
    rc = system(cmd);
    if (rc != 0)
        fprintf(stderr, "[PROFILE-XDP] failed to detach XDP from %s (system=%d)\n",
                ifname, rc);
    profile_xdp_stop_log("detach done", ifname);
}

void profile_iface_xdp_detach_ifname(const char *ifname)
{
    if (!ifname || !ifname[0])
        return;
    profile_iface_xdp_link_off(ifname);
}

void profile_iface_xdp_detach_config(const struct app_config *cfg)
{
    if (!cfg)
        return;
    for (int i = 0; i < cfg->local_count && i < MAX_INTERFACES; i++)
        profile_iface_xdp_detach_ifname(cfg->locals[i].ifname);
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        profile_iface_xdp_detach_ifname(cfg->wans[i].ifname);
}

void profile_iface_xdp_detach_local(struct ne_pair *p, int pair_li)
{
    if (!p || pair_li < 0 || pair_li >= MAX_INTERFACES)
        return;
    if (!p->xdp_local_on[pair_li] && !p->bpf_locals[pair_li])
        return;

    fprintf(stderr, "[PROFILE-XDP] DETACH LAN %s (slot %d)\n",
            p->locals[pair_li].ifname, pair_li);
    fflush(stderr);
    ne_pair_delete_local_xsks(p, pair_li);
    if (p->bpf_locals[pair_li]) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
    }
    p->xdp_local_on[pair_li] = 0;
    profile_iface_xdp_link_off(p->locals[pair_li].ifname);
}

void profile_iface_xdp_detach_wan(struct ne_pair *p, int dp_slot)
{
    if (!p || dp_slot < 0 || dp_slot >= MAX_INTERFACES)
        return;
    if (!p->xdp_wan_on[dp_slot] && !p->bpf_wans[dp_slot])
        return;

    fprintf(stderr, "[PROFILE-XDP] DETACH WAN %s (dp slot %d)\n",
            p->wans[dp_slot].ifname, dp_slot);
    fflush(stderr);
    ne_pair_delete_wan_xsks(p, dp_slot);
    if (p->bpf_wans[dp_slot]) {
        bpf_object__close(p->bpf_wans[dp_slot]);
        p->bpf_wans[dp_slot] = NULL;
    }
    p->xdp_wan_on[dp_slot] = 0;
    profile_iface_xdp_link_off(p->wans[dp_slot].ifname);
}

void profile_iface_xdp_prepare_init(const struct app_config *cfg)
{
    if (!cfg)
        return;
    fprintf(stderr, "[PROFILE-XDP] prepare: scrub leftover XDP on configured LAN/WAN\n");
    fflush(stderr);
    profile_iface_xdp_detach_config(cfg);

    usleep(200000);
    profile_iface_xdp_detach_config(cfg);
    interface_reset_redirect_maps();
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

/* --- BPF / XDP bind --- */

static int profile_iface_ifindex(const char *ifname, const char *role)
{
    unsigned int idx;

    if (!ifname || !ifname[0]) {
        fprintf(stderr, "[PROFILE-XDP] %s: missing interface name\n", role);
        return -1;
    }
    idx = if_nametoindex(ifname);
    if (idx == 0) {
        fprintf(stderr, "[PROFILE-XDP] %s %s: interface not found\n", role, ifname);
        return -1;
    }
    return (int)idx;
}

static int xdp_attach_prog(int ifindex, int prog_fd, const char *ifname, const char *role)
{
    int rc = bpf_xdp_attach(ifindex, prog_fd, NE_XDP_REQUIRED_MODE, NULL);

    if (rc) {
        fprintf(stderr,
                "[PROFILE-XDP] attach failed %s %s: native DRV mode required; "
                "SKB/generic fallback disabled: %s\n",
                role, ifname, strerror(rc < 0 ? -rc : rc));
        fflush(stderr);
        return -1;
    }
    fprintf(stderr,
            "[PROFILE-XDP] attach OK %s %s (drv, AF_XDP copy-only)\n",
            role, ifname);
    fflush(stderr);
    return 0;
}

static const char *resolve_bpf_object_path(const char *path, char resolved[PATH_MAX])
{
    char exe_path[PATH_MAX];
    ssize_t n;
    char *slash;

    if (!path || path[0] == '/' || access(path, R_OK) == 0)
        return path;

    n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n <= 0)
        return path;
    exe_path[n] = '\0';

    slash = strrchr(exe_path, '/');
    if (!slash)
        return path;
    *slash = '\0';

    if (snprintf(resolved, PATH_MAX, "%s/%s", exe_path, path) >= PATH_MAX)
        return path;
    return resolved;
}

static int open_bpf_object(const char *path, struct bpf_object **obj_out,
                           const char *prog_name, struct bpf_program **prog_out,
                           const char *map_name, struct bpf_map **map_out)
{
    char resolved_path[PATH_MAX];
    const char *open_path;
    struct bpf_object *obj;

    open_path = resolve_bpf_object_path(path, resolved_path);

    obj = bpf_object__open_file(open_path, NULL);

    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[PROFILE-XDP] bpf open failed: %s\n", open_path);
        return -1;
    }
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "[PROFILE-XDP] bpf load failed: %s\n", open_path);
        bpf_object__close(obj);
        return -1;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
    if (!prog || !map) {
        fprintf(stderr, "[PROFILE-XDP] bpf object %s missing prog/map\n", open_path);
        bpf_object__close(obj);
        return -1;
    }
    *obj_out = obj;
    *prog_out = prog;
    *map_out = map;
    return 0;
}

static int update_xsk_map_queue(struct xsk_socket *xsk, int map_fd, int queue_id)
{
    int key = queue_id;
    int fd = xsk_socket__fd(xsk);

    if (xsk_socket__update_xskmap(xsk, map_fd) == 0)
        return 0;
    return bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY);
}

static int update_xsk_map_iface(struct ne_iface *iface, int map_fd)
{
    for (int q = 0; q < iface->queue_count; q++) {
        if (!iface->queues[q].xsk)
            return -1;
        if (update_xsk_map_queue(iface->queues[q].xsk, map_fd, q) != 0)
            return -1;
    }
    return 0;
}

static void update_wan_fake_ethertype(struct bpf_object *obj, uint16_t fake_ethertype_ipv4)
{
    struct bpf_map *map;
    int key = 0;
    uint16_t et = (uint16_t)NE_L2_FAKE_ETHERTYPE;
    uint16_t udp_et = (uint16_t)NE_L2_FAKE_ETHERTYPE_UDP;

    (void)fake_ethertype_ipv4;
    if (!obj) {
        return;
    }
    map = bpf_object__find_map_by_name(obj, "wan_config_map");
    if (!map) {
        return;
    }
    (void)bpf_map_update_elem(bpf_map__fd(map), &key, &et, BPF_ANY);
    key = 1;
    (void)bpf_map_update_elem(bpf_map__fd(map), &key, &udp_et, BPF_ANY);
}

int profile_iface_xdp_bind_local(struct ne_pair *p, const struct app_config *cfg, int pair_li)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;
    const char *ifname;

    if (!p || !cfg || pair_li < 0 || pair_li >= p->local_count)
        return -1;

    ifname = p->locals[pair_li].ifname;
    if (profile_iface_ifindex(ifname, "LAN") < 0)
        return -1;

    if (p->bpf_locals[pair_li]) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
        p->xdp_local_on[pair_li] = 0;
    }

    if (open_bpf_object(cfg->bpf_file, &p->bpf_locals[pair_li],
                        "xdp_redirect_prog", &prog, "xsks_map", &map) != 0)
        return -1;
    profile_iface_xdp_link_off(ifname);
    if (xdp_attach_prog(p->locals[pair_li].ifindex, bpf_program__fd(prog),
                        ifname, "LAN") != 0) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
        return -1;
    }
    p->xdp_local_on[pair_li] = 1;
    return update_xsk_map_iface(&p->locals[pair_li], bpf_map__fd(map));
}

int profile_iface_xdp_bind_wan(struct ne_pair *p, const struct app_config *cfg, int dp_slot,
                               uint16_t fake_ethertype_ipv4)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;

    if (!p || !cfg || dp_slot < 0 || dp_slot >= p->wan_count)
        return -1;
    if (profile_iface_ifindex(p->wans[dp_slot].ifname, "WAN") < 0)
        return -1;
    if (open_bpf_object(cfg->bpf_wan_file, &p->bpf_wans[dp_slot],
                        "xdp_wan_redirect_prog", &prog, "wan_xsks_map", &map) != 0)
        return -1;
    update_wan_fake_ethertype(p->bpf_wans[dp_slot], fake_ethertype_ipv4);
    profile_iface_xdp_link_off(p->wans[dp_slot].ifname);
    if (xdp_attach_prog(p->wans[dp_slot].ifindex, bpf_program__fd(prog),
                        p->wans[dp_slot].ifname, "WAN") != 0) {
        bpf_object__close(p->bpf_wans[dp_slot]);
        p->bpf_wans[dp_slot] = NULL;
        return -1;
    }
    p->xdp_wan_on[dp_slot] = 1;
    return update_xsk_map_iface(&p->wans[dp_slot], bpf_map__fd(map));
}

int profile_iface_xdp_attach_init(struct ne_pair *p, const struct app_config *cfg)
{
    if (!p || !cfg)
        return -1;

    fprintf(stderr, "[PROFILE-XDP] cold attach: %d LAN, %d WAN(dp)\n",
            p->local_count, p->wan_count);
    fflush(stderr);

    for (int i = 0; i < p->local_count; i++) {
        if (profile_iface_xdp_bind_local(p, cfg, i) != 0) {
            fprintf(stderr, "[PROFILE-XDP] cold attach failed LAN %s (slot %d)\n",
                    p->locals[i].ifname, i);
            fflush(stderr);
            return -1;
        }
    }
    for (int di = 0; di < p->wan_count; di++) {
        if (profile_iface_xdp_bind_wan(p, cfg, di, cfg->fake_ethertype_ipv4) != 0) {
            fprintf(stderr, "[PROFILE-XDP] cold attach failed WAN %s (dp %d)\n",
                    p->wans[di].ifname, di);
            fflush(stderr);
            return -1;
        }
    }
    return 0;
}

int profile_iface_xdp_sync_wan_live(struct forwarder *fwd, const struct app_config *new_cfg,
                                    const struct app_config *old_cfg)
{
    if (!fwd || !new_cfg || !old_cfg || forwarder_should_stop())
        return -1;
    if (new_cfg->profile_count < 1)
        return 0;

    {
        const struct profile_config *prof = &new_cfg->profiles[0];
        struct profile_attach_sess sess;
        int need_attach = 0;

        for (int wi = 0; wi < prof->wan_count; wi++) {
            int ci = prof->wan_indices[wi];

            if (ci < 0 || ci >= new_cfg->wan_count)
                continue;
            if (!config_wan_live(new_cfg, ci))
                continue;
            if (pair_wan_dp_slot_live(fwd, new_cfg->wans[ci].ifname) >= 0)
                continue;
            need_attach = 1;
            break;
        }
        if (!need_attach)
            return 0;

        memset(&sess, 0, sizeof(sess));
        profile_iface_life_attach_wan_rows(fwd, new_cfg, prof->id, &sess);
        if (sess.validate_failed) {
            profile_iface_life_attach_rollback(fwd, &sess);
            fprintf(stderr,
                    "[PROFILE-XDP] profile %d: WAN live attach failed\n",
                    prof->id);
            return -1;
        }
        if (sess.wan_n > 0)
            profile_iface_life_reconcile_counts(fwd);
    }
    return 0;
}

#include "../../../inc/core/iface/xdp_attach.h"

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

/* The packaged libxdp carries the matching libbpf implementation, including
 * this API, while the appliance headers can predate its declaration. */
#ifndef BPF_F_XDP_HAS_FRAGS
#define BPF_F_XDP_HAS_FRAGS (1U << 5)
#endif
extern int bpf_program__set_flags(struct bpf_program *prog, __u32 flags);

static void xdp_attach_stop_log(const char *step, const char *ifname)
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

static int xdp_attach_ifname_safe(const char *ifname)
{
    if (!ifname || !ifname[0])
        return 0;
    for (const char *p = ifname; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.')
            return 0;
    }
    return 1;
}

static void xdp_attach_link_off(const char *ifname)
{
    char cmd[160];

    if (!xdp_attach_ifname_safe(ifname))
        return;

    xdp_attach_stop_log("detach begin", ifname);
    /* ip link only — bpf_xdp_detach on ice can block forever when no prog
     * is attached (post-crash scrub) or after bpf_object__close already ran. */
    snprintf(cmd, sizeof(cmd), "/sbin/ip link set dev %s xdp off >/dev/null 2>&1",
             ifname);
    int rc = system(cmd);
    (void)rc;
    xdp_attach_stop_log("detach done", ifname);
}

void xdp_attach_detach_ifname(const char *ifname)
{
    if (!ifname || !ifname[0])
        return;
    xdp_attach_link_off(ifname);
}

void xdp_attach_detach_config(const struct app_config *cfg)
{
    if (!cfg)
        return;
    for (int i = 0; i < cfg->local_count && i < MAX_INTERFACES; i++)
        xdp_attach_detach_ifname(cfg->locals[i].ifname);
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        xdp_attach_detach_ifname(cfg->wans[i].ifname);
}


void xdp_attach_prepare_init(const struct app_config *cfg)
{
    if (!cfg)
        return;
    fprintf(stderr, "[XDP] prepare: scrub leftover XDP on configured LAN/WAN\n");
    fflush(stderr);
    xdp_attach_detach_config(cfg);

    usleep(200000);
    xdp_attach_detach_config(cfg);
}

/* --- BPF / XDP bind --- */

static int xdp_attach_ifindex(const char *ifname, const char *role)
{
    unsigned int idx;

    if (!ifname || !ifname[0]) {
        fprintf(stderr, "[XDP] %s: missing interface name\n", role);
        return -1;
    }
    idx = if_nametoindex(ifname);
    if (idx == 0) {
        fprintf(stderr, "[XDP] %s %s: interface not found\n", role, ifname);
        return -1;
    }
    return (int)idx;
}

static int xdp_attach_prog(int ifindex, int prog_fd, const char *ifname, const char *role)
{
    int rc = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);

    if (rc) {
        fprintf(stderr, "[XDP] attach failed %s %s drv: %s\n",
                role, ifname, strerror(rc < 0 ? -rc : rc));
        fflush(stderr);
        return -1;
    }
    fprintf(stderr, "[XDP] attach OK %s %s (drv)\n", role, ifname);
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
        fprintf(stderr, "[XDP] bpf open failed: %s\n", open_path);
        return -1;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
    if (!prog || !map) {
        fprintf(stderr, "[XDP] bpf object %s missing prog/map\n", open_path);
        bpf_object__close(obj);
        return -1;
    }
    if (strstr(prog_name, "_frags") != NULL) {
        int rc = bpf_program__set_flags(prog, BPF_F_XDP_HAS_FRAGS);

        if (rc != 0) {
            fprintf(stderr,
                    "[XDP] cannot enable BPF_F_XDP_HAS_FRAGS: "
                    "%s program=%s rc=%d\n",
                    open_path, prog_name, rc);
            bpf_object__close(obj);
            return -1;
        }
    }
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "[XDP] bpf load failed: %s program=%s\n",
                open_path, prog_name);
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

    (void)fake_ethertype_ipv4;
    if (!obj) {
        return;
    }
    map = bpf_object__find_map_by_name(obj, "wan_config_map");
    if (!map) {
        return;
    }
    (void)bpf_map_update_elem(bpf_map__fd(map),&key, &et, BPF_ANY);
}

int xdp_attach_bind_local(struct ne_pair *p, const struct app_config *cfg, int pair_li)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;
    const char *ifname;
    const char *prog_name;

    if (!p || !cfg || pair_li < 0 || pair_li >= p->local_count)
        return -1;

    ifname = p->locals[pair_li].ifname;
    prog_name = p->locals[pair_li].xdp_sg_enabled
        ? "xdp_redirect_prog_frags" : "xdp_redirect_prog";
    if (xdp_attach_ifindex(ifname, "LAN") < 0)
        return -1;

    if (p->bpf_locals[pair_li]) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
        p->xdp_local_on[pair_li] = 0;
    }

    if (open_bpf_object(cfg->bpf_file, &p->bpf_locals[pair_li],
                        prog_name, &prog, "xsks_map", &map) != 0) {
        fprintf(stderr, "[XDP] LAN %s requires xdp.frags; load failed\n", ifname);
        return -1;
    }
    xdp_attach_link_off(ifname);
    if (xdp_attach_prog(p->locals[pair_li].ifindex, bpf_program__fd(prog),
                        ifname, "LAN") != 0) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
        return -1;
    }
    p->xdp_local_on[pair_li] = 1;
    fprintf(stderr, "[XDP] LAN %s program=%s\n", ifname, prog_name);
    fflush(stderr);
    return update_xsk_map_iface(&p->locals[pair_li], bpf_map__fd(map));
}

int xdp_attach_bind_wan(struct ne_pair *p, const struct app_config *cfg, int dp_slot,
                               uint16_t fake_ethertype_ipv4)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;
    const char *prog_name;

    if (!p || !cfg || dp_slot < 0 || dp_slot >= p->wan_count)
        return -1;
    if (xdp_attach_ifindex(p->wans[dp_slot].ifname, "WAN") < 0)
        return -1;
    prog_name = p->wans[dp_slot].xdp_sg_enabled
        ? "xdp_wan_redirect_prog_frags" : "xdp_wan_redirect_prog";
    if (open_bpf_object(cfg->bpf_wan_file, &p->bpf_wans[dp_slot],
                        prog_name, &prog, "wan_xsks_map", &map) != 0) {
        fprintf(stderr, "[XDP] WAN %s requires xdp.frags; load failed\n",
                p->wans[dp_slot].ifname);
        return -1;
    }
    update_wan_fake_ethertype(p->bpf_wans[dp_slot], fake_ethertype_ipv4);
    xdp_attach_link_off(p->wans[dp_slot].ifname);
    if (xdp_attach_prog(p->wans[dp_slot].ifindex, bpf_program__fd(prog),
                        p->wans[dp_slot].ifname, "WAN") != 0) {
        bpf_object__close(p->bpf_wans[dp_slot]);
        p->bpf_wans[dp_slot] = NULL;
        return -1;
    }
    p->xdp_wan_on[dp_slot] = 1;
    fprintf(stderr, "[XDP] WAN %s program=%s\n",
            p->wans[dp_slot].ifname, prog_name);
    fflush(stderr);
    return update_xsk_map_iface(&p->wans[dp_slot], bpf_map__fd(map));
}

int xdp_attach_all(struct ne_pair *p, const struct app_config *cfg)
{
    if (!p || !cfg)
        return -1;

    fprintf(stderr, "[XDP] cold attach: %d LAN, %d WAN(dp)\n",
            p->local_count, p->wan_count);
    fflush(stderr);

    for (int i = 0; i < p->local_count; i++) {
        if (xdp_attach_bind_local(p, cfg, i) != 0) {
            fprintf(stderr, "[XDP] cold attach failed LAN %s (slot %d)\n",
                    p->locals[i].ifname, i);
            fflush(stderr);
            return -1;
        }
    }
    for (int di = 0; di < p->wan_count; di++) {
        if (xdp_attach_bind_wan(p, cfg, di, cfg->fake_ethertype_ipv4) != 0) {
            fprintf(stderr, "[XDP] cold attach failed WAN %s (dp %d)\n",
                    p->wans[di].ifname, di);
            fflush(stderr);
            return -1;
        }
    }
    return 0;
}

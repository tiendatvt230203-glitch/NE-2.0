#include "../../../inc/core/flow/mac_learn.h"
#include "../../../inc/core/forwarder/forwarder.h"
#include "../../../inc/core/util/config.h"
#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/core/failover/cfm_diag.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define MAC_PURGE_LOG_INTERVAL_MS 10000ull
#define MAC_LAN_LOG_DIR           "/var/log/NE"
#define MAC_LAN_LOG_PATH          MAC_LAN_LOG_DIR "/mac_lan.log"
#define MAC_LAN_LOG_TMP           MAC_LAN_LOG_DIR "/mac_lan.log.tmp"
#define ETH_HEADER_SIZE           14u

enum mac_upsert_result {
    MAC_UPSERT_REFRESH = 0,
    MAC_UPSERT_NEW,
    MAC_UPSERT_MOVE,
};

static uint64_t g_last_purge_log_ms;
static uint64_t g_last_mismatch_log_ms;
static pthread_mutex_t g_mac_table_log_lock = PTHREAD_MUTEX_INITIALIZER;

static void mac_fdb_persist_save_locked(const struct mac_learn_table *t,
                                        const struct forwarder *fwd);
static int mac_fdb_persist_load_locked(struct mac_learn_table *t,
                                       const struct forwarder *fwd,
                                       int *skipped_ifname_out,
                                       int *skipped_other_out);
static int mac_is_zero(const uint8_t mac[MAC_LEN]);
static int mac_is_multicast(const uint8_t mac[MAC_LEN]);
static int mac_is_local_iface_locked(const struct mac_learn_table *t,
                                     const uint8_t mac[MAC_LEN]);
static void purge_local_iface_macs_locked(struct mac_learn_table *t);
static void enforce_one_mac_per_ifname_locked(struct mac_learn_table *t);
static int ingress_idx_by_ifname(const struct forwarder *fwd, const char *ifname);

/* Bridge name for a LAN ifname (same idea as main_diag iface table). */
static const char *mac_bridge_for_lan_ifname(const struct forwarder *fwd,
                                              const char *ifname)
{
    int local_idx = -1;

    if (!fwd || !fwd->cfg || !ifname || !ifname[0])
        return "-";
    for (int i = 0; i < fwd->cfg->local_count; i++) {
        if (strcmp(fwd->cfg->locals[i].ifname, ifname) == 0) {
            local_idx = i;
            break;
        }
    }
    if (local_idx < 0)
        return "-";
    if (fwd->cfg->profile_count > 0) {
        const struct profile_config *p = &fwd->cfg->profiles[0];

        for (int bi = 0; bi < p->bridge_count; bi++) {
            if (p->bridges[bi].local_idx == local_idx && p->bridges[bi].ifname[0])
                return p->bridges[bi].ifname;
        }
    }
    return "-";
}

static void mac_tbl_hline(void)
{
    fprintf(stderr,
            "+------+--------------+----------+-------------------+--------+\n");
}

/*
 * Một bảng hệ thống duy nhất (ngoài [policies]):
 *   role | interface | bridge | mac | state
 * LAN: mac từ FDB (hoặc "-" nếu chưa học). WAN: peer MAC + UP/DOWN từ CFM.
 * Bảng in lần mới nhất = snapshot đang dùng của hệ thống.
 */
void mac_learn_log_runtime_table(struct forwarder *fwd, const struct app_config *cfg,
                                 const char *event)
{
    struct cfm_wan_snap wan_rows[CFM_WAN_SNAP_MAX];
    int wan_n;
    int lan_n = 0;
    struct mac_learn_entry lan_copy[MAC_LEARN_MAX_ENTRIES];
    int printed = 0;

    pthread_mutex_lock(&g_mac_table_log_lock);

    if (!cfg && fwd)
        cfg = fwd->cfg;

    if (fwd) {
        pthread_spin_lock(&fwd->mac_table.lock);
        lan_n = fwd->mac_table.count;
        if (lan_n > MAC_LEARN_MAX_ENTRIES)
            lan_n = MAC_LEARN_MAX_ENTRIES;
        if (lan_n > 0)
            memcpy(lan_copy, fwd->mac_table.list, (size_t)lan_n * sizeof(lan_copy[0]));
        pthread_spin_unlock(&fwd->mac_table.lock);
    }

    wan_n = cfm_snapshot_wan_peers(wan_rows, CFM_WAN_SNAP_MAX);
    if (wan_n < 0)
        wan_n = 0;

    fprintf(stderr, "\n  [system] processing: %s\n", event ? event : "update");
    mac_tbl_hline();
    fprintf(stderr,
            "| %-4s | %-12s | %-8s | %-17s | %-6s |\n",
            "role", "interface", "bridge", "mac", "state");
    mac_tbl_hline();

    if (cfg) {
        for (int li = 0; li < cfg->local_count; li++) {
            const char *ifname = cfg->locals[li].ifname;
            const char *br = "-";
            int any = 0;

            if (!ifname[0])
                continue;
            if (fwd)
                br = mac_bridge_for_lan_ifname(fwd, ifname);
            else if (cfg->profile_count > 0) {
                const struct profile_config *p = &cfg->profiles[0];

                for (int bi = 0; bi < p->bridge_count; bi++) {
                    if (p->bridges[bi].local_idx == li &&
                        p->bridges[bi].ifname[0]) {
                        br = p->bridges[bi].ifname;
                        break;
                    }
                }
            }
            for (int i = 0; i < lan_n; i++) {
                char mac_s[24];

                if (strcmp(lan_copy[i].ifname, ifname) != 0)
                    continue;
                any = 1;
                snprintf(mac_s, sizeof(mac_s),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         lan_copy[i].mac[0], lan_copy[i].mac[1],
                         lan_copy[i].mac[2], lan_copy[i].mac[3],
                         lan_copy[i].mac[4], lan_copy[i].mac[5]);
                fprintf(stderr,
                        "| %-4s | %-12s | %-8s | %-17s | %-6s |\n",
                        "lan", ifname, br, mac_s, "-");
                printed++;
            }
            if (!any) {
                fprintf(stderr,
                        "| %-4s | %-12s | %-8s | %-17s | %-6s |\n",
                        "lan", ifname, br, "-", "-");
                printed++;
            }
        }
    } else {
        for (int i = 0; i < lan_n; i++) {
            char mac_s[24];
            const char *br = mac_bridge_for_lan_ifname(fwd, lan_copy[i].ifname);

            snprintf(mac_s, sizeof(mac_s),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     lan_copy[i].mac[0], lan_copy[i].mac[1], lan_copy[i].mac[2],
                     lan_copy[i].mac[3], lan_copy[i].mac[4], lan_copy[i].mac[5]);
            fprintf(stderr,
                    "| %-4s | %-12s | %-8s | %-17s | %-6s |\n",
                    "lan",
                    lan_copy[i].ifname[0] ? lan_copy[i].ifname : "-",
                    br, mac_s, "-");
            printed++;
        }
    }

    if (wan_n > 0) {
        for (int i = 0; i < wan_n; i++) {
            char mac_s[24];

            if (wan_rows[i].mac_learned) {
                snprintf(mac_s, sizeof(mac_s),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         wan_rows[i].peer_mac[0], wan_rows[i].peer_mac[1],
                         wan_rows[i].peer_mac[2], wan_rows[i].peer_mac[3],
                         wan_rows[i].peer_mac[4], wan_rows[i].peer_mac[5]);
            } else {
                snprintf(mac_s, sizeof(mac_s), "-");
            }
            fprintf(stderr,
                    "| %-4s | %-12s | %-8s | %-17s | %-6s |\n",
                    "wan",
                    wan_rows[i].ifname[0] ? wan_rows[i].ifname : "-",
                    wan_rows[i].bridge[0] ? wan_rows[i].bridge : "-",
                    mac_s,
                    wan_rows[i].is_up ? "UP" : "DOWN");
            printed++;
        }
    } else if (cfg) {
        for (int i = 0; i < cfg->wan_count; i++) {
            const char *ifname = cfg->wans[i].ifname;
            const char *br = "-";
            int wan_dp;

            if (!ifname[0] || !cfg->wans[i].dataplane)
                continue;
            wan_dp = config_wan_cfg_to_dp(cfg, i);
            if (cfg->profile_count > 0) {
                const struct profile_config *p = &cfg->profiles[0];

                for (int bi = 0; bi < p->bridge_count; bi++) {
                    if (p->bridges[bi].wan_dp == wan_dp &&
                        p->bridges[bi].ifname[0]) {
                        br = p->bridges[bi].ifname;
                        break;
                    }
                }
            }
            fprintf(stderr,
                    "| %-4s | %-12s | %-8s | %-17s | %-6s |\n",
                    "wan", ifname, br, "-", "-");
            printed++;
        }
    }

    if (!printed) {
        fprintf(stderr,
                "| %-4s | %-12s | %-8s | %-17s | %-6s |\n",
                "-", "-", "-", "(empty)", "-");
    }
    mac_tbl_hline();
    fflush(stderr);
    pthread_mutex_unlock(&g_mac_table_log_lock);
}

/* Caller already holds mac_table.lock — only used from learn/purge/restore paths. */
static void log_mac_runtime_table_from_locked(struct forwarder *fwd, const char *event)
{
    if (fwd)
        pthread_spin_unlock(&fwd->mac_table.lock);
    mac_learn_log_runtime_table(fwd, fwd ? fwd->cfg : NULL, event);
    if (fwd)
        pthread_spin_lock(&fwd->mac_table.lock);
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull);
}

#define MAC_RELAY_STAMP_MAX 32
#define MAC_RELAY_TTL_MS     3000ull

struct mac_relay_entry {
    uint8_t smac[MAC_LEN];
    uint32_t spa_be;
    uint64_t expire_ms;
};

static struct {
    struct mac_relay_entry entries[MAC_RELAY_STAMP_MAX];
    int next;
    pthread_spinlock_t lock;
    int inited;
} g_mac_relay;

static void mac_relay_init_once(void)
{
    if (g_mac_relay.inited)
        return;
    pthread_spin_init(&g_mac_relay.lock, PTHREAD_PROCESS_PRIVATE);
    g_mac_relay.inited = 1;
}

void mac_relay_stamp(const uint8_t smac[MAC_LEN], uint32_t spa_be)
{
    struct mac_relay_entry *e;
    uint64_t now_ms;

    if (!smac)
        return;
    mac_relay_init_once();

    now_ms = monotonic_ms();
    pthread_spin_lock(&g_mac_relay.lock);
    e = &g_mac_relay.entries[g_mac_relay.next];
    g_mac_relay.next = (g_mac_relay.next + 1) % MAC_RELAY_STAMP_MAX;
    memcpy(e->smac, smac, MAC_LEN);
    e->spa_be = spa_be;
    e->expire_ms = now_ms + MAC_RELAY_TTL_MS;
    pthread_spin_unlock(&g_mac_relay.lock);
}

int mac_relay_recent(const uint8_t smac[MAC_LEN], uint32_t spa_be)
{
    uint64_t now_ms;
    int hit = 0;

    if (!smac)
        return 0;
    mac_relay_init_once();

    now_ms = monotonic_ms();
    pthread_spin_lock(&g_mac_relay.lock);
    for (int i = 0; i < MAC_RELAY_STAMP_MAX; i++) {
        const struct mac_relay_entry *e = &g_mac_relay.entries[i];

        if (e->expire_ms <= now_ms)
            continue;
        if (e->spa_be == spa_be && memcmp(e->smac, smac, MAC_LEN) == 0) {
            hit = 1;
            break;
        }
    }
    pthread_spin_unlock(&g_mac_relay.lock);
    return hit;
}

static uint8_t mac_hash_key(const uint8_t mac[MAC_LEN])
{
    return mac[5];
}

static void hash_rebuild_locked(struct mac_learn_table *t)
{
    memset(t->hash_head, -1, sizeof(t->hash_head));
    memset(t->hash_next, -1, sizeof(t->hash_next));
    for (int i = 0; i < t->count; i++) {
        uint8_t b = mac_hash_key(t->list[i].mac);

        t->hash_next[i] = t->hash_head[b];
        t->hash_head[b] = i;
    }
}

static int find_idx_by_mac_locked(const struct mac_learn_table *t, const uint8_t mac[MAC_LEN])
{
    uint8_t b = mac_hash_key(mac);

    for (int i = t->hash_head[b]; i >= 0; i = t->hash_next[i]) {
        if (memcmp(t->list[i].mac, mac, MAC_LEN) == 0)
            return i;
    }
    return -1;
}

/*
 * L2 FDB: key = MAC, value = LAN ifname. Không lưu IP — client đổi subnet không ảnh hưởng.
 */
static enum mac_upsert_result upsert_locked(struct mac_learn_table *t, const char *ifname,
                                            const uint8_t mac[MAC_LEN],
                                            char old_ifname_out[IF_NAMESIZE])
{
    int mac_idx = find_idx_by_mac_locked(t, mac);
    int if_idx = -1;

    if (old_ifname_out)
        old_ifname_out[0] = '\0';

    for (int i = 0; i < t->count; i++) {
        if (strcmp(t->list[i].ifname, ifname) == 0) {
            if_idx = i;
            break;
        }
    }

    /* Same MAC already on this port — refresh only. */
    if (mac_idx >= 0) {
        if (strcmp(t->list[mac_idx].ifname, ifname) == 0)
            return MAC_UPSERT_REFRESH;

        if (old_ifname_out) {
            strncpy(old_ifname_out, t->list[mac_idx].ifname, IF_NAMESIZE - 1);
            old_ifname_out[IF_NAMESIZE - 1] = '\0';
        }
        strncpy(t->list[mac_idx].ifname, ifname, IF_NAMESIZE - 1);
        t->list[mac_idx].ifname[IF_NAMESIZE - 1] = '\0';
        return MAC_UPSERT_MOVE;
    }

    /* Replace existing MAC bound to this LAN port (one MAC per ifname). */
    if (if_idx >= 0) {
        memcpy(t->list[if_idx].mac, mac, MAC_LEN);
        hash_rebuild_locked(t);
        return MAC_UPSERT_REFRESH;
    }

    if (t->count >= MAC_LEARN_MAX_ENTRIES) {
        fprintf(stderr, "[MAC] table full on %s\n", ifname ? ifname : "-");
        return MAC_UPSERT_REFRESH;
    }

    {
        int i = t->count++;

        memcpy(t->list[i].mac, mac, MAC_LEN);
        strncpy(t->list[i].ifname, ifname, IF_NAMESIZE - 1);
        t->list[i].ifname[IF_NAMESIZE - 1] = '\0';
        hash_rebuild_locked(t);
    }
    return MAC_UPSERT_NEW;
}

static void table_init(struct mac_learn_table *t)
{
    memset(t, 0, sizeof(*t));
    memset(t->hash_head, -1, sizeof(t->hash_head));
    memset(t->hash_next, -1, sizeof(t->hash_next));
    pthread_spin_init(&t->lock, PTHREAD_PROCESS_PRIVATE);
}

static void table_learn(struct forwarder *fwd, struct mac_learn_table *t,
                        const char *ifname, const uint8_t mac[MAC_LEN],
                        enum mac_learn_src src)
{
    enum mac_upsert_result r;
    char old_ifname[IF_NAMESIZE];
    char old_mac[MAC_LEN];
    int replaced = 0;

    if (!t || !ifname || !mac || ifname[0] == '\0')
        return;
    if (src != MAC_LEARN_SRC_ARP)
        return;
    if (mac_is_zero(mac) || mac_is_multicast(mac))
        return;

    pthread_spin_lock(&t->lock);
    if (mac_is_local_iface_locked(t, mac)) {
        pthread_spin_unlock(&t->lock);
        return;
    }

    for (int i = 0; i < t->count; i++) {
        if (strcmp(t->list[i].ifname, ifname) == 0 &&
            memcmp(t->list[i].mac, mac, MAC_LEN) != 0) {
            memcpy(old_mac, t->list[i].mac, MAC_LEN);
            replaced = 1;
            break;
        }
    }

    r = upsert_locked(t, ifname, mac, old_ifname);

    if (r == MAC_UPSERT_NEW || replaced) {
        char ev[160];

        if (replaced) {
            snprintf(ev, sizeof(ev),
                     "learn if=%s mac=%02x:%02x:%02x:%02x:%02x:%02x "
                     "replace=%02x:%02x:%02x:%02x:%02x:%02x",
                     ifname,
                     (unsigned)mac[0], (unsigned)mac[1], (unsigned)mac[2],
                     (unsigned)mac[3], (unsigned)mac[4], (unsigned)mac[5],
                     (unsigned)old_mac[0], (unsigned)old_mac[1],
                     (unsigned)old_mac[2], (unsigned)old_mac[3],
                     (unsigned)old_mac[4], (unsigned)old_mac[5]);
        } else {
            snprintf(ev, sizeof(ev),
                     "learn if=%s mac=%02x:%02x:%02x:%02x:%02x:%02x",
                     ifname,
                     (unsigned)mac[0], (unsigned)mac[1], (unsigned)mac[2],
                     (unsigned)mac[3], (unsigned)mac[4], (unsigned)mac[5]);
        }
        log_mac_runtime_table_from_locked(fwd, ev);
    } else if (r == MAC_UPSERT_MOVE) {
        char ev[128];

        snprintf(ev, sizeof(ev),
                 "move if=%s->%s mac=%02x:%02x:%02x:%02x:%02x:%02x",
                 old_ifname[0] ? old_ifname : "-", ifname,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        log_mac_runtime_table_from_locked(fwd, ev);
    }
    if (r == MAC_UPSERT_NEW || r == MAC_UPSERT_MOVE || replaced)
        mac_fdb_persist_save_locked(t, fwd);
    pthread_spin_unlock(&t->lock);
}

static int table_lookup(struct mac_learn_table *t, const uint8_t mac[MAC_LEN],
                        char ifname[IF_NAMESIZE])
{
    int i;

    if (!t || !mac || !ifname)
        return -1;
    pthread_spin_lock(&t->lock);
    i = find_idx_by_mac_locked(t, mac);
    if (i < 0) {
        pthread_spin_unlock(&t->lock);
        return -1;
    }
    strncpy(ifname, t->list[i].ifname, IF_NAMESIZE - 1);
    ifname[IF_NAMESIZE - 1] = '\0';
    pthread_spin_unlock(&t->lock);
    return 0;
}

static int ifname_in_configured_locals(const struct forwarder *fwd, const char *ifname)
{
    if (!fwd || !ifname || !ifname[0])
        return 0;

    for (int i = 0; i < fwd->local_count; i++) {
        if (fwd->locals[i].ifname[0] == '\0')
            continue;
        if (strcmp(fwd->locals[i].ifname, ifname) == 0)
            return 1;
    }
    if (fwd->cfg) {
        for (int i = 0; i < fwd->cfg->local_count; i++) {
            if (fwd->cfg->locals[i].ifname[0] == '\0')
                continue;
            if (strcmp(fwd->cfg->locals[i].ifname, ifname) == 0)
                return 1;
        }
    }
    return 0;
}

static int parse_mac_colon(const char *s, uint8_t mac[MAC_LEN])
{
    unsigned m[6];

    if (!s || !mac)
        return -1;
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < MAC_LEN; i++)
        mac[i] = (uint8_t)m[i];
    return 0;
}

static int mac_is_zero(const uint8_t mac[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];

    return memcmp(mac, zero, MAC_LEN) == 0;
}

static int mac_is_multicast(const uint8_t mac[MAC_LEN])
{
    return (mac[0] & 0x01u) != 0;
}

static int mac_is_local_iface_locked(const struct mac_learn_table *t, const uint8_t mac[MAC_LEN])
{
    if (!t || !mac)
        return 0;
    for (int i = 0; i < t->iface_mac_count; i++) {
        if (memcmp(t->iface_macs[i], mac, MAC_LEN) == 0)
            return 1;
    }
    return 0;
}

static void refresh_iface_macs_add(struct mac_learn_table *t, int sock, const char *ifname)
{
    struct ifreq ifr;
    uint8_t hw[MAC_LEN];

    if (!t || !ifname || !ifname[0] || t->iface_mac_count >= MAX_INTERFACES)
        return;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0)
        return;
    memcpy(hw, ifr.ifr_hwaddr.sa_data, MAC_LEN);
    if (mac_is_zero(hw) || mac_is_multicast(hw))
        return;
    for (int i = 0; i < t->iface_mac_count; i++) {
        if (memcmp(t->iface_macs[i], hw, MAC_LEN) == 0)
            return;
    }
    memcpy(t->iface_macs[t->iface_mac_count], hw, MAC_LEN);
    t->iface_mac_count++;
}

static void refresh_iface_macs_locked(struct mac_learn_table *t, const struct forwarder *fwd)
{
    int sock;

    if (!t || !fwd)
        return;
    t->iface_mac_count = 0;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return;

    for (int i = 0; i < fwd->local_count; i++)
        refresh_iface_macs_add(t, sock, fwd->locals[i].ifname);
    if (fwd->cfg) {
        for (int i = 0; i < fwd->cfg->local_count; i++)
            refresh_iface_macs_add(t, sock, fwd->cfg->locals[i].ifname);
    }
    close(sock);
}

static void purge_local_iface_macs_locked(struct mac_learn_table *t)
{
    int w = 0;

    if (!t)
        return;
    for (int i = 0; i < t->count; i++) {
        if (mac_is_local_iface_locked(t, t->list[i].mac))
            continue;
        if (w != i)
            t->list[w] = t->list[i];
        w++;
    }
    if (w != t->count) {
        t->count = w;
        hash_rebuild_locked(t);
    }
}

/* Collapse duplicates: last entry per ifname wins. */
static void enforce_one_mac_per_ifname_locked(struct mac_learn_table *t)
{
    struct mac_learn_entry tmp[MAC_LEARN_MAX_ENTRIES];
    int n = 0;

    if (!t)
        return;
    for (int i = 0; i < t->count; i++) {
        int idx = -1;

        for (int j = 0; j < n; j++) {
            if (strcmp(tmp[j].ifname, t->list[i].ifname) == 0) {
                idx = j;
                break;
            }
        }
        if (idx >= 0)
            tmp[idx] = t->list[i];
        else if (n < MAC_LEARN_MAX_ENTRIES)
            tmp[n++] = t->list[i];
    }
    if (n != t->count) {
        memcpy(t->list, tmp, (size_t)n * sizeof(tmp[0]));
        t->count = n;
        hash_rebuild_locked(t);
    }
}

static int mac_fdb_ensure_log_dir(void)
{
    if (mkdir(MAC_LAN_LOG_DIR, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* Find MAC in a flat entry list (no hash). */
static int merge_find_mac(const struct mac_learn_entry *list, int count,
                          const uint8_t mac[MAC_LEN])
{
    for (int i = 0; i < count; i++) {
        if (memcmp(list[i].mac, mac, MAC_LEN) == 0)
            return i;
    }
    return -1;
}

/* Count non-comment data lines in existing log (for empty-guard). */
static int mac_fdb_log_has_entries(void)
{
    FILE *fp;
    char line[256];
    int n = 0;

    fp = fopen(MAC_LAN_LOG_PATH, "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        char ifname[IF_NAMESIZE];
        char mac_s[24];

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        if (sscanf(line, "%15s %23s", ifname, mac_s) >= 2)
            n++;
    }
    fclose(fp);
    return n;
}

/*
 * Merge persist: RAM overlays file by MAC; keep file-only entries whose
 * ifname left configured locals (orphan history for later restore).
 * fwd may be NULL → keep all file-only MACs not in RAM.
 * Empty-guard: never overwrite a non-empty log with RAM count==0.
 */
static void mac_fdb_persist_save_locked(const struct mac_learn_table *t,
                                        const struct forwarder *fwd)
{
    struct mac_learn_entry merged[MAC_LEARN_MAX_ENTRIES];
    int merged_count = 0;
    FILE *fp;
    FILE *out;
    char line[256];
    int fd;
    int kept_orphan = 0;

    if (!t || mac_fdb_ensure_log_dir() != 0)
        return;

    if (t->count == 0 && mac_fdb_log_has_entries() > 0) {
        fprintf(stderr,
                "[MAC-FDB] persist skip empty RAM — keep existing %s\n",
                MAC_LAN_LOG_PATH);
        fflush(stderr);
        return;
    }

    /* Seed from on-disk log. */
    fp = fopen(MAC_LAN_LOG_PATH, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp) &&
               merged_count < MAC_LEARN_MAX_ENTRIES) {
            char ifname[IF_NAMESIZE];
            char mac_s[24];
            char extra[16];
            uint8_t mac[MAC_LEN];
            int n;

            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
                continue;
            extra[0] = '\0';
            n = sscanf(line, "%15s %23s %15s", ifname, mac_s, extra);
            if (n < 2)
                continue;
            if (parse_mac_colon(mac_s, mac) != 0)
                continue;
            if (mac_is_zero(mac) || mac_is_multicast(mac))
                continue;
            if (t && mac_is_local_iface_locked(t, mac))
                continue;
            if (merge_find_mac(merged, merged_count, mac) >= 0)
                continue;
            memcpy(merged[merged_count].mac, mac, MAC_LEN);
            strncpy(merged[merged_count].ifname, ifname, IF_NAMESIZE - 1);
            merged[merged_count].ifname[IF_NAMESIZE - 1] = '\0';
            merged_count++;
        }
        fclose(fp);
    }

    /* Overlay RAM (current MAC → ifname wins). */
    for (int i = 0; i < t->count; i++) {
        const struct mac_learn_entry *e = &t->list[i];
        int idx = merge_find_mac(merged, merged_count, e->mac);

        if (idx >= 0) {
            strncpy(merged[idx].ifname, e->ifname, IF_NAMESIZE - 1);
            merged[idx].ifname[IF_NAMESIZE - 1] = '\0';
        } else if (merged_count < MAC_LEARN_MAX_ENTRIES) {
            merged[merged_count] = *e;
            merged_count++;
        }
    }

    /*
     * Drop file-only entries still on a configured LAN (stale) when fwd
     * known; keep orphans (ifname left config) for restore after re-add.
     */
    if (fwd) {
        int w = 0;

        for (int i = 0; i < merged_count; i++) {
            int in_ram = 0;

            for (int r = 0; r < t->count; r++) {
                if (memcmp(t->list[r].mac, merged[i].mac, MAC_LEN) == 0) {
                    in_ram = 1;
                    break;
                }
            }
            if (in_ram || !ifname_in_configured_locals(fwd, merged[i].ifname)) {
                if (!in_ram)
                    kept_orphan++;
                if (w != i)
                    merged[w] = merged[i];
                w++;
            }
        }
        merged_count = w;
    }

    out = fopen(MAC_LAN_LOG_TMP, "w");
    if (!out) {
        fprintf(stderr, "[MAC-FDB] persist FAIL write %s\n", MAC_LAN_LOG_TMP);
        fflush(stderr);
        return;
    }
    fprintf(out,
            "# NE MAC LAN FDB v2 — ifname mac (one client MAC per LAN port)\n");
    for (int i = 0; i < merged_count; i++) {
        const struct mac_learn_entry *e = &merged[i];

        fprintf(out, "%s %02x:%02x:%02x:%02x:%02x:%02x\n",
                e->ifname[0] ? e->ifname : "-",
                e->mac[0], e->mac[1], e->mac[2],
                e->mac[3], e->mac[4], e->mac[5]);
    }
    fflush(out);
    fd = fileno(out);
    if (fd >= 0)
        (void)fsync(fd);
    fclose(out);
    if (rename(MAC_LAN_LOG_TMP, MAC_LAN_LOG_PATH) != 0) {
        fprintf(stderr, "[MAC-FDB] persist FAIL rename -> %s\n", MAC_LAN_LOG_PATH);
        fflush(stderr);
        return;
    }
    fprintf(stderr, "[MAC-FDB] saved %d (ram=%d orphan_kept=%d) -> %s\n",
            merged_count, t->count, kept_orphan, MAC_LAN_LOG_PATH);
    fflush(stderr);
}

static int mac_fdb_persist_load_locked(struct mac_learn_table *t,
                                       const struct forwarder *fwd,
                                       int *skipped_ifname_out,
                                       int *skipped_other_out)
{
    FILE *fp;
    char line[256];
    int loaded = 0;
    int skip_ifname = 0;
    int skip_other = 0;

    if (skipped_ifname_out)
        *skipped_ifname_out = 0;
    if (skipped_other_out)
        *skipped_other_out = 0;
    if (!t || !fwd)
        return 0;
    fp = fopen(MAC_LAN_LOG_PATH, "r");
    if (!fp)
        return 0;

    while (fgets(line, sizeof(line), fp)) {
        char ifname[IF_NAMESIZE];
        char mac_s[24];
        char extra[16];
        uint8_t mac[MAC_LEN];
        int idx;
        int n;

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        extra[0] = '\0';
        n = sscanf(line, "%15s %23s %15s", ifname, mac_s, extra);
        if (n < 2) {
            skip_other++;
            continue;
        }
        if (!ifname_in_configured_locals(fwd, ifname)) {
            skip_ifname++;
            continue;
        }
        if (parse_mac_colon(mac_s, mac) != 0) {
            skip_other++;
            continue;
        }
        if (mac_is_zero(mac) || mac_is_multicast(mac)) {
            skip_other++;
            continue;
        }
        if (mac_is_local_iface_locked(t, mac)) {
            skip_other++;
            continue;
        }

        /* One MAC per LAN port: later lines in file replace earlier. */
        {
            int if_idx = -1;

            for (int i = 0; i < t->count; i++) {
                if (strcmp(t->list[i].ifname, ifname) == 0) {
                    if_idx = i;
                    break;
                }
            }
            if (if_idx >= 0) {
                memcpy(t->list[if_idx].mac, mac, MAC_LEN);
                loaded++;
                continue;
            }
        }

        if (find_idx_by_mac_locked(t, mac) >= 0) {
            skip_other++;
            continue;
        }
        if (t->count >= MAC_LEARN_MAX_ENTRIES)
            break;
        idx = t->count++;
        memcpy(t->list[idx].mac, mac, MAC_LEN);
        strncpy(t->list[idx].ifname, ifname, IF_NAMESIZE - 1);
        t->list[idx].ifname[IF_NAMESIZE - 1] = '\0';
        loaded++;
    }
    fclose(fp);
    if (loaded > 0) {
        enforce_one_mac_per_ifname_locked(t);
        hash_rebuild_locked(t);
    }
    if (skipped_ifname_out)
        *skipped_ifname_out = skip_ifname;
    if (skipped_other_out)
        *skipped_other_out = skip_other;
    return loaded;
}

static void table_purge_orphan_locked(struct mac_learn_table *t, struct forwarder *fwd,
                                      uint8_t *purged_mac, char purged_ifname[IF_NAMESIZE],
                                      int *purge_count)
{
    int w = 0;

    if (!t || !fwd)
        return;
    if (purge_count)
        *purge_count = 0;
    if (purged_ifname)
        purged_ifname[0] = '\0';

    for (int i = 0; i < t->count; i++) {
        if (ifname_in_configured_locals(fwd, t->list[i].ifname)) {
            if (w != i)
                t->list[w] = t->list[i];
            w++;
        } else {
            if (purge_count && *purge_count == 0) {
                if (purged_mac)
                    memcpy(purged_mac, t->list[i].mac, MAC_LEN);
                if (purged_ifname) {
                    strncpy(purged_ifname, t->list[i].ifname, IF_NAMESIZE - 1);
                    purged_ifname[IF_NAMESIZE - 1] = '\0';
                }
            }
            if (purge_count)
                (*purge_count)++;
        }
    }
    if (w != t->count) {
        t->count = w;
        hash_rebuild_locked(t);
    }
}

static void log_index_space_mismatch(struct forwarder *fwd)
{
    uint64_t now_ms;
    int cfg_n;

    if (!fwd || !fwd->cfg)
        return;
    cfg_n = fwd->cfg->local_count;
    if (fwd->local_count == cfg_n)
        return;

    now_ms = monotonic_ms();
    if (now_ms - g_last_mismatch_log_ms < MAC_PURGE_LOG_INTERVAL_MS)
        return;
    g_last_mismatch_log_ms = now_ms;

    fprintf(stderr,
            "[MAC] index-space fwd_local_count=%d cfg_local_count=%d table=%d\n",
            fwd->local_count, cfg_n, fwd->mac_table.count);
    for (int i = 0; i < fwd->local_count && i < MAX_INTERFACES; i++) {
        fprintf(stderr, "[MAC]   fwd[%d]=%s live=%d\n",
                i,
                fwd->locals[i].ifname[0] ? fwd->locals[i].ifname : "-",
                ne_pair_local_live(&fwd->pair, i));
    }
    for (int i = 0; i < cfg_n && i < MAX_INTERFACES; i++) {
        fprintf(stderr, "[MAC]   cfg[%d]=%s\n",
                i, fwd->cfg->locals[i].ifname[0] ? fwd->cfg->locals[i].ifname : "-");
    }
}

static void table_maintain(struct forwarder *fwd)
{
    uint8_t purged_mac[MAC_LEN];
    char purged_ifname[IF_NAMESIZE];
    int purge_count = 0;

    if (!fwd)
        return;
    log_index_space_mismatch(fwd);
    pthread_spin_lock(&fwd->mac_table.lock);
    table_purge_orphan_locked(&fwd->mac_table, fwd, purged_mac, purged_ifname, &purge_count);
    if (purge_count > 0)
        log_mac_runtime_table_from_locked(fwd, "purge");
    /* RAM-only purge — keep orphan MAC lines on disk for later restore. */
    pthread_spin_unlock(&fwd->mac_table.lock);

    if (purge_count > 0) {
        uint64_t now_ms = monotonic_ms();

        if (now_ms - g_last_purge_log_ms >= MAC_PURGE_LOG_INTERVAL_MS) {
            g_last_purge_log_ms = now_ms;
            fprintf(stderr, "[MAC] purge summary count=%d (first iface=%s)\n",
                    purge_count, purged_ifname[0] ? purged_ifname : "-");
        }
    }
}

int mac_fwd_local_for_cfg_idx(const struct forwarder *fwd, int cfg_li)
{
    const char *ifname;

    if (!fwd || !fwd->cfg || cfg_li < 0 || cfg_li >= fwd->cfg->local_count)
        return -1;
    ifname = fwd->cfg->locals[cfg_li].ifname;
    if (!ifname[0])
        return -1;

    for (int i = 0; i < fwd->local_count; i++) {
        if (!ne_pair_local_live(&fwd->pair, i))
            continue;
        if (strcmp(fwd->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

int mac_fwd_local_for_wan_dp(struct forwarder *fwd, int profile_pi, int wan_dp)
{
    const struct profile_config *prof;
    char ifname[IF_NAMESIZE];

    if (!fwd || !fwd->cfg || profile_pi < 0 || profile_pi >= fwd->cfg->profile_count)
        return -1;
    prof = &fwd->cfg->profiles[profile_pi];
    if (!prof->enabled)
        return -1;

    ifname[0] = '\0';
    for (int i = 0; i < prof->bridge_count; i++) {
        int ci;

        if (prof->bridges[i].wan_dp != wan_dp)
            continue;
        ci = prof->bridges[i].local_idx;
        if (ci < 0 || ci >= fwd->cfg->local_count)
            continue;
        if (!fwd->cfg->locals[ci].ifname[0])
            continue;
        strncpy(ifname, fwd->cfg->locals[ci].ifname, IF_NAMESIZE - 1);
        ifname[IF_NAMESIZE - 1] = '\0';
        break;
    }
    if (!ifname[0])
        return -1;
    return ingress_idx_by_ifname(fwd, ifname);
}

static int ingress_idx_by_ifname(const struct forwarder *fwd, const char *ifname)
{
    for (int i = 0; i < fwd->local_count; i++) {
        if (!ne_pair_local_live(&fwd->pair, i))
            continue;
        if (strcmp(fwd->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

void mac_learn_bootstrap(struct mac_learn_table *t)
{
    if (!t)
        return;
    table_init(t);
}

void mac_learn_refresh_iface_macs(struct forwarder *fwd)
{
    if (!fwd)
        return;
    pthread_spin_lock(&fwd->mac_table.lock);
    refresh_iface_macs_locked(&fwd->mac_table, fwd);
    purge_local_iface_macs_locked(&fwd->mac_table);
    pthread_spin_unlock(&fwd->mac_table.lock);
}

int mac_is_appliance_mac(struct forwarder *fwd, const uint8_t mac[MAC_LEN])
{
    int hit;

    if (!fwd || !mac)
        return 0;
    pthread_spin_lock(&fwd->mac_table.lock);
    hit = mac_is_local_iface_locked(&fwd->mac_table, mac);
    pthread_spin_unlock(&fwd->mac_table.lock);
    return hit;
}

void mac_learn_shutdown(struct mac_learn_table *t)
{
    if (!t)
        return;
    pthread_spin_destroy(&t->lock);
}

void mac_learn_persist(struct forwarder *fwd)
{
    if (!fwd)
        return;
    pthread_spin_lock(&fwd->mac_table.lock);
    mac_fdb_persist_save_locked(&fwd->mac_table, fwd);
    pthread_spin_unlock(&fwd->mac_table.lock);
}

void mac_learn_restore(struct forwarder *fwd)
{
    int loaded;
    int skip_ifname = 0;
    int skip_other = 0;

    if (!fwd)
        return;
    mac_learn_refresh_iface_macs(fwd);
    pthread_spin_lock(&fwd->mac_table.lock);
    loaded = mac_fdb_persist_load_locked(&fwd->mac_table, fwd,
                                         &skip_ifname, &skip_other);
    purge_local_iface_macs_locked(&fwd->mac_table);
    enforce_one_mac_per_ifname_locked(&fwd->mac_table);
    if (loaded > 0) {
        char ev[64];

        snprintf(ev, sizeof(ev), "restore loaded=%d", loaded);
        log_mac_runtime_table_from_locked(fwd, ev);
        mac_fdb_persist_save_locked(&fwd->mac_table, fwd);
    }
    pthread_spin_unlock(&fwd->mac_table.lock);

    if (loaded > 0)
        fprintf(stderr,
                "[MAC-FDB] restored %d (skipped ifname=%d other=%d) from %s\n",
                loaded, skip_ifname, skip_other, MAC_LAN_LOG_PATH);
    else if (skip_ifname > 0 || skip_other > 0)
        fprintf(stderr,
                "[MAC-FDB] restored 0 (skipped ifname=%d other=%d) from %s "
                "(wait LAN ARP learn)\n",
                skip_ifname, skip_other, MAC_LAN_LOG_PATH);
    else
        fprintf(stderr, "[MAC-FDB] no cache at %s (wait LAN ARP learn)\n",
                MAC_LAN_LOG_PATH);
    fflush(stderr);
}

void mac_learn_tick(struct forwarder *fwd)
{
    if (!fwd)
        return;
    table_maintain(fwd);
}

void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len,
               enum mac_learn_src src)
{
    const uint8_t *eth_src;

    if (!fwd || !pkt || len < ETH_HEADER_SIZE ||
        ingress_idx < 0 || ingress_idx >= fwd->local_count)
        return;
    if (!ne_pair_local_live(&fwd->pair, ingress_idx))
        return;
    if (src != MAC_LEARN_SRC_ARP || !dp_pkt_is_arp(pkt, len))
        return;

    eth_src = pkt + MAC_LEN;
    if (mac_is_zero(eth_src) || mac_is_multicast(eth_src))
        return;

    table_learn(fwd, &fwd->mac_table, fwd->locals[ingress_idx].ifname, eth_src, src);
}

int mac_lookup(struct forwarder *fwd, const uint8_t mac[MAC_LEN])
{
    char ifname[IF_NAMESIZE];
    int li;

    if (!fwd || !mac)
        return -1;
    if (table_lookup(&fwd->mac_table, mac, ifname) != 0)
        return -1;
    li = ingress_idx_by_ifname(fwd, ifname);
    return li;
}

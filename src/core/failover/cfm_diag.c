#include "core/failover/cfm.h"
#include "../../../inc/core/failover/cfm_diag.h"
#include "../../../inc/core/util/config.h"
#include "../../../inc/core/flow/mac_learn.h"
#include "../../../inc/core/forwarder/forwarder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#define CFM_STATUS_IPC_PATH "/var/run/network-encryptor-gs.sock"

#define CFM_INTERVAL_MS         100
#define CFM_TIMEOUT_MS          350
#define CFM_STARTUP_TIMEOUT_MS  1000
/* Consecutive 100ms eval ticks before committing UP/DOWN (anti-flap). */
#define CFM_DOWN_CONFIRM        2
#define CFM_UP_CONFIRM          3

typedef struct cfm_link {
    pthread_mutex_t lock;
    uint64_t last_recv_time;
    uint64_t rx_any;
    uint64_t rx_short;
    uint64_t rx_not_cfm;
    uint64_t rx_bad_ccm;
    uint64_t rx_peer_ccm;
    uint64_t rx_own_skip;
    int ifindex;
    int sock_fd;
    int local_mep_id;
    int remote_mep_id;
    int cfg_wan_idx;
    int wan_dp;
    int consecutive_fails;
    int consecutive_successes;
    uint32_t tx_seq;
    char ifname[IFNAMSIZ];
    char bridge[IFNAMSIZ];
    uint8_t local_mac[6];
    uint8_t remote_mac[6];
    bool is_up;
    bool mac_learned;
} cfm_link_t;

static cfm_link_t g_links[MAX_INTERFACES];
static int g_link_count = 0;

static pthread_t g_cfm_thread;
static volatile bool g_cfm_running = false;
static pthread_mutex_t g_cfm_init_lock = PTHREAD_MUTEX_INITIALIZER;

static cfm_link_state_cb g_state_cb;
static void *g_state_cb_user;
static pthread_mutex_t g_cb_lock = PTHREAD_MUTEX_INITIALIZER;

static void log_unified_mac_table(const char *event)
{
    struct forwarder *fwd = NULL;

    pthread_mutex_lock(&g_cb_lock);
    fwd = (struct forwarder *)g_state_cb_user;
    pthread_mutex_unlock(&g_cb_lock);
    mac_learn_log_runtime_table(fwd, fwd ? fwd->cfg : NULL, event);
}

static void notify_is_up(cfm_link_t *link, bool old_up, int print_table)
{
    cfm_link_state_cb cb;
    void *user;
    int old_state;
    int new_state;
    int wan_dp;

    if (link->is_up == old_up)
        return;

    old_state = old_up ? CFM_LINK_STATE_UP : CFM_LINK_STATE_DOWN;
    new_state = link->is_up ? CFM_LINK_STATE_UP : CFM_LINK_STATE_DOWN;
    wan_dp = link->wan_dp;

    pthread_mutex_lock(&g_cb_lock);
    cb = g_state_cb;
    user = g_state_cb_user;
    pthread_mutex_unlock(&g_cb_lock);
    if (cb)
        cb(wan_dp, link->ifname, old_state, new_state, user);
    if (print_table) {
        char ev[96];

        snprintf(ev, sizeof(ev),
                 "WAN %s if=%s (failover %s)",
                 link->is_up ? "UP" : "DOWN",
                 link->ifname[0] ? link->ifname : "-",
                 link->is_up ? "restore/-ai" : "kick/-di");
        log_unified_mac_table(ev);
    }
}

static cfm_link_t *find_link_by_wan_dp(int wan_dp)
{
    if (wan_dp < 0)
        return NULL;
    for (int i = 0; i < g_link_count; i++) {
        if (g_links[i].wan_dp == wan_dp)
            return &g_links[i];
    }
    return NULL;
}

static void cfm_bridge_for_wan_dp(const struct app_config *cfg, int wan_dp,
                                  char out[IFNAMSIZ])
{
    out[0] = '\0';
    if (!cfg || wan_dp < 0)
        return;
    if (cfg->profile_count > 0) {
        const struct profile_config *p = &cfg->profiles[0];

        for (int bi = 0; bi < p->bridge_count; bi++) {
            if (p->bridges[bi].wan_dp == wan_dp && p->bridges[bi].ifname[0]) {
                strncpy(out, p->bridges[bi].ifname, IFNAMSIZ - 1);
                out[IFNAMSIZ - 1] = '\0';
                return;
            }
        }
    }
}

int cfm_snapshot_wan_peers(struct cfm_wan_snap *out, int max)
{
    int n = 0;

    if (!out || max <= 0)
        return 0;
    for (int i = 0; i < g_link_count && n < max; i++) {
        pthread_mutex_lock(&g_links[i].lock);
        strncpy(out[n].ifname, g_links[i].ifname, sizeof(out[n].ifname) - 1);
        out[n].ifname[sizeof(out[n].ifname) - 1] = '\0';
        strncpy(out[n].bridge, g_links[i].bridge, sizeof(out[n].bridge) - 1);
        out[n].bridge[sizeof(out[n].bridge) - 1] = '\0';
        memcpy(out[n].peer_mac, g_links[i].remote_mac, 6);
        out[n].mac_learned = g_links[i].mac_learned ? 1 : 0;
        out[n].is_up = g_links[i].is_up ? 1 : 0;
        pthread_mutex_unlock(&g_links[i].lock);
        n++;
    }
    return n;
}

/* Same is_up the [mac] table prints — lookup by wan ifname or bridge. */
int cfm_wan_status_by_name(const char *name)
{
    int matched = 0;
    int any_up = 0;

    if (!name || !name[0])
        return -1;
    for (int i = 0; i < g_link_count; i++) {
        int up;

        pthread_mutex_lock(&g_links[i].lock);
        if (strcmp(name, g_links[i].ifname) != 0 &&
            strcmp(name, g_links[i].bridge) != 0) {
            pthread_mutex_unlock(&g_links[i].lock);
            continue;
        }
        up = g_links[i].is_up ? 1 : 0;
        pthread_mutex_unlock(&g_links[i].lock);
        matched = 1;
        if (up)
            any_up = 1;
    }
    if (!matched)
        return -1;
    return any_up;
}

static void *cfm_status_ipc_thread(void *arg)
{
    int listen_fd;
    struct sockaddr_un addr;

    (void)arg;
    unlink(CFM_STATUS_IPC_PATH);
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0)
        return NULL;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CFM_STATUS_IPC_PATH, sizeof(addr.sun_path) - 1);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(listen_fd, 4) < 0) {
        close(listen_fd);
        return NULL;
    }
    chmod(CFM_STATUS_IPC_PATH, 0660);

    for (;;) {
        char req[96];
        char name[IFNAMSIZ];
        int client_fd;
        int st;

        client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            usleep(50000);
            continue;
        }
        memset(req, 0, sizeof(req));
        name[0] = '\0';
        if (read(client_fd, req, sizeof(req) - 1) > 0)
            sscanf(req, "GS %15s", name);
        st = cfm_wan_status_by_name(name);
        if (st >= 0) {
            const char *reply = st ? "UP\n" : "DOWN\n";
            size_t reply_len = st ? 3U : 5U;

            if (write(client_fd, reply, reply_len) < 0)
                perror("[CFM] status IPC write");
        }
        close(client_fd);
    }
    return NULL;
}

void cfm_status_ipc_start(void)
{
    pthread_t th;

    if (pthread_create(&th, NULL, cfm_status_ipc_thread, NULL) == 0)
        pthread_detach(th);
}

int cfm_status_ipc_query(const char *name)
{
    int fd;
    struct sockaddr_un addr;
    char req[64];
    char buf[16];
    ssize_t n;
    int got = 0;

    if (!name || !name[0]) {
        fprintf(stderr, "[ERR] -gs requires <wan_if|bridge>\n");
        return 1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[ERR] -gs: socket failed\n");
        return 1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CFM_STATUS_IPC_PATH, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[ERR] -gs: daemon not running\n");
        close(fd);
        return 1;
    }
    snprintf(req, sizeof(req), "GS %s\n", name);
    if (write(fd, req, strlen(req)) < 0) {
        close(fd);
        return 1;
    }
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        fputs(buf, stdout);
        got = 1;
    }
    close(fd);
    if (!got) {
        fprintf(stderr, "[ERR] no WAN matched: %s\n", name);
        return 1;
    }
    return 0;
}

static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void send_ccm_packet(cfm_link_t *link) {
    struct cfm_ccm_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    // 1. Ethernet Header
    // If MAC is learned, use Unicast to bypass ISP multicast filters. Otherwise, use Multicast.
    pthread_mutex_lock(&link->lock);
    if (link->mac_learned) {
        memcpy(pkt.eth.dst_mac, link->remote_mac, 6);
    } else {
        memcpy(pkt.eth.dst_mac, CFM_MULTICAST_MAC, 6);
    }
    memcpy(pkt.eth.src_mac, link->local_mac, 6);
    pkt.eth.eth_type = htons(ETH_P_CFM);

    // 2. CFM CCM Header
    pkt.ccm.md_lvl_version = 0xA0; // Level 5, Version 0
    pkt.ccm.opcode = CFM_OPCODE_CCM;
    pkt.ccm.flags = 4;             // 100ms interval
    pkt.ccm.first_tlv_offset = 70;
    pkt.ccm.seq_number = htonl(link->tx_seq++);
    pkt.ccm.mep_id = htons(link->local_mep_id);

    // Fill MAID name for identification
    snprintf((char *)pkt.ccm.maid, sizeof(pkt.ccm.maid), "MA-WAN-PORT-%.16s", link->ifname);

    pkt.end_tlv = 0;

    // Send packet
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = link->ifindex;
    sll.sll_halen = 6;
    if (link->mac_learned) {
        memcpy(sll.sll_addr, link->remote_mac, 6);
    } else {
        memcpy(sll.sll_addr, CFM_MULTICAST_MAC, 6);
    }
    pthread_mutex_unlock(&link->lock);

    if (sendto(link->sock_fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        // Silent fail to avoid flooding stdout/stderr in case of temporary driver issues
    }
}

static void *cfm_monitor_thread(void *arg) {
    (void)arg;
    struct pollfd fds[MAX_INTERFACES];
    uint64_t last_tx_time = get_time_ms();
    uint64_t last_wait_log = 0;

    while (g_cfm_running) {
        int active_fds = 0;
        for (int i = 0; i < g_link_count; i++) {
            if (g_links[i].sock_fd >= 0) {
                fds[active_fds].fd = g_links[i].sock_fd;
                fds[active_fds].events = POLLIN;
                fds[active_fds].revents = 0;
                active_fds++;
            }
        }

        if (active_fds == 0) {
            usleep(100000);
            continue;
        }

        // Poll raw sockets for incoming CFM frames with 10ms timeout
        int ret = poll(fds, active_fds, 10);
        if (ret > 0) {
            for (int i = 0; i < active_fds; i++) {
                if (!(fds[i].revents & POLLIN))
                    continue;

                /* Drain pending frames; parse as raw bytes (không phụ thuộc overlay struct). */
                for (;;) {
                    uint8_t buf[2048];
                    ssize_t rx_bytes = recv(fds[i].fd, buf, sizeof(buf), 0);
                    uint16_t eth_type;
                    const uint8_t *src_mac;
                    const uint8_t *cfm;
                    uint8_t lvl;
                    uint8_t op;
                    uint16_t rx_mep_id;
                    int j;

                    if (rx_bytes < 0)
                        break;

                    for (j = 0; j < g_link_count; j++) {
                        if (g_links[j].sock_fd == fds[i].fd)
                            break;
                    }
                    if (j >= g_link_count)
                        continue;

                    pthread_mutex_lock(&g_links[j].lock);
                    g_links[j].rx_any++;
                    pthread_mutex_unlock(&g_links[j].lock);

                    if (rx_bytes < 14 + 4) {
                        pthread_mutex_lock(&g_links[j].lock);
                        g_links[j].rx_short++;
                        pthread_mutex_unlock(&g_links[j].lock);
                        continue;
                    }

                    eth_type = ((uint16_t)buf[12] << 8) | buf[13];
                    if (eth_type != ETH_P_CFM) {
                        pthread_mutex_lock(&g_links[j].lock);
                        g_links[j].rx_not_cfm++;
                        pthread_mutex_unlock(&g_links[j].lock);
                        continue;
                    }

                    if (rx_bytes < 14 + 10) {
                        pthread_mutex_lock(&g_links[j].lock);
                        g_links[j].rx_short++;
                        pthread_mutex_unlock(&g_links[j].lock);
                        continue;
                    }

                    src_mac = buf + 6;
                    cfm = buf + 14;
                    lvl = (cfm[0] >> 5) & 0x07;
                    op = cfm[1];
                    if (lvl != 5 || op != CFM_OPCODE_CCM) {
                        pthread_mutex_lock(&g_links[j].lock);
                        g_links[j].rx_bad_ccm++;
                        pthread_mutex_unlock(&g_links[j].lock);
                        continue;
                    }

                    /*
                     * CCM: [0]=lvl [1]=op [2]=flags [3]=tlv_off
                     *      [4..7]=seq  [8..9]=mep_id  [10..]=MAID
                     * (trước đây đọc cfm[6..7] = đuôi seq → MEP sai → CCM sau bị discard)
                     */
                    rx_mep_id = ((uint16_t)cfm[8] << 8) | cfm[9];

                    /* Never learn our own CCM (TX loopback). */
                    if (memcmp(src_mac, g_links[j].local_mac, 6) == 0) {
                        pthread_mutex_lock(&g_links[j].lock);
                        g_links[j].rx_own_skip++;
                        pthread_mutex_unlock(&g_links[j].lock);
                        continue;
                    }

                    {
                        bool old_up;
                        uint64_t now = get_time_ms();

                        pthread_mutex_lock(&g_links[j].lock);
                        old_up = g_links[j].is_up;
                        if (!g_links[j].mac_learned) {
                            char ev[96];

                            memcpy(g_links[j].remote_mac, src_mac, 6);
                            g_links[j].remote_mep_id = rx_mep_id;
                            g_links[j].mac_learned = true;
                            g_links[j].is_up = true;
                            g_links[j].last_recv_time = now;
                            g_links[j].consecutive_fails = 0;
                            g_links[j].consecutive_successes = CFM_UP_CONFIRM;
                            g_links[j].rx_peer_ccm++;
                            snprintf(ev, sizeof(ev),
                                     "learn-peer if=%s mac=%02x:%02x:%02x:%02x:%02x:%02x",
                                     g_links[j].ifname,
                                     src_mac[0], src_mac[1], src_mac[2],
                                     src_mac[3], src_mac[4], src_mac[5]);
                            pthread_mutex_unlock(&g_links[j].lock);
                            log_unified_mac_table(ev);
                            notify_is_up(&g_links[j], old_up, 0);
                            continue;
                        } else if (memcmp(src_mac, g_links[j].remote_mac, 6) != 0) {
                            /* Peer MAC đổi — cập nhật, không giữ MAC cũ. */
                            char ev[128];
                            uint8_t old_mac[6];

                            memcpy(old_mac, g_links[j].remote_mac, 6);
                            memcpy(g_links[j].remote_mac, src_mac, 6);
                            g_links[j].remote_mep_id = rx_mep_id;
                            g_links[j].last_recv_time = now;
                            g_links[j].consecutive_fails = 0;
                            g_links[j].consecutive_successes = CFM_UP_CONFIRM;
                            g_links[j].is_up = true;
                            g_links[j].rx_peer_ccm++;
                            snprintf(ev, sizeof(ev),
                                     "peer-mac-change if=%s "
                                     "old=%02x:%02x:%02x:%02x:%02x:%02x "
                                     "new=%02x:%02x:%02x:%02x:%02x:%02x",
                                     g_links[j].ifname,
                                     old_mac[0], old_mac[1], old_mac[2],
                                     old_mac[3], old_mac[4], old_mac[5],
                                     src_mac[0], src_mac[1], src_mac[2],
                                     src_mac[3], src_mac[4], src_mac[5]);
                            pthread_mutex_unlock(&g_links[j].lock);
                            log_unified_mac_table(ev);
                            notify_is_up(&g_links[j], old_up, 0);
                            continue;
                        } else if (rx_mep_id == g_links[j].remote_mep_id) {
                            g_links[j].last_recv_time = now;
                            g_links[j].consecutive_fails = 0;
                            if (g_links[j].consecutive_successes < CFM_UP_CONFIRM)
                                g_links[j].consecutive_successes++;
                            if (g_links[j].consecutive_successes >= CFM_UP_CONFIRM)
                                g_links[j].is_up = true;
                            g_links[j].rx_peer_ccm++;
                        }
                        pthread_mutex_unlock(&g_links[j].lock);
                        notify_is_up(&g_links[j], old_up, 1);
                    }
                }
            }
        }

        // Periodic TX and timeout evaluation
        uint64_t now = get_time_ms();
        if (now - last_tx_time >= CFM_INTERVAL_MS) {
            for (int i = 0; i < g_link_count; i++) {
                if (g_links[i].sock_fd >= 0) {
                    bool old_up;

                    // Send out heartbeat
                    send_ccm_packet(&g_links[i]);

                    // Evaluate health status (debounce + startup timeout)
                    pthread_mutex_lock(&g_links[i].lock);
                    old_up = g_links[i].is_up;
                    if (g_links[i].mac_learned) {
                        if (now - g_links[i].last_recv_time > CFM_TIMEOUT_MS) {
                            g_links[i].consecutive_fails++;
                            g_links[i].consecutive_successes = 0;
                            if (g_links[i].consecutive_fails >= CFM_DOWN_CONFIRM)
                                g_links[i].is_up = false;
                        } else {
                            g_links[i].consecutive_fails = 0;
                            if (g_links[i].consecutive_successes < CFM_UP_CONFIRM)
                                g_links[i].consecutive_successes++;
                            if (g_links[i].consecutive_successes >= CFM_UP_CONFIRM)
                                g_links[i].is_up = true;
                        }
                    } else {
                        /* No peer yet: stay UP briefly, then DOWN if never learned. */
                        if (now - g_links[i].last_recv_time > CFM_STARTUP_TIMEOUT_MS) {
                            g_links[i].is_up = false;
                        } else {
                            g_links[i].is_up = true;
                        }
                    }
                    pthread_mutex_unlock(&g_links[i].lock);
                    notify_is_up(&g_links[i], old_up, 1);
                }
            }
            last_tx_time = now;
        }

        /* Waiting for peer MAC: one table, not per-iface spam mixed with traffic. */
        now = get_time_ms();
        if (now - last_wait_log >= 5000) {
            int waiting = 0;

            for (int i = 0; i < g_link_count; i++) {
                if (g_links[i].sock_fd < 0)
                    continue;
                pthread_mutex_lock(&g_links[i].lock);
                if (!g_links[i].mac_learned)
                    waiting++;
                pthread_mutex_unlock(&g_links[i].lock);
            }
            if (waiting > 0)
                log_unified_mac_table("wait-peer");
            last_wait_log = now;
        }
    }
    return NULL;
}

int cfm_init(const struct app_config *cfg) {
    pthread_mutex_lock(&g_cfm_init_lock);
    if (g_cfm_running) {
        g_cfm_running = false;
        pthread_mutex_unlock(&g_cfm_init_lock);
        pthread_join(g_cfm_thread, NULL);
        pthread_mutex_lock(&g_cfm_init_lock);
        for (int i = 0; i < g_link_count; i++) {
            if (g_links[i].sock_fd >= 0) {
                close(g_links[i].sock_fd);
            }
            pthread_mutex_destroy(&g_links[i].lock);
        }
        g_link_count = 0;
    }

    g_link_count = 0;
    memset(g_links, 0, sizeof(g_links));

    int initialized_links = 0;
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++) {
        const struct wan_config *wan = &cfg->wans[i];
        if (strlen(wan->ifname) == 0) continue;

        // Skip interfaces that have a dst_ip configured (these are authen/IP interfaces)
        if (wan->dst_ip != 0) {
            continue;
        }

        int ifindex = if_nametoindex(wan->ifname);
        if (ifindex == 0) {
            fprintf(stderr, "[CFM-INIT] Warning: Interface %s index not found.\n", wan->ifname);
            continue;
        }

        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) {
            fprintf(stderr, "[CFM-INIT] Error: Cannot create raw socket for %s: %s\n", wan->ifname, strerror(errno));
            continue;
        }

        // Bind socket to specific interface
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            fprintf(stderr, "[CFM-INIT] Error: Cannot bind raw socket to %s: %s\n", wan->ifname, strerror(errno));
            close(sock);
            continue;
        }

        /*
         * Cần để nhận CCM peer (dst=01:80:c2:00:00:35):
         * tcpdump thấy được vì bật promisc; AF_PACKET mặc định thường không.
         */
        {
            int ignore_out = 1;
            if (setsockopt(sock, SOL_PACKET, PACKET_IGNORE_OUTGOING,
                           &ignore_out, sizeof(ignore_out)) < 0) {
                fprintf(stderr, "[CFM-INIT] Warning: PACKET_IGNORE_OUTGOING %s: %s\n",
                        wan->ifname, strerror(errno));
            }
        }
        {
            struct ifreq ifr_p;
            memset(&ifr_p, 0, sizeof(ifr_p));
            strncpy(ifr_p.ifr_name, wan->ifname, IFNAMSIZ - 1);
            if (ioctl(sock, SIOCGIFFLAGS, &ifr_p) == 0) {
                ifr_p.ifr_flags |= IFF_PROMISC;
                if (ioctl(sock, SIOCSIFFLAGS, &ifr_p) < 0) {
                    fprintf(stderr, "[CFM-INIT] Warning: IFF_PROMISC %s: %s\n",
                            wan->ifname, strerror(errno));
                }
            }
        }
        {
            struct packet_mreq mreq;
            memset(&mreq, 0, sizeof(mreq));
            mreq.mr_ifindex = ifindex;
            mreq.mr_type = PACKET_MR_PROMISC;
            if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
                fprintf(stderr, "[CFM-INIT] Warning: PACKET_MR_PROMISC %s: %s\n",
                        wan->ifname, strerror(errno));
            }
            memset(&mreq, 0, sizeof(mreq));
            mreq.mr_ifindex = ifindex;
            mreq.mr_type = PACKET_MR_MULTICAST;
            mreq.mr_alen = 6;
            memcpy(mreq.mr_address, CFM_MULTICAST_MAC, 6);
            if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
                fprintf(stderr, "[CFM-INIT] Warning: CFM multicast join %s: %s\n",
                        wan->ifname, strerror(errno));
            }
        }

        // Set non-blocking socket
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        cfm_link_t *link = &g_links[g_link_count];
        strncpy(link->ifname, wan->ifname, IFNAMSIZ - 1);
        link->ifindex = ifindex;
        link->sock_fd = sock;
        link->cfg_wan_idx = i;
        link->wan_dp = config_wan_cfg_to_dp(cfg, i);
        cfm_bridge_for_wan_dp(cfg, link->wan_dp, link->bridge);

        // Query local MAC address dynamically, fallback to DB configuration
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, wan->ifname, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
            memcpy(link->local_mac, ifr.ifr_hwaddr.sa_data, 6);
        } else {
            memcpy(link->local_mac, wan->src_mac, 6);
        }

        // Assign local MEP ID based on the local MAC address (13-bit hash)
        link->local_mep_id = ((link->local_mac[4] << 8) | link->local_mac[5]) & 0x1FFF;
        if (link->local_mep_id == 0) link->local_mep_id = 1;

        // Check if destination MAC is configured in the DB
        bool zero_dst_mac = true;
        for (int k = 0; k < 6; k++) {
            if (wan->dst_mac[k] != 0) {
                zero_dst_mac = false;
                break;
            }
        }

        if (!zero_dst_mac) {
            memcpy(link->remote_mac, wan->dst_mac, 6);
            link->remote_mep_id = ((wan->dst_mac[4] << 8) | wan->dst_mac[5]) & 0x1FFF;
            if (link->remote_mep_id == 0) link->remote_mep_id = 1;
            link->mac_learned = true;
        } else {
            memset(link->remote_mac, 0, 6);
            link->remote_mep_id = 0;
            link->mac_learned = false;
        }

        link->last_recv_time = get_time_ms();
        link->tx_seq = 0;
        link->consecutive_fails = 0;
        link->consecutive_successes = link->mac_learned ? CFM_UP_CONFIRM : 0;
        link->is_up = true; // Assume UP initially so we don't disrupt traffic before learning
        pthread_mutex_init(&link->lock, NULL);

        g_link_count++;
        initialized_links++;
    }

    if (initialized_links > 0) {
        log_unified_mac_table("init");
        g_cfm_running = true;
        if (pthread_create(&g_cfm_thread, NULL, cfm_monitor_thread, NULL) != 0) {
            fprintf(stderr, "[CFM-INIT] Error: Failed to create CFM monitor thread.\n");
            g_cfm_running = false;
            for (int i = 0; i < g_link_count; i++) {
                close(g_links[i].sock_fd);
                pthread_mutex_destroy(&g_links[i].lock);
            }
            g_link_count = 0;
            pthread_mutex_unlock(&g_cfm_init_lock);
            return -1;
        }
        fprintf(stderr, "[CFM-INIT] CFM started on %d WAN(s)\n", initialized_links);
        fflush(stderr);
    } else {
        fprintf(stderr, "[CFM-INIT] No WAN interfaces initialized for CFM.\n");
        fflush(stderr);
    }

    pthread_mutex_unlock(&g_cfm_init_lock);
    return 0;
}

int cfm_link_is_down(int wan_dp)
{
    cfm_link_t *link = find_link_by_wan_dp(wan_dp);
    bool is_up;

    if (!link)
        return 0;

    pthread_mutex_lock(&link->lock);
    is_up = link->is_up;
    pthread_mutex_unlock(&link->lock);
    return is_up ? 0 : 1;
}

void cfm_cleanup(void) {
    pthread_mutex_lock(&g_cfm_init_lock);
    if (!g_cfm_running) {
        pthread_mutex_unlock(&g_cfm_init_lock);
        return;
    }

    g_cfm_running = false;
    pthread_join(g_cfm_thread, NULL);

    for (int i = 0; i < g_link_count; i++) {
        if (g_links[i].sock_fd >= 0) {
            close(g_links[i].sock_fd);
        }
        pthread_mutex_destroy(&g_links[i].lock);
    }
    g_link_count = 0;

    printf("[CFM-CLEANUP] CFM diagnostic daemon stopped.\n");
    pthread_mutex_unlock(&g_cfm_init_lock);
}

void cfm_set_state_callback(cfm_link_state_cb cb, void *user)
{
    pthread_mutex_lock(&g_cb_lock);
    g_state_cb = cb;
    g_state_cb_user = user;
    pthread_mutex_unlock(&g_cb_lock);
}

#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/iface/profile_iface_xdp.h"
#include "../../../inc/core/dataplane/dataplane_stats.h"
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>

static __thread const char *tls_dp_tx_dir;
static __thread int tls_dp_tx_slot = -1;

void ne_dp_tx_ctx(const char *dir, int tx_slot)
{
    tls_dp_tx_dir = dir;
    tls_dp_tx_slot = tx_slot;
}

void ne_dp_warn_rx(const char *dir, int cpu, int batch_rcvd)
{
    (void)dir;
    (void)cpu;
    (void)batch_rcvd;
}

void ne_dp_warn_rx_drop(const char *dir, int cpu, int worker, uint32_t q_depth)
{
    (void)dir;
    (void)cpu;
    (void)worker;
    (void)q_depth;
}

void ne_dp_warn_crypto(int cpu, int worker, uint32_t lan_q, uint32_t wan_q)
{
    (void)cpu;
    (void)worker;
    (void)lan_q;
    (void)wan_q;
}

static int ne_rx_slots_for_queues(int queue_total, uint32_t slots_max)
{
    if (queue_total <= 0)
        return 1;
    if ((uint32_t)queue_total < slots_max)
        return queue_total;
    return (int)slots_max;
}

int ne_rx_lan_slots_for(int local_queue_total)
{
    return ne_rx_slots_for_queues(local_queue_total, NE_RX_LAN_SLOTS);
}

int ne_rx_wan_slots_for(int wan_queue_total)
{
    return ne_rx_slots_for_queues(wan_queue_total, NE_RX_WAN_SLOTS);
}

static int ifname_is_safe(const char *ifname)
{
    if (!ifname || !ifname[0])
        return 0;
    for (const unsigned char *p = (const unsigned char *)ifname; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

static int interface_set_promisc_off(const char *ifname)
{
    if (!ifname_is_safe(ifname))
        return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s promisc off >/dev/null 2>&1", ifname);
    return system(cmd) == 0 ? 0 : -1;
}

void interface_promisc_off_config(const struct app_config *cfg)
{
    if (!cfg)
        return;
    for (int i = 0; i < cfg->local_count && i < MAX_INTERFACES; i++)
        interface_set_promisc_off(cfg->locals[i].ifname);
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        interface_set_promisc_off(cfg->wans[i].ifname);
}

void interface_reset_redirect_maps(void) {}

int interface_set_queue_count(const char *ifname, int desired_count)
{
    if (!ifname_is_safe(ifname) || desired_count <= 0)
        return -1;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ethtool -L %s combined %d >/dev/null 2>&1",
             ifname, desired_count);
    if (system(cmd) == 0) {
        return 0;
    }

    snprintf(cmd, sizeof(cmd), "ethtool -L %s rx %d tx %d >/dev/null 2>&1",
             ifname, desired_count, desired_count);
    if (system(cmd) == 0)
        return 0;

    return -1;
}

static int interface_set_promisc(const char *ifname)
{
    if (!ifname_is_safe(ifname))
        return -1;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s promisc on >/dev/null 2>&1", ifname);
    if (system(cmd) == 0)
        return 0;

    return -1;
}

int interface_get_queue_count(const char *ifname)
{
    char path[256];
    int count = 0;

    if (!ifname_is_safe(ifname))
        return 1;

    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", ifname);
    DIR *dir = opendir(path);
    if (!dir)
        return 1;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "rx-", 3) == 0)
            count++;
    }
    closedir(dir);
    return count > 0 ? count : 1;
}

static int resolve_iface_queue_count(const char *ifname)
{
    int hw = interface_get_queue_count(ifname);
    if (hw < 1)
        hw = 1;

#if NE_QUEUE_OVERRIDE > 0
    int want = NE_QUEUE_OVERRIDE;
#else
    int want = hw;
#endif

    if (want > MAX_QUEUES)
        want = MAX_QUEUES;
    if (want < 1)
        want = 1;
    return want;
}

static int apply_iface_queue_count(const char *ifname, int want)
{
#if NE_QUEUE_OVERRIDE > 0
    int hw = interface_get_queue_count(ifname);

    if (hw != want)
        return interface_set_queue_count(ifname, want);
#endif
    (void)ifname;
    (void)want;
    return 0;
}

int ne_ring_init(struct ne_ring *r, uint32_t cap, int mpsc_pop)
{
    if (!r || cap == 0 || (cap & (cap - 1)) != 0)
        return -1;
    memset(r, 0, sizeof(*r));
    r->buf = calloc(cap, sizeof(*r->buf));
    if (!r->buf)
        return -1;
    r->cap = cap;
    r->mask = cap - 1;
    r->mpsc_pop = mpsc_pop ? 1 : 0;
    if (pthread_spin_init(&r->push_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        free(r->buf);
        memset(r, 0, sizeof(*r));
        return -1;
    }
    if (r->mpsc_pop && pthread_spin_init(&r->pop_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        pthread_spin_destroy(&r->push_lock);
        free(r->buf);
        memset(r, 0, sizeof(*r));
        return -1;
    }
    return 0;
}

void ne_ring_destroy(struct ne_ring *r)
{
    if (!r)
        return;
    if (r->mpsc_pop)
        pthread_spin_destroy(&r->pop_lock);
    pthread_spin_destroy(&r->push_lock);
    free(r->buf);
    memset(r, 0, sizeof(*r));
}

// Push gói tin đi vào ring (muilti core push)
int ne_ring_try_push(struct ne_ring *r, const struct ne_packet *pkt)
{
    uint32_t head, tail;

    if (!r || !pkt)
        return -1;

    pthread_spin_lock(&r->push_lock);
    head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
    tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    if ((uint32_t)(head - tail) >= r->cap) {
        pthread_spin_unlock(&r->push_lock);
        return -1;
    }
    r->buf[head & r->mask] = *pkt;
    __atomic_store_n(&r->head, head + 1, __ATOMIC_RELEASE);
    pthread_spin_unlock(&r->push_lock);
    return 0;
}

// Pop gói tin đi ra khỏi ring
int ne_ring_try_pop(struct ne_ring *r, struct ne_packet *pkt)
{
    uint32_t tail, head;

    if (!r || !pkt)
        return -1;

    if (r->mpsc_pop)
        pthread_spin_lock(&r->pop_lock);
    tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
    head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    if (tail == head) { // ring trống
        if (r->mpsc_pop)
            pthread_spin_unlock(&r->pop_lock);
        return -1;
    }
    *pkt = r->buf[tail & r->mask];
    __atomic_store_n(&r->tail, tail + 1, __ATOMIC_RELEASE);
    if (r->mpsc_pop)
        pthread_spin_unlock(&r->pop_lock);
    return 0;
}

uint32_t ne_ring_count(const struct ne_ring *r)
{
    uint32_t head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    return head - tail;
}

static int pool_init(struct ne_pool *p, uint32_t cap)
{
    if (!p || cap == 0 || (cap & (cap - 1)) != 0)
        return -1;
    memset(p, 0, sizeof(*p));
    p->buf = calloc(cap, sizeof(*p->buf));
    if (!p->buf)
        return -1;
    p->cap = cap;
    p->mask = cap - 1;
    if (pthread_spin_init(&p->lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        free(p->buf);
        memset(p, 0, sizeof(*p));
        return -1;
    }
    return 0;
}

static void pool_destroy(struct ne_pool *p)
{
    if (!p || !p->buf)
        return;
    pthread_spin_destroy(&p->lock);
    free(p->buf);
    memset(p, 0, sizeof(*p));
}

static uint32_t pool_push(struct ne_pool *p, const uint64_t *addrs, uint32_t n)
{
    pthread_spin_lock(&p->lock);
    uint32_t free_slots = p->cap - (p->head - p->tail);
    uint32_t put = n < free_slots ? n : free_slots;
    uint32_t head = p->head;
    for (uint32_t i = 0; i < put; i++)
        p->buf[(head + i) & p->mask] = addrs[i];
    p->head += put;
    pthread_spin_unlock(&p->lock);
    return put;
}

static uint32_t pool_pop(struct ne_pool *p, uint64_t *addrs, uint32_t n)
{
    pthread_spin_lock(&p->lock);
    uint32_t avail = p->head - p->tail;
    uint32_t got = n < avail ? n : avail;
    uint32_t tail = p->tail;
    for (uint32_t i = 0; i < got; i++)
        addrs[i] = p->buf[(tail + i) & p->mask];
    p->tail += got;
    pthread_spin_unlock(&p->lock);
    return got;
}

int ne_frame_alloc(struct ne_pair *p, uint64_t *addr_out)
{
    if (p && addr_out && pool_pop(&p->pool, addr_out, 1) == 1)
        return 0;
    return -1;
}

uint32_t ne_frame_alloc_batch(struct ne_pair *p, uint64_t *addrs_out, uint32_t max_n)
{
    if (!p || !addrs_out || max_n == 0)
        return 0;
    return pool_pop(&p->pool, addrs_out, max_n);
}

void ne_frame_free(struct ne_pair *p, uint64_t addr)
{
    if (p)
        (void)pool_push(&p->pool, &addr, 1);
}

uint32_t ne_pool_free_count(struct ne_pair *p)
{
    uint32_t n;

    if (!p || !p->pool.buf)
        return 0;
    pthread_spin_lock(&p->pool.lock);
    n = p->pool.head - p->pool.tail;
    pthread_spin_unlock(&p->pool.lock);
    return n;
}

void *ne_packet_data(struct ne_pair *p, uint64_t addr)
{
    return xsk_umem__get_data(p->bufs, addr);
}

static int interface_is_up(const char *ifname)
{
    int fd;
    struct ifreq ifr;

    if (!ifname_is_safe(ifname))
        return 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
        close(fd);
        return 0;
    }
    close(fd);
    return (ifr.ifr_flags & IFF_UP) != 0;
}

static int interface_is_bridge_slave(const char *ifname)
{
    char path[256];

    if (!ifname_is_safe(ifname))
        return 0;
    snprintf(path, sizeof(path), "/sys/class/net/%s/master", ifname);
    return access(path, F_OK) == 0;
}

static int interface_get_mtu(const char *ifname)
{
    int fd;
    struct ifreq ifr;

    if (!ifname_is_safe(ifname))
        return -1;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFMTU, &ifr) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return ifr.ifr_mtu;
}

static void interface_log_xsk_context(const char *ifname, int queue_id, int ret)
{
    char master[IF_NAMESIZE];
    char path[256];
    int mtu;
    int nq;
    int err = ret < 0 ? -ret : ret;

    master[0] = '\0';
    if (ifname_is_safe(ifname)) {
        snprintf(path, sizeof(path), "/sys/class/net/%s/master", ifname);
        if (access(path, F_OK) == 0) {
            char link[256];
            ssize_t n = readlink(path, link, sizeof(link) - 1);
            if (n > 0) {
                link[n] = '\0';
                const char *base = strrchr(link, '/');
                const char *name = base ? base + 1 : link;
                size_t nlen = strlen(name);
                if (nlen >= sizeof(master))
                    nlen = sizeof(master) - 1;
                memcpy(master, name, nlen);
                master[nlen] = '\0';
            }
        }
    }
    mtu = interface_get_mtu(ifname);
    nq = interface_get_queue_count(ifname);
    fprintf(stderr,
            "[DP] XSK create failed %s q=%d: %s (%d) — mtu=%d queues=%d frame=%u master=%s%s\n",
            ifname, queue_id, strerror(err), ret, mtu, nq, NE_FRAME,
            master[0] ? master : "-",
            interface_is_bridge_slave(ifname) ? " (bridge-slave, Br kept)" : "");
    fflush(stderr);
}

static int interface_preflight(const char *ifname)
{
    if (!ifname_is_safe(ifname))
        return -1;
    if (if_nametoindex(ifname) == 0) {
        fprintf(stderr, "[DP] %s: interface not found\n", ifname);
        fflush(stderr);
        return -1;
    }
    if (!interface_is_up(ifname)) {
        fprintf(stderr, "[DP] %s: link is DOWN\n", ifname);
        fflush(stderr);
        return -1;
    }
    /* Br membership is intentional (customer default) — do not reject. */
    (void)interface_is_bridge_slave(ifname);
    return 0;
}

static int is_umem_fq_owner_queue(const struct ne_pair *p, const struct ne_iface *iface, int q)
{
    if (!p || !iface || p->umem_fq_li < 0 || p->umem_fq_q < 0)
        return 0;
    if (p->umem_fq_li >= MAX_INTERFACES)
        return 0;
    return iface == &p->locals[p->umem_fq_li] && q == p->umem_fq_q;
}

static void zero_queue_rings(struct ne_xsk_queue *slot, int preserve_fq_cq)
{
    if (!slot)
        return;
    slot->rx_pending = 0;
    memset(&slot->rx, 0, sizeof(slot->rx));
    memset(&slot->tx, 0, sizeof(slot->tx));
    if (!preserve_fq_cq) {
        memset(&slot->fq, 0, sizeof(slot->fq));
        memset(&slot->cq, 0, sizeof(slot->cq));
    }
}

static void drain_cq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool);

static void reclaim_rx_queue(struct ne_xsk_queue *slot, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t n;

    if (!slot || !pool || !slot->rx.ring)
        return;

    if (slot->rx_pending) {
        uint32_t start = slot->rx.cached_cons - slot->rx_pending;
        uint32_t pending = slot->rx_pending;
        uint32_t off = 0;

        while (off < pending) {
            uint32_t batch = pending - off;
            uint32_t i;

            if (batch > NE_BATCH_SIZE)
                batch = NE_BATCH_SIZE;
            for (i = 0; i < batch; i++)
                addrs[i] = xsk_ring_cons__rx_desc(&slot->rx, start + off + i)->addr;
            (void)pool_push(pool, addrs, batch);
            off += batch;
        }
        xsk_ring_cons__release(&slot->rx, pending);
        slot->rx_pending = 0;
    }

    while ((n = xsk_ring_cons__peek(&slot->rx, NE_BATCH_SIZE, &idx)) > 0) {
        for (uint32_t i = 0; i < n; i++)
            addrs[i] = xsk_ring_cons__rx_desc(&slot->rx, idx + i)->addr;
        (void)pool_push(pool, addrs, n);
        xsk_ring_cons__release(&slot->rx, n);
        if (n < NE_BATCH_SIZE)
            break;
    }
}

static void reclaim_iface_umem_frames(struct ne_pair *p, struct ne_iface *iface)
{
    if (!p || !iface)
        return;
    for (int q = 0; q < iface->queue_count; q++) {
        struct ne_xsk_queue *slot = &iface->queues[q];

        drain_cq_queue(slot, &p->pool);
        reclaim_rx_queue(slot, &p->pool);
    }
}

static int queue_holds_umem_fd(const struct ne_pair *p, const struct ne_xsk_queue *slot)
{
    if (!p || !p->umem || !slot || !slot->xsk)
        return 0;
    return xsk_socket__fd(slot->xsk) == xsk_umem__fd(p->umem);
}

static int iface_holds_umem_fd(const struct ne_pair *p, const struct ne_iface *iface, int nq)
{
    for (int q = 0; q < nq; q++) {
        if (queue_holds_umem_fd(p, &iface->queues[q]))
            return 1;
    }
    return 0;
}

static int ne_pair_other_live_count(const struct ne_pair *p, int skip_local, int skip_wan)
{
    int n = 0;

    if (!p)
        return 0;
    for (int i = 0; i < p->local_count; i++) {
        if (i == skip_local)
            continue;
        if (p->local_live[i])
            n++;
    }
    for (int i = 0; i < p->wan_count; i++) {
        if (i == skip_wan)
            continue;
        if (p->wan_live[i])
            n++;
    }
    return n;
}

/* Delete XSK sockets: non-UMEM-fd first, UMEM-fd last (libxdp shares via umem->fd). */
static void delete_iface_xsks(struct ne_pair *p, struct ne_iface *iface, int nq)
{
    for (int pass = 0; pass < 2; pass++) {
        for (int q = 0; q < nq; q++) {
            struct ne_xsk_queue *slot = &iface->queues[q];
            int is_umem_fd;

            if (!slot->xsk)
                continue;
            is_umem_fd = queue_holds_umem_fd(p, slot);
            if (pass == 0 && is_umem_fd)
                continue;
            if (pass == 1 && !is_umem_fd)
                continue;
            xsk_socket__delete(slot->xsk);
            slot->xsk = NULL;
        }
    }
}

void ne_pair_delete_local_xsks(struct ne_pair *p, int pair_li)
{
    if (!p || pair_li < 0 || pair_li >= MAX_INTERFACES)
        return;
    delete_iface_xsks(p, &p->locals[pair_li], p->locals[pair_li].queue_count);
}

void ne_pair_delete_wan_xsks(struct ne_pair *p, int dp_slot)
{
    if (!p || dp_slot < 0 || dp_slot >= MAX_INTERFACES)
        return;
    delete_iface_xsks(p, &p->wans[dp_slot], p->wans[dp_slot].queue_count);
}

static void delete_all_live_xsks(struct ne_pair *p)
{
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (p->local_live[i] || p->locals[i].queue_count > 0)
            delete_iface_xsks(p, &p->locals[i], p->locals[i].queue_count);
        if (p->wan_live[i] || p->wans[i].queue_count > 0)
            delete_iface_xsks(p, &p->wans[i], p->wans[i].queue_count);
    }
}

static int pool_reset_full(struct ne_pool *pool, uint32_t n_frames, uint32_t frame_size)
{
    if (!pool || !pool->buf || n_frames == 0)
        return -1;
    pthread_spin_lock(&pool->lock);
    pool->head = 0;
    pool->tail = 0;
    pthread_spin_unlock(&pool->lock);
    for (uint32_t i = 0; i < n_frames; i++) {
        uint64_t addr = (uint64_t)i * frame_size;
        if (pool_push(pool, &addr, 1) != 1)
            return -1;
    }
    return 0;
}

static int ne_pair_destroy_umem(struct ne_pair *p)
{
    if (!p)
        return -1;

    if (p->umem) {
        (void)xsk_umem__delete(p->umem);
        p->umem = NULL;
    }
    p->umem_fq_li = -1;
    p->umem_fq_q = -1;

    if (!p->bufs || p->bufs == MAP_FAILED || p->n_frames == 0)
        return 0;
    if (pool_reset_full(&p->pool, p->n_frames, p->frame_size) != 0) {
        fprintf(stderr, "[DP] umem destroy: pool reset failed\n");
        fflush(stderr);
        return -1;
    }
    fprintf(stderr, "[DP] umem cleared — next LAN plumb will create fresh\n");
    fflush(stderr);
    return 0;
}

static int ne_pair_create_umem_on_local(struct ne_pair *p, int pair_li)
{
    struct xsk_umem_config ucfg = {
        .fill_size = NE_RING,
        .comp_size = NE_RING,
        .frame_size = 0,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    if (!p || !p->bufs || p->bufs == MAP_FAILED || pair_li < 0 ||
        pair_li >= MAX_INTERFACES)
        return -1;
    if (p->umem)
        return 0;

    if (pool_reset_full(&p->pool, p->n_frames, p->frame_size) != 0) {
        fprintf(stderr, "[DP] umem create: pool reset failed\n");
        fflush(stderr);
        return -1;
    }

    ucfg.frame_size = p->frame_size;
    memset(&p->locals[pair_li].queues[0].fq, 0, sizeof(p->locals[pair_li].queues[0].fq));
    memset(&p->locals[pair_li].queues[0].cq, 0, sizeof(p->locals[pair_li].queues[0].cq));
    if (xsk_umem__create(&p->umem, p->bufs, p->bufsize,
                         &p->locals[pair_li].queues[0].fq,
                         &p->locals[pair_li].queues[0].cq, &ucfg) != 0) {
        fprintf(stderr, "[DP] umem create on LAN slot %d failed: %s\n",
                pair_li, strerror(errno));
        fflush(stderr);
        return -1;
    }
    p->umem_fq_li = pair_li;
    p->umem_fq_q = 0;
    fprintf(stderr, "[DP] fresh umem on LAN slot %d\n", pair_li);
    fflush(stderr);
    return 0;
}

static void clear_iface_queues_after_delete(struct ne_pair *p, struct ne_iface *iface, int nq)
{
    if (!p || !iface)
        return;
    for (int q = 0; q < nq; q++) {
        struct ne_xsk_queue *slot = &iface->queues[q];

        slot->xsk = NULL;
        zero_queue_rings(slot, is_umem_fq_owner_queue(p, iface, q));
    }
    iface->ifindex = 0;
    iface->ifname[0] = '\0';
    iface->queue_count = 0;
    iface->xdp_flags = 0;
}

static int xsk_create_queue(struct ne_pair *p, struct ne_iface *iface, const char *ifname,
                            int q, uint32_t xdp_flags)
{
    struct ne_xsk_queue *slot = &iface->queues[q];
    int preserve = is_umem_fq_owner_queue(p, iface, q);
    struct xsk_socket_config cfg = {
        .rx_size = NE_RING,
        .tx_size = NE_RING,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = xdp_flags,
        /* Toggle AF_XDP mode here only: XDP_COPY (ixgbe) or XDP_ZEROCOPY (ice). */
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };

    zero_queue_rings(slot, preserve);
    return xsk_socket__create_shared(&slot->xsk, ifname, (uint32_t)q, p->umem,
                                     &slot->rx, &slot->tx,
                                     &slot->fq, &slot->cq, &cfg);
}

static void open_iface_queues_rollback(struct ne_pair *p, struct ne_iface *iface, int opened)
{
    for (int j = 0; j < opened; j++) {
        if (iface->queues[j].xsk) {
            xsk_socket__delete(iface->queues[j].xsk);
            iface->queues[j].xsk = NULL;
        }
        zero_queue_rings(&iface->queues[j], is_umem_fq_owner_queue(p, iface, j));
    }
    iface->queue_count = 0;
    iface->ifindex = 0;
    iface->ifname[0] = '\0';
    iface->xdp_flags = 0;
}

static int open_iface_queues(struct ne_pair *p, struct ne_iface *iface,
                             const char *ifname, int queue_count)
{
    const uint32_t mode = XDP_FLAGS_DRV_MODE;
    int q;
    int ret = 0;

    iface->ifindex = (int)if_nametoindex(ifname);
    if (!iface->ifindex) {
        fprintf(stderr, "[DP] XSK open failed %s: interface not found\n", ifname);
        fflush(stderr);
        return -1;
    }
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    iface->ifname[sizeof(iface->ifname) - 1] = '\0';
    iface->queue_count = queue_count;
    iface->xdp_flags = 0;

    for (q = 0; q < queue_count; q++) {
        ret = xsk_create_queue(p, iface, ifname, q, mode);
        if (ret) {
            open_iface_queues_rollback(p, iface, q);
            interface_log_xsk_context(ifname, q, ret);
            iface->queue_count = 0;
            iface->ifindex = 0;
            iface->ifname[0] = '\0';
            iface->xdp_flags = 0;
            return -1;
        }
    }
    iface->xdp_flags = mode;
    return 0;
}

static void prefill_queue(struct ne_pair *p, struct ne_xsk_queue *slot, uint32_t want)
{
    uint64_t addrs[NE_BATCH_SIZE];

    while (want > 0) {
        uint32_t n = want > NE_BATCH_SIZE ? NE_BATCH_SIZE : want;
        uint32_t got = pool_pop(&p->pool, addrs, n);
        if (got == 0)
            return;

        uint32_t idx = 0;
        uint32_t reserved = xsk_ring_prod__reserve(&slot->fq, got, &idx);
        if (reserved != got) {
            (void)pool_push(&p->pool, addrs, got);
            return;
        }
        for (uint32_t i = 0; i < got; i++)
            *xsk_ring_prod__fill_addr(&slot->fq, idx + i) = addrs[i];
        xsk_ring_prod__submit(&slot->fq, got);
        want -= got;
    }
}

static void prefill_iface(struct ne_pair *p, struct ne_iface *iface, uint32_t want_per_queue)
{
    for (int q = 0; q < iface->queue_count; q++)
        prefill_queue(p, &iface->queues[q], want_per_queue);
}

int ne_pair_open(struct ne_pair *p, const struct app_config *cfg)
{
#define NE_TRY(expr) do { if (expr) goto fail; } while (0)
    if (!p || !cfg || cfg->local_count <= 0)
        return -1;

    memset(p, 0, sizeof(*p));
    p->umem_fq_li = -1;
    p->umem_fq_q = -1;
    p->local_count = cfg->local_count;
    if (p->local_count > MAX_INTERFACES)
        p->local_count = MAX_INTERFACES;
    p->wan_count = config_count_dataplane_wans(cfg);
    if (p->wan_count > MAX_INTERFACES)
        p->wan_count = MAX_INTERFACES;
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    (void)setrlimit(RLIMIT_MEMLOCK, &rl);

    p->frame_size = NE_FRAME;
    p->xdp_flags = XDP_FLAGS_DRV_MODE;

    p->local_queue_total = 0;
    p->wan_queue_total = 0;

    for (int i = 0; i < p->local_count; i++) {
        int nq = resolve_iface_queue_count(cfg->locals[i].ifname);
        NE_TRY(apply_iface_queue_count(cfg->locals[i].ifname, nq));
        p->locals[i].queue_count = nq;
        p->local_queue_total += nq;
    }
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        int nq = resolve_iface_queue_count(cfg->wans[ci].ifname);
        NE_TRY(apply_iface_queue_count(cfg->wans[ci].ifname, nq));
        p->wans[di].queue_count = nq;
        p->wan_queue_total += nq;
    }

    p->n_frames = NE_N_FRAMES;
    p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;

    p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p->bufs == MAP_FAILED)
        return -1;

    NE_TRY(pool_init(&p->pool, p->n_frames));
    for (uint32_t i = 0; i < p->n_frames; i++) {
        uint64_t addr = (uint64_t)i * p->frame_size;
        (void)pool_push(&p->pool, &addr, 1);
    }

    for (int i = 0; i < p->local_count; i++)
        NE_TRY(interface_set_promisc(cfg->locals[i].ifname));
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        NE_TRY(interface_set_promisc(cfg->wans[ci].ifname));
    }

    /* Scrub stale XDP before AF_XDP bind (delete→create EINVAL -22). */
    for (int i = 0; i < p->local_count; i++)
        profile_iface_xdp_detach_ifname(cfg->locals[i].ifname);
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        profile_iface_xdp_detach_ifname(cfg->wans[ci].ifname);
    }
    usleep(50000);

    struct xsk_umem_config ucfg = {
        .fill_size = NE_RING,
        .comp_size = NE_RING,
        .frame_size = p->frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    NE_TRY(xsk_umem__create(&p->umem, p->bufs, p->bufsize,
                            &p->locals[0].queues[0].fq,
                            &p->locals[0].queues[0].cq, &ucfg));
    p->umem_fq_li = 0;
    p->umem_fq_q = 0;

    for (int i = 0; i < p->local_count; i++) {
        int rc = open_iface_queues(p, &p->locals[i], cfg->locals[i].ifname,
                                   p->locals[i].queue_count);
        if (rc) {
            /* One scrub+retry — common after rapid delete/recreate. */
            fprintf(stderr,
                    "[DP] LAN %s XSK bind failed — scrub XDP and retry once\n",
                    cfg->locals[i].ifname);
            fflush(stderr);
            profile_iface_xdp_detach_ifname(cfg->locals[i].ifname);
            usleep(150000);
            rc = open_iface_queues(p, &p->locals[i], cfg->locals[i].ifname,
                                   p->locals[i].queue_count);
        }
        NE_TRY(rc);
    }
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        int rc;
        if (ci < 0)
            goto fail;
        rc = open_iface_queues(p, &p->wans[di], cfg->wans[ci].ifname,
                               p->wans[di].queue_count);
        if (rc) {
            fprintf(stderr,
                    "[DP] WAN %s XSK bind failed — scrub XDP and retry once\n",
                    cfg->wans[ci].ifname);
            fflush(stderr);
            profile_iface_xdp_detach_ifname(cfg->wans[ci].ifname);
            usleep(150000);
            rc = open_iface_queues(p, &p->wans[di], cfg->wans[ci].ifname,
                                   p->wans[di].queue_count);
        }
        NE_TRY(rc);
    }

    uint32_t prefill = NE_FQ_PREFILL;

    for (int i = 0; i < p->local_count; i++)
        prefill_iface(p, &p->locals[i], prefill);
    for (int i = 0; i < p->wan_count; i++)
        prefill_iface(p, &p->wans[i], prefill);

    for (int i = 0; i < p->local_count; i++)
        p->local_live[i] = 1;
    for (int i = 0; i < p->wan_count; i++)
        p->wan_live[i] = 1;

    return 0;

fail:
    profile_iface_xdp_detach_config(cfg);
    ne_pair_close(p, cfg);
    return -1;
#undef NE_TRY
}

void ne_pair_close(struct ne_pair *p, const struct app_config *cfg)
{
    if (!p)
        return;


    fprintf(stderr, "[STOP] ne_pair_close: (1/4) delete XSK\n");
    fflush(stderr);
    delete_all_live_xsks(p);

    fprintf(stderr, "[STOP] ne_pair_close: (2/4) close BPF\n");
    fflush(stderr);
    for (int i = 0; i < p->local_count; i++) {
        if (p->bpf_locals[i]) {
            bpf_object__close(p->bpf_locals[i]);
            p->bpf_locals[i] = NULL;
        }
        p->xdp_local_on[i] = 0;
    }
    for (int i = 0; i < p->wan_count; i++) {
        if (p->bpf_wans[i]) {
            bpf_object__close(p->bpf_wans[i]);
            p->bpf_wans[i] = NULL;
        }
        p->xdp_wan_on[i] = 0;
    }

    fprintf(stderr, "[STOP] ne_pair_close: (3/4) ip link xdp off\n");
    fflush(stderr);
    if (cfg)
        profile_iface_xdp_detach_config(cfg);
    else {
        for (int i = 0; i < p->local_count; i++) {
            if (p->locals[i].ifname[0])
                profile_iface_xdp_detach_ifname(p->locals[i].ifname);
        }
        for (int i = 0; i < p->wan_count; i++) {
            if (p->wans[i].ifname[0])
                profile_iface_xdp_detach_ifname(p->wans[i].ifname);
        }
    }

    fprintf(stderr, "[STOP] ne_pair_close: (4/4) delete UMEM\n");
    fflush(stderr);
    if (p->umem) {
        xsk_umem__delete(p->umem);
        p->umem = NULL;
    }
    pool_destroy(&p->pool);
    if (p->bufs && p->bufs != MAP_FAILED)
        munmap(p->bufs, p->bufsize);
    memset(p, 0, sizeof(*p));
}

int ne_pair_local_live(const struct ne_pair *p, int pair_local_idx)
{
    if (!p || pair_local_idx < 0 || pair_local_idx >= p->local_count)
        return 0;
    return p->local_live[pair_local_idx] != 0;
}

int ne_pair_wan_live(const struct ne_pair *p, int dp_slot)
{
    if (!p || dp_slot < 0 || dp_slot >= p->wan_count)
        return 0;
    return p->wan_live[dp_slot] != 0;
}

int ne_pair_plumb_local(struct ne_pair *p, const struct app_config *cfg, int cfg_local_idx,
                        int pair_li)
{
    if (!p || !cfg || cfg_local_idx < 0 || cfg_local_idx >= cfg->local_count)
        return -1;
    if (pair_li < 0 || pair_li >= MAX_INTERFACES)
        return -1;
    if (!p->bufs || p->bufs == MAP_FAILED)
        return -1;

    const char *ifname = cfg->locals[cfg_local_idx].ifname;

    if (interface_preflight(ifname) != 0)
        return -1;

    
    profile_iface_xdp_detach_ifname(ifname);

    int nq = resolve_iface_queue_count(ifname);
    if (apply_iface_queue_count(ifname, nq) != 0) {
        fprintf(stderr, "[DP] plumb LAN %s: queue_count apply failed (want=%d)\n",
                ifname, nq);
        fflush(stderr);
        return -1;
    }
    p->locals[pair_li].queue_count = nq;
    if (interface_set_promisc(ifname) != 0) {
        fprintf(stderr, "[DP] plumb LAN %s: promisc on failed\n", ifname);
        fflush(stderr);
        return -1;
    }
    if (!p->umem && ne_pair_create_umem_on_local(p, pair_li) != 0) {
        p->locals[pair_li].queue_count = 0;
        return -1;
    }
    if (open_iface_queues(p, &p->locals[pair_li], ifname, nq) != 0) {
        fprintf(stderr, "[DP] plumb LAN %s: open_iface_queues/XSK failed\n", ifname);
        fflush(stderr);
        p->locals[pair_li].queue_count = 0;
        if (p->umem_fq_li == pair_li && ne_pair_other_live_count(p, -1, -1) <= 0)
            (void)ne_pair_destroy_umem(p);
        return -1;
    }

    if (pair_li >= p->local_count)
        p->local_count = pair_li + 1;
    p->local_queue_total += nq;
    prefill_iface(p, &p->locals[pair_li], NE_FQ_PREFILL);
    p->local_live[pair_li] = 1;
    return 0;
}

int ne_pair_plumb_wan_dp(struct ne_pair *p, const struct app_config *cfg, int cfg_wan_idx,
                         int dp_slot)
{
    if (!p || !cfg || !p->umem || cfg_wan_idx < 0 || cfg_wan_idx >= cfg->wan_count)
        return -1;
    if (!cfg->wans[cfg_wan_idx].dataplane || dp_slot < 0 || dp_slot >= MAX_INTERFACES)
        return -1;

    const char *ifname = cfg->wans[cfg_wan_idx].ifname;

    if (interface_preflight(ifname) != 0)
        return -1;

    profile_iface_xdp_detach_ifname(ifname);

    int nq = resolve_iface_queue_count(ifname);
    if (apply_iface_queue_count(ifname, nq) != 0) {
        fprintf(stderr, "[DP] plumb WAN %s: queue_count apply failed (want=%d)\n",
                ifname, nq);
        fflush(stderr);
        return -1;
    }
    p->wans[dp_slot].queue_count = nq;
    if (interface_set_promisc(ifname) != 0) {
        fprintf(stderr, "[DP] plumb WAN %s: promisc on failed\n", ifname);
        fflush(stderr);
        return -1;
    }
    if (open_iface_queues(p, &p->wans[dp_slot], ifname, nq) != 0) {
        fprintf(stderr, "[DP] plumb WAN %s: open_iface_queues/XSK failed\n", ifname);
        fflush(stderr);
        p->wans[dp_slot].queue_count = 0;
        return -1;
    }

    if (dp_slot >= p->wan_count)
        p->wan_count = dp_slot + 1;
    p->wan_queue_total += nq;
    prefill_iface(p, &p->wans[dp_slot], NE_FQ_PREFILL);
    p->wan_live[dp_slot] = 1;
    return 0;
}

void ne_pair_unplumb_local(struct ne_pair *p, int pair_li)
{
    int nq;
    int holds;

    if (!p || pair_li < 0 || pair_li >= p->local_count || !p->local_live[pair_li])
        return;

    nq = p->locals[pair_li].queue_count;
    holds = iface_holds_umem_fd(p, &p->locals[pair_li], nq);

    profile_iface_xdp_detach_local(p, pair_li);
    p->local_live[pair_li] = 0;

    reclaim_iface_umem_frames(p, &p->locals[pair_li]);
    delete_iface_xsks(p, &p->locals[pair_li], nq);
    clear_iface_queues_after_delete(p, &p->locals[pair_li], nq);
    if (p->local_queue_total >= nq)
        p->local_queue_total -= nq;
    else
        p->local_queue_total = 0;

    if (holds && ne_pair_other_live_count(p, -1, -1) <= 0)
        (void)ne_pair_destroy_umem(p);
}

int ne_pair_teardown_live(struct ne_pair *p)
{
    if (!p)
        return -1;

    fprintf(stderr, "[DP] teardown all live XSK + clear UMEM\n");
    fflush(stderr);

    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (p->local_live[i] || p->locals[i].queue_count > 0 || p->bpf_locals[i])
            profile_iface_xdp_detach_local(p, i);
        if (p->wan_live[i] || p->wans[i].queue_count > 0 || p->bpf_wans[i])
            profile_iface_xdp_detach_wan(p, i);
    }

    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (p->locals[i].queue_count > 0)
            reclaim_iface_umem_frames(p, &p->locals[i]);
        if (p->wans[i].queue_count > 0)
            reclaim_iface_umem_frames(p, &p->wans[i]);
    }

    delete_all_live_xsks(p);

    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (p->locals[i].queue_count > 0)
            clear_iface_queues_after_delete(p, &p->locals[i], p->locals[i].queue_count);
        if (p->wans[i].queue_count > 0)
            clear_iface_queues_after_delete(p, &p->wans[i], p->wans[i].queue_count);
        p->local_live[i] = 0;
        p->wan_live[i] = 0;
    }

    p->local_queue_total = 0;
    p->wan_queue_total = 0;
    p->local_count = 0;
    p->wan_count = 0;

    return ne_pair_destroy_umem(p);
}

void ne_pair_unplumb_wan_dp(struct ne_pair *p, int dp_slot)
{
    int nq;

    if (!p || dp_slot < 0 || dp_slot >= p->wan_count || !p->wan_live[dp_slot])
        return;

    profile_iface_xdp_detach_wan(p, dp_slot);
    p->wan_live[dp_slot] = 0;
    nq = p->wans[dp_slot].queue_count;

    reclaim_iface_umem_frames(p, &p->wans[dp_slot]);
    delete_iface_xsks(p, &p->wans[dp_slot], nq);
    clear_iface_queues_after_delete(p, &p->wans[dp_slot], nq);
    if (p->wan_queue_total >= nq)
        p->wan_queue_total -= nq;
    else
        p->wan_queue_total = 0;
}
// RX
static int recv_queue(struct ne_xsk_queue *slot, struct ne_packet *out, uint32_t max,
                      uint8_t dir, uint8_t wan_idx, uint8_t local_idx)
{
    uint32_t idx = 0;
    uint32_t n = xsk_ring_cons__peek(&slot->rx, max, &idx);
    for (uint32_t i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&slot->rx, idx + i);
        out[i].addr = d->addr;
        out[i].len = d->len;
        out[i].dir = dir;
        out[i].wan_idx = wan_idx;
        out[i].local_idx = local_idx;
        out[i].tx_slot = 0;
    }
    slot->rx_pending = n;
    return (int)n;
}

static int xsk_queue_for_rx_slot(int q, int rx_slot, int nq, int rx_slots)
{
    int slots = nq < rx_slots ? (nq > 0 ? nq : 1) : rx_slots;

    if (rx_slot >= slots)
        return 0;
    return (q % slots) == rx_slot;
}

int ne_recv_local_slot(struct ne_pair *p, int rx_slot, struct ne_packet *out, uint32_t max)
{
    uint32_t total = 0;
    struct ne_packet *out_ptr = out;

    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_LAN_SLOTS)
        return 0;

    for (int i = 0; i < p->local_count && total < max; i++) {
        if (!p->local_live[i])
            continue;
        struct ne_iface *iface = &p->locals[i];
        int q_count = iface->queue_count;

        for (int q = 0; q < q_count && total < max; q++) {
            if (!xsk_queue_for_rx_slot(q, rx_slot, q_count, (int)NE_RX_LAN_SLOTS))
                continue;
            iface->queues[q].rx_pending = 0;

            int n = recv_queue(&iface->queues[q], out_ptr, max - total,
                               NE_DIR_LOCAL, 0, (uint8_t)i);

            total += (uint32_t)n;
            out_ptr += n;
        }
    }
    return (int)total;
}

int ne_recv_wan_slot(struct ne_pair *p, int rx_slot, struct ne_packet *out, uint32_t max)
{
    uint32_t total = 0;
    struct ne_packet *out_ptr = out;

    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_WAN_SLOTS)
        return 0;

    for (int i = 0; i < p->wan_count && total < max; i++) {
        if (!p->wan_live[i])
            continue;
        struct ne_iface *iface = &p->wans[i];
        int q_count = iface->queue_count;

        for (int q = 0; q < q_count && total < max; q++) {
            if (!xsk_queue_for_rx_slot(q, rx_slot, q_count, (int)NE_RX_WAN_SLOTS))
                continue;
            iface->queues[q].rx_pending = 0;

            int n = recv_queue(&iface->queues[q], out_ptr, max - total,
                               NE_DIR_WAN, (uint8_t)i, 0);

            total += (uint32_t)n;
            out_ptr += n;
        }
    }
    return (int)total;
}

void ne_recv_release_local_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_LAN_SLOTS)
        return;

    for (int i = 0; i < p->local_count; i++) {
        struct ne_iface *iface = &p->locals[i];
        for (int q = 0; q < iface->queue_count; q++) {
            if (!xsk_queue_for_rx_slot(q, rx_slot, iface->queue_count, (int)NE_RX_LAN_SLOTS))
                continue;
            if (iface->queues[q].rx_pending) {
                xsk_ring_cons__release(&iface->queues[q].rx, iface->queues[q].rx_pending);
                iface->queues[q].rx_pending = 0;
            }
        }
    }
}

void ne_recv_release_wan_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_WAN_SLOTS)
        return;

    for (int i = 0; i < p->wan_count; i++) {
        struct ne_iface *iface = &p->wans[i];
        for (int q = 0; q < iface->queue_count; q++) {
            if (!xsk_queue_for_rx_slot(q, rx_slot, iface->queue_count, (int)NE_RX_WAN_SLOTS))
                continue;
            if (iface->queues[q].rx_pending) {
                xsk_ring_cons__release(&iface->queues[q].rx, iface->queues[q].rx_pending);
                iface->queues[q].rx_pending = 0;
            }
        }
    }
}

// CQ
static void drain_cq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t n;

    while ((n = xsk_ring_cons__peek(&slot->cq, NE_BATCH_SIZE, &idx)) > 0) {
        for (uint32_t i = 0; i < n; i++)
            addrs[i] = *xsk_ring_cons__comp_addr(&slot->cq, idx + i);
        uint32_t pushed = pool_push(pool, addrs, n);
        if (pushed > 0)
            xsk_ring_cons__release(&slot->cq, pushed);
        if (pushed < n || n < NE_BATCH_SIZE)
            break;
    }
}

static int xsk_queue_for_tx_slot(int q, int tx_slot, int nq)
{
    int slots = nq < (int)NE_TX_SLOTS ? (nq > 0 ? nq : 1) : (int)NE_TX_SLOTS;

    if (tx_slot >= slots)
        return 0;
    return (q % slots) == tx_slot;
}

static void drain_cq_iface_slot(struct ne_iface *iface, struct ne_pool *pool, int tx_slot)
{
    int nq = iface->queue_count;

    for (int q = 0; q < nq; q++) {
        if (!xsk_queue_for_tx_slot(q, tx_slot, nq))
            continue;
        drain_cq_queue(&iface->queues[q], pool);
    }
}

void ne_drain_cq_local(struct ne_pair *p, int tx_slot)
{
    if (!p || tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return;
    for (int i = 0; i < p->local_count; i++) {
        if (!p->local_live[i])
            continue;
        drain_cq_iface_slot(&p->locals[i], &p->pool, tx_slot);
    }
}

void ne_drain_cq_wan(struct ne_pair *p, int tx_slot)
{
    if (!p || tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return;
    for (int i = 0; i < p->wan_count; i++) {
        if (!p->wan_live[i])
            continue;
        drain_cq_iface_slot(&p->wans[i], &p->pool, tx_slot);
    }
}

static void refill_fq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t free_slots = xsk_prod_nb_free(&slot->fq, NE_BATCH_SIZE);
    uint32_t want;
    uint32_t got;

    if (!free_slots)
        return;
    want = free_slots > NE_BATCH_SIZE ? NE_BATCH_SIZE : free_slots;
    got = pool_pop(pool, addrs, want);
    if (!got)
        return;
    if (xsk_ring_prod__reserve(&slot->fq, got, &idx) != got) {
        (void)pool_push(pool, addrs, got);
        return;
    }
    for (uint32_t i = 0; i < got; i++)
        *xsk_ring_prod__fill_addr(&slot->fq, idx + i) = addrs[i];
    xsk_ring_prod__submit(&slot->fq, got);
    if (slot->xsk && xsk_ring_prod__needs_wakeup(&slot->fq))
        (void)recvfrom(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
}

static void refill_fq_iface_slot(struct ne_iface *iface, struct ne_pool *pool, int rx_slot,
                                  int rx_slots)
{
    int nq = iface->queue_count;

    for (int q = 0; q < nq; q++) {
        if (!xsk_queue_for_rx_slot(q, rx_slot, nq, rx_slots))
            continue;
        refill_fq_queue(&iface->queues[q], pool);
    }
}

void ne_refill_fq_local_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_LAN_SLOTS)
        return;
    for (int i = 0; i < p->local_count; i++) {
        if (!p->local_live[i])
            continue;
        refill_fq_iface_slot(&p->locals[i], &p->pool, rx_slot, (int)NE_RX_LAN_SLOTS);
    }
}

void ne_refill_fq_wan_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_WAN_SLOTS)
        return;
    for (int i = 0; i < p->wan_count; i++) {
        if (!p->wan_live[i])
            continue;
        refill_fq_iface_slot(&p->wans[i], &p->pool, rx_slot, (int)NE_RX_WAN_SLOTS);
    }
}

static void kick_fq_queue(struct ne_xsk_queue *slot)
{
    if (!slot || !slot->xsk)
        return;
    if (!xsk_ring_prod__needs_wakeup(&slot->fq))
        return;
    (void)recvfrom(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
}

static void kick_fq_iface_slot(struct ne_iface *iface, int rx_slot, int rx_slots)
{
    int nq;

    if (!iface)
        return;
    nq = iface->queue_count;
    for (int q = 0; q < nq; q++) {
        if (!xsk_queue_for_rx_slot(q, rx_slot, nq, rx_slots))
            continue;
        kick_fq_queue(&iface->queues[q]);
    }
}

void ne_kick_fq_local_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_LAN_SLOTS)
        return;
    for (int i = 0; i < p->local_count; i++) {
        if (!p->local_live[i])
            continue;
        kick_fq_iface_slot(&p->locals[i], rx_slot, (int)NE_RX_LAN_SLOTS);
    }
}

void ne_kick_fq_wan_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_WAN_SLOTS)
        return;
    for (int i = 0; i < p->wan_count; i++) {
        if (!p->wan_live[i])
            continue;
        kick_fq_iface_slot(&p->wans[i], rx_slot, (int)NE_RX_WAN_SLOTS);
    }
}

static int collect_iface_rx_fds(struct ne_iface *iface, int rx_slot, int rx_slots,
                                int *fds, int max, int n)
{
    int nq;

    if (!iface || !fds || n >= max)
        return n;
    nq = iface->queue_count;
    for (int q = 0; q < nq && n < max; q++) {
        int fd;

        if (!xsk_queue_for_rx_slot(q, rx_slot, nq, rx_slots))
            continue;
        if (!iface->queues[q].xsk)
            continue;
        fd = xsk_socket__fd(iface->queues[q].xsk);
        if (fd < 0)
            continue;
        fds[n++] = fd;
    }
    return n;
}

int ne_rx_local_fds(struct ne_pair *p, int rx_slot, int *fds, int max)
{
    int n = 0;

    if (!p || !fds || max <= 0 || rx_slot < 0 || rx_slot >= (int)NE_RX_LAN_SLOTS)
        return 0;
    for (int i = 0; i < p->local_count && n < max; i++) {
        if (!p->local_live[i])
            continue;
        n = collect_iface_rx_fds(&p->locals[i], rx_slot, (int)NE_RX_LAN_SLOTS, fds, max, n);
    }
    return n;
}

int ne_rx_wan_fds(struct ne_pair *p, int rx_slot, int *fds, int max)
{
    int n = 0;

    if (!p || !fds || max <= 0 || rx_slot < 0 || rx_slot >= (int)NE_RX_WAN_SLOTS)
        return 0;
    for (int i = 0; i < p->wan_count && n < max; i++) {
        if (!p->wan_live[i])
            continue;
        n = collect_iface_rx_fds(&p->wans[i], rx_slot, (int)NE_RX_WAN_SLOTS, fds, max, n);
    }
    return n;
}

// TX
#define NE_XSK_COPY_TX_BATCH 32u

static int tx_drain_queue(struct ne_xsk_queue *slot, struct ne_ring *src, uint32_t max_frame,
                          uint64_t *tx_no_free)
{
    struct ne_packet jobs[NE_XSK_COPY_TX_BATCH];
    uint32_t queued = ne_ring_count(src);
    uint32_t want;
    uint32_t free_slots;
    uint32_t idx = 0;
    uint32_t reserved;
    uint32_t popped = 0;

    if (!queued)
        return 0;

    want = queued > NE_XSK_COPY_TX_BATCH ? NE_XSK_COPY_TX_BATCH : queued;
    free_slots = xsk_prod_nb_free(&slot->tx, want);

    if (!free_slots) {
        if (tx_no_free)
            (*tx_no_free)++;
        if (tls_dp_tx_dir && tls_dp_tx_slot >= 0) {
            if (tls_dp_tx_dir[0] == 'L' || tls_dp_tx_dir[0] == 'l')
                ne_dp_stats_tx_full_lan(tls_dp_tx_slot, 1);
            else
                ne_dp_stats_tx_full_wan(tls_dp_tx_slot, 1);
        }
        if (xsk_ring_prod__needs_wakeup(&slot->tx)) {
            (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
        return 0;
    }


    if (want > free_slots)
        want = free_slots;
    reserved = xsk_ring_prod__reserve(&slot->tx, want, &idx);
    if (!reserved)
        return 0;

    while (popped < reserved && ne_ring_try_pop(src, &jobs[popped]) == 0)
        popped++;

    if (popped < reserved)
        slot->tx.cached_prod -= (reserved - popped);
    if (!popped)
        return 0;

    for (uint32_t i = 0; i < popped; i++) {
        struct xdp_desc *d = xsk_ring_prod__tx_desc(&slot->tx, idx + i);
        d->addr = jobs[i].addr;
        d->len = jobs[i].len > max_frame ? max_frame : jobs[i].len;
    }

    xsk_ring_prod__submit(&slot->tx, popped);
    if (xsk_ring_prod__needs_wakeup(&slot->tx)) {
        (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }
    if (tls_dp_tx_dir && tls_dp_tx_slot >= 0) {
        uint64_t tx_bytes = 0;
        for (uint32_t i = 0; i < popped; i++)
            tx_bytes += jobs[i].len;
        if (tls_dp_tx_dir[0] == 'L' || tls_dp_tx_dir[0] == 'l')
            ne_dp_stats_tx_lan(tls_dp_tx_slot, popped, tx_bytes);
        else
            ne_dp_stats_tx_wan(tls_dp_tx_slot, popped, tx_bytes);
    }
    return (int)popped;
}

static int tx_drain_iface_ring(struct ne_iface *iface, struct ne_ring *src, uint32_t max_frame,
                               int tx_slot)
{
    int nq = iface->queue_count;
    int primary = -1;


    for (int q = 0; q < nq; q++) {
        if (!xsk_queue_for_tx_slot(q, tx_slot, nq))
            continue;
        primary = q;
        break;
    }
    if (primary < 0)
        return 0;
    return tx_drain_queue(&iface->queues[primary], src, max_frame, &iface->tx_no_free);
}

static __thread uint32_t tls_tx_drain_rr;

static int tx_drain_iface_all_rings(struct ne_iface *iface, struct ne_ring *srcs[],
                                    int src_count, uint32_t max_frame, int tx_slot)
{
    int sent = 0;
    int start;

    if (!srcs || src_count <= 0)
        return 0;

    start = (int)(tls_tx_drain_rr % (uint32_t)src_count);
    for (int i = 0; i < src_count; i++) {
        int s = (start + i) % src_count;

        if (!srcs[s])
            continue;
        sent += tx_drain_iface_ring(iface, srcs[s], max_frame, tx_slot);
    }
    if (sent > 0)
        tls_tx_drain_rr++;
    return sent;
}

int ne_tx_drain_local_all(struct ne_pair *p, struct ne_ring *srcs[], int src_count,
                          int local_idx, int tx_slot)
{
    if (!p || local_idx < 0 || local_idx >= p->local_count)
        return 0;
    if (!p->local_live[local_idx])
        return 0;
    if (tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;
    return tx_drain_iface_all_rings(&p->locals[local_idx], srcs, src_count, p->frame_size,
                                    tx_slot);
}

int ne_tx_drain_wan_all(struct ne_pair *p, struct ne_ring *srcs[], int src_count,
                        int wan_idx, int tx_slot)
{
    if (!p || wan_idx < 0 || wan_idx >= p->wan_count)
        return 0;
    if (!p->wan_live[wan_idx])
        return 0;
    if (tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;
    return tx_drain_iface_all_rings(&p->wans[wan_idx], srcs, src_count, p->frame_size, tx_slot);
}

static int collect_iface_tx_fds(struct ne_iface *iface, int tx_slot, int *fds, int max, int n)
{
    int nq;

    if (!iface || !fds || n >= max)
        return n;
    nq = iface->queue_count;
    for (int q = 0; q < nq && n < max; q++) {
        int fd;

        if (!xsk_queue_for_tx_slot(q, tx_slot, nq))
            continue;
        if (!iface->queues[q].xsk)
            continue;
        fd = xsk_socket__fd(iface->queues[q].xsk);
        if (fd < 0)
            continue;
        fds[n++] = fd;
    }
    return n;
}

int ne_tx_local_fds(struct ne_pair *p, int tx_slot, int *fds, int max)
{
    int n = 0;

    if (!p || !fds || max <= 0 || tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;
    for (int i = 0; i < p->local_count && n < max; i++) {
        if (!p->local_live[i])
            continue;
        n = collect_iface_tx_fds(&p->locals[i], tx_slot, fds, max, n);
    }
    return n;
}

int ne_tx_wan_fds(struct ne_pair *p, int tx_slot, int *fds, int max)
{
    int n = 0;

    if (!p || !fds || max <= 0 || tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;
    for (int i = 0; i < p->wan_count && n < max; i++) {
        if (!p->wan_live[i])
            continue;
        n = collect_iface_tx_fds(&p->wans[i], tx_slot, fds, max, n);
    }
    return n;
}

int ne_tx_fds(struct ne_pair *p, int tx_slot, int *fds, int max)
{
    int n = ne_tx_local_fds(p, tx_slot, fds, max);

    if (n >= max)
        return n;
    return n + ne_tx_wan_fds(p, tx_slot, fds + n, max - n);
}
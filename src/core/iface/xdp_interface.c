#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/iface/xdp_attach.h"
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

static void xdp_stats_add(struct ne_xdp_socket_stats *dst,
                          const struct xdp_statistics *src)
{
    dst->rx_dropped += src->rx_dropped;
    dst->rx_invalid_descs += src->rx_invalid_descs;
    dst->tx_invalid_descs += src->tx_invalid_descs;
    dst->rx_ring_full += src->rx_ring_full;
    dst->rx_fill_ring_empty_descs += src->rx_fill_ring_empty_descs;
    dst->tx_ring_empty_descs += src->tx_ring_empty_descs;
}

static void collect_xdp_stats(const struct ne_iface *ifaces, int iface_count,
                              struct ne_xdp_socket_stats *out)
{
    int seen_fds[MAX_INTERFACES * MAX_QUEUES];
    int seen_count = 0;

    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    for (int i = 0; ifaces && i < iface_count; i++) {
        const struct ne_iface *iface = &ifaces[i];

        for (int q = 0; q < iface->queue_count; q++) {
            struct xdp_statistics stats = {0};
            socklen_t stats_len = sizeof(stats);
            int fd;
            int duplicate = 0;

            if (!iface->queues[q].xsk)
                continue;
            fd = xsk_socket__fd(iface->queues[q].xsk);
            if (fd < 0)
                continue;
            for (int n = 0; n < seen_count; n++) {
                if (seen_fds[n] == fd) {
                    duplicate = 1;
                    break;
                }
            }
            if (duplicate)
                continue;
            if (seen_count < (int)(MAX_INTERFACES * MAX_QUEUES))
                seen_fds[seen_count++] = fd;
            out->sockets_queried++;
            if (getsockopt(fd, SOL_XDP, XDP_STATISTICS,
                           &stats, &stats_len) == 0)
                xdp_stats_add(out, &stats);
            else
                out->query_errors++;
        }
    }
}

void ne_pair_xdp_socket_stats(const struct ne_pair *p,
                              struct ne_xdp_socket_stats *lan,
                              struct ne_xdp_socket_stats *wan)
{
    if (!p) {
        if (lan)
            memset(lan, 0, sizeof(*lan));
        if (wan)
            memset(wan, 0, sizeof(*wan));
        return;
    }
    collect_xdp_stats(p->locals, p->local_count, lan);
    collect_xdp_stats(p->wans, p->wan_count, wan);
}

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
    if (!r || !r->buf)
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

int ne_ring_try_push_pair(struct ne_ring *r, const struct ne_packet *first,
                          const struct ne_packet *second)
{
    uint32_t head, tail;

    if (!r || !first || !second || r->cap < 2u)
        return -1;

    pthread_spin_lock(&r->push_lock);
    head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
    tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    if ((uint32_t)(head - tail) > r->cap - 2u) {
        pthread_spin_unlock(&r->push_lock);
        return -1;
    }
    r->buf[head & r->mask] = *first;
    r->buf[(head + 1u) & r->mask] = *second;
    /* Publish both fragments together so another producer cannot interleave
     * a datagram and the consumer can never observe only the first half. */
    __atomic_store_n(&r->head, head + 2u, __ATOMIC_RELEASE);
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
    slot->rx_reject_count = 0;
    slot->rx_reject_chain = 0;
    memset(&slot->rx, 0, sizeof(slot->rx));
    memset(&slot->tx, 0, sizeof(slot->tx));
    if (!preserve_fq_cq) {
        memset(&slot->fq, 0, sizeof(slot->fq));
        memset(&slot->cq, 0, sizeof(slot->cq));
    }
}


static int queue_holds_umem_fd(const struct ne_pair *p, const struct ne_xsk_queue *slot)
{
    if (!p || !p->umem || !slot || !slot->xsk)
        return 0;
    return xsk_socket__fd(slot->xsk) == xsk_umem__fd(p->umem);
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

static void delete_all_live_xsks(struct ne_pair *p)
{
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (p->local_live[i] || p->locals[i].queue_count > 0)
            delete_iface_xsks(p, &p->locals[i], p->locals[i].queue_count);
        if (p->wan_live[i] || p->wans[i].queue_count > 0)
            delete_iface_xsks(p, &p->wans[i], p->wans[i].queue_count);
    }
}


static int xsk_create_queue(struct ne_pair *p, struct ne_iface *iface, const char *ifname,
                            int q, uint32_t xdp_flags, int use_sg)
{
    struct ne_xsk_queue *slot = &iface->queues[q];
    int preserve = is_umem_fq_owner_queue(p, iface, q);
    struct xsk_socket_config cfg = {
        .rx_size = NE_RING,
        .tx_size = NE_RING,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = xdp_flags,
        /* Toggle AF_XDP mode here only: XDP_COPY (ixgbe) or XDP_ZEROCOPY (ice). */
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP |
            (use_sg ? XDP_USE_SG : 0u),
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
    iface->xdp_sg_enabled = 0;
}

static int open_iface_queues(struct ne_pair *p, struct ne_iface *iface,
                             const char *ifname, int queue_count)
{
    const uint32_t mode = XDP_FLAGS_DRV_MODE;
    int ret = 0;

    iface->ifindex = (int)if_nametoindex(ifname);
    if (!iface->ifindex) {
        fprintf(stderr, "[DP] XSK open failed %s: interface not found\n", ifname);
        fflush(stderr);
        return -1;
    }
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    iface->ifname[sizeof(iface->ifname) - 1] = '\0';
    for (int attempt = 0; attempt < 2; attempt++) {
        int use_sg = attempt == 0;
        int q;

        iface->ifindex = (int)if_nametoindex(ifname);
        strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
        iface->ifname[sizeof(iface->ifname) - 1] = '\0';
        iface->queue_count = queue_count;
        iface->xdp_flags = 0;
        iface->xdp_sg_enabled = 0;

        for (q = 0; q < queue_count; q++) {
            ret = xsk_create_queue(p, iface, ifname, q, mode, use_sg);
            if (ret)
                break;
        }
        if (q == queue_count) {
            iface->xdp_flags = mode;
            iface->xdp_sg_enabled = use_sg ? 1u : 0u;
            fprintf(stderr, "[DP] XSK %s mode=%s frame=%u queues=%d\n",
                    ifname, use_sg ? "xdp.frags" : "legacy",
                    p->frame_size, queue_count);
            fflush(stderr);
            return 0;
        }

        open_iface_queues_rollback(p, iface, q);
        if (use_sg) {
            fprintf(stderr,
                    "[DP] XSK %s XDP_USE_SG unavailable (%d), fallback legacy\n",
                    ifname, ret);
            fflush(stderr);
            continue;
        }
        interface_log_xsk_context(ifname, q, ret);
        return -1;
    }
    return -1;
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

static uint32_t prefill_per_queue(const struct ne_pair *p, int queue_total)
{
    uint64_t budget;
    uint64_t per_queue;

    if (!p || queue_total <= 0)
        return NE_BATCH_SIZE;
    /* Keep 25% of UMEM outside FQ rings for TX, crypto split and bursts. */
    budget = ((uint64_t)p->n_frames * 3u) / 4u;
    per_queue = budget / (uint32_t)queue_total;
    if (per_queue > NE_FQ_PREFILL)
        per_queue = NE_FQ_PREFILL;
    if (per_queue < NE_BATCH_SIZE)
        per_queue = NE_BATCH_SIZE;
    return (uint32_t)per_queue;
}


int ne_pair_open(struct ne_pair *p, const struct app_config *cfg)
{
#define NE_OPEN_TRY(expr, stage_name, interface_name) do { \
        fail_stage = (stage_name); \
        fail_ifname = (interface_name); \
        errno = 0; \
        fail_rc = (expr); \
        fail_errno = errno; \
        if (fail_rc != 0) \
            goto fail; \
    } while (0)
#define NE_OPEN_ABORT(stage_name, interface_name, error_code) do { \
        fail_stage = (stage_name); \
        fail_ifname = (interface_name); \
        fail_rc = (error_code); \
        fail_errno = errno; \
        goto fail; \
    } while (0)
    const char *fail_stage = "input-validation";
    const char *fail_ifname = NULL;
    int fail_rc = -1;
    int fail_errno = 0;

    if (!p || !cfg || cfg->local_count <= 0) {
        fprintf(stderr,
                "[DP][FATAL] ne_pair_open invalid input: pair=%s config=%s local_count=%d\n",
                p ? "ok" : "null", cfg ? "ok" : "null",
                cfg ? cfg->local_count : -1);
        fflush(stderr);
        return -1;
    }

    memset(p, 0, sizeof(*p));
    p->umem_fq_li = -1;
    p->umem_fq_q = -1;
    p->local_count = cfg->local_count;
    if (p->local_count > MAX_INTERFACES)
        p->local_count = MAX_INTERFACES;
    p->wan_count = cfg->wan_count;
    if (p->wan_count > MAX_INTERFACES)
        p->wan_count = MAX_INTERFACES;
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        fprintf(stderr, "[DP][WARN] setrlimit(RLIMIT_MEMLOCK) failed: %s (%d)\n",
                strerror(errno), errno);
        fflush(stderr);
    }

    p->frame_size = NE_FRAME;
    p->xdp_flags = XDP_FLAGS_DRV_MODE;

    p->local_queue_total = 0;
    p->wan_queue_total = 0;

    for (int i = 0; i < p->local_count; i++) {
        int nq = resolve_iface_queue_count(cfg->locals[i].ifname);
        NE_OPEN_TRY(interface_preflight(cfg->locals[i].ifname),
                    "LAN-preflight", cfg->locals[i].ifname);
        NE_OPEN_TRY(apply_iface_queue_count(cfg->locals[i].ifname, nq),
                    "LAN-queue-config", cfg->locals[i].ifname);
        p->locals[i].queue_count = nq;
        p->local_queue_total += nq;
    }
    for (int i = 0; i < p->wan_count; i++) {
        int nq = resolve_iface_queue_count(cfg->wans[i].ifname);
        NE_OPEN_TRY(interface_preflight(cfg->wans[i].ifname),
                    "WAN-preflight", cfg->wans[i].ifname);
        NE_OPEN_TRY(apply_iface_queue_count(cfg->wans[i].ifname, nq),
                    "WAN-queue-config", cfg->wans[i].ifname);
        p->wans[i].queue_count = nq;
        p->wan_queue_total += nq;
    }

    p->n_frames = NE_N_FRAMES;
    p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;

    fprintf(stderr,
            "[DP] UMEM frame=%u frames=%u bytes=%zu packet_max_segs=%u "
            "jumbo_max=%u phase=mtu1500-validation\n",
            p->frame_size, p->n_frames, p->bufsize,
            NE_PACKET_MAX_SEGS, NE_JUMBO_FRAME_MAX);
    fflush(stderr);

    p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p->bufs == MAP_FAILED)
        NE_OPEN_ABORT("UMEM-mmap", NULL, -errno);

    NE_OPEN_TRY(pool_init(&p->pool, p->n_frames), "UMEM-pool-init", NULL);
    for (uint32_t i = 0; i < p->n_frames; i++) {
        uint64_t addr = (uint64_t)i * p->frame_size;
        (void)pool_push(&p->pool, &addr, 1);
    }

    for (int i = 0; i < p->local_count; i++) {
        NE_OPEN_TRY(interface_set_promisc(cfg->locals[i].ifname),
                    "LAN-promisc-on", cfg->locals[i].ifname);
    }
    for (int i = 0; i < p->wan_count; i++)
        NE_OPEN_TRY(interface_set_promisc(cfg->wans[i].ifname),
                    "WAN-promisc-on", cfg->wans[i].ifname);

    /* Scrub stale XDP before AF_XDP bind (delete→create EINVAL -22). */
    for (int i = 0; i < p->local_count; i++)
        xdp_attach_detach_ifname(cfg->locals[i].ifname);
    for (int i = 0; i < p->wan_count; i++)
        xdp_attach_detach_ifname(cfg->wans[i].ifname);
    usleep(50000);

    struct xsk_umem_config ucfg = {
        .fill_size = NE_RING,
        .comp_size = NE_RING,
        .frame_size = p->frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    NE_OPEN_TRY(xsk_umem__create(&p->umem, p->bufs, p->bufsize,
                                 &p->locals[0].queues[0].fq,
                                 &p->locals[0].queues[0].cq, &ucfg),
                "XSK-UMEM-create", cfg->locals[0].ifname);
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
            xdp_attach_detach_ifname(cfg->locals[i].ifname);
            usleep(150000);
            rc = open_iface_queues(p, &p->locals[i], cfg->locals[i].ifname,
                                   p->locals[i].queue_count);
        }
        if (rc)
            NE_OPEN_ABORT("LAN-XSK-create", cfg->locals[i].ifname, rc);
    }
    for (int di = 0; di < p->wan_count; di++) {
        int rc;
        rc = open_iface_queues(p, &p->wans[di], cfg->wans[di].ifname,
                               p->wans[di].queue_count);
        if (rc) {
            fprintf(stderr,
                    "[DP] WAN %s XSK bind failed — scrub XDP and retry once\n",
                    cfg->wans[di].ifname);
            fflush(stderr);
            xdp_attach_detach_ifname(cfg->wans[di].ifname);
            usleep(150000);
            rc = open_iface_queues(p, &p->wans[di], cfg->wans[di].ifname,
                                   p->wans[di].queue_count);
        }
        if (rc)
            NE_OPEN_ABORT("WAN-XSK-create", cfg->wans[di].ifname, rc);
    }

    uint32_t prefill = prefill_per_queue(
        p, p->local_queue_total + p->wan_queue_total);

    fprintf(stderr, "[DP] FQ prefill=%u per_queue total_queues=%d reserve=25%%\n",
            prefill, p->local_queue_total + p->wan_queue_total);
    fflush(stderr);

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
    {
        int report_errno = fail_errno;

        if (report_errno == 0 && fail_rc < 0 && fail_rc >= -4095)
            report_errno = -fail_rc;
        fprintf(stderr,
                "[DP][FATAL] ne_pair_open failed stage=%s iface=%s rc=%d",
                fail_stage ? fail_stage : "unknown",
                fail_ifname && fail_ifname[0] ? fail_ifname : "-", fail_rc);
        if (report_errno > 0)
            fprintf(stderr, " errno=%d (%s)", report_errno, strerror(report_errno));
        if (fail_ifname && fail_ifname[0])
            fprintf(stderr, " ifindex=%u mtu=%d queues=%d",
                    if_nametoindex(fail_ifname), interface_get_mtu(fail_ifname),
                    interface_get_queue_count(fail_ifname));
        fputc('\n', stderr);
        fflush(stderr);
    }
    xdp_attach_detach_config(cfg);
    ne_pair_close(p, cfg);
    return -1;
#undef NE_OPEN_ABORT
#undef NE_OPEN_TRY
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
        xdp_attach_detach_config(cfg);
    else {
        for (int i = 0; i < p->local_count; i++) {
            if (p->locals[i].ifname[0])
                xdp_attach_detach_ifname(p->locals[i].ifname);
        }
        for (int i = 0; i < p->wan_count; i++) {
            if (p->wans[i].ifname[0])
                xdp_attach_detach_ifname(p->wans[i].ifname);
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

int ne_pair_local_live(const struct ne_pair *p, int local_idx)
{
    return p && local_idx >= 0 && local_idx < p->local_count &&
           p->local_live[local_idx] != 0;
}

int ne_pair_wan_live(const struct ne_pair *p, int wan_idx)
{
    return p && wan_idx >= 0 && wan_idx < p->wan_count &&
           p->wan_live[wan_idx] != 0;
}

// RX
static int recv_queue(struct ne_xsk_queue *slot, struct ne_packet *out, uint32_t max,
                      uint8_t dir, uint8_t wan_idx, uint8_t local_idx)
{
    uint32_t idx = 0;
    uint32_t n = xsk_ring_cons__peek(&slot->rx, max, &idx);
    uint32_t out_n = 0;

    for (uint32_t i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&slot->rx, idx + i);
        int continued = (d->options & XDP_PKT_CONTD) != 0;

        if (slot->rx_reject_chain || continued) {
            if (slot->rx_reject_count < NE_BATCH_SIZE)
                slot->rx_reject_addrs[slot->rx_reject_count++] = d->addr;
            slot->rx_reject_chain = continued ? 1u : 0u;
            if (!continued)
                slot->rx_multibuf_dropped++;
            continue;
        }

        out[out_n].addr = d->addr;
        out[out_n].len = d->len;
        out[out_n].dir = dir;
        out[out_n].wan_idx = wan_idx;
        out[out_n].local_idx = local_idx;
        out[out_n].tx_slot = 0;
        out_n++;
    }
    slot->rx_pending = n;
    return (int)out_n;
}

static void release_rx_queue(struct ne_xsk_queue *slot, struct ne_pool *pool)
{
    if (!slot || !pool)
        return;
    if (slot->rx_pending) {
        xsk_ring_cons__release(&slot->rx, slot->rx_pending);
        slot->rx_pending = 0;
    }
    if (slot->rx_reject_count) {
        (void)pool_push(pool, slot->rx_reject_addrs, slot->rx_reject_count);
        slot->rx_reject_count = 0;
    }
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
            release_rx_queue(&iface->queues[q], &p->pool);
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
            release_rx_queue(&iface->queues[q], &p->pool);
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
        d->options = 0;
    }

    xsk_ring_prod__submit(&slot->tx, popped);
    if (xsk_ring_prod__needs_wakeup(&slot->tx)) {
        (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
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

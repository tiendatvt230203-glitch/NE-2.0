#ifndef INTERFACE_H
#define INTERFACE_H

#include "core/util/config.h"
#include <linux/if_link.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <xdp/xsk.h>

#define MAX_QUEUES     64

#define NE_RING        16384u
/* A logical 9K packet is carried by up to four 4K UMEM chunks. */
#define NE_FRAME       4096u
#define NE_N_FRAMES    524288u
#define NE_PACKET_MAX_SEGS 4u
#define NE_JUMBO_FRAME_MAX 9216u
#define NE_BATCH_SIZE   64u

#define NE_QUEUE_OVERRIDE 0

#define NE_FQ_PREFILL   16384u

#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif
#ifndef XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
#define XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (1U << 0)
#endif
#ifndef XDP_USE_SG
#define XDP_USE_SG (1U << 4)
#endif
#ifndef XDP_PKT_CONTD
/* UAPI value from linux/if_xdp.h.  Older distro kernel headers can expose
 * struct xdp_desc without the multi-buffer continuation flag. */
#define XDP_PKT_CONTD (1U << 0)
#endif

#include "core/util/cpu_map.h"

struct bpf_object;

enum ne_packet_dir {
    NE_DIR_LOCAL = 0,
    NE_DIR_WAN = 1,
};

struct ne_packet {
    uint64_t addr;
    uint64_t seg_addr[NE_PACKET_MAX_SEGS - 1u];
    uint32_t len;
    uint16_t seg_len[NE_PACKET_MAX_SEGS];
    uint16_t seg_cap[NE_PACKET_MAX_SEGS];
    uint8_t dir;
    uint8_t wan_idx;
    uint8_t local_idx;
    uint8_t tx_slot;
    uint8_t nsegs;
};

_Static_assert(NE_FRAME * NE_PACKET_MAX_SEGS >= NE_JUMBO_FRAME_MAX,
               "UMEM segment budget cannot hold the planned jumbo frame");

struct ne_ring {
    struct ne_packet *buf;
    uint32_t cap;
    uint32_t mask;
    __attribute__((aligned(64))) volatile uint32_t head;
    __attribute__((aligned(64))) volatile uint32_t tail;
    pthread_spinlock_t push_lock;
    pthread_spinlock_t pop_lock;
    uint8_t mpsc_pop;
};

struct ne_pool {
    uint64_t *buf;
    uint32_t cap;
    uint32_t mask;
    uint32_t head;
    uint32_t tail;
    pthread_spinlock_t lock;
};

struct ne_xsk_queue {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    uint32_t rx_pending;
    uint64_t rx_reject_addrs[NE_BATCH_SIZE + NE_PACKET_MAX_SEGS];
    uint32_t rx_reject_count;
    uint64_t rx_chain_dropped;
    struct ne_packet rx_chain;
    uint8_t rx_chain_invalid;
};

struct ne_iface {
    int ifindex;
    char ifname[IF_NAMESIZE];
    int queue_count;
    struct ne_xsk_queue queues[MAX_QUEUES];
    uint64_t tx_no_free;
    uint32_t xdp_flags;
    uint8_t xdp_sg_enabled;
};

struct ne_pair {
    void *bufs;
    size_t bufsize;
    uint32_t frame_size;
    uint32_t n_frames;
    struct xsk_umem *umem;
    int umem_fq_li;
    int umem_fq_q;
    struct ne_iface locals[MAX_INTERFACES];
    int local_count;
    struct ne_iface wans[MAX_INTERFACES];
    int wan_count;
    int local_queue_total;
    int wan_queue_total;
    struct ne_pool pool;
    struct bpf_object *bpf_locals[MAX_INTERFACES];
    struct bpf_object *bpf_wans[MAX_INTERFACES];
    uint8_t xdp_local_on[MAX_INTERFACES];
    uint8_t xdp_wan_on[MAX_INTERFACES];
    uint8_t local_live[MAX_INTERFACES];
    uint8_t wan_live[MAX_INTERFACES];
    uint32_t xdp_flags;
};

struct ne_xdp_socket_stats {
    uint32_t sockets_queried;
    uint32_t query_errors;
    uint64_t rx_dropped;
    uint64_t rx_invalid_descs;
    uint64_t tx_invalid_descs;
    uint64_t rx_ring_full;
    uint64_t rx_fill_ring_empty_descs;
    uint64_t tx_ring_empty_descs;
};

int ne_pair_local_live(const struct ne_pair *p, int local_idx);
int ne_pair_wan_live(const struct ne_pair *p, int wan_idx);

int ne_ring_init(struct ne_ring *r, uint32_t cap, int mpsc_pop);
void ne_ring_destroy(struct ne_ring *r);
int ne_ring_try_push(struct ne_ring *r, const struct ne_packet *pkt);
int ne_ring_try_push_pair(struct ne_ring *r, const struct ne_packet *first,
                          const struct ne_packet *second);
int ne_ring_try_pop(struct ne_ring *r, struct ne_packet *pkt);
uint32_t ne_ring_count(const struct ne_ring *r);

int ne_pair_open(struct ne_pair *p, const struct app_config *cfg);
void ne_pair_close(struct ne_pair *p, const struct app_config *cfg);

int ne_recv_local_slot(struct ne_pair *p, int rx_slot, struct ne_packet *out, uint32_t max);
int ne_recv_wan_slot(struct ne_pair *p, int rx_slot, struct ne_packet *out, uint32_t max);
void ne_recv_release_local_slot(struct ne_pair *p, int rx_slot);
void ne_recv_release_wan_slot(struct ne_pair *p, int rx_slot);

void ne_drain_cq_local(struct ne_pair *p, int tx_slot);
void ne_drain_cq_wan(struct ne_pair *p, int tx_slot);
void ne_refill_fq_local_slot(struct ne_pair *p, int rx_slot);
void ne_refill_fq_wan_slot(struct ne_pair *p, int rx_slot);
void ne_dp_tx_ctx(const char *dir, int tx_slot);
void ne_dp_warn_rx(const char *dir, int cpu, int batch_rcvd);
void ne_dp_warn_rx_drop(const char *dir, int cpu, int worker, uint32_t q_depth);
int ne_tx_drain_local_all(struct ne_pair *p, struct ne_ring *srcs[], int src_count,
                          int local_idx, int tx_slot);
int ne_tx_drain_wan_all(struct ne_pair *p, struct ne_ring *srcs[], int src_count,
                        int wan_idx, int tx_slot);

void *ne_packet_data(struct ne_pair *p, uint64_t addr);
int ne_packet_linearize(struct ne_pair *p, const struct ne_packet *pkt,
                        uint8_t *dst, uint32_t dst_size);
int ne_packet_write(struct ne_pair *p, struct ne_packet *pkt,
                    const uint8_t *src, uint32_t len);
void ne_packet_free(struct ne_pair *p, struct ne_packet *pkt);
int ne_frame_alloc(struct ne_pair *p, uint64_t *addr_out);
uint32_t ne_frame_alloc_batch(struct ne_pair *p, uint64_t *addrs_out, uint32_t max_n);
void ne_frame_free(struct ne_pair *p, uint64_t addr);
/* Frames currently idle in the shared UMEM pool (leak watchdog metric). */
uint32_t ne_pool_free_count(struct ne_pair *p);
void ne_pair_xdp_socket_stats(const struct ne_pair *p,
                              struct ne_xdp_socket_stats *lan,
                              struct ne_xdp_socket_stats *wan);

int interface_set_queue_count(const char *ifname, int desired_count);
int interface_get_queue_count(const char *ifname);

int ne_rx_lan_slots_for(int local_queue_total);
int ne_rx_wan_slots_for(int wan_queue_total);

int ne_rx_local_fds(struct ne_pair *p, int rx_slot, int *fds, int max);
int ne_rx_wan_fds(struct ne_pair *p, int rx_slot, int *fds, int max);
void ne_kick_fq_local_slot(struct ne_pair *p, int rx_slot);
void ne_kick_fq_wan_slot(struct ne_pair *p, int rx_slot);

#endif

#ifndef FORWARDER_H
#define FORWARDER_H

#include "core/iface/interface.h"
#include "core/dataplane/crypto_route.h"
#include "core/flow/mac_learn.h"

struct fwd_iface {
    int ifindex;
    char ifname[IF_NAMESIZE];
};

struct forwarder {
    struct app_config *cfg;

    struct fwd_iface locals[MAX_INTERFACES];
    int local_count;
    struct fwd_iface wans[MAX_INTERFACES];
    int wan_count;
    int wan_cfg_idx[MAX_INTERFACES];

    struct ne_pair pair;
    struct ne_ring local_to_mid[NE_CRYPTO_WORKERS];
    struct ne_ring wan_to_mid[NE_CRYPTO_WORKERS];
    struct ne_ring mid_to_wan[MAX_INTERFACES][NE_CRYPTO_WORKERS];
    struct ne_ring mid_to_local[MAX_INTERFACES][NE_CRYPTO_WORKERS];

    pthread_t local_rx_threads[NE_RX_LAN_SLOTS];
    pthread_t tx_threads[NE_TX_SLOTS];
    pthread_t crypto_threads[NE_CRYPTO_WORKERS];
    pthread_t wan_rx_threads[NE_RX_WAN_SLOTS];
    int threads_started;

    uint64_t split_tail_cache[NE_CRYPTO_WORKERS][64];
    uint16_t split_tail_count[NE_CRYPTO_WORKERS];

    struct mac_learn_table mac_table;
};

static inline uint32_t fwd_mid_to_wan_depth(const struct forwarder *fwd, int wan_dp)
{
    uint32_t d = 0;
    if (!fwd || wan_dp < 0)
        return 0;
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        d += ne_ring_count(&fwd->mid_to_wan[wan_dp][w]);
    return d;
}

void forwarder_pin_cpu(void);
int forwarder_init(struct forwarder *fwd, struct app_config *cfg);
#define FORWARDER_WAN_DRAIN_SEC 5

void forwarder_runtime_lock(void);
void forwarder_runtime_unlock(void);

void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);
void forwarder_stop(void);
void forwarder_clear_stop(void);
void forwarder_shutdown_resources(void);
int forwarder_should_stop(void);

#endif
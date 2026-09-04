#ifndef FORWARDER_H
#define FORWARDER_H

#include "core/iface/interface.h"
#include "core/dataplane/crypto_route.h"
#include "core/flow/flow_table.h"
#include "crypto/packet_crypto.h"

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
    struct ne_pair pair;
    struct packet_crypto_ctx crypto;
    struct flow_table wan_flows;
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

};

int forwarder_init(struct forwarder *fwd, struct app_config *cfg);
void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);
void forwarder_stop(void);
int forwarder_should_stop(void);

#endif

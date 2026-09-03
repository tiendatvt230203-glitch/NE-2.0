#ifndef DATAPLANE_STATS_H
#define DATAPLANE_STATS_H

#include <stdint.h>

struct forwarder;

void ne_dp_stats_init(void);
int ne_dp_stats_on(void);

void ne_dp_stats_rx_lan(int slot, uint32_t pkts, uint64_t bytes);
void ne_dp_stats_rx_wan(int slot, uint32_t pkts, uint64_t bytes);
void ne_dp_stats_rx_ring_drop_lan(int slot, uint32_t n);
void ne_dp_stats_rx_ring_drop_wan(int slot, uint32_t n);

void ne_dp_stats_local_bypass(uint32_t n);
void ne_dp_stats_local_drop(uint32_t n);
void ne_dp_stats_wan_fwd(uint32_t n);
void ne_dp_stats_wan_drop(uint32_t n);
void ne_dp_stats_wan_policy_drop(uint32_t n);
void ne_dp_stats_mid_ring_drop(uint32_t n);
void ne_dp_stats_seq_untracked(uint32_t n);

void ne_dp_stats_tx_lan(int slot, uint32_t pkts, uint64_t bytes);
void ne_dp_stats_tx_wan(int slot, uint32_t pkts, uint64_t bytes);
void ne_dp_stats_tx_full_lan(int slot, uint32_t n);
void ne_dp_stats_tx_full_wan(int slot, uint32_t n);

void ne_dp_stats_crypto_lan(int worker, uint32_t n);
void ne_dp_stats_crypto_wan(int worker, uint32_t n);
void ne_dp_stats_crypto_ring_drop(int worker, uint32_t n);

void ne_dp_stats_tick(struct forwarder *fwd);

#endif

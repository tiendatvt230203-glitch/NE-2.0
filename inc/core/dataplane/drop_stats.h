#ifndef DROP_STATS_H
#define DROP_STATS_H

#include <stdint.h>

enum dp_drop_reason {
    DP_DROP_RX_TO_CRYPTO_RING_TIMEOUT = 0,
    DP_DROP_CRYPTO_TO_TX_RING_TIMEOUT,
    DP_DROP_UMEM_ALLOC_FAILED,
    DP_DROP_JUMBO_REASSEMBLY_TIMEOUT,
    DP_DROP_REASON_COUNT,
};

void dp_drop_count(enum dp_drop_reason reason);
void dp_jumbo_stat_tx_built(uint32_t fragment_count);
void dp_jumbo_stat_tx_submitted(uint32_t groups, uint32_t frag0,
                                uint32_t frag1, uint32_t frag2,
                                uint32_t frag_other,
                                uint32_t broken_edges);
void dp_jumbo_stat_rx_seen(uint8_t fragment_index);
void dp_jumbo_stat_rx_complete(void);
void dp_jumbo_stat_rx_timeout(uint8_t got_mask, uint8_t fragment_count);
void dp_diag_log(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
void dp_drop_report(void);
void dp_drop_reset(void);

#endif

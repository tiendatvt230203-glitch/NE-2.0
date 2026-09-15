#ifndef DROP_STATS_H
#define DROP_STATS_H

enum dp_drop_reason {
    DP_DROP_RX_TO_CRYPTO_RING_TIMEOUT = 0,
    DP_DROP_CRYPTO_TO_TX_RING_TIMEOUT,
    DP_DROP_UMEM_ALLOC_FAILED,
    DP_DROP_JUMBO_REASSEMBLY_TIMEOUT,
    DP_DROP_REASON_COUNT,
};

void dp_drop_count(enum dp_drop_reason reason);
void dp_drop_report(void);
void dp_drop_reset(void);

#endif

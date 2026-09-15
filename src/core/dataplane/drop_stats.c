#define _POSIX_C_SOURCE 199309L

#include "../../../inc/core/dataplane/drop_stats.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define DP_DROP_REPORT_NS (5ULL * 1000000000ULL)

static atomic_ullong drop_totals[DP_DROP_REASON_COUNT];
static uint64_t drop_reported[DP_DROP_REASON_COUNT];
static uint64_t drop_last_report_ns;

static uint64_t drop_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void dp_drop_count(enum dp_drop_reason reason)
{
    if (reason < 0 || reason >= DP_DROP_REASON_COUNT)
        return;
    atomic_fetch_add_explicit(&drop_totals[reason], 1,
                              memory_order_relaxed);
}

void dp_drop_reset(void)
{
    for (int i = 0; i < DP_DROP_REASON_COUNT; i++) {
        atomic_store_explicit(&drop_totals[i], 0, memory_order_relaxed);
        drop_reported[i] = 0;
    }
    drop_last_report_ns = 0;
}

void dp_drop_report(void)
{
    uint64_t now = drop_now_ns();
    uint64_t total[DP_DROP_REASON_COUNT];
    uint64_t delta[DP_DROP_REASON_COUNT];
    uint64_t delta_sum = 0;
    uint64_t window_ms;

    if (!now)
        return;
    if (!drop_last_report_ns) {
        drop_last_report_ns = now;
        return;
    }
    if (now - drop_last_report_ns < DP_DROP_REPORT_NS)
        return;

    window_ms = (now - drop_last_report_ns) / 1000000ULL;
    drop_last_report_ns = now;
    for (int i = 0; i < DP_DROP_REASON_COUNT; i++) {
        total[i] = atomic_load_explicit(&drop_totals[i],
                                        memory_order_relaxed);
        delta[i] = total[i] - drop_reported[i];
        drop_reported[i] = total[i];
        delta_sum += delta[i];
    }
    if (!delta_sum)
        return;

    fprintf(stderr,
            "[DP-DROP] window_ms=%llu "
            "rx_to_crypto_ring_timeout=%llu "
            "crypto_to_tx_ring_timeout=%llu "
            "umem_alloc_failed=%llu "
            "jumbo_reassembly_timeout=%llu total=%llu\n",
            (unsigned long long)window_ms,
            (unsigned long long)delta[DP_DROP_RX_TO_CRYPTO_RING_TIMEOUT],
            (unsigned long long)delta[DP_DROP_CRYPTO_TO_TX_RING_TIMEOUT],
            (unsigned long long)delta[DP_DROP_UMEM_ALLOC_FAILED],
            (unsigned long long)delta[DP_DROP_JUMBO_REASSEMBLY_TIMEOUT],
            (unsigned long long)delta_sum);
    fflush(stderr);
}

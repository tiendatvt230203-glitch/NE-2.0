#define _POSIX_C_SOURCE 199309L

#include "../../../inc/core/dataplane/drop_stats.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DP_DROP_REPORT_NS (5ULL * 1000000000ULL)
#define DP_DIAG_LOG_DIR "/var/log/NE"
#define DP_DIAG_LOG_PATH DP_DIAG_LOG_DIR "/dataplane.log"
#define DP_DIAG_LOG_OLD  DP_DIAG_LOG_DIR "/dataplane.log.1"
#define DP_DIAG_LOG_MAX_BYTES (16ULL * 1024ULL * 1024ULL)

enum dp_jumbo_stat {
    DP_JUMBO_TX_BUILT_GROUP = 0,
    DP_JUMBO_TX_BUILT_FRAG0,
    DP_JUMBO_TX_BUILT_FRAG1,
    DP_JUMBO_TX_BUILT_FRAG2,
    DP_JUMBO_TX_BUILT_OTHER,
    DP_JUMBO_TX_SUBMITTED_GROUP,
    DP_JUMBO_TX_SUBMITTED_FRAG0,
    DP_JUMBO_TX_SUBMITTED_FRAG1,
    DP_JUMBO_TX_SUBMITTED_FRAG2,
    DP_JUMBO_TX_SUBMITTED_OTHER,
    DP_JUMBO_TX_BROKEN_EDGE,
    DP_JUMBO_RX_SEEN_FRAG0,
    DP_JUMBO_RX_SEEN_FRAG1,
    DP_JUMBO_RX_SEEN_FRAG2,
    DP_JUMBO_RX_SEEN_OTHER,
    DP_JUMBO_RX_COMPLETE,
    DP_JUMBO_RX_MISSING_FRAG0,
    DP_JUMBO_RX_MISSING_FRAG1,
    DP_JUMBO_RX_MISSING_FRAG2,
    DP_JUMBO_RX_MISSING_OTHER,
    DP_JUMBO_STAT_COUNT,
};

static atomic_ullong drop_totals[DP_DROP_REASON_COUNT];
static uint64_t drop_reported[DP_DROP_REASON_COUNT];
static atomic_ullong jumbo_totals[DP_JUMBO_STAT_COUNT];
static uint64_t jumbo_reported[DP_JUMBO_STAT_COUNT];
static uint64_t drop_last_report_ns;
static pthread_mutex_t diag_log_lock = PTHREAD_MUTEX_INITIALIZER;

void dp_diag_log(const char *format, ...)
{
    char timestamp[32] = "time-unknown";
    struct stat st;
    struct tm local;
    time_t wall;
    FILE *out = NULL;
    va_list args;

    if (!format)
        return;
    pthread_mutex_lock(&diag_log_lock);
    if (mkdir(DP_DIAG_LOG_DIR, 0755) == 0 || errno == EEXIST) {
        if (stat(DP_DIAG_LOG_PATH, &st) == 0 &&
            (uint64_t)st.st_size >= DP_DIAG_LOG_MAX_BYTES)
            (void)rename(DP_DIAG_LOG_PATH, DP_DIAG_LOG_OLD);
        out = fopen(DP_DIAG_LOG_PATH, "a");
    }
    if (!out)
        out = stderr;

    wall = time(NULL);
    if (wall != (time_t)-1 && localtime_r(&wall, &local))
        (void)strftime(timestamp, sizeof(timestamp),
                       "%Y-%m-%dT%H:%M:%S%z", &local);
    fprintf(out, "%s pid=%ld ", timestamp, (long)getpid());
    va_start(args, format);
    vfprintf(out, format, args);
    va_end(args);
    fputc('\n', out);
    fflush(out);
    if (out != stderr)
        fclose(out);
    pthread_mutex_unlock(&diag_log_lock);
}

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

static void jumbo_count(enum dp_jumbo_stat stat, uint64_t count)
{
    if (stat < 0 || stat >= DP_JUMBO_STAT_COUNT || count == 0)
        return;
    atomic_fetch_add_explicit(&jumbo_totals[stat], count,
                              memory_order_relaxed);
}

static enum dp_jumbo_stat built_fragment_stat(uint32_t index)
{
    if (index == 0)
        return DP_JUMBO_TX_BUILT_FRAG0;
    if (index == 1)
        return DP_JUMBO_TX_BUILT_FRAG1;
    if (index == 2)
        return DP_JUMBO_TX_BUILT_FRAG2;
    return DP_JUMBO_TX_BUILT_OTHER;
}

void dp_jumbo_stat_tx_built(uint32_t fragment_count)
{
    if (fragment_count < 2)
        return;
    jumbo_count(DP_JUMBO_TX_BUILT_GROUP, 1);
    for (uint32_t i = 0; i < fragment_count; i++)
        jumbo_count(built_fragment_stat(i), 1);
}

void dp_jumbo_stat_tx_submitted(uint32_t groups, uint32_t frag0,
                                uint32_t frag1, uint32_t frag2,
                                uint32_t frag_other,
                                uint32_t broken_edges)
{
    jumbo_count(DP_JUMBO_TX_SUBMITTED_GROUP, groups);
    jumbo_count(DP_JUMBO_TX_SUBMITTED_FRAG0, frag0);
    jumbo_count(DP_JUMBO_TX_SUBMITTED_FRAG1, frag1);
    jumbo_count(DP_JUMBO_TX_SUBMITTED_FRAG2, frag2);
    jumbo_count(DP_JUMBO_TX_SUBMITTED_OTHER, frag_other);
    jumbo_count(DP_JUMBO_TX_BROKEN_EDGE, broken_edges);
}

void dp_jumbo_stat_rx_seen(uint8_t fragment_index)
{
    enum dp_jumbo_stat stat = DP_JUMBO_RX_SEEN_OTHER;

    if (fragment_index == 0)
        stat = DP_JUMBO_RX_SEEN_FRAG0;
    else if (fragment_index == 1)
        stat = DP_JUMBO_RX_SEEN_FRAG1;
    else if (fragment_index == 2)
        stat = DP_JUMBO_RX_SEEN_FRAG2;
    jumbo_count(stat, 1);
}

void dp_jumbo_stat_rx_complete(void)
{
    jumbo_count(DP_JUMBO_RX_COMPLETE, 1);
}

void dp_jumbo_stat_rx_timeout(uint8_t got_mask, uint8_t fragment_count)
{
    for (uint32_t i = 0; i < fragment_count && i < 8u; i++) {
        enum dp_jumbo_stat stat;

        if (got_mask & (uint8_t)(1u << i))
            continue;
        if (i == 0)
            stat = DP_JUMBO_RX_MISSING_FRAG0;
        else if (i == 1)
            stat = DP_JUMBO_RX_MISSING_FRAG1;
        else if (i == 2)
            stat = DP_JUMBO_RX_MISSING_FRAG2;
        else
            stat = DP_JUMBO_RX_MISSING_OTHER;
        jumbo_count(stat, 1);
    }
}

void dp_drop_reset(void)
{
    for (int i = 0; i < DP_DROP_REASON_COUNT; i++) {
        atomic_store_explicit(&drop_totals[i], 0, memory_order_relaxed);
        drop_reported[i] = 0;
    }
    for (int i = 0; i < DP_JUMBO_STAT_COUNT; i++) {
        atomic_store_explicit(&jumbo_totals[i], 0, memory_order_relaxed);
        jumbo_reported[i] = 0;
    }
    drop_last_report_ns = 0;
}

void dp_drop_report(void)
{
    uint64_t now = drop_now_ns();
    uint64_t total[DP_DROP_REASON_COUNT];
    uint64_t delta[DP_DROP_REASON_COUNT];
    uint64_t jumbo_total[DP_JUMBO_STAT_COUNT];
    uint64_t jumbo_delta[DP_JUMBO_STAT_COUNT];
    uint64_t delta_sum = 0;
    uint64_t jumbo_delta_sum = 0;
    uint64_t tx_delta_sum;
    uint64_t rx_delta_sum;
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
    for (int i = 0; i < DP_JUMBO_STAT_COUNT; i++) {
        jumbo_total[i] = atomic_load_explicit(&jumbo_totals[i],
                                              memory_order_relaxed);
        jumbo_delta[i] = jumbo_total[i] - jumbo_reported[i];
        jumbo_reported[i] = jumbo_total[i];
        jumbo_delta_sum += jumbo_delta[i];
    }

    if (delta_sum) {
        dp_diag_log(
            "[DP-DROP] window_ms=%llu "
            "rx_to_crypto_ring_timeout=%llu "
            "crypto_to_tx_ring_timeout=%llu "
            "umem_alloc_failed=%llu "
            "jumbo_reassembly_timeout=%llu total=%llu",
            (unsigned long long)window_ms,
            (unsigned long long)delta[DP_DROP_RX_TO_CRYPTO_RING_TIMEOUT],
            (unsigned long long)delta[DP_DROP_CRYPTO_TO_TX_RING_TIMEOUT],
            (unsigned long long)delta[DP_DROP_UMEM_ALLOC_FAILED],
            (unsigned long long)delta[DP_DROP_JUMBO_REASSEMBLY_TIMEOUT],
            (unsigned long long)delta_sum);
    }
    tx_delta_sum = jumbo_delta[DP_JUMBO_TX_BUILT_GROUP] +
        jumbo_delta[DP_JUMBO_TX_BUILT_FRAG0] +
        jumbo_delta[DP_JUMBO_TX_BUILT_FRAG1] +
        jumbo_delta[DP_JUMBO_TX_BUILT_FRAG2] +
        jumbo_delta[DP_JUMBO_TX_BUILT_OTHER] +
        jumbo_delta[DP_JUMBO_TX_SUBMITTED_GROUP] +
        jumbo_delta[DP_JUMBO_TX_SUBMITTED_FRAG0] +
        jumbo_delta[DP_JUMBO_TX_SUBMITTED_FRAG1] +
        jumbo_delta[DP_JUMBO_TX_SUBMITTED_FRAG2] +
        jumbo_delta[DP_JUMBO_TX_SUBMITTED_OTHER] +
        jumbo_delta[DP_JUMBO_TX_BROKEN_EDGE];
    rx_delta_sum = jumbo_delta_sum - tx_delta_sum;
    if (tx_delta_sum) {
        dp_diag_log(
            "[JUMBO-TX] window_ms=%llu "
            "tx_built_groups=%llu tx_built=%llu/%llu/%llu/%llu "
            "tx_submitted_groups=%llu tx_submitted=%llu/%llu/%llu/%llu "
            "tx_broken_edges=%llu",
            (unsigned long long)window_ms,
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_BUILT_GROUP],
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_BUILT_FRAG0],
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_BUILT_FRAG1],
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_BUILT_FRAG2],
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_BUILT_OTHER],
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_SUBMITTED_GROUP],
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_SUBMITTED_FRAG0],
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_SUBMITTED_FRAG1],
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_SUBMITTED_FRAG2],
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_SUBMITTED_OTHER],
            (unsigned long long)jumbo_delta[DP_JUMBO_TX_BROKEN_EDGE]);
    }
    if (rx_delta_sum) {
        dp_diag_log(
            "[JUMBO-RX] window_ms=%llu rx_seen=%llu/%llu/%llu/%llu "
            "rx_complete=%llu rx_missing=%llu/%llu/%llu/%llu",
            (unsigned long long)window_ms,
            (unsigned long long)jumbo_delta[DP_JUMBO_RX_SEEN_FRAG0],
            (unsigned long long)jumbo_delta[DP_JUMBO_RX_SEEN_FRAG1],
            (unsigned long long)jumbo_delta[DP_JUMBO_RX_SEEN_FRAG2],
            (unsigned long long)jumbo_delta[DP_JUMBO_RX_SEEN_OTHER],
            (unsigned long long)jumbo_delta[DP_JUMBO_RX_COMPLETE],
            (unsigned long long)jumbo_delta[DP_JUMBO_RX_MISSING_FRAG0],
            (unsigned long long)jumbo_delta[DP_JUMBO_RX_MISSING_FRAG1],
            (unsigned long long)jumbo_delta[DP_JUMBO_RX_MISSING_FRAG2],
            (unsigned long long)jumbo_delta[DP_JUMBO_RX_MISSING_OTHER]);
    }
}

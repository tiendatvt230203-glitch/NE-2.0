#ifndef DP_IDLE_H
#define DP_IDLE_H

#include "core/util/cpu_map.h"

#include <stdint.h>

#define NE_DP_WAKE_CRYPTO(w) ((int)(w))
#define NE_DP_WAKE_TX(slot)  ((int)NE_CRYPTO_WORKERS + (int)(slot))
#define NE_DP_WAKE_N         ((int)NE_CRYPTO_WORKERS + (int)NE_TX_SLOTS)

#define NE_DP_POLLFD_MAX 128

struct ne_dp_idle {
    uint64_t idle_start_ns;
};

void ne_dp_idle_init(void);
void ne_dp_idle_shutdown(void);

void ne_dp_idle_note_work(struct ne_dp_idle *st);

/*
 * Hot/warm handled internally (pause / short nanosleep).
 * Returns 1 if the caller must cold-poll: sleeping is set when wake_id >= 0.
 * Caller must then ne_dp_idle_poll() or ne_dp_idle_disarm().
 */
int ne_dp_idle_arm(struct ne_dp_idle *st, int wake_id);

void ne_dp_idle_poll(int wake_id, const int *extra_fds, int extra_nfds);
void ne_dp_idle_disarm(int wake_id);

void ne_dp_idle_wake(int wake_id);
void ne_dp_idle_wake_all(void);

static inline void ne_dp_idle_wake_tx_slot(int tx_slot)
{
    if (tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return;
    ne_dp_idle_wake(NE_DP_WAKE_TX(tx_slot));
}

/* Output ring w is owned by TX slot (w % NE_TX_SLOTS). */
static inline void ne_dp_idle_wake_tx_worker(int worker_idx)
{
    if (worker_idx < 0)
        return;
    ne_dp_idle_wake_tx_slot(worker_idx % (int)NE_TX_SLOTS);
}

#endif

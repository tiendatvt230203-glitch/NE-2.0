#include "../../../../inc/crypto/mtu1500_udp_option.h"
#include "../../pqc/include/pqc_l2_mtu1500_udp.h"

#include <stdatomic.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

static atomic_uint_fast32_t g_udp_epoch;
static __thread uint32_t g_udp_tx_seq;
static __thread uint32_t g_udp_tx_datagram_id;
static __thread uint32_t g_udp_tx_datagram_clock;
static __thread uint32_t g_udp_rx_epoch;
static __thread uint32_t g_udp_rx_seq;
static __thread uint8_t g_udp_tx_valid;
static __thread uint8_t g_udp_rx_valid;

const struct crypto_option_ops *crypto_opt_l2_pqc_udp_1500_ops(void)
{
    static const struct crypto_option_ops ops = {
        .need_split = pqc_l2_mtu1500_udp_need_split,
        .split = pqc_l2_mtu1500_udp_split,
        .encrypt = pqc_l2_mtu1500_udp_encrypt,
        .decrypt = pqc_l2_mtu1500_udp_decrypt,
        .is_fragment = pqc_l2_mtu1500_udp_is_fragment,
        .reasm = pqc_l2_mtu1500_udp_reassemble,
        .frag_gc = pqc_l2_mtu1500_udp_frag_gc,
    };

    return &ops;
}

static uint32_t mtu1500_udp_epoch(void)
{
    uint32_t epoch = (uint32_t)atomic_load_explicit(&g_udp_epoch,
                                                    memory_order_acquire);

    if (epoch != 0)
        return epoch;
    if (getrandom(&epoch, sizeof(epoch), GRND_NONBLOCK) != (ssize_t)sizeof(epoch) ||
        epoch == 0) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        epoch = (uint32_t)ts.tv_nsec ^ (uint32_t)ts.tv_sec ^
            ((uint32_t)getpid() * 0x9e3779b9u);
        if (epoch == 0)
            epoch = 1u;
    }
    {
        uint_fast32_t expected = 0;

        if (!atomic_compare_exchange_strong_explicit(&g_udp_epoch, &expected, epoch,
                                                      memory_order_release,
                                                      memory_order_acquire))
            epoch = (uint32_t)expected;
    }
    return epoch;
}

void crypto_mtu1500_udp_set_tx_seq(uint32_t seq)
{
    g_udp_tx_seq = seq;
    g_udp_tx_datagram_id = g_udp_tx_datagram_clock++;
    g_udp_tx_valid = 1u;
}

int crypto_mtu1500_udp_tx_meta(uint32_t *epoch, uint32_t *seq,
                               uint32_t *datagram_id)
{
    if (!epoch || !seq || !datagram_id || !g_udp_tx_valid)
        return -1;
    *epoch = mtu1500_udp_epoch();
    *seq = g_udp_tx_seq;
    *datagram_id = g_udp_tx_datagram_id;
    return 0;
}

void crypto_mtu1500_udp_clear_rx_meta(void)
{
    g_udp_rx_valid = 0u;
}

void crypto_mtu1500_udp_set_rx_meta(uint32_t epoch, uint32_t seq)
{
    g_udp_rx_epoch = epoch;
    g_udp_rx_seq = seq;
    g_udp_rx_valid = 1u;
}

int crypto_mtu1500_udp_take_rx_meta(uint32_t *epoch, uint32_t *seq)
{
    if (!epoch || !seq || !g_udp_rx_valid)
        return -1;
    *epoch = g_udp_rx_epoch;
    *seq = g_udp_rx_seq;
    g_udp_rx_valid = 0u;
    return 0;
}

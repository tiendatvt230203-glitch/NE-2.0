#ifndef CPU_MAP_H
#define CPU_MAP_H

#include <stdint.h>


static const uint8_t NE_CPU_RX_LAN[]  = { 0u };
static const uint8_t NE_CPU_TX[]      = { 1u, 2u, 9u, 10u };
static const uint8_t NE_CPU_CRYPTO[]  = { 3u, 4u, 5u, 6u, 7u, 8u };
static const uint8_t NE_CPU_RX_WAN[]  = { 11u };

#define NE_RX_LAN_SLOTS   ((uint32_t)(sizeof(NE_CPU_RX_LAN) / sizeof(NE_CPU_RX_LAN[0])))
#define NE_RX_WAN_SLOTS   ((uint32_t)(sizeof(NE_CPU_RX_WAN) / sizeof(NE_CPU_RX_WAN[0])))
#define NE_TX_SLOTS       ((uint32_t)(sizeof(NE_CPU_TX) / sizeof(NE_CPU_TX[0])))
#define NE_TX_WAN_SLOTS   NE_TX_SLOTS
#define NE_CRYPTO_WORKERS ((uint32_t)(sizeof(NE_CPU_CRYPTO) / sizeof(NE_CPU_CRYPTO[0])))

static inline uint8_t ne_cpu_rx_lan(uint32_t slot)
{
    return NE_CPU_RX_LAN[slot < NE_RX_LAN_SLOTS ? slot : 0u];
}

static inline uint8_t ne_cpu_rx_wan(uint32_t slot)
{
    return NE_CPU_RX_WAN[slot < NE_RX_WAN_SLOTS ? slot : 0u];
}

static inline uint8_t ne_cpu_tx(uint32_t slot)
{
    return NE_CPU_TX[slot < NE_TX_SLOTS ? slot : 0u];
}

static inline uint8_t ne_cpu_crypto(uint32_t worker)
{
    return NE_CPU_CRYPTO[worker < NE_CRYPTO_WORKERS ? worker : 0u];
}

int ne_cpu_map_validate(void);
void ne_cpu_map_log(void);

#endif

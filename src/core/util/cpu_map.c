#include "../../../inc/core/util/cpu_map.h"

#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int validate_group(const char *name, const uint8_t *cpus, uint32_t count,
                          const cpu_set_t *allowed, uint8_t seen[CPU_SETSIZE])
{
    for (uint32_t i = 0; i < count; i++) {
        unsigned int cpu = cpus[i];

        if (cpu >= CPU_SETSIZE || !CPU_ISSET(cpu, allowed)) {
            fprintf(stderr, "[DP-CONF] %s[%u]=CPU%u is offline or outside cpuset\n",
                    name, i, cpu);
            return -1;
        }
        if (seen[cpu]) {
            fprintf(stderr, "[DP-CONF] CPU%u is assigned to more than one dataplane role\n",
                    cpu);
            return -1;
        }
        seen[cpu] = 1;
    }
    return 0;
}

int ne_cpu_map_validate(void)
{
    cpu_set_t allowed;
    uint8_t seen[CPU_SETSIZE];

    CPU_ZERO(&allowed);
    memset(seen, 0, sizeof(seen));
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        perror("[DP-CONF] sched_getaffinity");
        return -1;
    }
    if (validate_group("RX_LAN", NE_CPU_RX_LAN, NE_RX_LAN_SLOTS,
                       &allowed, seen) != 0 ||
        validate_group("TX", NE_CPU_TX, NE_TX_SLOTS, &allowed, seen) != 0 ||
        validate_group("CRYPTO", NE_CPU_CRYPTO, NE_CRYPTO_WORKERS,
                       &allowed, seen) != 0 ||
        validate_group("RX_WAN", NE_CPU_RX_WAN, NE_RX_WAN_SLOTS,
                       &allowed, seen) != 0)
        return -1;
    return 0;
}

void ne_cpu_map_log(void)
{
    fprintf(stderr, "[DP-CONF] RX_LAN (%u):", (unsigned)NE_RX_LAN_SLOTS);
    for (uint32_t i = 0; i < NE_RX_LAN_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_RX_LAN[i]);
    fprintf(stderr, "\n[DP-CONF] TX (%u):", (unsigned)NE_TX_SLOTS);
    for (uint32_t i = 0; i < NE_TX_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_TX[i]);
    fprintf(stderr, "\n[DP-CONF] CRYPTO (%u):", (unsigned)NE_CRYPTO_WORKERS);
    for (uint32_t i = 0; i < NE_CRYPTO_WORKERS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_CRYPTO[i]);
    fprintf(stderr, "\n[DP-CONF] RX_WAN (%u):", (unsigned)NE_RX_WAN_SLOTS);
    for (uint32_t i = 0; i < NE_RX_WAN_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_RX_WAN[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
}

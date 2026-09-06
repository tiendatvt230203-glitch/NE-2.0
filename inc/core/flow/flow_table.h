#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "core/util/config.h"
#include <stdint.h>

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

/* Preallocate/free the lock-free smooth-WRR cache for the calling worker. */
int flow_table_thread_init(void);
void flow_table_thread_cleanup(void);

int flow_table_pick_wan_per_packet(const int *allowed_wans,
                                   const int *allowed_weights,
                                   int allowed_count);

/*
 * Per-flow smooth WRR.  State is thread-local because an encrypted flow is
 * owned by one crypto worker; this keeps the packet hot path lock-free and
 * avoids the old process-wide sequence cache-line contention.
 */
int flow_table_pick_wan_per_flow_packet(uint32_t src_ip, uint32_t dst_ip,
                                        uint16_t src_port, uint16_t dst_port,
                                        uint8_t protocol,
                                        const int *allowed_wans,
                                        const int *allowed_weights,
                                        int allowed_count);

#endif

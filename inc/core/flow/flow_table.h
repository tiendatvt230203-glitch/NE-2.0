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

/*
 * WAN window selection is explicitly tied to the active dataplane mode.
 * MTU 9000 uses one window per original packet; AF_XDP continuation
 * descriptors and the resulting wire fragments never count separately.
 */
enum flow_wan_window_class {
    FLOW_WAN_WINDOW_MTU1500_OTHER = 0,
    FLOW_WAN_WINDOW_MTU1500_TCP,
    FLOW_WAN_WINDOW_MTU1500_UDP,
    FLOW_WAN_WINDOW_MTU9000,
};

/* Preallocate/free the lock-free per-flow WAN cache for the calling worker. */
int flow_table_thread_init(void);
void flow_table_thread_cleanup(void);

int flow_table_pick_wan_per_packet(const int *allowed_wans, int allowed_count);

/*
 * Per-flow equal-share scheduling. State is thread-local because a flow is
 * owned by one crypto worker; this keeps the packet hot path lock-free and
 * avoids the old process-wide sequence cache-line contention.
 */
int flow_table_pick_wan_per_flow_packet(uint32_t src_ip, uint32_t dst_ip,
                                        uint16_t src_port, uint16_t dst_port,
                                        uint8_t protocol,
                                        const int *allowed_wans,
                                        int allowed_count,
                                        enum flow_wan_window_class window_class);

void flow_table_packet_complete(enum flow_wan_window_class window_class,
                                int sent);
#endif

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

/* Preallocate/free the lock-free per-flow byte-window cache for this worker. */
int flow_table_thread_init(void);
void flow_table_thread_cleanup(void);

int flow_table_pick_wan_per_packet(const int *allowed_wans,
                                   const int *allowed_weights,
                                   int allowed_count);

/*
 * Keep one canonical 5-tuple on a WAN for a byte window. WAN selection at a
 * window boundary is weighted by the bytes already assigned to each WAN.
 */
int flow_table_pick_wan_per_flow_window(uint32_t src_ip, uint32_t dst_ip,
                                        uint16_t src_port, uint16_t dst_port,
                                        uint8_t protocol,
                                        const int *allowed_wans,
                                        const int *allowed_weights,
                                        int allowed_count,
                                        uint32_t path_mtu);

/* Account bytes only after the original packet/datagram was queued. */
void flow_table_account_per_flow_bytes(uint32_t src_ip, uint32_t dst_ip,
                                       uint16_t src_port, uint16_t dst_port,
                                       uint8_t protocol, uint64_t wire_bytes);

/* A congested/down selected WAN ends the current window early and rebinds it. */
void flow_table_rebind_per_flow_wan(uint32_t src_ip, uint32_t dst_ip,
                                    uint16_t src_port, uint16_t dst_port,
                                    uint8_t protocol, int wan_cfg,
                                    const int *allowed_weights,
                                    int allowed_count, uint32_t path_mtu);

#endif

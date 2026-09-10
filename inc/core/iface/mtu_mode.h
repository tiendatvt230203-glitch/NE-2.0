#ifndef MTU_MODE_H
#define MTU_MODE_H

#include "core/util/config.h"

#include <stddef.h>
#include <stdint.h>

enum ne_mtu_mode {
    NE_MTU_MODE_INVALID = 0,
    NE_MTU_MODE_1500,
    NE_MTU_MODE_9000,
};

const char *ne_mtu_mode_name(enum ne_mtu_mode mode);
uint32_t ne_mtu_mode_value(enum ne_mtu_mode mode);
int ne_mtu_mode_is_jumbo(enum ne_mtu_mode mode);

/* Detect one strict mode across every configured LAN and dataplane WAN.
 * MTU 9000 additionally requires the project-supported i40e/ice drivers. */
int ne_mtu_mode_detect(const struct app_config *cfg, enum ne_mtu_mode *mode_out,
                       char *error, size_t error_size);

/* Hot reload may add/remove interfaces, but it cannot change the dataplane
 * mode while workers and AF_XDP sockets are running. */
int ne_mtu_mode_validate(const struct app_config *cfg, enum ne_mtu_mode expected,
                         char *error, size_t error_size);

#endif

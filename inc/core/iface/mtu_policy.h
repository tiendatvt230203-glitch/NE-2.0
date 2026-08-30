#ifndef NE_MTU_POLICY_H
#define NE_MTU_POLICY_H

#include <stdint.h>

/* The dataplane does not support shrinking a decrypted LAN jumbo frame onto
 * a smaller WAN. Equal MTUs and a WAN larger than the LAN are supported. */
static inline int ne_mtu_topology_supported(uint32_t lan_mtu,
                                             uint32_t wan_mtu)
{
    return lan_mtu <= wan_mtu;
}

#endif

#ifndef PQC_FRAG_LAYOUT_H
#define PQC_FRAG_LAYOUT_H

#include <stdint.h>

/* A full or fragmented UDP packet grows by 47 bytes compared with the
 * original Ethernet frame: policy/core/nonce, marker, authenticated shim and
 * GCM tag. The configured path MTU is intentionally used as the maximum XDP
 * descriptor-chain length for each encrypted UDP fragment. */
#define CRYPTO_PQC_UDP_WIRE_OVERHEAD 47u

struct crypto_pqc_udp_frag_layout {
    uint32_t frag0_plain_len;
    uint32_t frag1_payload_len;
    uint32_t frag0_wire_len;
    uint32_t frag1_wire_len;
};

static inline int crypto_pqc_udp_fragment_layout(
    uint32_t path_mtu, uint32_t l3_off, uint32_t ip_header_len,
    uint32_t udp_payload_len, struct crypto_pqc_udp_frag_layout *layout)
{
    uint32_t wire_fixed;
    uint32_t frag0_fixed;
    uint32_t max_frag0_plain;
    uint32_t frag0_payload;

    if (!layout || ip_header_len < 20u || udp_payload_len == 0u)
        return -1;
    if (l3_off > UINT32_MAX - CRYPTO_PQC_UDP_WIRE_OVERHEAD)
        return -1;
    wire_fixed = l3_off + CRYPTO_PQC_UDP_WIRE_OVERHEAD;
    frag0_fixed = ip_header_len + 8u; /* IPv4 header + UDP header. */
    if (wire_fixed >= path_mtu || frag0_fixed >= path_mtu - wire_fixed)
        return -1;

    max_frag0_plain = path_mtu - wire_fixed;
    frag0_payload = max_frag0_plain - frag0_fixed;
    /* This helper is for a real two-fragment packet. A full packet that fits
     * must stay on the non-fragmented path. */
    if (frag0_payload >= udp_payload_len)
        return -1;

    layout->frag0_plain_len = frag0_fixed + frag0_payload;
    layout->frag1_payload_len = udp_payload_len - frag0_payload;
    layout->frag0_wire_len = wire_fixed + layout->frag0_plain_len;
    layout->frag1_wire_len = wire_fixed + layout->frag1_payload_len;
    return 0;
}

static inline int crypto_pqc_udp_needs_fragment(uint32_t frame_len,
                                                 uint32_t path_mtu)
{
    return frame_len > path_mtu ||
        CRYPTO_PQC_UDP_WIRE_OVERHEAD > path_mtu - frame_len;
}

#endif

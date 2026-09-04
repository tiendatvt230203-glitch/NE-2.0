#include "../../../inc/crypto/eth_parse.h"

#define ETH_P_8021Q  0x8100u
#define ETH_P_IP     0x0800u
#define ETH_P_ARP    0x0806u
static uint16_t eth_read_et(const uint8_t *pkt, int off)
{
    return (uint16_t)(((uint16_t)pkt[off] << 8) | pkt[off + 1]);
}

static int eth_match_et(uint16_t et, uint16_t target, uint16_t fake)
{
    return et == target || (fake != 0 && et == fake);
}

int crypto_eth_inner_et_off(const uint8_t *pkt, size_t pkt_len)
{
    const uint16_t fake = NE_L2_FAKE_ETHERTYPE;
    const uint16_t fake_udp = NE_L2_FAKE_ETHERTYPE_UDP;
    const uint16_t fake_arp = NE_L2_FAKE_ETHERTYPE_ARP;
    uint16_t et;

    if (!pkt || pkt_len < 14)
        return -1;

    et = eth_read_et(pkt, 12);
    if (eth_match_et(et, ETH_P_IP, fake) || et == fake_udp || et == fake_arp)
        return 12;

    if (et != ETH_P_8021Q)
        return -1;
    if (pkt_len < 18)
        return -1;

    et = eth_read_et(pkt, 16);
    if (eth_match_et(et, ETH_P_IP, fake) || et == fake_udp || et == fake_arp)
        return 16;

    return -1;
}

int crypto_eth_ipv4_offset(const uint8_t *pkt, size_t pkt_len)
{
    int et_off = crypto_eth_inner_et_off(pkt, pkt_len);

    if (et_off < 0)
        return -1;
    if (eth_read_et(pkt, et_off) != ETH_P_IP)
        return -1;
    if (pkt_len < (size_t)(et_off + 2 + 20))
        return -1;
    return et_off + 2;
}

int crypto_eth_arp_offset(const uint8_t *pkt, size_t pkt_len) {
    int et_off;
    uint16_t et;

    if (!pkt || pkt_len < 14) {
        return -1;
    }

    et = eth_read_et(pkt, 12);
    if (et == ETH_P_8021Q) {
        if (pkt_len < 18) {
            return -1;
        }
        et_off = 16;
        et = eth_read_et(pkt, et_off);
    }
    else {
        et_off = 12;
    }
    if (et != ETH_P_ARP) {
        return -1;
    }
    if (pkt_len < (size_t)(et_off + 2 + 28)) {
        return -1;
    }
    return et_off + 2;
}

int crypto_eth_l2_prefix_len(const uint8_t *pkt, size_t pkt_len)
{
    int et_off = crypto_eth_inner_et_off(pkt, pkt_len);

    if (et_off < 0)
        return -1;
    return et_off;
}

int crypto_pkt_is_ipv4(const uint8_t *pkt, size_t pkt_len)
{
    return crypto_eth_ipv4_offset(pkt, pkt_len) >= 0;
}

int crypto_pkt_is_arp(const uint8_t *pkt, size_t pkt_len) {
    return crypto_eth_arp_offset(pkt, pkt_len) >= 0;
}

void crypto_eth_set_ipv4_et(uint8_t *pkt, int inner_et_off)
{
    if (!pkt || inner_et_off < 0)
        return;
    pkt[inner_et_off] = 0x08;
    pkt[inner_et_off + 1] = 0x00;
}

void crypto_eth_set_arp_et(uint8_t *pkt, int inner_et_off) {
    if (!pkt || inner_et_off < 0) {
        return;
    }
    pkt[inner_et_off] = 0x08;
    pkt[inner_et_off + 1] = 0x06;
}

int crypto_eth_l2_has_marker(const uint8_t *pkt, size_t pkt_len)
{
    int et_off;
    uint16_t et;

    et_off = crypto_eth_inner_et_off(pkt, pkt_len);
    if (et_off < 0)
        return 0;
    et = eth_read_et(pkt, et_off);
    return et == NE_L2_FAKE_ETHERTYPE || et == NE_L2_FAKE_ETHERTYPE_UDP;
}

int crypto_eth_l2_has_arp_marker(const uint8_t *pkt, size_t pkt_len)
{
    int et_off;
    uint16_t et;

    et_off = crypto_eth_inner_et_off(pkt, pkt_len);
    if (et_off < 0)
        return 0;
    et = eth_read_et(pkt, et_off);
    return et == NE_L2_FAKE_ETHERTYPE_ARP;
}

int crypto_eth_l2_core_id_off(const uint8_t *packet, size_t pkt_len)
{
    int off = crypto_eth_inner_et_off(packet, pkt_len);

    if (off < 0)
        return -1;
    if (pkt_len < (size_t)(off + 3))
        return -1;
    return off + 2;
}

int crypto_eth_l2_frag_magic_off(const uint8_t *packet, size_t pkt_len, int nonce_size)
{
    int off = crypto_eth_l2_core_id_off(packet, pkt_len);

    if (off < 0 || nonce_size < 0)
        return -1;
    if (pkt_len < (size_t)(off + 1 + nonce_size))
        return -1;
    return off + 1 + nonce_size;
}

int crypto_eth_l2_read_worker_idx(const uint8_t *packet, uint32_t pkt_len, uint8_t *worker_idx_out)
{
    int core_off;

    if (!packet || !worker_idx_out)
        return -1;
    if (!crypto_eth_l2_has_marker(packet, pkt_len))
        return -1;
    core_off = crypto_eth_l2_core_id_off(packet, pkt_len);
    if (core_off < 0)
        return -1;
    *worker_idx_out = packet[core_off];
    return 0;
}

static void tcp_checksum_replace_word(uint8_t *tcp, uint16_t old_word, uint16_t new_word)
{
    uint32_t sum;
    uint16_t hc;

    if (!tcp || old_word == new_word)
        return;

    hc = (uint16_t)(((uint16_t)tcp[16] << 8) | tcp[17]);
    sum = (uint32_t)(~hc & 0xFFFFu) + (uint32_t)(~old_word & 0xFFFFu) + (uint32_t)new_word;
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    hc = (uint16_t)(~sum);
    tcp[16] = (uint8_t)(hc >> 8);
    tcp[17] = (uint8_t)(hc & 0xFF);
}

int crypto_tcp_clamp_mss(uint8_t *pkt, uint32_t pkt_len, uint32_t path_mtu, uint32_t wire_overhead)
{
    int l3_off;
    uint8_t *ip;
    uint8_t *tcp;
    uint32_t ihl;
    uint32_t data_off;
    uint32_t opt_off;
    uint32_t opt_end;
    uint8_t flags;
    uint32_t mss_cap;
    int changed = 0;

    if (!pkt || path_mtu < 576)
        return -1;

    l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    ip = pkt + l3_off;
    if ((ip[0] & 0xF0) != 0x40)
        return -1;
    if (ip[9] != 6) /* IPPROTO_TCP */
        return -1;

    ihl = (uint32_t)(ip[0] & 0x0F) * 4u;
    if (ihl < 20 || pkt_len < (uint32_t)(l3_off + ihl + 20))
        return -1;

    tcp = ip + ihl;
    flags = tcp[13];
    if ((flags & 0x02) == 0) /* SYN */
        return 0;

    data_off = (uint32_t)((tcp[12] >> 4) & 0x0F) * 4u;
    if (data_off < 20 || pkt_len < (uint32_t)(l3_off + ihl + data_off))
        return -1;

    if (path_mtu <= ihl + 20u + wire_overhead)
        return -1;
    mss_cap = path_mtu - ihl - 20u - wire_overhead;
    if (mss_cap < 536u)
        mss_cap = 536u;
    if (mss_cap > 0xFFFFu)
        mss_cap = 0xFFFFu;

    opt_off = 20;
    opt_end = data_off;
    while (opt_off + 1 < opt_end) {
        uint8_t kind = tcp[opt_off];
        uint8_t olen;

        if (kind == 0) /* EOL */
            break;
        if (kind == 1) { /* NOP */
            opt_off++;
            continue;
        }
        if (opt_off + 1 >= opt_end)
            break;
        olen = tcp[opt_off + 1];
        if (olen < 2 || opt_off + olen > opt_end)
            break;

        if (kind == 2 && olen == 4 && opt_off + 4 <= opt_end) {
            uint16_t old_mss = (uint16_t)(((uint16_t)tcp[opt_off + 2] << 8) | tcp[opt_off + 3]);
            uint16_t new_mss = old_mss;

            if (old_mss > (uint16_t)mss_cap)
                new_mss = (uint16_t)mss_cap;
            if (new_mss != old_mss) {
                tcp[opt_off + 2] = (uint8_t)(new_mss >> 8);
                tcp[opt_off + 3] = (uint8_t)(new_mss & 0xFF);
                tcp_checksum_replace_word(tcp, old_mss, new_mss);
                changed = 1;
            }
            break;
        }
        opt_off += olen;
    }

    return changed ? 1 : 0;
}

#include "core/dataplane/mtu1500/tcp_mss.h"
#include "crypto/crypto_option.h"

static void tcp_checksum_replace_word(uint8_t *tcp, uint16_t old_word,
                                      uint16_t new_word)
{
    uint32_t sum;
    uint16_t hc;

    if (!tcp || old_word == new_word)
        return;

    hc = (uint16_t)(((uint16_t)tcp[16] << 8) | tcp[17]);
    sum = (uint32_t)(~hc & 0xFFFFu) + (uint32_t)(~old_word & 0xFFFFu) +
        (uint32_t)new_word;
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    hc = (uint16_t)(~sum);
    tcp[16] = (uint8_t)(hc >> 8);
    tcp[17] = (uint8_t)(hc & 0xFF);
}

int dp_mtu1500_tcp_clamp_mss(struct forwarder *fwd, uint8_t *pkt,
                             uint32_t pkt_len, int l3_off)
{
    uint8_t *ip;
    uint8_t *tcp;
    uint32_t ihl;
    uint32_t data_off;
    uint32_t opt_off;
    uint32_t opt_end;
    uint8_t flags;
    uint32_t path_mtu;
    uint32_t wire_overhead;
    uint32_t mss_cap;
    int changed = 0;

    if (!fwd || fwd->mtu_mode != NE_MTU_MODE_1500)
        return 0;
    path_mtu = ne_mtu_mode_value(fwd->mtu_mode);
    wire_overhead = crypto_option_wire_overhead(CRYPTO_OPT_L2_PQC);
    if (!pkt || path_mtu < 576 || l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    ip = pkt + l3_off;
    if ((ip[0] & 0xF0) != 0x40 || ip[9] != 6)
        return -1;
    /* A non-initial IP fragment does not begin with a TCP header. */
    if ((ip[6] & 0x1fu) || ip[7])
        return 0;

    ihl = (uint32_t)(ip[0] & 0x0F) * 4u;
    if (ihl < 20 || pkt_len < (uint32_t)(l3_off + ihl + 20))
        return -1;

    tcp = ip + ihl;
    flags = tcp[13];
    if ((flags & 0x02) == 0)
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

        if (kind == 0)
            break;
        if (kind == 1) {
            opt_off++;
            continue;
        }
        if (opt_off + 1 >= opt_end)
            break;
        olen = tcp[opt_off + 1];
        if (olen < 2 || opt_off + olen > opt_end)
            break;

        if (kind == 2 && olen == 4 && opt_off + 4 <= opt_end) {
            uint16_t old_mss = (uint16_t)(
                ((uint16_t)tcp[opt_off + 2] << 8) | tcp[opt_off + 3]);
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

#include "crypto/eth_parse.h"
#include "crypto/pqc_frag_layout.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define TEST_PATH_MTU      9000u
#define TEST_WIRE_OVERHEAD 42u
#define TEST_TCP_MSS_CAP   8918u

static void test_udp_two_fragment_layout(void)
{
    struct crypto_pqc_udp_frag_layout layout;

    /* Ethernet(14) + IPv4(20) + UDP(8) + payload(8972) is a 9014-byte
     * original frame. Encryption makes fragment 0 exactly 9000 bytes. */
    assert(crypto_pqc_udp_fragment_layout(TEST_PATH_MTU, 14, 20, 8972,
                                           &layout) == 0);
    assert(layout.frag0_plain_len == 8939);
    assert(layout.frag0_wire_len == TEST_PATH_MTU);
    assert(layout.frag1_payload_len == 61);
    assert(layout.frag1_wire_len == 122);

    /* The same policy follows a smaller configured path MTU dynamically. */
    assert(crypto_pqc_udp_fragment_layout(5000, 14, 20, 4972,
                                           &layout) == 0);
    assert(layout.frag0_wire_len == 5000);
    assert(layout.frag1_payload_len == 61);
}

static void test_udp_fragment_boundary(void)
{
    assert(!crypto_pqc_udp_needs_fragment(8953, TEST_PATH_MTU));
    assert(crypto_pqc_udp_needs_fragment(8954, TEST_PATH_MTU));
    assert(crypto_pqc_udp_needs_fragment(9014, TEST_PATH_MTU));
    assert(!crypto_pqc_udp_needs_fragment(1500, TEST_PATH_MTU));
}

static uint16_t read_mss(const uint8_t *pkt)
{
    const uint8_t *mss = pkt + 14 + 20 + 22;

    return (uint16_t)(((uint16_t)mss[0] << 8) | mss[1]);
}

static void make_tcp_syn(uint8_t *pkt, uint16_t mss, int syn)
{
    uint8_t *ip;
    uint8_t *tcp;

    memset(pkt, 0, 14 + 20 + 24);
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    ip = pkt + 14;
    ip[0] = 0x45;
    ip[9] = 6;
    tcp = ip + 20;
    tcp[12] = 6u << 4; /* 24-byte TCP header. */
    tcp[13] = syn ? 0x02 : 0x10;
    tcp[20] = 2;      /* MSS option. */
    tcp[21] = 4;
    tcp[22] = (uint8_t)(mss >> 8);
    tcp[23] = (uint8_t)mss;
}

static void test_tcp_mss_is_only_lowered_when_needed(void)
{
    uint8_t pkt[14 + 20 + 24];

    make_tcp_syn(pkt, TEST_TCP_MSS_CAP, 1);
    assert(crypto_tcp_clamp_mss(pkt, sizeof(pkt), TEST_PATH_MTU,
                                TEST_WIRE_OVERHEAD) == 0);
    assert(read_mss(pkt) == TEST_TCP_MSS_CAP);

    make_tcp_syn(pkt, TEST_TCP_MSS_CAP + 1u, 1);
    assert(crypto_tcp_clamp_mss(pkt, sizeof(pkt), TEST_PATH_MTU,
                                TEST_WIRE_OVERHEAD) == 1);
    assert(read_mss(pkt) == TEST_TCP_MSS_CAP);

    make_tcp_syn(pkt, 1460, 1);
    assert(crypto_tcp_clamp_mss(pkt, sizeof(pkt), TEST_PATH_MTU,
                                TEST_WIRE_OVERHEAD) == 0);
    assert(read_mss(pkt) == 1460);

    make_tcp_syn(pkt, 9000, 0);
    assert(crypto_tcp_clamp_mss(pkt, sizeof(pkt), TEST_PATH_MTU,
                                TEST_WIRE_OVERHEAD) == 0);
    assert(read_mss(pkt) == 9000);
}

int main(void)
{
    test_udp_two_fragment_layout();
    test_udp_fragment_boundary();
    test_tcp_mss_is_only_lowered_when_needed();
    puts("MTU policy tests: OK");
    return 0;
}

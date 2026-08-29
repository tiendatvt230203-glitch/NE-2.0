#include "core/iface/interface.h"

#include <assert.h>
#include <stdio.h>

static void test_segment_count(void)
{
    assert(ne_packet_segment_count_for_len(0) == 0);
    assert(ne_packet_segment_count_for_len(1500) == 1);
    assert(ne_packet_segment_count_for_len(4096) == 1);
    assert(ne_packet_segment_count_for_len(4097) == 2);
    assert(ne_packet_segment_count_for_len(9018) == 3);
    assert(ne_packet_segment_count_for_len(9064) == 3);
    assert(ne_packet_segment_count_for_len(NE_PACKET_CAPACITY) == 3);
    assert(ne_packet_segment_count_for_len(NE_PACKET_CAPACITY + 1u) == 0);
}

static void test_linearize_9k_frame(void)
{
    uint8_t source[9018];
    uint8_t linear[NE_PACKET_CAPACITY] = {0};
    uint32_t used = 0;
    uint32_t off = 0;

    for (uint32_t i = 0; i < sizeof(source); i++)
        source[i] = (uint8_t)(i * 31u + 7u);

    while (off < sizeof(source)) {
        uint32_t part = (uint32_t)sizeof(source) - off;

        if (part > NE_FRAME)
            part = NE_FRAME;
        assert(ne_jumbo_append_bytes(linear, sizeof(linear), &used,
                                     source + off, part) == 0);
        off += part;
    }
    assert(used == sizeof(source));
    assert(memcmp(source, linear, sizeof(source)) == 0);
    assert(ne_jumbo_append_bytes(linear, used, &used, source, 1) == -1);
}

int main(void)
{
    test_segment_count();
    test_linearize_9k_frame();
    puts("jumbo layout tests: OK");
    return 0;
}

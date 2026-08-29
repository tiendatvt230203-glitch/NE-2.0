#include "core/dataplane/udp_reorder.h"

#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct test_ctx {
    uint32_t emitted[32];
    uint32_t emitted_count;
    uint32_t dropped;
};

static int test_emit(void *opaque, struct dp_udp_reorder_item *item)
{
    struct test_ctx *ctx = opaque;

    assert(ctx->emitted_count < 32u);
    ctx->emitted[ctx->emitted_count++] = item->packet.len;
    return 0;
}

static void test_drop(void *opaque, struct dp_udp_reorder_item *item)
{
    struct test_ctx *ctx = opaque;

    (void)item;
    ctx->dropped++;
}

static void submit(int worker, const struct dp_udp_reorder_key *key,
                   uint32_t epoch, uint32_t seq, uint64_t now_ns,
                   const struct dp_udp_reorder_ops *ops)
{
    struct dp_udp_reorder_item item;

    memset(&item, 0, sizeof(item));
    item.packet.len = seq;
    dp_udp_reorder_submit(worker, key, epoch, seq, &item, now_ns, ops);
}

int main(void)
{
    struct test_ctx ctx = {0};
    struct dp_udp_reorder_ops ops = {
        .ctx = &ctx,
        .emit = test_emit,
        .drop = test_drop,
    };
    struct dp_udp_reorder_key tcp = {
        .src_ip = 1u,
        .dst_ip = 2u,
        .src_port = 1000u,
        .dst_port = 2000u,
        .protocol = IPPROTO_TCP,
    };
    struct dp_udp_reorder_key udp = tcp;
    const uint64_t start = 1000000000ULL;

    udp.protocol = IPPROTO_UDP;

    submit(0, &tcp, 7u, 0u, start, &ops);
    submit(0, &tcp, 7u, 2u, start + 1000u, &ops);
    submit(0, &tcp, 7u, 1u, start + 2000u, &ops);
    assert(ctx.emitted_count == 3u);
    assert(ctx.emitted[0] == 0u);
    assert(ctx.emitted[1] == 1u);
    assert(ctx.emitted[2] == 2u);

    /* TCP and UDP using the same 4-tuple must have independent sequence state. */
    submit(0, &udp, 7u, 0u, start + 3000u, &ops);
    assert(ctx.emitted_count == 4u);
    assert(ctx.emitted[3] == 0u);

    /* Timeout releases an ahead packet; a later old packet is forwarded,
     * never converted into an artificial dataplane drop. */
    submit(0, &tcp, 7u, 4u, start + 4000u, &ops);
    for (int i = 0; i < 16; i++)
        dp_udp_reorder_gc(0, start + 6000000ULL, &ops);
    assert(ctx.emitted_count == 5u);
    assert(ctx.emitted[4] == 4u);
    submit(0, &tcp, 7u, 3u, start + 7000000ULL, &ops);
    assert(ctx.emitted_count == 6u);
    assert(ctx.emitted[5] == 3u);
    assert(ctx.dropped == 0u);

    dp_udp_reorder_reset_worker(0, &ops);
    puts("bond reorder tests: OK");
    return 0;
}

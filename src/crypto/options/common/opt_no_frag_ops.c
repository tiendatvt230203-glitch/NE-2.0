#include "opt_no_frag_ops.h"

int opt_no_frag_need_split(uint32_t pkt_len)
{
    (void)pkt_len;
    return 0;
}

int opt_no_frag_split(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len,
                      size_t frag0_max, uint32_t *frag0_len,
                      uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    (void)ctx;
    (void)pkt_data;
    (void)pkt_len;
    (void)frag0_max;
    (void)frag0_len;
    (void)frag1;
    (void)frag1_max;
    (void)frag1_len;
    return -1;
}

int opt_no_frag_is_fragment(const struct app_config *cfg, const uint8_t *pkt_data,
                            uint32_t pkt_len, uint16_t *pkt_id, uint8_t *frag_index)
{
    (void)cfg;
    (void)pkt_data;
    (void)pkt_len;
    (void)pkt_id;
    (void)frag_index;
    return 0;
}

int opt_no_frag_reasm(int profile_slot, int worker_idx, struct packet_crypto_ctx *ctx,
                      uint8_t *pkt_data, uint32_t *pkt_len,
                      uint8_t *out_buf, uint32_t *out_len)
{
    (void)profile_slot;
    (void)worker_idx;
    (void)ctx;
    (void)pkt_data;
    (void)pkt_len;
    (void)out_buf;
    (void)out_len;
    return -1;
}

void opt_no_frag_frag_gc(int profile_slot, int worker_idx, uint64_t now_ns)
{
    (void)profile_slot;
    (void)worker_idx;
    (void)now_ns;
}

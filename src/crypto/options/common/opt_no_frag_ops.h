#ifndef OPT_NO_FRAG_OPS_H
#define OPT_NO_FRAG_OPS_H

#include "crypto_option.h"

int opt_no_frag_need_split(uint32_t pkt_len);
int opt_no_frag_split(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len,
                      size_t frag0_max, uint32_t *frag0_len,
                      uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len);
int opt_no_frag_is_fragment(const struct app_config *cfg, const uint8_t *pkt_data,
                            uint32_t pkt_len, uint16_t *pkt_id, uint8_t *frag_index);
int opt_no_frag_reasm(int profile_slot, int worker_idx, struct packet_crypto_ctx *ctx,
                      uint8_t *pkt_data, uint32_t *pkt_len,
                      uint8_t *out_buf, uint32_t *out_len);
void opt_no_frag_frag_gc(int profile_slot, int worker_idx, uint64_t now_ns);

#define CRYPTO_OPS_PLAIN(export_fn, enc_fn, dec_fn) \
const struct crypto_option_ops *export_fn(void) \
{ \
    static const struct crypto_option_ops ops = { \
        .need_split = opt_no_frag_need_split, \
        .split = opt_no_frag_split, \
        .encrypt = enc_fn, \
        .decrypt = dec_fn, \
        .is_fragment = opt_no_frag_is_fragment, \
        .reasm = opt_no_frag_reasm, \
        .frag_gc = opt_no_frag_frag_gc, \
    }; \
    return &ops; \
}

#endif

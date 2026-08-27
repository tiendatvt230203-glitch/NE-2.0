#include "../../../inc/crypto/crypto_option.h"

int crypto_opt_bypass_need_split(uint32_t pkt_len)
{ (void)pkt_len; return 0; }
int crypto_opt_bypass_split(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len, size_t frag0_max, uint32_t *frag0_len, uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{ (void)ctx; (void)pkt_data; (void)pkt_len; (void)frag0_max; (void)frag0_len; (void)frag1; (void)frag1_max; (void)frag1_len; return -1; }
int crypto_opt_bypass_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{ (void)ctx; (void)pkt; (void)pkt_len; return 0; }
int crypto_opt_bypass_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{ (void)ctx; (void)pkt; (void)pkt_len; return 0; }
int crypto_opt_bypass_is_fragment(const struct app_config *cfg, const uint8_t *pkt_data, uint32_t pkt_len, uint16_t *pkt_id, uint8_t *frag_index)
{ (void)cfg; (void)pkt_data; (void)pkt_len; (void)pkt_id; (void)frag_index; return 0; }
int crypto_opt_bypass_reasm(int profile_slot, int worker_idx, struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t *pkt_len, uint8_t *out_buf, uint32_t *out_len)
{ (void)profile_slot; (void)worker_idx; (void)ctx; (void)pkt_data; (void)pkt_len; (void)out_buf; (void)out_len; return -1; }
void crypto_opt_bypass_frag_gc(int profile_slot, int worker_idx, uint64_t now_ns)
{ (void)profile_slot; (void)worker_idx; (void)now_ns; }

static const struct crypto_option_ops bypass_ops = {
    .need_split = crypto_opt_bypass_need_split,
    .split = crypto_opt_bypass_split,
    .encrypt = crypto_opt_bypass_encrypt,
    .decrypt = crypto_opt_bypass_decrypt,
    .is_fragment = crypto_opt_bypass_is_fragment,
    .reasm = crypto_opt_bypass_reasm,
    .frag_gc = crypto_opt_bypass_frag_gc,
};

const struct crypto_option_ops *crypto_opt_bypass_tcp_ops(void) { return &bypass_ops; }
const struct crypto_option_ops *crypto_opt_bypass_udp_ops(void) { return &bypass_ops; }
const struct crypto_option_ops *crypto_opt_bypass_icmp_ops(void) { return &bypass_ops; }
const struct crypto_option_ops *crypto_opt_bypass_ospf_ops(void) { return &bypass_ops; }
const struct crypto_option_ops *crypto_opt_bypass_other_ops(void) { return &bypass_ops; }

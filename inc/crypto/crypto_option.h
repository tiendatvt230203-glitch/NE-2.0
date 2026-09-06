#ifndef CRYPTO_OPTION_H
#define CRYPTO_OPTION_H

#include <stdint.h>
#include <stddef.h>

#include "../core/util/config.h"
#include "packet_crypto.h"

#define CRYPTO_OPT_FRAG_MTU_DEFAULT  1500u
#define OPT_FRAG_TABLE_SIZE          4096
#define OPT_FRAG_TIMEOUT_NS          (200ULL * 1000000ULL)

/* --- worker bind (forwarder sets once per crypto thread) --- */

void crypto_option_bind_worker_idx(uint8_t worker_idx);
uint8_t crypto_option_worker_idx(void);

struct ne_pair;
void crypto_l2_pqc_bind_pair(struct ne_pair *p);
void crypto_l2_pqc_reasm_set_addr(uint64_t addr);
int crypto_l2_pqc_reasm_held(void);
uint64_t crypto_l2_pqc_reasm_out_addr(void);

/* --- option router --- */

void crypto_option_udp_set_tx_seq(uint32_t seq);
int crypto_option_udp_tx_meta(uint32_t *epoch, uint32_t *seq,
                              uint32_t *datagram_id);
void crypto_option_udp_clear_rx_meta(void);
void crypto_option_udp_set_rx_meta(uint32_t epoch, uint32_t seq);
int crypto_option_udp_take_rx_meta(uint32_t *epoch, uint32_t *seq);
void crypto_option_set_mtu(uint32_t mtu);
uint32_t crypto_option_get_mtu(void);

typedef enum {
    CRYPTO_OPT_L2_PQC = 0,
    CRYPTO_OPT_COUNT
} crypto_option_id;

typedef enum {
    CRYPTO_PROTO_TCP = 0,
    CRYPTO_PROTO_UDP,
    CRYPTO_PROTO_ICMP,
    CRYPTO_PROTO_OSPF,
    CRYPTO_PROTO_OTHER,
    CRYPTO_PROTO_ARP,
    CRYPTO_PROTO_COUNT
} crypto_proto_class;

crypto_proto_class crypto_proto_classify(uint8_t ip_proto);

struct crypto_option_ops {
    int (*need_split)(uint32_t pkt_len);
    int (*split)(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len,
                 size_t frag0_max, uint32_t *frag0_len,
                 uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len);
    int (*encrypt)(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len);
    int (*decrypt)(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len);
    int (*is_fragment)(const struct app_config *cfg, const uint8_t *pkt_data,
                       uint32_t pkt_len, uint16_t *pkt_id, uint8_t *frag_index);
    int (*reasm)(int profile_slot, int worker_idx, struct packet_crypto_ctx *ctx,
                 uint8_t *pkt_data, uint32_t *pkt_len, uint8_t *out_buf, uint32_t *out_len);
    void (*frag_gc)(int profile_slot, int worker_idx, uint64_t now_ns);
};

const struct crypto_option_ops *crypto_option_ops(crypto_option_id id, crypto_proto_class proto);

uint32_t crypto_option_wire_overhead(crypto_option_id id);

int crypto_option_need_split(crypto_option_id id, crypto_proto_class proto, uint32_t pkt_len);
int crypto_option_split(crypto_option_id id, crypto_proto_class proto,
                        struct packet_crypto_ctx *ctx,
                        uint8_t *pkt_data, uint32_t pkt_len,
                        size_t frag0_max, uint32_t *frag0_len,
                        uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len);
int crypto_option_encrypt(crypto_option_id id, crypto_proto_class proto,
                          struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len);
int crypto_option_decrypt(crypto_option_id id, crypto_proto_class proto,
                          struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len);
int crypto_option_is_fragment(crypto_option_id id, crypto_proto_class proto,
                              const struct app_config *cfg,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint16_t *pkt_id, uint8_t *frag_index);
int crypto_option_reassemble(crypto_option_id id, crypto_proto_class proto,
                             int profile_slot, int worker_idx,
                             struct packet_crypto_ctx *ctx,
                             uint8_t *pkt_data, uint32_t *pkt_len,
                             uint8_t *out_buf, uint32_t *out_len);
void crypto_option_frag_gc(crypto_option_id id, crypto_proto_class proto,
                           int profile_slot, int worker_idx, uint64_t now_ns);
void crypto_option_frag_gc_all(int profile_slot, int worker_idx, uint64_t now_ns);

#endif

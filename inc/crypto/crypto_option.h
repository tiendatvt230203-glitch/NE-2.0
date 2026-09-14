#ifndef CRYPTO_OPTION_H
#define CRYPTO_OPTION_H

#include <stdint.h>
#include <stddef.h>

#include "../core/util/config.h"
#include "packet_crypto.h"

/* --- worker bind (forwarder sets once per crypto thread) --- */

void crypto_option_bind_worker_idx(uint8_t worker_idx);
uint8_t crypto_option_worker_idx(void);

/* --- option router --- */

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
    int (*encrypt)(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len);
    int (*decrypt)(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len);
};

const struct crypto_option_ops *crypto_option_ops(crypto_option_id id, crypto_proto_class proto);

uint32_t crypto_option_wire_overhead(crypto_option_id id);


int crypto_l2_pqc_encrypt_ipv4_l3(struct packet_crypto_ctx *ctx,
                                  uint8_t *pkt, uint32_t *pkt_len,
                                  int l3_off);

int crypto_option_encrypt(crypto_option_id id, crypto_proto_class proto,
                          struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len);
int crypto_option_decrypt(crypto_option_id id, crypto_proto_class proto,
                          struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len);
#endif

#include "../../../inc/crypto/crypto_option.h"

static const struct crypto_option_ops *g_l2_pqc_ops[CRYPTO_PROTO_COUNT];

extern const struct crypto_option_ops *crypto_opt_l2_pqc_tcp_ops(void);
extern const struct crypto_option_ops *crypto_opt_l2_pqc_udp_ops(void);
extern const struct crypto_option_ops *crypto_opt_l2_pqc_icmp_ops(void);
extern const struct crypto_option_ops *crypto_opt_l2_pqc_ospf_ops(void);
extern const struct crypto_option_ops *crypto_opt_l2_pqc_arp_ops(void);

static void crypto_option_registry_init(void)
{
    static int done;
    if (done)
        return;
    done = 1;
    g_l2_pqc_ops[CRYPTO_PROTO_TCP] = crypto_opt_l2_pqc_tcp_ops();
    g_l2_pqc_ops[CRYPTO_PROTO_UDP] = crypto_opt_l2_pqc_udp_ops();
    g_l2_pqc_ops[CRYPTO_PROTO_ICMP] = crypto_opt_l2_pqc_icmp_ops();
    g_l2_pqc_ops[CRYPTO_PROTO_OSPF] = crypto_opt_l2_pqc_ospf_ops();
    g_l2_pqc_ops[CRYPTO_PROTO_OTHER] = crypto_opt_l2_pqc_icmp_ops();
    g_l2_pqc_ops[CRYPTO_PROTO_ARP] = crypto_opt_l2_pqc_arp_ops();
}

const struct crypto_option_ops *crypto_option_ops(crypto_option_id id, crypto_proto_class proto)
{
    crypto_option_registry_init();
    if (id != CRYPTO_OPT_L2_PQC)
        return NULL;
    if (proto < 0 || proto >= CRYPTO_PROTO_COUNT)
        proto = CRYPTO_PROTO_OTHER;
    return g_l2_pqc_ops[proto];
}

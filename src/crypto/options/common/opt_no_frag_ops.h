#ifndef OPT_NO_FRAG_OPS_H
#define OPT_NO_FRAG_OPS_H

#include "crypto_option.h"

#define CRYPTO_OPS_PLAIN(export_fn, enc_fn, dec_fn) \
const struct crypto_option_ops *export_fn(void) \
{ \
    static const struct crypto_option_ops ops = { \
        .encrypt = enc_fn, \
        .decrypt = dec_fn, \
    }; \
    return &ops; \
}

#endif

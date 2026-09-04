#ifndef STATIC_CONFIG_H
#define STATIC_CONFIG_H

#include "core/util/config.h"

/* Build the fixed MTU-9000 topology for payloads up to 1500 bytes. */
int static_config_build(struct app_config *cfg);
/* Resolve a decrypted destination MAC through the fixed client table. */
int static_config_local_for_dmac(const struct app_config *cfg,
                             const uint8_t dmac[MAC_LEN]);

#endif

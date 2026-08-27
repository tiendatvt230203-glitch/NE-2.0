#ifndef FORWARDER_RELOAD_H
#define FORWARDER_RELOAD_H

#include "core/util/config.h"
#include "core/forwarder/forwarder.h"

int forwarder_same_topology(const struct app_config *a, const struct app_config *b);

int forwarder_reload_config(struct forwarder *fwd, struct app_config *cfg);

/* Called from middle core while holding forwarder runtime lock. */
int fwd_reload_apply_if_pending(void);

void fwd_reload_shutdown(void);

#endif

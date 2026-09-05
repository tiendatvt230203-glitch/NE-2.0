#ifndef STATIC_CONFIG_H
#define STATIC_CONFIG_H

#include "core/util/config.h"

/* Build the fixed MTU-9000 topology for the 1500/9000 core dataplane. */
int static_config_build(struct app_config *cfg);

#endif

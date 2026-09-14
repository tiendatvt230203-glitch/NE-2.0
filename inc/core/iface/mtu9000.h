#ifndef MTU9000_H
#define MTU9000_H

#include "core/util/config.h"

#include <stddef.h>

int ne_mtu9000_validate(const struct app_config *cfg,
                        char *error, size_t error_size);

#endif

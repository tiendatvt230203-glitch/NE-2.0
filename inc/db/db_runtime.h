#ifndef DB_RUNTIME_H
#define DB_RUNTIME_H

#include "core/util/config.h"

int ne_profile_id_exists(int profile_id);
int load_profile_config(struct app_config *out_cfg, int profile_id);

#endif

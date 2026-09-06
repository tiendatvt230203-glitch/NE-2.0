#ifndef DB_CONFIG_H
#define DB_CONFIG_H

#include "core/util/config.h"

int config_load_from_db(struct app_config *cfg, int ne_profile_id, const char *conn_str);

int config_apply_crypto_from_policies(struct app_config *cfg);

#endif

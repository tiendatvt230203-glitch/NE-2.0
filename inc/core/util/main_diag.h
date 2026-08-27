#ifndef MAIN_DIAG_H
#define MAIN_DIAG_H

#include <stdint.h>

struct app_config;
struct forwarder;

void main_diag_log_db_apply(const struct app_config *cfg, int trigger_profile_id,
                            const struct app_config *prev_cfg);
/* DB notify when only policies/profiles changed. */
void main_diag_log_db_policy_apply(const struct app_config *cfg, int trigger_profile_id,
                                   const struct app_config *prev_cfg);
void main_diag_log_no_update(int trigger_profile_id, const struct app_config *cfg);
void main_diag_log_config_summary(struct app_config *cfg, int trigger_profile_id,
                                  int is_reload, int policy_only);
void main_diag_log_dataplane_ready(struct forwarder *fwd);

/* [NE-KEY] PQC: traffic key actually passed to GCM (from crypto_pqc_sess_load). */

void main_diag_log_ne_pqc_match(int profile_id, int policy_id, const uint8_t ne_key[32]);
void main_diag_ne_pqc_clear(int profile_id, int policy_id);
void main_diag_ne_pqc_clear_all(void);
#endif
#ifndef FORWARDER_CRYPTO_RUNTIME_H
#define FORWARDER_CRYPTO_RUNTIME_H

#include "core/util/config.h"
#include "core/forwarder/forwarder.h"
#include "crypto/crypto_option.h"
#include "crypto/packet_crypto.h"

#define FWD_CRYPTO_PROFILE_RELOAD_GRACE_MS 3000u

void fwd_crypto_reset_on_init(void);
int fwd_crypto_rebuild(struct app_config *cfg);
void fwd_crypto_snapshot_active_to_prev(void);
void fwd_crypto_maybe_expire_prev_grace(void);
void fwd_crypto_clear_grace(void);
void fwd_crypto_frag_gc_worker_tick(int worker_idx);

int fwd_crypto_profile_slot_for_id(int profile_id);
struct packet_crypto_ctx *fwd_crypto_ctx_for_wire_id(uint8_t wire_id);
int fwd_crypto_profile_id_for_wire_id(uint8_t wire_id);
int fwd_crypto_policy_ready(int policy_index);
struct packet_crypto_ctx *fwd_crypto_policy_ctx(int policy_index);
int fwd_crypto_has_l2_marker(const uint8_t *pkt, uint32_t pkt_len);

void forwarder_pre_diversify_pqc_keys(int profile_id);
void fwd_crypto_sync_pqc_session_keys(const struct app_config *cfg);
void fwd_crypto_discard_pqc_prev_key(int policy_id);
void fwd_crypto_pqc_key_lifetime_tick(void);
int fwd_crypto_format_pqc_key_times(char *out, size_t out_max, int policy_id);

#endif

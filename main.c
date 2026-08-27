#include <bpf/libbpf.h>
#include <libpq-fe.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "vault.h"
#include "core/util/config.h"
#include "db_env.h"
#include "db_runtime.h"
#include "core/forwarder/forwarder.h"
#include "core/forwarder/forwarder_reload.h"
#include "core/iface/interface.h"
#include "core/util/main_diag.h"
#include "core/iface/profile_iface_xdp.h"
#include "core/failover/wan_admin.h"
#include "core/failover/cfm_diag.h"
#include "pqc_handshake.h"
#include "pqc_ipc.h"
#include "traffic_crypto.h"
#include "pqc_vault.h"

#define NOTIFY_CHANNEL "xdp_start"
#define WAN_ADMIN_CHANNEL "xdp_wan_admin"

static volatile sig_atomic_t g_stop_requested = 0;
static volatile sig_atomic_t g_stop_logged = 0;
static volatile sig_atomic_t g_stop_signal_count = 0;

static void on_stop_signal(int sig) {
    (void)sig;
    g_stop_signal_count++;
    g_stop_requested = 1;
    forwarder_stop();
    if (!g_stop_logged) {
        g_stop_logged = 1;
        fprintf(stderr, "\n[STOP] shutting down (Ctrl+C / SIGTERM)\n");
    }
    if (g_stop_signal_count >= 2) {
        fprintf(stderr, "[STOP] shutdown in progress (do not spam Ctrl+C)\n");
    }
}

static int parse_notify_profile_id(const char *payload) {
    if (!payload || !*payload)
        return -1;
    char *end = NULL;
    long v = strtol(payload, &end, 10);
    if (!end || *end != '\0' || v <= 0 || v > INT_MAX)
        return -1;
    return (int)v;
}

static int parse_notify_profile_cmd(const char *payload, int *out_id)
{
    const char *p = payload;

    if (!out_id)
        return -1;
    *out_id = -1;
    if (!p || !*p)
        return -1;
    if (!strncmp(p, "del:", 4))
        p += 4;
    else if (!strncmp(p, "load:", 5))
        p += 5;
    *out_id = parse_notify_profile_id(p);
    return (*out_id > 0) ? 0 : -1;
}

struct runtime_state {
    pthread_t thread;
    int has_thread;
    int running;
    struct forwarder fwd;
    struct app_config cfg_slots[2];
    int active_slot;
};

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s               # daemon (passive LISTEN %s; no auto DB load)\n"
            "  %s -gi            # generate new identity key and load into RAM\n"
            "  %s -check-identity # check PQC DB identity integrity and link to RAM cache\n"
            "  %s -id <ID>       # load/apply profile (create or edit)\n"
            "  %s -di <wan_if>   # notify daemon: hard-detach WAN from bonding/profile\n"
            "  %s -ai <wan_if>   # notify daemon: hot-add WAN back into bonding/profile\n"
            "  %s -gs <name>     # print UP or DOWN for wan_if / bridge\n"
            "  %s -check [ID]    # check database config consistency\n"
            "  %s -r <policy_id> # trigger manual handshake retry for policy\n",
            prog, NOTIFY_CHANNEL, prog, prog, prog, prog, prog, prog, prog, prog);
}

static int parse_profile_id_token(const char *token, int *out_id) {
    if (!token || !*token)
        return -1;
    char *end = NULL;
    long v = strtol(token, &end, 10);
    if (!end || *end != '\0' || v <= 0 || v > INT_MAX)
        return -1;
    *out_id = (int)v;
    return 0;
}

static int parse_startup_profile_id(int argc, char **argv, int *out_id) {
    *out_id = -1;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "-id") == 0) {
            if (*out_id >= 0) {
                fprintf(stderr, "[FATAL] -id specified more than once\n");
                return -1;
            }
            if (i + 1 >= argc) {
                fprintf(stderr, "[FATAL] -id requires ne_profiles.id\n");
                return -1;
            }
            if (parse_profile_id_token(argv[++i], out_id) != 0) {
                fprintf(stderr, "[FATAL] invalid ne_profiles.id: %s\n", argv[i]);
                return -1;
            }
            continue;
        }

        if (strncmp(arg, "-id=", 4) == 0) {
            if (*out_id >= 0) {
                fprintf(stderr, "[FATAL] -id specified more than once\n");
                return -1;
            }
            const char *id_str = arg + 4;
            if (parse_profile_id_token(id_str, out_id) != 0) {
                fprintf(stderr, "[FATAL] invalid ne_profiles.id: %s\n", id_str);
                return -1;
            }
            continue;
        }

        fprintf(stderr, "[FATAL] unknown option: %s\n", arg);
        return -1;
    }
    return 0;
}


static int libbpf_print_silent(enum libbpf_print_level level,
                               const char *format,
                               va_list args) {
    (void)level;
    (void)format;
    (void)args;
    return 0;
}

static int notify_profile_load(int profile_id)
{
    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0)
        return -1;

    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[ERR] DB: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT pg_notify('%s', 'load:%d')", NOTIFY_CHANNEL, profile_id);
    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[ERR] pg_notify failed: %s", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return -1;
    }
    PQclear(res);
    PQfinish(conn);
    return 0;
}

static int notify_wan_admin(const char *op, const char *ifname)
{
    struct ne_postgres_conn pg;
    char payload[IF_NAMESIZE + 8];
    char sql[160];
    PGconn *conn;
    PGresult *res;

    if (!op || !ifname || !ifname[0] || strlen(ifname) >= IF_NAMESIZE) {
        fprintf(stderr, "[ERR] invalid WAN ifname\n");
        return -1;
    }
    if (ne_postgres_conn_fill(&pg) != 0)
        return -1;

    conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[ERR] DB: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    snprintf(payload, sizeof(payload), "%s:%s", op, ifname);
    snprintf(sql, sizeof(sql), "SELECT pg_notify('%s', '%s')", WAN_ADMIN_CHANNEL, payload);
    res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[ERR] pg_notify %s failed: %s", WAN_ADMIN_CHANNEL, PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return -1;
    }
    PQclear(res);
    PQfinish(conn);
    fprintf(stderr,
            "[NOTIFY] sent %s to channel %s (daemon applies on mid-core)\n",
            payload, WAN_ADMIN_CHANNEL);
    return 0;
}

static int handle_wan_admin_notify(struct runtime_state *rt, const char *payload)
{
    const char *ifname;
    int rc;

    if (!rt || !payload || !payload[0])
        return -1;
    if (!rt->has_thread || !rt->running) {
        fprintf(stderr, "[WAN-ADMIN] ignore %s — dataplane not running (load a profile first)\n",
                payload);
        fflush(stderr);
        return -1;
    }

    if (strncmp(payload, "di:", 3) == 0) {
        ifname = payload + 3;
        fprintf(stderr, "\n[WAN-ADMIN] notify KICK %s\n", ifname);
        fflush(stderr);
        rc = wan_admin_kick(&rt->fwd, ifname);
        if (rc != 0)
            fprintf(stderr, "[WAN-ADMIN] KICK failed for %s\n", ifname);
        return rc;
    }
    if (strncmp(payload, "ai:", 3) == 0) {
        ifname = payload + 3;
        fprintf(stderr, "\n[WAN-ADMIN] notify RESTORE %s\n", ifname);
        fflush(stderr);
        rc = wan_admin_restore(&rt->fwd, ifname);
        if (rc != 0)
            fprintf(stderr, "[WAN-ADMIN] RESTORE failed for %s\n", ifname);
        return rc;
    }

    fprintf(stderr, "[WARN] ignoring WAN_ADMIN payload: \"%s\"\n", payload);
    return -1;
}

static void *forwarder_thread_main(void *arg) {
    forwarder_pin_cpu();
    struct runtime_state *rt = (struct runtime_state *)arg;
    if (forwarder_init(&rt->fwd, &rt->cfg_slots[rt->active_slot]) != 0) {
        forwarder_cleanup(&rt->fwd);
        if (forwarder_should_stop()) {
            fprintf(stderr, "[STOP] forwarder init aborted\n");
        } 
        else {
            fprintf(stderr, "[FATAL] forwarder_init failed\n");
        }
        rt->running = 0;
        return NULL;
    }
    if (forwarder_should_stop()) {
        fprintf(stderr, "[STOP] forwarder init aborted\n");
        forwarder_cleanup(&rt->fwd);
        rt->running = 0;
        return NULL;
    }
    if (forwarder_should_stop()) {
        forwarder_cleanup(&rt->fwd);
        rt->running = 0;
        return NULL;
    }
    rt->running = 1;
    forwarder_run(&rt->fwd);
    rt->running = 0;
    return NULL;
}

static int runtime_start(struct runtime_state *rt, const struct app_config *cfg) {
    rt->active_slot = 0;
    rt->cfg_slots[rt->active_slot] = *cfg;
    rt->running = 0;

    forwarder_clear_stop();
    if (pthread_create(&rt->thread, NULL, forwarder_thread_main, rt) != 0) {
        fprintf(stderr, "[FATAL] failed to create forwarder thread\n");
        return -1;
    }
    rt->has_thread = 1;
    return 0;
}

static int runtime_stop_forwarder(struct runtime_state *rt);

static int policy_fields_equal(const struct crypto_policy *a,
                               const struct crypto_policy *b)
{
    return a->id == b->id &&
           a->db_id == b->db_id &&
           a->priority == b->priority &&
           a->action == b->action &&
           a->protocol == b->protocol &&
           a->src_port_from == b->src_port_from &&
           a->src_port_to == b->src_port_to &&
           a->dst_port_from == b->dst_port_from &&
           a->dst_port_to == b->dst_port_to &&
           a->src_any == b->src_any &&
           a->dst_any == b->dst_any &&
           a->src_negate == b->src_negate &&
           a->dst_negate == b->dst_negate &&
           a->src_net == b->src_net &&
           a->src_mask == b->src_mask &&
           a->dst_net == b->dst_net &&
           a->dst_mask == b->dst_mask &&
           a->crypto_mode == b->crypto_mode &&
           a->aes_bits == b->aes_bits &&
           memcmp(a->key, b->key, AES_KEY_LEN) == 0;
}

static const struct crypto_policy *policy_by_db_id(const struct app_config *cfg,
                                                   int db_id)
{
    for (int i = 0; i < cfg->policy_count; i++) {
        if (cfg->policies[i].db_id == db_id)
            return &cfg->policies[i];
    }
    return NULL;
}

static void log_policy_db_ids(const char *tag, const struct app_config *cfg)
{
    if (!cfg)
        return;
    fprintf(stderr, "%s policy db_ids(%d):", tag, cfg->policy_count);
    for (int i = 0; i < cfg->policy_count; i++)
        fprintf(stderr, " %d", cfg->policies[i].db_id);
    fprintf(stderr, "\n");
}

static int policies_db_unchanged(const struct app_config *old,
                                 const struct app_config *new)
{
    if (old->policy_count != new->policy_count)
        return 0;
    for (int i = 0; i < old->policy_count; i++) {
        int db_id = old->policies[i].db_id;
        const struct crypto_policy *np = policy_by_db_id(new, db_id);
        if (!np || !policy_fields_equal(&old->policies[i], np))
            return 0;
    }
    for (int i = 0; i < new->policy_count; i++) {
        int db_id = new->policies[i].db_id;
        const struct crypto_policy *op = policy_by_db_id(old, db_id);
        if (!op || !policy_fields_equal(op, &new->policies[i]))
            return 0;
    }
    return 1;
}

static const struct local_config *local_by_ifname(const struct app_config *cfg,
                                                  const char *ifname)
{
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return &cfg->locals[i];
    }
    return NULL;
}

static int local_db_equal(const struct local_config *a, const struct local_config *b)
{
    return strcmp(a->ifname, b->ifname) == 0;
}

static const struct wan_config *wan_by_ifname(const struct app_config *cfg,
                                              const char *ifname)
{
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return &cfg->wans[i];
    }
    return NULL;
}

static int wan_db_equal(const struct wan_config *a, const struct wan_config *b)
{
    return strcmp(a->ifname, b->ifname) == 0 &&
           a->dst_ip == b->dst_ip &&
           a->window_size == b->window_size &&
           a->dataplane == b->dataplane;
}

static int profile_db_unchanged(const struct profile_config *old,
                                const struct profile_config *new,
                                const struct app_config *ocfg,
                                const struct app_config *ncfg)
{
    if (old->id != new->id ||
        old->enabled != new->enabled ||
        old->bridge_enable != new->bridge_enable ||
        old->bridge_count != new->bridge_count ||
        old->policy_count != new->policy_count ||
        old->local_count != new->local_count ||
        old->wan_count != new->wan_count ||
        strcmp(old->name, new->name) != 0 ||
        strcmp(old->local_identity_fingerprint, new->local_identity_fingerprint) != 0 ||
        strcmp(old->peer_fingerprint, new->peer_fingerprint) != 0 ||
        old->pqc_is_initiator != new->pqc_is_initiator ||
        old->has_pqc_identity != new->has_pqc_identity ||
        strcmp(old->pqc_peer_pub, new->pqc_peer_pub) != 0)
        return 0;

    for (int i = 0; i < old->policy_count; i++) {
        int odb = ocfg->policies[old->policy_indices[i]].db_id;
        int found = 0;
        for (int j = 0; j < new->policy_count; j++) {
            int ndb = ncfg->policies[new->policy_indices[j]].db_id;
            if (odb == ndb) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }
    for (int j = 0; j < new->policy_count; j++) {
        int ndb = ncfg->policies[new->policy_indices[j]].db_id;
        int found = 0;
        for (int i = 0; i < old->policy_count; i++) {
            int odb = ocfg->policies[old->policy_indices[i]].db_id;
            if (odb == ndb) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }

    for (int i = 0; i < old->local_count; i++) {
        if (old->local_indices[i] != new->local_indices[i])
            return 0;
    }
    for (int i = 0; i < old->wan_count; i++) {
        if (old->wan_indices[i] != new->wan_indices[i] ||
            old->wan_bandwidth_weight[i] != new->wan_bandwidth_weight[i])
            return 0;
    }
    for (int i = 0; i < old->bridge_count; i++) {
        if (old->bridges[i].local_idx != new->bridges[i].local_idx ||
            old->bridges[i].wan_dp != new->bridges[i].wan_dp ||
            strcmp(old->bridges[i].ifname, new->bridges[i].ifname) != 0)
            return 0;
    }
    return 1;
}

static int config_db_unchanged(const struct app_config *old,
                               const struct app_config *new)
{
    if (!old || !new)
        return 0;

    if (old->local_count != new->local_count ||
        old->wan_count != new->wan_count ||
        old->policy_count != new->policy_count ||
        old->profile_count != new->profile_count ||
        old->crypto_enabled != new->crypto_enabled ||
        old->fake_ethertype_ipv4 != new->fake_ethertype_ipv4 ||
        old->crypto_mode != new->crypto_mode ||
        old->aes_bits != new->aes_bits ||
        memcmp(old->crypto_key, new->crypto_key, AES_KEY_LEN) != 0 ||
        strcmp(old->bpf_file, new->bpf_file) != 0 ||
        strcmp(old->bpf_wan_file, new->bpf_wan_file) != 0)
        return 0;

    for (int i = 0; i < old->local_count; i++) {
        const struct local_config *nl =
            local_by_ifname(new, old->locals[i].ifname);
        if (!nl || !local_db_equal(&old->locals[i], nl))
            return 0;
    }

    for (int i = 0; i < old->wan_count; i++) {
        const struct wan_config *nw = wan_by_ifname(new, old->wans[i].ifname);
        if (!nw || !wan_db_equal(&old->wans[i], nw))
            return 0;
    }

    if (!policies_db_unchanged(old, new))
        return 0;

    if (old->profile_count < 1 || new->profile_count < 1)
        return 0;
    return profile_db_unchanged(&old->profiles[0], &new->profiles[0], old, new);
}

static int profiles_fully_unchanged(const struct app_config *old,
                                    const struct app_config *new)
{
    if (!old || !new || old->profile_count < 1 || new->profile_count < 1)
        return 0;
    return profile_db_unchanged(&old->profiles[0], &new->profiles[0], old, new);
}


static int lan_wan_db_unchanged(const struct app_config *old,
                                const struct app_config *new)
{
    if (!old || !new)
        return 0;
    if (old->local_count != new->local_count ||
        old->wan_count != new->wan_count)
        return 0;

    for (int i = 0; i < old->local_count; i++) {
        const struct local_config *nl =
            local_by_ifname(new, old->locals[i].ifname);
        if (!nl || !local_db_equal(&old->locals[i], nl))
            return 0;
    }
    for (int i = 0; i < old->wan_count; i++) {
        const struct wan_config *nw = wan_by_ifname(new, old->wans[i].ifname);
        if (!nw || !wan_db_equal(&old->wans[i], nw))
            return 0;
    }
    return 1;
}


static int runtime_tuning_only_change(const struct app_config *old,
                                      const struct app_config *new)
{
    if (!old || !new || lan_wan_db_unchanged(old, new))
        return 0;
    if (!forwarder_same_topology(old, new))
        return 0;
    if (!policies_db_unchanged(old, new))
        return 0;
    return profiles_fully_unchanged(old, new);
}

static int apply_active_configs(struct runtime_state *rt, int profile_id) {
    struct app_config *new_cfg = calloc(1, sizeof(*new_cfg));
    if (!new_cfg) {
        fprintf(stderr, "[FATAL] out of memory building config\n");
        return -1;
    }
    if (load_profile_config(new_cfg, profile_id) != 0) {
        fprintf(stderr,
                "[ERR] profile %d: failed to load config from Postgres (see [DB] lines above)\n",
                profile_id);
        free(new_cfg);
        return -1;
    }

    if (!rt->has_thread) {
        fprintf(stderr, "[LOAD] active: %d\n", profile_id);
        main_diag_log_db_apply(new_cfg, profile_id, NULL);
        int rc = runtime_start(rt, new_cfg);
        free(new_cfg);
        return rc != 0 ? -1 : 0;
    }

    int next_slot = 1 - rt->active_slot;
    const struct app_config *prev_cfg = &rt->cfg_slots[rt->active_slot];

    rt->cfg_slots[next_slot] = *new_cfg;
    free(new_cfg);

    if (config_db_unchanged(prev_cfg, &rt->cfg_slots[next_slot])) {
        fprintf(stderr,
                "[DB] profile %d — no change on first read (Postgres may not have committed yet), retry...\n",
                profile_id);
        fflush(stderr);
        usleep(500000);
        if (load_profile_config(&rt->cfg_slots[next_slot], profile_id) != 0) {
            fprintf(stderr,
                    "[ERR] profile %d: DB reload retry failed (see [DB] lines above)\n",
                    profile_id);
            return -1;
        }
    }

    if (config_db_unchanged(prev_cfg, &rt->cfg_slots[next_slot])) {
        log_policy_db_ids("[DB] Postgres", &rt->cfg_slots[next_slot]);
        log_policy_db_ids("[DB] running", prev_cfg);
        main_diag_log_no_update(profile_id, prev_cfg);
        return 0;
    }

    int policy_only = lan_wan_db_unchanged(prev_cfg, &rt->cfg_slots[next_slot]);
    int topo_ok = forwarder_same_topology(prev_cfg, &rt->cfg_slots[next_slot]);

    if (policy_only)
        main_diag_log_db_policy_apply(&rt->cfg_slots[next_slot], profile_id, prev_cfg);
    else
        main_diag_log_db_apply(&rt->cfg_slots[next_slot], profile_id, prev_cfg);

    if (!topo_ok) {
        fprintf(stderr,
                "[RELOAD] profile %d — LAN/WAN change — full dataplane restart "
                "(clean UMEM; service stays up)\n",
                profile_id);
        fflush(stderr);
        if (runtime_stop_forwarder(rt) != 0)
            return -1;
        if (g_stop_requested)
            return -1;
        rt->active_slot = next_slot;
        if (runtime_start(rt, &rt->cfg_slots[rt->active_slot]) != 0)
            return -1;
        fprintf(stderr,
                "[RELOAD] OK profile %d — applied (full dataplane restart)\n",
                profile_id);
        main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], profile_id, 1, 0);
        fflush(stderr);
        return 0;
    }

    if (!policy_only) {

        int tuning = runtime_tuning_only_change(prev_cfg, &rt->cfg_slots[next_slot]);
        fprintf(stderr,
                "[RELOAD] profile %d — same LAN/WAN ifnames (%s, hot reload)\n",
                profile_id, tuning ? "tuning" : "settings/profile fields");
        fflush(stderr);
        if (forwarder_reload_config(&rt->fwd, &rt->cfg_slots[next_slot]) == 0) {
            rt->active_slot = next_slot;
            fprintf(stderr,
                    "[RELOAD] OK profile %d — applied (same-topology hot reload)\n",
                    profile_id);
            main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot],
                                         profile_id, 1, 0);
            fflush(stderr);
            return 0;
        }
        fprintf(stderr,
                "[ERR] profile %d: same-topology hot reload failed — "
                "running dataplane unchanged (no full restart)\n",
                profile_id);
        fflush(stderr);
        return -1;
    }

    fprintf(stderr,
            "[RELOAD] profile %d — policies/crypto only (LAN/WAN ifaces unchanged)\n",
            profile_id);
    fflush(stderr);

    if (forwarder_reload_config(&rt->fwd, &rt->cfg_slots[next_slot]) == 0) {
        rt->active_slot = next_slot;
        fprintf(stderr, "[RELOAD] OK profile %d — applied (hot reload)\n", profile_id);
        fprintf(stderr, "[RELOAD] active: %d\n", profile_id);
        main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], profile_id, 1, 1);
        fflush(stderr);
        return 0;
    }
    fprintf(stderr,
            "[ERR] profile %d: policy hot reload failed — "
            "running dataplane unchanged (no full restart)\n",
            profile_id);
    fflush(stderr);
    return -1;
}

static void stop_log_step(const char *step)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        fprintf(stderr, "[STOP] %s\n", step);
        fflush(stderr);
        return;
    }
    fprintf(stderr, "[STOP] %ld.%03ld %s\n",
            (long)ts.tv_sec, ts.tv_nsec / 1000000L, step);
    fflush(stderr);
}

static int runtime_stop_forwarder(struct runtime_state *rt) {
    if (!rt->has_thread)
        return 0;

    fprintf(stderr, "[STOP] stopping dataplane...\n");
    fflush(stderr);
    stop_log_step("forwarder_stop");
    forwarder_stop();
    forwarder_shutdown_resources();
    stop_log_step("pthread_join forwarder");
    pthread_join(rt->thread, NULL);
    stop_log_step("forwarder_cleanup begin");
    forwarder_cleanup(&rt->fwd);
    stop_log_step("forwarder_cleanup done");

    stop_log_step("promisc off");
    interface_promisc_off_config(&rt->cfg_slots[rt->active_slot]);

    stop_log_step("done (dataplane stopped; xdp/id cleared until -id)");
    rt->has_thread = 0;
    rt->running = 0;
    return 0;
}


static int load_profile_and_run(struct runtime_state *rt,
                                int *active_profile_id,
                                int profile_id) {
    if (apply_active_configs(rt, profile_id) != 0)
        return -1;

    *active_profile_id = profile_id;
    return 0;
}

static const char *g_prog_name = "network-encryptor";

static void daemon_idle_log(void)
{
    fprintf(stderr,
            "[DAEMON] listening %s + %s — use %s -id <id> | -di <wan> | -ai <wan> | -gs <name>\n",
            NOTIFY_CHANNEL, WAN_ADMIN_CHANNEL, g_prog_name);
    fflush(stderr);
}

static void return_to_blank_daemon(struct runtime_state *rt,
                                   int *active_profile_id)
{
    if (active_profile_id)
        *active_profile_id = 0;

    if (rt && rt->has_thread)
        (void)runtime_stop_forwarder(rt);

    /* Tear down PQC bindings left from the deleted/previous profile. */
    sig_pqc_prepare_reload();
    sig_pqc_finalize_reload();
    forwarder_clear_stop();
    main_diag_ne_pqc_clear_all();

    if (rt)
        memset(rt, 0, sizeof(*rt));

    daemon_idle_log();
}

static int handle_profile_notify(struct runtime_state *rt,
                                 int *active_profile_id,
                                 int profile_id) {
    if (g_stop_requested)
        return 0;

    if (ne_profile_id_exists(profile_id) != 0) {
        fprintf(stderr,
                "[FAIL] profile id=%d not found in DB — load aborted\n",
                profile_id);
        fflush(stderr);
        return_to_blank_daemon(rt, active_profile_id);
        return 0;
    }

    if (rt->has_thread && *active_profile_id <= 0) {
        fprintf(stderr,
                "[LOAD] stale dataplane (thread without active profile) — reset to idle\n");
        fflush(stderr);
        return_to_blank_daemon(rt, active_profile_id);
    } else if (rt->has_thread && !rt->running) {
        fprintf(stderr,
                "[LOAD] dataplane thread not running — reset to idle before load\n");
        fflush(stderr);
        return_to_blank_daemon(rt, active_profile_id);
    } else if (*active_profile_id > 0 && *active_profile_id != profile_id) {
        fprintf(stderr,
                "[LOAD] replace profile %d → %d (clear old, then load)\n",
                *active_profile_id, profile_id);
        fflush(stderr);
        return_to_blank_daemon(rt, active_profile_id);
    }

    if (load_profile_and_run(rt, active_profile_id, profile_id) != 0) {
        fprintf(stderr,
                "[FAIL] load profile id=%d failed — load aborted\n",
                profile_id);
        fflush(stderr);
        return_to_blank_daemon(rt, active_profile_id);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    g_prog_name = argv[0] ? argv[0] : "network-encryptor";

    int ipc_rc = sig_pqc_handle_ipc_cli(argc, argv);
    if (ipc_rc >= 0) {
        return ipc_rc;
    }

    if (argc > 1 && strcmp(argv[1], "-gi") == 0) {
        sig_pqc_handle_gen_identity();
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "-gs") == 0)
        return cfm_status_ipc_query(argv[2]);
    if (argc == 2 && strcmp(argv[1], "-gs") == 0) {
        fprintf(stderr, "[ERR] -gs requires <wan_if|bridge>\n");
        return 1;
    }

    if (argc == 3 && strcmp(argv[1], "-di") == 0) {
        if (load_ne_env() != 0) {
            fprintf(stderr,
                    "[FATAL] Vault/DB bootstrap failed "
                    "(check " NE_ENV_FILE " VAULT_* / UNSEAL_KEY_* and Vault "
                    NE_VAULT_SECRET_PATH ")\n");
            return 1;
        }
        return notify_wan_admin("di", argv[2]) != 0 ? 1 : 0;
    }
    if (argc == 3 && strcmp(argv[1], "-ai") == 0) {
        if (load_ne_env() != 0) {
            fprintf(stderr,
                    "[FATAL] Vault/DB bootstrap failed "
                    "(check " NE_ENV_FILE " VAULT_* / UNSEAL_KEY_* and Vault "
                    NE_VAULT_SECRET_PATH ")\n");
            return 1;
        }
        return notify_wan_admin("ai", argv[2]) != 0 ? 1 : 0;
    }

    setbuf(stderr, NULL);
    if (trf_pqc_init_global() != TRF_PQC_OK) {
        fprintf(stderr, "[FATAL] trf_pqc_init_global failed\n");
        return 1;
    }

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        fprintf(stderr, "network-encryptor\n");
        return 0;
    }

    int profile_id = -1;
    if (parse_startup_profile_id(argc, argv, &profile_id) != 0) {
        usage(argv[0]);
        return 1;
    }

    if (profile_id >= 0) {
        if (load_ne_env() != 0) {
            fprintf(stderr,
                    "[FATAL] Vault/DB bootstrap failed "
                    "(check " NE_ENV_FILE " VAULT_* / UNSEAL_KEY_* and Vault "
                    NE_VAULT_SECRET_PATH ")\n");
            return 1;
        }
        if (notify_profile_load(profile_id) != 0)
            return 1;
        fprintf(stderr, "[NOTIFY] sent load:%d\n", profile_id);
        return 0;
    }

    if (argc > 1) {
        fprintf(stderr, "[FATAL] unknown arguments (got %d)\n", argc - 1);
        usage(argv[0]);
        return 1;
    }

    {
        struct sigaction sa = { .sa_handler = on_stop_signal };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
    }

    if (load_ne_env() != 0) {
        fprintf(stderr,
                "[FATAL] Vault/DB bootstrap failed "
                "(check " NE_ENV_FILE " VAULT_* / UNSEAL_KEY_* and Vault "
                NE_VAULT_SECRET_PATH ")\n");
        return 1;
    }

    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0) {
        fprintf(stderr,
                "[FATAL] Vault " NE_VAULT_SECRET_PATH
                " empty or incomplete — need POSTGRES_SERVER/PORT/USER/DB/PASSWORD\n");
        return 1;
    }

    sig_pqc_start_ipc_server();
    cfm_status_ipc_start();
    sig_pqc_init_vault();
    libbpf_set_print(libbpf_print_silent);

    forwarder_pin_cpu();
    PGconn *listen_conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        fprintf(stderr, "[FATAL] DB connection failed: %s", PQerrorMessage(listen_conn));
        fprintf(stderr,
                "[DB] tried host=%s port=%s dbname=%s user=%s (from Vault "
                NE_VAULT_SECRET_PATH ")\n",
                pg.values[0], pg.values[1], pg.values[2], pg.values[3]);
        PQfinish(listen_conn);
        return 1;
    }
    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
    PQclear(PQexec(listen_conn, "LISTEN " WAN_ADMIN_CHANNEL));

    daemon_idle_log();

    struct runtime_state *rt = calloc(1, sizeof(*rt));
    if (!rt) {
        fprintf(stderr, "[FATAL] out of memory for runtime state\n");
        PQfinish(listen_conn);
        return 1;
    }

    int active_profile_id = 0;

    while (!g_stop_requested) {
        int pq_fd = PQsocket(listen_conn);
        if (pq_fd < 0) {
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
            PQclear(PQexec(listen_conn, "LISTEN " WAN_ADMIN_CHANNEL));
            usleep(200000);
            continue;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pq_fd, &rfds);

        struct timeval tv = { .tv_sec = g_stop_requested ? 0 : 1,
                              .tv_usec = g_stop_requested ? 200000 : 0 };
        int sr = select(pq_fd + 1, &rfds, NULL, NULL, &tv);
        if (sr < 0) {
            if (errno == EINTR) {
                if (g_stop_requested)
                    break;
                continue;
            }
            usleep(200000);
            continue;
        }
        if (sr == 0)
            continue;

        if (!FD_ISSET(pq_fd, &rfds))
            continue;

        PQconsumeInput(listen_conn);
        PGnotify *notify;
        while ((notify = PQnotifies(listen_conn)) != NULL) {
            if (notify->relname && strcmp(notify->relname, WAN_ADMIN_CHANNEL) == 0) {
                (void)handle_wan_admin_notify(rt, notify->extra);
            } else {
                int id = -1;
                if (parse_notify_profile_cmd(notify->extra, &id) != 0) {
                    fprintf(stderr,
                            "[WARN] ignoring NOTIFY with invalid payload: \"%s\"\n",
                            notify->extra ? notify->extra : "");
                } else {
                    fprintf(stderr, "\n[NOTIFY] profile %d\n", id);
                    fflush(stderr);
                    (void)handle_profile_notify(rt, &active_profile_id, id);
                }
            }
            PQfreemem(notify);
        }

        if (PQstatus(listen_conn) != CONNECTION_OK) {
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
            PQclear(PQexec(listen_conn, "LISTEN " WAN_ADMIN_CHANNEL));
        }
    }

    if (rt->has_thread) {
        runtime_stop_forwarder(rt);
    }
    free(rt);
    PQfinish(listen_conn);
    trf_pqc_cleanup();
    return 0;
}
#include "../../inc/db/db_runtime.h"
#include "../../inc/crypto/pqc_handshake.h"

#include "../../inc/db/db_config.h"
#include "../../inc/db/db_env.h"

#include <libpq-fe.h>
#include <stdio.h>
#include <string.h>

int ne_profile_id_exists(int profile_id) {
    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0)
        return -1;

    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[DB] connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
                                 "SELECT 1 FROM ne_profiles WHERE id = $1",
                                 1, NULL, params, NULL, NULL, 0);
    int ok = 0;
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0)
        ok = 1;

    PQclear(res);
    PQfinish(conn);
    return ok ? 0 : -1;
}

int load_profile_config(struct app_config *out_cfg, int profile_id)
{
    if (!out_cfg || profile_id <= 0)
        return -1;

    sig_pqc_prepare_reload();
    if (config_load_from_db(out_cfg, profile_id, NULL) != 0)
        return -1;
    sig_pqc_finalize_reload();
    return 0;
}

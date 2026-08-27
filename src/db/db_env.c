#include "../../inc/db/db_env.h"
#include "../../inc/db/vault.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static void ne_sync_pgpassword(void) {
    const char *pass = getenv("POSTGRES_PASSWORD");
    if (pass && pass[0])
        setenv("PGPASSWORD", pass, 1);
}

int load_ne_env(void) {
    if (access(NE_ENV_FILE, R_OK) != 0) {
        fprintf(stderr, "[ENV] Missing or unreadable: " NE_ENV_FILE "\n");
        return -1;
    }

    fprintf(stderr,
            "[ENV] " NE_ENV_FILE " holds VAULT config only; "
            "POSTGRES_* come from Vault " NE_VAULT_SECRET_PATH "\n");

    if (ne_vault_unseal_and_login() != 0) {
        fprintf(stderr,
                "[ENV] cannot login/unseal Vault — check VAULT_ADDR, VAULT_TOKEN, "
                "UNSEAL_KEY_1/2/3 in " NE_ENV_FILE " (wrong key/token?)\n");
        return -1;
    }

    if (ne_vault_load_secrets() != 0) {
        fprintf(stderr,
                "[ENV] Vault " NE_VAULT_SECRET_PATH
                " empty or inaccessible — no usable POSTGRES_* "
                "(wrong token / empty secret?)\n");
        return -1;
    }

    ne_sync_pgpassword();
    fprintf(stderr,
            "[ENV] POSTGRES_* ready (from Vault " NE_VAULT_SECRET_PATH
            "; NE_VAULT_DEBUG=%s)\n",
            getenv("NE_VAULT_DEBUG") ? getenv("NE_VAULT_DEBUG") : "0");
    return 0;
}

int ne_postgres_conn_fill(struct ne_postgres_conn *out) {
    if (!out)
        return -1;

    memset(out, 0, sizeof(*out));

    const char *host = getenv("POSTGRES_SERVER");
    if (!host || !host[0])
        host = getenv("POSTGRES_HOST");
    const char *port = getenv("POSTGRES_PORT");
    const char *user = getenv("POSTGRES_USER");
    const char *dbname = getenv("POSTGRES_DB");
    const char *pass = resolve_db_password();

    if (!host || !host[0] || !port || !port[0] || !user || !user[0] ||
        !dbname || !dbname[0] || !pass || !pass[0]) {
        fprintf(stderr,
                "[DB] Vault " NE_VAULT_SECRET_PATH
                " empty or incomplete — missing POSTGRES_SERVER/PORT/USER/DB/PASSWORD\n");
        return -1;
    }

    static const char *kw[] = {
        "host", "port", "dbname", "user", "password", "connect_timeout", NULL
    };
    for (int i = 0; kw[i]; i++)
        out->keywords[i] = kw[i];
    out->keywords[6] = NULL;
    out->values[0] = host;
    out->values[1] = port;
    out->values[2] = dbname;
    out->values[3] = user;
    out->values[4] = pass;
    out->values[5] = "10";
    out->values[6] = NULL;
    return 0;
}

const char *resolve_db_password(void) {
    const char *p = getenv("POSTGRES_PASSWORD");
    if (p && *p) return p;
    p = getenv("PGPASSWORD");
    if (p && *p) return p;
    return NULL;
}
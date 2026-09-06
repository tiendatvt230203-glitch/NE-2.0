#ifndef DB_ENV_H
#define DB_ENV_H

#define NE_ENV_FILE "/opt/SEP/be/.env"
#define NE_STATE_DIR  "/var/lib/network-encryptor"



struct ne_postgres_conn {
    const char *keywords[7];
    const char *values[7];
};

int load_ne_env(void);
int ne_postgres_conn_fill(struct ne_postgres_conn *out);
const char *resolve_db_password(void);

#endif

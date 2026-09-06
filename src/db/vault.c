#include "../../inc/db/vault.h"
#include "../../inc/db/db_env.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NE_VAULT_HTTP_TIMEOUT_SEC 10
#define NE_VAULT_HTTP_BUF       65536
#define NE_VAULT_VAL_BUF          2048

struct ne_vault_cfg {
    char addr[256];
    char host[128];
    int port;
    char token[256];
    char k1[256];
    char k2[256];
    char k3[256];
    int debug; /* 0/1: dump POSTGRES_* from Vault to stderr */
};

/* Effective debug flag after reading .env (compile default + NE_VAULT_DEBUG). */
static int g_ne_vault_debug = NE_VAULT_DEBUG_LOG;

static void strip_env_quotes(char *val)
{
    size_t len = strlen(val);

    if (len >= 2 && val[0] == '"' && val[len - 1] == '"') {
        val[len - 1] = '\0';
        memmove(val, val + 1, len - 1);
        return;
    }
    if (len >= 2 && val[0] == '\'' && val[len - 1] == '\'') {
        val[len - 1] = '\0';
        memmove(val, val + 1, len - 1);
    }
}

static int ne_vault_key_allowed(const char *key)
{
    static const char *allowed[] = {
        "VAULT_ADDR",
        "VAULT_TOKEN",
        "UNSEAL_KEY_1",
        "UNSEAL_KEY_2",
        "UNSEAL_KEY_3",
        "NE_VAULT_DEBUG", /* 0|1 dump DB secrets from Vault */
        NULL
    };

    if (!key || !key[0])
        return 0;
    for (int i = 0; allowed[i]; i++) {
        if (strcmp(key, allowed[i]) == 0)
            return 1;
    }
    return 0;
}

static void ne_vault_parse_url(struct ne_vault_cfg *cfg, const char *url)
{
    const char *p = url;

    if (!cfg || !url || !url[0])
        return;

    strncpy(cfg->addr, url, sizeof(cfg->addr) - 1);
    if (strncmp(p, "http://", 7) == 0)
        p += 7;
    else if (strncmp(p, "https://", 8) == 0)
        p += 8;

    {
        char hostport[256];
        char *colon;
        char *slash;

        strncpy(hostport, p, sizeof(hostport) - 1);
        hostport[sizeof(hostport) - 1] = '\0';
        slash = strchr(hostport, '/');
        if (slash)
            *slash = '\0';
        colon = strchr(hostport, ':');
        if (colon) {
            *colon = '\0';
            cfg->port = atoi(colon + 1);
        } else {
            cfg->port = 8200;
        }
        strncpy(cfg->host, hostport, sizeof(cfg->host) - 1);
    }

    if (strcmp(cfg->host, "localhost") == 0)
        strncpy(cfg->host, "127.0.0.1", sizeof(cfg->host) - 1);
}

static int ne_vault_load_cfg(struct ne_vault_cfg *cfg)
{
    FILE *fp;
    char line[2048];

    if (!cfg)
        return -1;

    memset(cfg, 0, sizeof(*cfg));
    cfg->port = 8200;
    cfg->debug = NE_VAULT_DEBUG_LOG;
    strncpy(cfg->host, "127.0.0.1", sizeof(cfg->host) - 1);

    fp = fopen(NE_ENV_FILE, "r");
    if (!fp) {
        fprintf(stderr, "[VAULT] Could not open: " NE_ENV_FILE "\n");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        char *eq;
        char *key;
        char *val;

        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '\n' || *p == '#')
            continue;

        eq = strchr(p, '=');
        if (!eq)
            continue;

        *eq = '\0';
        key = p;
        val = eq + 1;

        {
            char *end = key + strlen(key) - 1;
            while (end > key && (*end == ' ' || *end == '\t'))
                *end-- = '\0';
        }

        while (*val == ' ' || *val == '\t')
            val++;

        {
            size_t len = strlen(val);
            while (len > 0 && (val[len - 1] == '\n' || val[len - 1] == '\r'))
                val[--len] = '\0';
        }

        strip_env_quotes(val);

        if (!ne_vault_key_allowed(key) || !val[0])
            continue;

        if (strcmp(key, "VAULT_ADDR") == 0)
            ne_vault_parse_url(cfg, val);
        else if (strcmp(key, "VAULT_TOKEN") == 0)
            strncpy(cfg->token, val, sizeof(cfg->token) - 1);
        else if (strcmp(key, "UNSEAL_KEY_1") == 0)
            strncpy(cfg->k1, val, sizeof(cfg->k1) - 1);
        else if (strcmp(key, "UNSEAL_KEY_2") == 0)
            strncpy(cfg->k2, val, sizeof(cfg->k2) - 1);
        else if (strcmp(key, "UNSEAL_KEY_3") == 0)
            strncpy(cfg->k3, val, sizeof(cfg->k3) - 1);
        else if (strcmp(key, "NE_VAULT_DEBUG") == 0)
            cfg->debug = (val[0] == '1') ? 1 : 0;
    }

    fclose(fp);

    g_ne_vault_debug = cfg->debug ? 1 : 0;
    setenv("NE_VAULT_DEBUG", g_ne_vault_debug ? "1" : "0", 1);

    if (cfg->addr[0])
        setenv("VAULT_ADDR", cfg->addr, 1);
    if (cfg->token[0])
        setenv("VAULT_TOKEN", cfg->token, 1);

    fprintf(stderr,
            "[VAULT] config from " NE_ENV_FILE
            " (addr=%s unseal_keys=%d token=%s debug=%d)\n",
            cfg->addr[0] ? cfg->addr : "-",
            (cfg->k1[0] ? 1 : 0) + (cfg->k2[0] ? 1 : 0) + (cfg->k3[0] ? 1 : 0),
            cfg->token[0] ? "set" : "missing",
            g_ne_vault_debug);

    return 0;
}

static int ne_vault_cfg_present(const struct ne_vault_cfg *cfg)
{
    return cfg && cfg->addr[0] && cfg->token[0] &&
           cfg->k1[0] && cfg->k2[0] && cfg->k3[0];
}

static int ne_vault_http_request(const struct ne_vault_cfg *cfg, const char *method,
                                 const char *path, const char *body,
                                 char *resp_buf, size_t max_resp)
{
    int sockfd;
    struct timeval tv;
    struct sockaddr_in serv_addr;
    char req[16384];
    int req_len;
    int body_len;
    int total_recv;
    int n;

    if (!cfg || !method || !path || !resp_buf || max_resp < 2)
        return -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        return -1;

    tv.tv_sec = NE_VAULT_HTTP_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons((uint16_t)cfg->port);

    if (inet_pton(AF_INET, cfg->host, &serv_addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(cfg->host);
        if (!he) {
            close(sockfd);
            return -1;
        }
        memcpy(&serv_addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "[VAULT] HTTP connect %s:%d failed: %s\n",
                cfg->host, cfg->port, strerror(errno));
        close(sockfd);
        return -1;
    }

    body_len = body ? (int)strlen(body) : 0;
    req_len = snprintf(req, sizeof(req),
                       "%s %s HTTP/1.1\r\n"
                       "Host: %s:%d\r\n"
                       "User-Agent: network-encryptor-db\r\n"
                       "Accept: application/json\r\n"
                       "Content-Type: application/json\r\n"
                       "X-Vault-Token: %s\r\n"
                       "Content-Length: %d\r\n"
                       "Connection: close\r\n\r\n"
                       "%s",
                       method, path, cfg->host, cfg->port,
                       cfg->token[0] ? cfg->token : "",
                       body_len, body ? body : "");
    if (req_len <= 0 || req_len >= (int)sizeof(req)) {
        close(sockfd);
        return -1;
    }

    if (send(sockfd, req, (size_t)req_len, 0) < 0) {
        close(sockfd);
        return -1;
    }

    memset(resp_buf, 0, max_resp);
    total_recv = 0;
    while ((n = recv(sockfd, resp_buf + total_recv,
                     (int)max_resp - 1 - total_recv, 0)) > 0) {
        total_recv += n;
        if (total_recv >= (int)max_resp - 1)
            break;
    }
    close(sockfd);
    resp_buf[total_recv] = '\0';
    return total_recv > 0 ? total_recv : -1;
}

static int ne_vault_json_bool_false(const char *json, const char *key)
{
    char pattern[64];
    const char *p;

    if (!json || !key)
        return 0;
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(json, pattern);
    if (!p)
        return 0;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t')
        p++;
    return strncmp(p, "false", 5) == 0;
}

static int ne_vault_json_extract_string(const char *json, const char *key,
                                        char *out, size_t outsz)
{
    char pattern[128];
    const char *p;
    size_t i;

    if (!json || !key || !out || outsz == 0)
        return -1;

    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(json, pattern);
    if (!p)
        return -1;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t')
        p++;
    if (*p != '"')
        return -1;
    p++;

    i = 0;
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\') {
            p++;
            if (!*p)
                break;
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0 ? 0 : -1;
}

static int ne_vault_http_status(const char *response)
{
    const char *p;

    if (!response)
        return -1;
    /* "HTTP/1.x NNN ..." */
    p = strstr(response, "HTTP/");
    if (!p)
        return -1;
    p = strchr(p, ' ');
    if (!p)
        return -1;
    return atoi(p + 1);
}

static int ne_vault_http_unseal_key(const struct ne_vault_cfg *cfg, const char *key)
{
    char payload[1024];
    char response[8192];
    int status;

    if (!key || !key[0])
        return -1;

    snprintf(payload, sizeof(payload), "{\"key\":\"%s\"}", key);
    if (ne_vault_http_request(cfg, "POST", "/v1/sys/unseal", payload,
                              response, sizeof(response)) < 0) {
        fprintf(stderr, "[VAULT] HTTP unseal request failed\n");
        return -1;
    }
    status = ne_vault_http_status(response);
    if (status == 400 || status == 500) {
        fprintf(stderr,
                "[VAULT] unseal rejected (HTTP %d) — UNSEAL_KEY likely wrong\n",
                status);
        return -1;
    }
    return ne_vault_json_bool_false(response, "sealed") ? 0 : 1;
}

static int ne_secret_key_wanted(const char *key)
{
    if (!key || !key[0])
        return 0;
    if (strncmp(key, "POSTGRES_", 9) == 0)
        return 1;
    if (strcmp(key, "LISTEN_PORT") == 0)
        return 1;
    return 0;
}

static int ne_vault_kv_apply_from_json(const char *json)
{
    static const char *keys[] = {
        "LISTEN_PORT",
        "POSTGRES_DB",
        "POSTGRES_PASSWORD",
        "POSTGRES_PORT",
        "POSTGRES_SERVER",
        "POSTGRES_USER",
        "POSTGRES_HOST",
        NULL
    };
    char val[NE_VAULT_VAL_BUF];
    int loaded = 0;

    for (int i = 0; keys[i]; i++) {
        if (ne_vault_json_extract_string(json, keys[i], val, sizeof(val)) != 0)
            continue;
        if (!ne_secret_key_wanted(keys[i]))
            continue;
        setenv(keys[i], val, 1);
        if (strcmp(keys[i], "POSTGRES_HOST") == 0)
            setenv("POSTGRES_SERVER", val, 1);
        loaded++;
    }
    return loaded;
}

static void ne_vault_log_loaded_secrets(void)
{
    const char *db = getenv("POSTGRES_DB");
    const char *pass = getenv("POSTGRES_PASSWORD");
    const char *port = getenv("POSTGRES_PORT");
    const char *user = getenv("POSTGRES_USER");

    if (!g_ne_vault_debug)
        return;

    fprintf(stderr,
            "[VAULT-DEBUG] DB from Vault " NE_VAULT_SECRET_PATH ":\n"
            "  \"POSTGRES_DB\": \"%s\",\n"
            "  \"POSTGRES_PASSWORD\": \"%s\",\n"
            "  \"POSTGRES_PORT\": \"%s\",\n"
            "  \"POSTGRES_USER\": \"%s\",\n",
            (db && db[0]) ? db : "",
            (pass && pass[0]) ? pass : "",
            (port && port[0]) ? port : "",
            (user && user[0]) ? user : "");
    fflush(stderr);
}

static void ne_vault_kv_api_path(char *out, size_t outsz)
{
    const char *p = NE_VAULT_SECRET_PATH;
    const char *slash = strchr(p, '/');

    if (!slash || slash == p) {
        snprintf(out, outsz, "/v1/%s", p);
        return;
    }
    snprintf(out, outsz, "/v1/%.*s/data%s",
             (int)(slash - p), p, slash);
}

static int ne_vault_kv_get_and_apply(const struct ne_vault_cfg *cfg)
{
    char *response;
    char api_path[128];
    int loaded;
    int status;
    const char *body;

    response = malloc(NE_VAULT_HTTP_BUF);
    if (!response)
        return -1;

    ne_vault_kv_api_path(api_path, sizeof(api_path));
    if (ne_vault_http_request(cfg, "GET", api_path, NULL,
                              response, NE_VAULT_HTTP_BUF) < 0) {
        snprintf(api_path, sizeof(api_path), "/v1/%s", NE_VAULT_SECRET_PATH);
        if (ne_vault_http_request(cfg, "GET", api_path, NULL,
                                  response, NE_VAULT_HTTP_BUF) < 0) {
            fprintf(stderr, "[VAULT] HTTP kv get failed for " NE_VAULT_SECRET_PATH "\n");
            free(response);
            return -1;
        }
    }

    status = ne_vault_http_status(response);
    if (status == 401 || status == 403) {
        fprintf(stderr,
                "[VAULT] cannot read " NE_VAULT_SECRET_PATH
                " (HTTP %d) — VAULT_TOKEN wrong or permission denied\n",
                status);
        free(response);
        return -1;
    }
    if (status == 404) {
        fprintf(stderr,
                "[VAULT] secret path " NE_VAULT_SECRET_PATH
                " not found (HTTP 404) — empty/missing in Vault\n");
        free(response);
        return -1;
    }
    if (status > 0 && (status < 200 || status >= 300)) {
        fprintf(stderr,
                "[VAULT] kv get " NE_VAULT_SECRET_PATH " failed (HTTP %d)\n",
                status);
        free(response);
        return -1;
    }

    body = strstr(response, "\r\n\r\n");
    if (body)
        body += 4;
    else {
        body = strstr(response, "\n\n");
        if (body)
            body += 2;
        else
            body = response;
    }

    loaded = ne_vault_kv_apply_from_json(body);
    free(response);

    if (loaded == 0) {
        fprintf(stderr,
                "[VAULT] " NE_VAULT_SECRET_PATH
                " empty — no POSTGRES_DB/PASSWORD/PORT/USER fields\n");
        return -1;
    }
    return 0;
}

static int ne_vault_verify_postgres_env(void)
{
    const char *host = getenv("POSTGRES_SERVER");
    const char *port = getenv("POSTGRES_PORT");
    const char *user = getenv("POSTGRES_USER");
    const char *dbname = getenv("POSTGRES_DB");
    const char *pass = getenv("POSTGRES_PASSWORD");

    if (!host || !host[0])
        host = getenv("POSTGRES_HOST");
    if ((!host || !host[0]) && getenv("POSTGRES_HOST"))
        setenv("POSTGRES_SERVER", getenv("POSTGRES_HOST"), 1);

    host = getenv("POSTGRES_SERVER");
    if (!host || !host[0])
        host = getenv("POSTGRES_HOST");

    if (!host || !host[0]) {
        fprintf(stderr, "[VAULT] missing POSTGRES_SERVER in " NE_VAULT_SECRET_PATH "\n");
        return -1;
    }
    if (!port || !port[0]) {
        fprintf(stderr, "[VAULT] missing POSTGRES_PORT in " NE_VAULT_SECRET_PATH "\n");
        return -1;
    }
    if (!user || !user[0]) {
        fprintf(stderr, "[VAULT] missing POSTGRES_USER in " NE_VAULT_SECRET_PATH "\n");
        return -1;
    }
    if (!dbname || !dbname[0]) {
        fprintf(stderr, "[VAULT] missing POSTGRES_DB in " NE_VAULT_SECRET_PATH "\n");
        return -1;
    }
    if (!pass || !pass[0]) {
        fprintf(stderr, "[VAULT] missing POSTGRES_PASSWORD in " NE_VAULT_SECRET_PATH "\n");
        return -1;
    }
    return 0;
}

int ne_vault_unseal_and_login(void)
{
    struct ne_vault_cfg cfg;
    char response[8192];
    int fail = 0;

    if (ne_vault_load_cfg(&cfg) != 0)
        return -1;

    if (!ne_vault_cfg_present(&cfg)) {
        fprintf(stderr,
                "[VAULT] missing VAULT_ADDR/TOKEN/UNSEAL_KEY_1/2/3 in "
                NE_ENV_FILE "\n");
        return -1;
    }

    fprintf(stderr, "[VAULT] unseal via HTTP addr=%s (timeout=%ds)\n",
            cfg.addr, NE_VAULT_HTTP_TIMEOUT_SEC);

    if (ne_vault_http_request(&cfg, "GET", "/v1/sys/seal-status", NULL,
                              response, sizeof(response)) < 0) {
        fprintf(stderr, "[VAULT] seal-status request failed\n");
        return -1;
    }

    if (ne_vault_json_bool_false(response, "sealed")) {
        fprintf(stderr, "[VAULT] unseal ok (already unsealed)\n");
        return 0;
    }

    if (cfg.k1[0] && ne_vault_http_unseal_key(&cfg, cfg.k1) < 0)
        fail = 1;
    if (cfg.k2[0] && ne_vault_http_unseal_key(&cfg, cfg.k2) < 0)
        fail = 1;
    if (cfg.k3[0] && ne_vault_http_unseal_key(&cfg, cfg.k3) < 0)
        fail = 1;

    if (ne_vault_http_request(&cfg, "GET", "/v1/sys/seal-status", NULL,
                              response, sizeof(response)) < 0) {
        fprintf(stderr, "[VAULT] seal-status verify failed\n");
        return -1;
    }

    if (!ne_vault_json_bool_false(response, "sealed")) {
        fprintf(stderr,
                "[VAULT] still sealed after UNSEAL_KEY_1/2/3 — keys wrong or incomplete\n");
        fail = 1;
    }

    if (fail) {
        fprintf(stderr,
                "[VAULT] unseal/login failed with keys+token from " NE_ENV_FILE "\n");
        return -1;
    }

    fprintf(stderr, "[VAULT] unseal ok\n");
    return 0;
}

int ne_vault_load_secrets(void)
{
    struct ne_vault_cfg cfg;

    if (ne_vault_load_cfg(&cfg) != 0)
        return -1;

    if (!cfg.addr[0]) {
        fprintf(stderr, "[VAULT] missing VAULT_ADDR in " NE_ENV_FILE "\n");
        return -1;
    }
    if (!cfg.token[0]) {
        fprintf(stderr, "[VAULT] missing VAULT_TOKEN in " NE_ENV_FILE "\n");
        return -1;
    }

    fprintf(stderr, "[VAULT] HTTP kv get " NE_VAULT_SECRET_PATH
            " (timeout=%ds)\n", NE_VAULT_HTTP_TIMEOUT_SEC);

    if (ne_vault_kv_get_and_apply(&cfg) != 0)
        return -1;

    if (ne_vault_verify_postgres_env() != 0)
        return -1;

    ne_vault_log_loaded_secrets();
    fprintf(stderr, "[VAULT] POSTGRES_* loaded from " NE_VAULT_SECRET_PATH "\n");
    return 0;
}
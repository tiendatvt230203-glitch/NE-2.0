#include "core/forwarder/forwarder.h"
#include "core/util/static_config.h"
#include "crypto/traffic_crypto.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void stop_signal(int sig)
{
    (void)sig;
    forwarder_stop();
}

int main(void)
{
    struct app_config *cfg = calloc(1, sizeof(*cfg));
    struct forwarder *fwd = calloc(1, sizeof(*fwd));
    struct sigaction sa = { .sa_handler = stop_signal };
    int ready = 0;
    int rc = 1;

    setbuf(stderr, NULL);
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    if (!cfg || !fwd || static_config_build(cfg) != 0) goto out;
    if (trf_pqc_init_global() != TRF_PQC_OK) {
        fprintf(stderr, "[CORE] crypto library initialization failed\n");
        goto out;
    }
    if (forwarder_init(fwd, cfg) != 0) goto crypto_out;
    ready = 1;
    fprintf(stderr, "[CORE] dataplane running\n");
    forwarder_run(fwd);
    rc = 0;
crypto_out:
    if (ready) forwarder_cleanup(fwd);
    trf_pqc_cleanup();
out:
    free(fwd);
    free(cfg);
    return rc;
}

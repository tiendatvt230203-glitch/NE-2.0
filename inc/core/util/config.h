#ifndef CONFIG_H
#define CONFIG_H

#include <net/if.h>
#include <stdint.h>

#define MAX_INTERFACES 16
#define AES_KEY_LEN 32

struct local_config { char ifname[IF_NAMESIZE]; };
struct wan_config { char ifname[IF_NAMESIZE]; };

/* Hard-coded runtime only. There is no DB/profile/policy representation. */
struct app_config {
    struct local_config locals[MAX_INTERFACES];
    int local_count;
    struct wan_config wans[MAX_INTERFACES];
    int wan_count;
    char bpf_file[256];
    char bpf_wan_file[256];
    uint16_t fake_ethertype_ipv4;
    uint8_t key[AES_KEY_LEN];
};

#endif

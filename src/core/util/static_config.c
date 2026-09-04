#include "../../../inc/core/util/static_config.h"
#include "../../../inc/crypto/eth_parse.h"

#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/* The only traffic key. Keep this identical on both appliances. */
static const uint8_t core_key[AES_KEY_LEN] = {
    0x73,0x21,0x4a,0x9c,0xe1,0x5d,0x2f,0xb8,
    0x16,0xc7,0x3b,0x90,0xad,0x44,0xf2,0x6e,
    0x58,0x0d,0xa1,0x37,0xcb,0x7f,0x24,0x95,
    0xee,0x63,0x18,0xd4,0x89,0xba,0x05,0xcf,
};

/* EDIT ON EACH APPLIANCE: client reachable through each LAN. */
static const uint8_t client_macs[2][MAC_LEN] = {
    {0x00,0x00,0x00,0x00,0x00,0x00}, /* enp1s0f0 */
    {0x00,0x00,0x00,0x00,0x00,0x00}, /* enp1s0f1 */
};

static void copy_ifname(char dst[IF_NAMESIZE], const char *src)
{
    strncpy(dst, src, IF_NAMESIZE - 1);
    dst[IF_NAMESIZE - 1] = '\0';
}

static int valid_mac(const uint8_t mac[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];
    return memcmp(mac, zero, MAC_LEN) != 0 && !(mac[0] & 1u);
}

static int require_mtu_9000(const char *ifname)
{
    struct ifreq ifr = {0};
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int ok = 0;

    if (fd < 0) return -1;
    copy_ifname(ifr.ifr_name, ifname);
    ok = ioctl(fd, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu >= 9000;
    close(fd);
    if (!ok) fprintf(stderr, "[CORE] %s must be UP with MTU >= 9000\n", ifname);
    return ok ? 0 : -1;
}

int static_config_local_for_dmac(const struct app_config *cfg, const uint8_t dmac[MAC_LEN])
{
    if (!cfg || !dmac) return -1;
    for (int i = 0; i < cfg->local_count; i++)
        if (memcmp(cfg->client_mac[i], dmac, MAC_LEN) == 0) return i;
    return -1;
}

int static_config_build(struct app_config *cfg)
{
    static const char *lans[2] = {"enp1s0f0", "enp1s0f1"};
    static const char *wans[2] = {"enp2s0f0", "enp2s0f1"};

    if (!cfg) return -1;
    memset(cfg, 0, sizeof(*cfg));
    for (int i = 0; i < 2; i++) {
        if (!valid_mac(client_macs[i]) ||
            (i && memcmp(client_macs[0], client_macs[1], MAC_LEN) == 0)) {
            fprintf(stderr, "[CORE] set unique client_macs[%d] before build\n", i);
            return -1;
        }
        if (require_mtu_9000(lans[i]) || require_mtu_9000(wans[i])) return -1;
        copy_ifname(cfg->locals[i].ifname, lans[i]);
        copy_ifname(cfg->wans[i].ifname, wans[i]);
        memcpy(cfg->client_mac[i], client_macs[i], MAC_LEN);
    }
    cfg->local_count = 2;
    cfg->wan_count = 2;
    cfg->fake_ethertype_ipv4 = NE_L2_FAKE_ETHERTYPE;
    memcpy(cfg->key, core_key, sizeof(core_key));
    strcpy(cfg->bpf_file, "./lib/lan.o");
    strcpy(cfg->bpf_wan_file, "./lib/wan.o");
    fprintf(stderr,
            "[CORE] static L2 key=%02x%02x%02x%02x...; 2 LAN; 2 WAN equal-share\n",
            core_key[0], core_key[1], core_key[2], core_key[3]);
    return 0;
}

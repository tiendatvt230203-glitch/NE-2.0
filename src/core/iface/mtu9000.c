#include "../../../inc/core/iface/mtu9000.h"

#include <errno.h>
#include <linux/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int validate_iface(int fd, const char *role, const char *ifname,
                          char *error, size_t error_size)
{
    struct ifreq ifr;
    char path[256];
    char target[512];
    const char *driver;
    ssize_t n;

    if (!ifname || !ifname[0]) {
        snprintf(error, error_size, "%s: missing interface", role);
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(fd, SIOCGIFMTU, &ifr) != 0) {
        snprintf(error, error_size, "%s %s: cannot read MTU: %s",
                 role, ifname, strerror(errno));
        return -1;
    }
    if (ifr.ifr_mtu != 9000) {
        snprintf(error, error_size, "%s %s: MTU %d, expected 9000",
                 role, ifname, ifr.ifr_mtu);
        return -1;
    }
    if (snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver",
                 ifname) >= (int)sizeof(path)) {
        snprintf(error, error_size, "%s %s: interface name too long",
                 role, ifname);
        return -1;
    }
    n = readlink(path, target, sizeof(target) - 1u);
    if (n <= 0) {
        snprintf(error, error_size, "%s %s: cannot identify NIC driver",
                 role, ifname);
        return -1;
    }
    target[n] = '\0';
    driver = strrchr(target, '/');
    driver = driver ? driver + 1 : target;
    if (strcmp(driver, "i40e") != 0 && strcmp(driver, "ice") != 0) {
        snprintf(error, error_size,
                 "%s %s: MTU 9000 requires i40e/ice (driver=%s)",
                 role, ifname, driver);
        return -1;
    }
    return 0;
}

int ne_mtu9000_validate(const struct app_config *cfg,
                        char *error, size_t error_size)
{
    int fd;

    if (!cfg || !error || error_size == 0)
        return -1;
    error[0] = '\0';
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        snprintf(error, error_size, "cannot open MTU query socket: %s",
                 strerror(errno));
        return -1;
    }
    for (int i = 0; i < cfg->local_count; i++) {
        if (validate_iface(fd, "LAN", cfg->locals[i].ifname,
                           error, error_size) != 0)
            goto fail;
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        if (!cfg->wans[i].dataplane)
            continue;
        if (validate_iface(fd, "WAN", cfg->wans[i].ifname,
                           error, error_size) != 0)
            goto fail;
    }
    close(fd);
    return 0;

fail:
    close(fd);
    return -1;
}

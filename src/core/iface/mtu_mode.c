#include "../../../inc/core/iface/mtu_mode.h"

#include <errno.h>
#include <linux/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define NE_MTU_STANDARD 1500u
#define NE_MTU_JUMBO    9000u

static int read_iface_mtu(int fd, const char *ifname, uint32_t *mtu_out)
{
    struct ifreq ifr;

    if (fd < 0 || !ifname || !ifname[0] || !mtu_out)
        return -1;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(fd, SIOCGIFMTU, &ifr) != 0 || ifr.ifr_mtu <= 0)
        return -1;
    *mtu_out = (uint32_t)ifr.ifr_mtu;
    return 0;
}

static int read_iface_driver(const char *ifname, char *driver, size_t driver_size)
{
    char path[256];
    char target[512];
    const char *base;
    ssize_t n;

    if (!ifname || !ifname[0] || !driver || driver_size == 0)
        return -1;
    if (snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", ifname) >=
        (int)sizeof(path))
        return -1;
    n = readlink(path, target, sizeof(target) - 1u);
    if (n <= 0)
        return -1;
    target[n] = '\0';
    base = strrchr(target, '/');
    base = base ? base + 1 : target;
    if (!base[0] || strlen(base) >= driver_size)
        return -1;
    memcpy(driver, base, strlen(base) + 1u);
    return 0;
}

static int jumbo_driver_supported(const char *ifname, char *driver,
                                  size_t driver_size)
{
    if (read_iface_driver(ifname, driver, driver_size) != 0)
        return 0;
    return strcmp(driver, "i40e") == 0 || strcmp(driver, "ice") == 0;
}

static enum ne_mtu_mode mode_for_mtu(uint32_t mtu)
{
    if (mtu == NE_MTU_STANDARD)
        return NE_MTU_MODE_1500;
    if (mtu == NE_MTU_JUMBO)
        return NE_MTU_MODE_9000;
    return NE_MTU_MODE_INVALID;
}

static int check_iface(int fd, const char *role, const char *ifname,
                       enum ne_mtu_mode *detected, char *error,
                       size_t error_size)
{
    enum ne_mtu_mode mode;
    uint32_t mtu;

    if (read_iface_mtu(fd, ifname, &mtu) != 0) {
        snprintf(error, error_size, "%s %s: cannot read MTU: %s",
                 role, ifname ? ifname : "?", strerror(errno));
        return -1;
    }
    mode = mode_for_mtu(mtu);
    if (mode == NE_MTU_MODE_INVALID) {
        snprintf(error, error_size,
                 "%s %s: unsupported MTU %u (only 1500 or 9000)",
                 role, ifname, mtu);
        return -1;
    }
    if (*detected != NE_MTU_MODE_INVALID && *detected != mode) {
        snprintf(error, error_size,
                 "%s %s: MTU %u conflicts with selected %s mode",
                 role, ifname, mtu, ne_mtu_mode_name(*detected));
        return -1;
    }
    *detected = mode;
    return 0;
}

static int validate_jumbo_driver(const char *role, const char *ifname,
                                 char *error, size_t error_size)
{
    char driver[64] = "unknown";

    if (jumbo_driver_supported(ifname, driver, sizeof(driver)))
        return 0;
    snprintf(error, error_size,
             "%s %s: MTU 9000 requires i40e/ice (driver=%s)",
             role, ifname, driver);
    return -1;
}

const char *ne_mtu_mode_name(enum ne_mtu_mode mode)
{
    switch (mode) {
    case NE_MTU_MODE_1500:
        return "1500";
    case NE_MTU_MODE_9000:
        return "9000";
    default:
        return "invalid";
    }
}

uint32_t ne_mtu_mode_value(enum ne_mtu_mode mode)
{
    if (mode == NE_MTU_MODE_9000)
        return NE_MTU_JUMBO;
    if (mode == NE_MTU_MODE_1500)
        return NE_MTU_STANDARD;
    return 0;
}

int ne_mtu_mode_is_jumbo(enum ne_mtu_mode mode)
{
    return mode == NE_MTU_MODE_9000;
}

int ne_mtu_mode_detect(const struct app_config *cfg, enum ne_mtu_mode *mode_out,
                       char *error, size_t error_size)
{
    enum ne_mtu_mode detected = NE_MTU_MODE_INVALID;
    int fd;

    if (error && error_size > 0)
        error[0] = '\0';
    if (!cfg || !mode_out || !error || error_size == 0)
        return -1;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        snprintf(error, error_size, "cannot open MTU query socket: %s",
                 strerror(errno));
        return -1;
    }

    for (int i = 0; i < cfg->local_count; i++) {
        if (check_iface(fd, "LAN", cfg->locals[i].ifname, &detected,
                        error, error_size) != 0)
            goto fail;
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        if (!cfg->wans[i].dataplane)
            continue;
        if (check_iface(fd, "WAN", cfg->wans[i].ifname, &detected,
                        error, error_size) != 0)
            goto fail;
    }
    close(fd);

    if (detected == NE_MTU_MODE_INVALID) {
        snprintf(error, error_size, "no LAN/dataplane WAN available for MTU detection");
        return -1;
    }
    if (detected == NE_MTU_MODE_9000) {
        for (int i = 0; i < cfg->local_count; i++) {
            if (validate_jumbo_driver("LAN", cfg->locals[i].ifname,
                                      error, error_size) != 0)
                return -1;
        }
        for (int i = 0; i < cfg->wan_count; i++) {
            if (!cfg->wans[i].dataplane)
                continue;
            if (validate_jumbo_driver("WAN", cfg->wans[i].ifname,
                                      error, error_size) != 0)
                return -1;
        }
    }
    *mode_out = detected;
    return 0;

fail:
    close(fd);
    return -1;
}

int ne_mtu_mode_validate(const struct app_config *cfg, enum ne_mtu_mode expected,
                         char *error, size_t error_size)
{
    enum ne_mtu_mode detected;

    if (ne_mtu_mode_detect(cfg, &detected, error, error_size) != 0)
        return -1;
    if (detected != expected) {
        snprintf(error, error_size,
                 "configuration requires MTU %s mode; running dataplane is MTU %s",
                 ne_mtu_mode_name(detected), ne_mtu_mode_name(expected));
        return -1;
    }
    return 0;
}

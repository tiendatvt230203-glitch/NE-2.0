#include "core/util/packet_log.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static const char *g_packet_log_path = NE_PACKET_LOG_DEFAULT_PATH;

const char *ne_packet_log_path(void)
{
    return g_packet_log_path;
}

static int mkdir_parents(const char *file_path)
{
    char path[PATH_MAX];
    size_t len;

    if (!file_path || file_path[0] != '/') {
        errno = EINVAL;
        return -1;
    }

    len = strlen(file_path);
    if (len == 0 || len >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    memcpy(path, file_path, len + 1);
    for (char *p = path + 1; *p; p++) {
        if (*p != '/')
            continue;

        *p = '\0';
        if (mkdir(path, 0750) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    return 0;
}

int ne_packet_log_redirect(void)
{
    const char *configured = getenv("NE_PACKET_LOG_PATH");
    char timestamp[32] = "unknown-time";
    struct tm tm_now;
    time_t now;
    int fd;
    int saved_errno;

    if (configured && configured[0] != '\0')
        g_packet_log_path = configured;

    if (mkdir_parents(g_packet_log_path) != 0)
        return -1;

    fd = open(g_packet_log_path,
              O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
              0640);
    if (fd < 0)
        return -1;

    /* Redirect stderr last so an error can still be reported to the caller. */
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (fd != STDERR_FILENO && fd != STDOUT_FILENO)
        close(fd);

    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    now = time(NULL);
    if (localtime_r(&now, &tm_now) != NULL)
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S %z", &tm_now);

    fprintf(stderr,
            "\n===== NE daemon session start %s pid=%ld log=%s =====\n",
            timestamp, (long)getpid(), g_packet_log_path);
    return 0;
}

#include "../../../inc/core/dataplane/dp_idle.h"

#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#define NE_DP_IDLE_HOT_NS   5000ull
#define NE_DP_IDLE_COLD_NS  25000ull
#define NE_DP_IDLE_WARM_NS  5000L
#define NE_DP_IDLE_POLL_MS  1

static int g_busy_poll = -1;
static int g_efd[NE_DP_WAKE_N];
static atomic_int g_sleeping[NE_DP_WAKE_N];
static int g_ready;

static void efd_reset_all(void)
{
    int i;

    for (i = 0; i < NE_DP_WAKE_N; i++)
        g_efd[i] = -1;
}

static void cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

static uint64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int wake_ok(int wake_id)
{
    return wake_id >= 0 && wake_id < NE_DP_WAKE_N;
}

void ne_dp_idle_init(void)
{
    const char *env;
    int i;

    if (g_ready)
        return;

    env = getenv("NE_DP_BUSY_POLL");
    g_busy_poll = (env && env[0] == '1') ? 1 : 0;
    efd_reset_all();

    for (i = 0; i < NE_DP_WAKE_N; i++) {
        g_efd[i] = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        atomic_store_explicit(&g_sleeping[i], 0, memory_order_relaxed);
        if (g_efd[i] < 0)
            fprintf(stderr, "[DP-IDLE] eventfd %d failed: %s\n", i, strerror(errno));
    }

    g_ready = 1;
    if (g_busy_poll)
        fprintf(stderr, "[DP-IDLE] busy-poll (NE_DP_BUSY_POLL=1)\n");
    else
        fprintf(stderr, "[DP-IDLE] adaptive idle (set NE_DP_BUSY_POLL=1 to spin)\n");
    fflush(stderr);
}

void ne_dp_idle_shutdown(void)
{
    int i;

    if (!g_ready)
        return;
    for (i = 0; i < NE_DP_WAKE_N; i++) {
        if (g_efd[i] >= 0) {
            close(g_efd[i]);
            g_efd[i] = -1;
        }
        atomic_store_explicit(&g_sleeping[i], 0, memory_order_relaxed);
    }
    g_ready = 0;
    g_busy_poll = -1;
}

void ne_dp_idle_note_work(struct ne_dp_idle *st)
{
    if (st)
        st->idle_start_ns = 0;
}

static void set_sleeping(int wake_id, int on)
{
    if (!wake_ok(wake_id))
        return;
    atomic_store_explicit(&g_sleeping[wake_id], on ? 1 : 0, memory_order_release);
}

int ne_dp_idle_arm(struct ne_dp_idle *st, int wake_id)
{
    uint64_t t;
    uint64_t dt;
    struct timespec ts;

    if (!st)
        return 0;
    if (!g_ready)
        ne_dp_idle_init();
    if (g_busy_poll) {
        sched_yield();
        return 0;
    }

    t = now_ns();
    if (!t) {
        cpu_relax();
        return 0;
    }
    if (!st->idle_start_ns)
        st->idle_start_ns = t;
    dt = t - st->idle_start_ns;

    if (dt < NE_DP_IDLE_HOT_NS) {
        cpu_relax();
        return 0;
    }
    if (dt < NE_DP_IDLE_COLD_NS) {
        ts.tv_sec = 0;
        ts.tv_nsec = NE_DP_IDLE_WARM_NS;
        nanosleep(&ts, NULL);
        return 0;
    }

    set_sleeping(wake_id, 1);
    return 1;
}

static void drain_eventfd(int fd)
{
    uint64_t v;

    if (fd < 0)
        return;
    while (read(fd, &v, sizeof(v)) == (ssize_t)sizeof(v))
        continue;
}

static void eventfd_signal(int fd)
{
    uint64_t one = 1;
    ssize_t n;

    if (fd < 0)
        return;
    n = write(fd, &one, sizeof(one));
    (void)n;
}

void ne_dp_idle_poll(int wake_id, const int *extra_fds, int extra_nfds)
{
    struct pollfd pfds[NE_DP_POLLFD_MAX + 1];
    int n = 0;
    int i;

    if (!g_ready)
        ne_dp_idle_init();
    if (g_busy_poll) {
        ne_dp_idle_disarm(wake_id);
        sched_yield();
        return;
    }

    if (wake_ok(wake_id) && g_efd[wake_id] >= 0) {
        pfds[n].fd = g_efd[wake_id];
        pfds[n].events = POLLIN;
        pfds[n].revents = 0;
        n++;
    }
    if (extra_fds) {
        for (i = 0; i < extra_nfds && n < (int)(sizeof(pfds) / sizeof(pfds[0])); i++) {
            if (extra_fds[i] < 0)
                continue;
            pfds[n].fd = extra_fds[i];
            pfds[n].events = POLLIN;
            pfds[n].revents = 0;
            n++;
        }
    }

    if (n > 0)
        (void)poll(pfds, (nfds_t)n, NE_DP_IDLE_POLL_MS);
    else {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000L };

        nanosleep(&ts, NULL);
    }

    if (wake_ok(wake_id))
        drain_eventfd(g_efd[wake_id]);
    ne_dp_idle_disarm(wake_id);
}

void ne_dp_idle_disarm(int wake_id)
{
    set_sleeping(wake_id, 0);
}

void ne_dp_idle_wake(int wake_id)
{
    if (!g_ready || g_busy_poll)
        return;
    if (!wake_ok(wake_id) || g_efd[wake_id] < 0)
        return;
    if (!atomic_load_explicit(&g_sleeping[wake_id], memory_order_acquire))
        return;
    eventfd_signal(g_efd[wake_id]);
}

void ne_dp_idle_wake_all(void)
{
    int i;

    if (!g_ready)
        return;
    for (i = 0; i < NE_DP_WAKE_N; i++) {
        if (g_efd[i] < 0)
            continue;
        atomic_store_explicit(&g_sleeping[i], 1, memory_order_release);
        eventfd_signal(g_efd[i]);
    }
}

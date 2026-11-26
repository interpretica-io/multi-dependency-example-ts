/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: small plain helpers of the hypothesis tests
 *
 * Runs a command through system() with stdout and stderr in a file under
 * /tmp, reads the file back, starts and stops a background process and
 * makes one raw TCP exchange. Nothing here returns before it has done what
 * it says, nothing skips, and every failing test puts the log text into the
 * message of its TEST_FAIL, so that the text reaches the report.
 *
 * @author midair <midair@localhost>
 */

#ifndef MDE_TSD_H
#define MDE_TSD_H

#include "te_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tapi_test.h"

/** Written by ts_build when it passed; read by the tests that need it. */
#define TSD_BUILD_MARK  "/tmp/mde-ts-build.passed"

/** Root of the project under test. */
static inline const char *
tsd_src(void)
{
    static char root[PATH_MAX];
    const char *e = getenv("TE_TS_MDE_SRC");

    if (access("/work/src", F_OK) == 0 || e == NULL || e[0] == '\0')
        return "/work/src";
    snprintf(root, sizeof(root), "%s", e);
    return root;
}

/** Monotonic time in milliseconds. */
static inline long long
tsd_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/** Read at most size - 1 bytes of the start of a file; returns the count. */
static inline size_t
tsd_head(const char *path, char *buf, size_t size)
{
    FILE   *f = fopen(path, "r");
    size_t  n = 0;

    buf[0] = '\0';
    if (f == NULL)
    {
        snprintf(buf, size, "(cannot read %s: %s)", path, strerror(errno));
        return strlen(buf);
    }
    n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n;
}

/** Read the last at most size - 1 bytes of a file. */
static inline size_t
tsd_tail(const char *path, char *buf, size_t size)
{
    FILE   *f = fopen(path, "r");
    size_t  n;
    long    len;

    buf[0] = '\0';
    if (f == NULL)
    {
        snprintf(buf, size, "(cannot read %s: %s)", path, strerror(errno));
        return strlen(buf);
    }
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    if (len > (long)(size - 1))
        fseek(f, len - (long)(size - 1), SEEK_SET);
    else
        fseek(f, 0, SEEK_SET);
    n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n;
}

/** Exit code of a wait status: the code, or 128 + the signal. */
static inline int
tsd_code(int st)
{
    if (st == -1)
        return -1;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}

/**
 * Run @p cmd with bash, from @p cwd, under timeout(1) for @p tmo seconds,
 * stdout and stderr in @p log. Returns the exit code (124 when the limit
 * was reached).
 */
static inline int
tsd_sh(const char *cwd, const char *cmd, int tmo, const char *log)
{
    char full[1024];

    setenv("TSD_CMD", cmd, 1);
    snprintf(full, sizeof(full),
             "cd '%s' && timeout -k 5 %d bash -c \"$TSD_CMD\" > '%s' 2>&1",
             cwd, tmo, log);
    return tsd_code(system(full));
}

/** Start @p cmd in the background, output in @p log; returns its pid. */
static inline pid_t
tsd_spawn(const char *cwd, const char *cmd, const char *log)
{
    pid_t pid = fork();

    if (pid == 0)
    {
        int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0644);

        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        setpgid(0, 0);
        if (fd >= 0)
        {
            dup2(fd, 1);
            dup2(fd, 2);
            close(fd);
        }
        if (cwd != NULL && chdir(cwd) != 0)
            _exit(126);
        execl("/bin/bash", "bash", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    return pid;
}

/** True while @p pid has not exited (the exit status is kept in @p st). */
static inline bool
tsd_alive(pid_t pid, int *st)
{
    int s = 0;
    pid_t r = waitpid(pid, &s, WNOHANG);

    if (r == 0)
        return true;
    if (r == pid && st != NULL)
        *st = s;
    return false;
}

/**
 * Send @p sig to @p pid and wait up to @p secs for it to end. Returns the
 * exit code, 128 + signal, or -2 when it was still there (then killed).
 */
static inline int
tsd_stop(pid_t pid, int sig, int secs)
{
    long long end = tsd_ms() + secs * 1000LL;
    int       st = 0;

    kill(pid, sig);
    while (tsd_ms() < end)
    {
        if (!tsd_alive(pid, &st))
            return tsd_code(st);
        usleep(50000);
    }
    kill(-pid, SIGKILL);
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    return -2;
}

/** Connect to 127.0.0.1:port; the descriptor, or -1. */
static inline int
tsd_connect(unsigned port)
{
    struct sockaddr_in sa = { .sin_family = AF_INET,
                              .sin_port = htons(port) };
    int                fd = socket(AF_INET, SOCK_STREAM, 0);

    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

/** Wait up to @p secs for something to accept connections on the port. */
static inline bool
tsd_wait_port(unsigned port, int secs)
{
    long long end = tsd_ms() + secs * 1000LL;

    while (tsd_ms() < end)
    {
        int fd = tsd_connect(port);

        if (fd >= 0)
        {
            close(fd);
            return true;
        }
        usleep(100000);
    }
    return false;
}

/**
 * Send @p req (@p reqlen bytes) to 127.0.0.1:port and read the reply until
 * the peer closes or @p tmo_ms passes. Returns the reply length, -1 when
 * the connect failed, 0 when nothing came back.
 */
static inline ssize_t
tsd_exchange(unsigned port, const char *req, size_t reqlen, int tmo_ms,
             char *out, size_t size)
{
    int       fd = tsd_connect(port);
    size_t    sent = 0;
    size_t    got = 0;
    long long end = tsd_ms() + tmo_ms;

    out[0] = '\0';
    if (fd < 0)
        return -1;
    while (sent < reqlen)
    {
        ssize_t n = send(fd, req + sent, reqlen - sent, MSG_NOSIGNAL);

        if (n <= 0)
            break;
        sent += n;
    }
    while (got < size - 1)
    {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        long long     left = end - tsd_ms();
        ssize_t       n;

        if (left <= 0 || poll(&p, 1, (int)left) <= 0)
            break;
        n = recv(fd, out + got, size - 1 - got, 0);
        if (n <= 0)
            break;
        got += n;
    }
    out[got] = '\0';
    close(fd);
    return (ssize_t)got;
}

/** Status code of an HTTP reply, or 0. */
static inline int
tsd_status(const char *reply)
{
    return strncmp(reply, "HTTP/1.", 7) == 0 ? atoi(reply + 9) : 0;
}

/** Body of an HTTP reply (after the blank line), or the whole text. */
static inline const char *
tsd_body(const char *reply)
{
    const char *p = strstr(reply, "\r\n\r\n");

    return p != NULL ? p + 4 : reply;
}

/** Fail unless the build of the group passed; says "blocked by H2". */
#define TSD_NEED_BUILD(_id) \
    do {                                                                \
        if (access(TSD_BUILD_MARK, R_OK) != 0)                          \
        {                                                               \
            RING_VERDICT("%s blocked by H2: ts_build did not pass "     \
                         "(no %s)", _id, TSD_BUILD_MARK);               \
            TEST_FAIL("%s blocked by H2: ts_build did not pass, so the "\
                      "TypeScript example was not built; see the "      \
                      "ts_build message", _id);                         \
        }                                                               \
    } while (0)

#endif /* MDE_TSD_H */

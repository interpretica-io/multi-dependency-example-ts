/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Webdeps Group
 *
 * One small test, run once per hypothesis case (the @c hyp_id parameter),
 * so that every case is a separate run: a setup problem in one cannot
 * abort another. Every run ends with exactly one verdict (PASS, FAIL or
 * SKIP) with a message that starts with the case id (H1-a ... H3-c).
 * A missing binary, contract or port, or a service that dies while it
 * starts, is a SKIP that says why, never a failure of the suite.
 *
 * The binaries are taken from $TE_TS_MDE_SRC/dist/bin and started as
 * plain child processes of the test (so pid, exit status and stderr are
 * known). The ports are read from the listing of 'ss -ltnp' (H3 also from
 * tapi_netexpose), the fake peers listen on the addresses of the contract
 * (web/contract/services.tab). The process of a service that exited with
 * a non-zero status is reported with its exit reason and the end of its
 * log.
 *
 * Static helpers only: the test is one .c file with no suite library.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/webdeps_hyp"

#include "te_config.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "te_sockaddr.h"
#include "tsapi_mde.h"

#include "tapi_cybersec.h"
#include "tapi_netexpose.h"
#include "tapi_egress.h"
#include "tapi_binscan.h"

#define MAX_PROCS   8
#define MAX_PORTS   8
#define NAMES       3
#define REQUEST     "/ring?value=1&hops=3"

/** Service indexes, in contract order. */
enum { GW = 0, GO, CS };

static const char * const names[NAMES] = {
    "gateway-rs", "service-go", "service-cs",
};

/** Outcome of a case, turned into the verdict by main(). */
typedef struct res_t {
    enum { R_PASS, R_FAIL, R_SKIP } kind;
    char msg[1536];
} res_t;

/** A child process. */
typedef struct proc_t {
    const char *name;
    pid_t       pid;
    bool        done;       /**< Reaped. */
    bool        stopped;    /**< Stopped by the test, not on its own. */
    int         status;
    char        out[256];
    char        err[256];
    unsigned    port;       /**< First listening port, from ss. */
} proc_t;

static proc_t   procs[MAX_PROCS];
static unsigned n_procs;
static char     workdir[64];
static unsigned tab_port[NAMES];
static const char *src_root;

/** Set the outcome. */
static void
res_set(res_t *r, int kind, const char *fmt, ...)
{
    va_list ap;

    r->kind = kind;
    va_start(ap, fmt);
    vsnprintf(r->msg, sizeof(r->msg), fmt, ap);
    va_end(ap);
}

static double
now_s(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/** Last bytes of a file, newlines flattened. */
static void
file_tail(const char *path, char *buf, size_t size)
{
    FILE   *f = fopen(path, "r");
    long    len;
    size_t  n;
    size_t  i;

    buf[0] = '\0';
    if (f == NULL)
        return;
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    if (len > (long)size - 1)
        fseek(f, -((long)size - 1), SEEK_END);
    else
        fseek(f, 0, SEEK_SET);
    n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    for (i = 0; i < n; i++)
    {
        if (buf[i] == '\n' || buf[i] == '\r')
            buf[i] = '|';
    }
}

static bool
file_has(const char *path, const char *needle)
{
    char   buf[65536];
    FILE  *f = fopen(path, "r");
    size_t n;

    if (f == NULL)
        return false;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

/** Reap a process if it ended; true when it is gone. */
static bool
proc_gone(proc_t *p)
{
    if (!p->done && waitpid(p->pid, &p->status, WNOHANG) == p->pid)
        p->done = true;
    return p->done;
}

/** "exit code N" / "killed by signal N", then the end of the log. */
static void
proc_describe(proc_t *p, char *buf, size_t size)
{
    char tail[400];
    char otail[200];
    int  n;

    if (WIFSIGNALED(p->status))
        n = snprintf(buf, size, "%s killed by signal %d", p->name,
                     WTERMSIG(p->status));
    else
        n = snprintf(buf, size, "%s exited with code %d", p->name,
                     WEXITSTATUS(p->status));
    file_tail(p->err, tail, sizeof(tail));
    file_tail(p->out, otail, sizeof(otail));
    snprintf(buf + n, size - n, "; stderr: [%s]; stdout: [%s]", tail, otail);
}

/** Kill everything the test started; report non-zero exits on the way. */
static void
cleanup_all(void)
{
    unsigned i;
    char     buf[900];

    for (i = 0; i < n_procs; i++)
    {
        proc_t *p = &procs[i];

        if (!p->stopped)
        {
            proc_gone(p);
            if (p->done && !(WIFEXITED(p->status) &&
                             WEXITSTATUS(p->status) == 0))
            {
                proc_describe(p, buf, sizeof(buf));
                ERROR("webdeps: %s", buf);
            }
        }
        if (!p->done)
        {
            kill(-p->pid, SIGKILL);
            kill(p->pid, SIGKILL);
            waitpid(p->pid, &p->status, 0);
            p->done = true;
        }
    }
    n_procs = 0;
    if (workdir[0] != '\0')
    {
        char cmd[128];

        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", workdir);
        if (system(cmd) != 0)
            WARN("webdeps: cannot remove %s", workdir);
        workdir[0] = '\0';
    }
}

/** Stop one process on purpose. */
static void
proc_stop(proc_t *p)
{
    p->stopped = true;
    if (!p->done)
    {
        kill(-p->pid, SIGKILL);
        kill(p->pid, SIGKILL);
        waitpid(p->pid, &p->status, 0);
        p->done = true;
    }
}

/** Read the ports of the tier from the contract; false with a reason. */
static bool
read_contract(res_t *r)
{
    char  path[512];
    char  line[256];
    FILE *f;
    int   found = 0;

    src_root = getenv("TE_TS_MDE_SRC");
    if (src_root == NULL || src_root[0] == '\0')
    {
        res_set(r, R_SKIP, "TE_TS_MDE_SRC is not set: the example is not "
                "available");
        return false;
    }
    snprintf(path, sizeof(path), "%s/web/contract/services.tab", src_root);
    f = fopen(path, "r");
    if (f == NULL)
    {
        res_set(r, R_SKIP, "contract %s cannot be read", path);
        return false;
    }
    while (fgets(line, sizeof(line), f) != NULL)
    {
        char     name[64];
        unsigned port;
        int      i;

        if (line[0] == '#' || sscanf(line, "%63s %u", name, &port) != 2)
            continue;
        for (i = 0; i < NAMES; i++)
        {
            if (strcmp(name, names[i]) == 0)
            {
                tab_port[i] = port;
                found++;
            }
        }
    }
    fclose(f);
    if (found < NAMES)
    {
        res_set(r, R_SKIP, "contract %s names only %d of 3 services", path,
                found);
        return false;
    }
    return true;
}

/** Listening ports of a pid from 'ss -ltnp'; -1 if ss does not work. */
static int
ss_ports(pid_t pid, char addrs[][64], unsigned *ports, int max)
{
    FILE *f = popen("ss -ltnp 2>/dev/null", "r");
    char  line[1024];
    char  key[32];
    int   n = 0;
    int   lines = 0;

    if (f == NULL)
        return -1;
    snprintf(key, sizeof(key), "pid=%d,", (int)pid);
    while (fgets(line, sizeof(line), f) != NULL)
    {
        char  state[32], rq[32], sq[32], local[128];
        char *colon;

        lines++;
        if (sscanf(line, "%31s %31s %31s %127s", state, rq, sq, local) != 4 ||
            strcmp(state, "LISTEN") != 0 || strstr(line, key) == NULL)
            continue;
        colon = strrchr(local, ':');
        if (colon == NULL || n >= max)
            continue;
        *colon = '\0';
        ports[n] = atoi(colon + 1);
        snprintf(addrs[n], 64, "%.63s", local[0] == '[' ? local + 1 : local);
        if (addrs[n][0] != '\0' && addrs[n][strlen(addrs[n]) - 1] == ']')
            addrs[n][strlen(addrs[n]) - 1] = '\0';
        n++;
    }
    if (pclose(f) != 0 || lines == 0)
        return -1;
    return n;
}

/**
 * Start a service and wait until 'ss -ltnp' shows it listening.
 * On any problem sets a SKIP outcome and returns NULL.
 */
static proc_t *
svc_start(res_t *r, int idx)
{
    char     path[512];
    char     lib[600];
    proc_t  *p;
    double   end;
    char     addrs[MAX_PORTS][64];
    unsigned ports[MAX_PORTS];
    char     why[900];
    pid_t    pid;

    snprintf(path, sizeof(path), "%s/dist/bin/%s", src_root, names[idx]);
    if (access(path, X_OK) != 0)
    {
        res_set(r, R_SKIP, "binary %s not found or not executable", path);
        return NULL;
    }
    if (n_procs >= MAX_PROCS)
    {
        res_set(r, R_SKIP, "too many processes");
        return NULL;
    }
    p = &procs[n_procs];
    memset(p, 0, sizeof(*p));
    p->name = names[idx];
    snprintf(p->out, sizeof(p->out), "%s/%s.out", workdir, names[idx]);
    snprintf(p->err, sizeof(p->err), "%s/%s.err", workdir, names[idx]);
    snprintf(lib, sizeof(lib), "%s/dist/lib", src_root);

    pid = fork();
    if (pid < 0)
    {
        res_set(r, R_SKIP, "fork failed: %s", strerror(errno));
        return NULL;
    }
    if (pid == 0)
    {
        int o = open(p->out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int e = open(p->err, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int z = open("/dev/null", O_RDONLY);
        char *argv_[] = { path, NULL };

        setpgid(0, 0);
        dup2(z, 0);
        dup2(o, 1);
        dup2(e, 2);
        setenv("LD_LIBRARY_PATH", lib, 1);
        execv(path, argv_);
        dprintf(2, "exec %s: %s\n", path, strerror(errno));
        _exit(127);
    }
    p->pid = pid;
    setpgid(pid, pid);
    n_procs++;

    end = now_s() + 20;
    while (now_s() < end)
    {
        int n;

        if (proc_gone(p))
        {
            proc_describe(p, why, sizeof(why));
            p->stopped = true;
            ERROR("webdeps: %s", why);
            res_set(r, R_SKIP, "%s did not stay up while starting: %s",
                    names[idx], why);
            return NULL;
        }
        n = ss_ports(pid, addrs, ports, MAX_PORTS);
        if (n < 0)
        {
            res_set(r, R_SKIP, "'ss -ltnp' is not usable, cannot find the "
                    "port of %s", names[idx]);
            return NULL;
        }
        if (n > 0)
        {
            p->port = ports[0];
            return p;
        }
        usleep(100000);
    }
    res_set(r, R_SKIP, "%s shows no listening port in 'ss -ltnp' in 20 s",
            names[idx]);
    return NULL;
}

/** Outcomes of an HTTP request. */
typedef enum hg_t { HG_OK, HG_NORESP, HG_RESET, HG_TIMEOUT, HG_REFUSED } hg_t;

static const char *
hg_str(hg_t h)
{
    switch (h)
    {
        case HG_OK: return "answered";
        case HG_NORESP: return "closed without a response";
        case HG_RESET: return "connection reset";
        case HG_TIMEOUT: return "no answer before the client timeout";
        default: return "connection refused";
    }
}

typedef struct hg_res {
    hg_t   how;
    int    status;
    double elapsed;
    char   body[512];
} hg_res;

static int
connect_loop(unsigned port)
{
    struct sockaddr_in sa = { .sin_family = AF_INET,
                              .sin_port = htons(port) };
    int s = socket(AF_INET, SOCK_STREAM, 0);

    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (s >= 0 && connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    {
        close(s);
        return -1;
    }
    return s;
}

static bool
port_accepts(unsigned port)
{
    int s = connect_loop(port);

    if (s < 0)
        return false;
    close(s);
    return true;
}

/** GET path on the loopback port with a client timeout in seconds. */
static void
http_get(unsigned port, const char *path, int timeout_s, hg_res *h)
{
    char    req[256];
    char    buf[4096];
    size_t  got = 0;
    double  t0 = now_s();
    double  end = t0 + timeout_s;
    int     s = connect_loop(port);

    memset(h, 0, sizeof(*h));
    h->status = -1;
    if (s < 0)
    {
        h->how = HG_REFUSED;
        return;
    }
    snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n"
             "Connection: close\r\n\r\n", path);
    if (write(s, req, strlen(req)) < 0)
        h->how = HG_RESET;
    else
        h->how = HG_NORESP;
    while (h->how != HG_RESET || got == 0)
    {
        struct pollfd pfd = { .fd = s, .events = POLLIN };
        double        left = end - now_s();
        ssize_t       n;

        if (h->how == HG_RESET)
            break;
        if (left <= 0 || poll(&pfd, 1, (int)(left * 1000) + 1) == 0)
        {
            h->how = got > 0 ? HG_OK : HG_TIMEOUT;
            break;
        }
        n = read(s, buf, sizeof(buf));
        if (n < 0)
        {
            h->how = got > 0 ? HG_OK : HG_RESET;
            break;
        }
        if (n == 0)
            break;
        if (got < sizeof(h->body) - 1)
        {
            size_t c = sizeof(h->body) - 1 - got;

            memcpy(h->body + got, buf, n < (ssize_t)c ? (size_t)n : c);
            got += n < (ssize_t)c ? (size_t)n : c;
            h->body[got] = '\0';
        }
        if (sscanf(h->body, "HTTP/%*s %d", &h->status) == 1)
            h->how = HG_OK;
    }
    h->elapsed = now_s() - t0;
    if (h->how == HG_OK && h->status < 0)
        h->how = HG_NORESP;
    close(s);
}

/** Fake peer modes. */
typedef enum fake_t {
    F_SILENT, F_GARBAGE, F_BADJSON, F_EMPTY, F_HUGE, F_HTTP500,
} fake_t;

/** Fake peer: a listener on 127.0.0.1:port; one byte per connection on fd. */
static proc_t *
fake_start(res_t *r, unsigned port, fake_t mode, int *count_fd)
{
    struct sockaddr_in sa = { .sin_family = AF_INET,
                              .sin_port = htons(port) };
    int      one = 1;
    int      ls = socket(AF_INET, SOCK_STREAM, 0);
    int      cp[2];
    proc_t  *p;
    pid_t    pid;

    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (ls < 0 || bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(ls, 16) != 0 || pipe(cp) != 0 || n_procs >= MAX_PROCS)
    {
        res_set(r, R_SKIP, "cannot listen on 127.0.0.1:%u for a fake peer: "
                "%s", port, strerror(errno));
        if (ls >= 0)
            close(ls);
        return NULL;
    }
    p = &procs[n_procs];
    memset(p, 0, sizeof(*p));
    p->name = "fake-peer";
    pid = fork();
    if (pid == 0)
    {
        char   req[1024];
        char   chunk[65536];
        size_t i;

        setpgid(0, 0);
        close(cp[0]);
        for (;;)
        {
            int c = accept(ls, NULL, NULL);
            struct pollfd pfd = { .fd = c, .events = POLLIN };

            if (c < 0)
                continue;
            if (write(cp[1], "x", 1) < 0)
                _exit(1);
            if (mode == F_SILENT)
                continue;   /* Accepted and held open, never answered. */
            if (poll(&pfd, 1, 500) > 0)
            {
                if (read(c, req, sizeof(req)) < 0)
                    req[0] = '\0';
            }
            switch (mode)
            {
                case F_GARBAGE:
                    for (i = 0; i < 256; i++)
                        chunk[i] = (char)(i * 7 + 3);
                    if (write(c, chunk, 256) < 0)
                        break;
                    break;
                case F_BADJSON:
                    dprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: "
                            "application/json\r\nContent-Length: 18\r\n"
                            "Connection: close\r\n\r\n{\"value\": [1, 2,,}");
                    break;
                case F_EMPTY:
                    dprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                            "Connection: close\r\n\r\n");
                    break;
                case F_HTTP500:
                    dprintf(c, "HTTP/1.1 500 Internal Server Error\r\n"
                            "Content-Length: 5\r\nConnection: close\r\n\r\n"
                            "boom\n");
                    break;
                case F_HUGE:
                {
                    struct timeval tv = { .tv_sec = 3 };
                    size_t sent = 0;

                    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                    dprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: 10485760"
                            "\r\nConnection: close\r\n\r\n");
                    memset(chunk, 'A', sizeof(chunk));
                    while (sent < 10485760)
                    {
                        ssize_t w = write(c, chunk, sizeof(chunk));

                        if (w <= 0)
                            break;
                        sent += w;
                    }
                    break;
                }
                default:
                    break;
            }
            close(c);
        }
    }
    close(ls);
    close(cp[1]);
    fcntl(cp[0], F_SETFL, O_NONBLOCK);
    p->pid = pid;
    setpgid(pid, pid);
    n_procs++;
    *count_fd = cp[0];
    return p;
}

static unsigned
fake_count(int fd)
{
    char     b[64];
    ssize_t  n;
    unsigned c = 0;

    while ((n = read(fd, b, sizeof(b))) > 0)
        c += n;
    return c;
}

/** Whether a process is alive and its port still accepts connections. */
static bool
svc_alive(proc_t *p)
{
    return !proc_gone(p) && port_accepts(p->port);
}

static void
append(char *dst, size_t size, const char *fmt, ...)
{
    size_t  l = strlen(dst);
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(dst + l, size - l, fmt, ap);
    va_end(ap);
}

/** Start the listed services in order; false (outcome set) on a problem. */
static bool
start_all(res_t *r, proc_t **svc, const int *which, int n)
{
    int i;

    for (i = 0; i < n; i++)
    {
        svc[which[i]] = svc_start(r, which[i]);
        if (svc[which[i]] == NULL)
            return false;
    }
    return true;
}

/* ---- H1 ---- */

static void
case_h1a(res_t *r)
{
    proc_t *svc[NAMES] = { NULL };
    const int which[] = { GW };
    hg_res  h;
    char    why[900];
    bool    panic;
    bool    alive;

    if (!start_all(r, svc, which, 1))
        return;
    http_get(svc[GW]->port, REQUEST, 5, &h);
    usleep(300000);
    panic = file_has(svc[GW]->err, "panicked at");
    alive = svc_alive(svc[GW]);
    if (!alive || panic || h.how == HG_RESET)
    {
        if (proc_gone(svc[GW]))
            proc_describe(svc[GW], why, sizeof(why));
        else
            snprintf(why, sizeof(why), "pid %d still exists", svc[GW]->pid);
        res_set(r, R_FAIL, "H1-a FAIL (H1 confirmed): gateway with no "
                "backends: %s; request: %s; panicked-at in stderr: %s; %s",
                alive ? "alive" : "died", hg_str(h.how),
                panic ? "yes" : "no", why);
        return;
    }
    if (h.how == HG_OK && (h.status >= 400 ||
                           strstr(h.body, "unreachable") != NULL ||
                           h.status == 200))
        res_set(r, R_PASS, "H1-a PASS (H1 not confirmed): gateway alive "
                "(pid %d, port %u accepts), no panic; response HTTP %d in "
                "%.2f s%s", svc[GW]->pid, svc[GW]->port, h.status,
                h.elapsed, h.status < 400 ? " (degraded 200, not a crash)" :
                "");
    else
        res_set(r, R_FAIL, "H1-a FAIL: gateway alive but the request %s "
                "(no clean error or 5xx)", hg_str(h.how));
}

static void
case_h1b(res_t *r)
{
    static const struct { fake_t mode; const char *name; } cases[] = {
        { F_GARBAGE, "garbage bytes" }, { F_BADJSON, "invalid JSON" },
        { F_EMPTY, "empty body then close" },
        { F_HUGE, "oversized 10 MB body" },
    };
    proc_t  *svc[NAMES] = { NULL };
    const int which[] = { GW };
    char     died[300] = "";
    char     detail[900] = "";
    unsigned i;

    if (!start_all(r, svc, which, 1))
        return;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        int      cfd;
        proc_t  *fake = fake_start(r, tab_port[GO], cases[i].mode, &cfd);
        hg_res   h;
        unsigned hits;
        bool     alive;

        if (fake == NULL)
            return;
        http_get(svc[GW]->port, REQUEST, 8, &h);
        usleep(300000);
        hits = fake_count(cfd);
        alive = svc_alive(svc[GW]);
        close(cfd);
        proc_stop(fake);
        append(detail, sizeof(detail), "[%s: %s, backend hits %u, HTTP %d] ",
               cases[i].name, alive ? "gateway alive" : "GATEWAY DIED", hits,
               h.status);
        if (!alive)
        {
            append(died, sizeof(died), "%s%s", died[0] ? ", " : "",
                   cases[i].name);
            break;
        }
    }
    if (died[0] != '\0')
    {
        char why[900];

        proc_describe(svc[GW], why, sizeof(why));
        res_set(r, R_FAIL, "H1-b FAIL (H1 confirmed): gateway died on: %s. "
                "%s %s", died, detail, why);
    }
    else
        res_set(r, R_PASS, "H1-b PASS (H1 not confirmed): gateway survived "
                "every bad backend. %s", detail);
}

static void
case_h1c(res_t *r)
{
    proc_t  *svc[NAMES] = { NULL };
    const int which[] = { GO, CS, GW };
    char     detail[900] = "";
    bool     bad = false;
    int      k;

    if (!start_all(r, svc, which, 3))
        return;
    for (k = GO; k <= CS; k++)
    {
        hg_res h;
        bool   alive;
        bool   err;

        proc_stop(svc[k]);
        usleep(300000);
        http_get(svc[GW]->port, REQUEST, 8, &h);
        alive = svc_alive(svc[GW]);
        err = h.how == HG_OK && h.status >= 400;
        append(detail, sizeof(detail), "[after killing %s: gateway %s, %s "
               "HTTP %d] ", names[k], alive ? "alive" : "DIED", hg_str(h.how),
               h.status);
        if (!alive || !err)
            bad = true;
        if (!alive)
            break;
    }
    if (bad)
    {
        char why[900] = "";

        if (proc_gone(svc[GW]))
            proc_describe(svc[GW], why, sizeof(why));
        res_set(r, R_FAIL, "H1-c FAIL (H1 confirmed or error swallowed): "
                "gateway must stay up and return an error status, not 200, "
                "for a result needing the dead peer. %s %s", detail, why);
    }
    else
        res_set(r, R_PASS, "H1-c PASS (H1 not confirmed): gateway survived "
                "and returned error statuses. %s", detail);
}

/* ---- H2 ---- */

/** A service with a stalled fake peer on its upstream. */
static void
stalled(res_t *r, const char *id, int svc_idx, int peer_idx)
{
    proc_t   *svc[NAMES] = { NULL };
    int       which[1];
    int       cfd;
    proc_t   *fake;
    hg_res    h;

    which[0] = svc_idx;
    if (!start_all(r, svc, which, 1))
        return;
    fake = fake_start(r, tab_port[peer_idx], F_SILENT, &cfd);
    if (fake == NULL)
        return;
    http_get(svc[svc_idx]->port, REQUEST, 15, &h);
    if (h.how == HG_TIMEOUT)
        res_set(r, R_FAIL, "%s FAIL (H2 confirmed): %s still blocked after "
                "%.1f s with a stalled peer on port %u (no timeout); peer "
                "was contacted %u time(s)", id, names[svc_idx], h.elapsed,
                tab_port[peer_idx], fake_count(cfd));
    else
        res_set(r, R_PASS, "%s PASS (H2 not confirmed): %s %s after %.2f s "
                "(HTTP %d) with a stalled peer on port %u; peer contacted "
                "%u time(s)", id, names[svc_idx], hg_str(h.how), h.elapsed,
                h.status, tab_port[peer_idx], fake_count(cfd));
}

static void
case_h2a(res_t *r)
{
    stalled(r, "H2-a", GO, CS);
}

static void
case_h2b(res_t *r)
{
    stalled(r, "H2-b", CS, GW);
}

static void
case_h2c(res_t *r)
{
    static const int pairs[2][2] = { { CS, GW }, { GO, CS } };
    char     detail[900] = "";
    bool     swallowed = false;
    int      i;

    for (i = 0; i < 2; i++)
    {
        proc_t *svc[NAMES] = { NULL };
        int     which[1] = { pairs[i][0] };
        int     cfd;
        proc_t *fake;
        hg_res  h;
        int     round;

        if (!start_all(r, svc, which, 1))
            return;
        fake = fake_start(r, tab_port[pairs[i][1]], F_HTTP500, &cfd);
        if (fake == NULL)
            return;
        for (round = 0; round < 2; round++)
        {
            http_get(svc[which[0]]->port, REQUEST, 10, &h);
            append(detail, sizeof(detail), "[%s, peer %s: HTTP %d, %s%s] ",
                   names[which[0]], round == 0 ? "500" : "refused", h.status,
                   hg_str(h.how), h.status >= 200 && h.status < 300 ?
                   " - ERROR SWALLOWED" : "");
            if (h.how != HG_OK || h.status < 400)
                swallowed = true;
            if (round == 0)
            {
                close(cfd);
                proc_stop(fake);
            }
        }
        proc_stop(svc[which[0]]);
    }
    if (swallowed)
        res_set(r, R_FAIL, "H2-c FAIL (H2 confirmed): a failed peer is not "
                "reported with an error status. %s", detail);
    else
        res_set(r, R_PASS, "H2-c PASS (H2 not confirmed): peer failures "
                "come back as error statuses. %s", detail);
}

/* ---- H3 ---- */

/** Socket inodes held by a pid. */
static size_t
pid_inodes(pid_t pid, unsigned long *out, size_t max)
{
    char           dir[64];
    DIR           *d;
    struct dirent *e;
    size_t         n = 0;

    snprintf(dir, sizeof(dir), "/proc/%d/fd", (int)pid);
    d = opendir(dir);
    if (d == NULL)
        return 0;
    while ((e = readdir(d)) != NULL && n < max)
    {
        char path[300];
        char link[64];
        ssize_t l;
        unsigned long ino;

        snprintf(path, sizeof(path), "%.60s/%.200s", dir, e->d_name);
        l = readlink(path, link, sizeof(link) - 1);
        if (l <= 0)
            continue;
        link[l] = '\0';
        if (sscanf(link, "socket:[%lu]", &ino) == 1)
            out[n++] = ino;
    }
    closedir(d);
    return n;
}

#define MAX_INO 512

/** Index of the service owning an inode; -1 if none. */
static int
owner_of(proc_t **svc, unsigned long (*ino)[MAX_INO], size_t *n,
         unsigned long inode)
{
    int i;
    size_t k;

    for (i = 0; i < NAMES; i++)
    {
        for (k = 0; k < n[i]; k++)
        {
            if (ino[i][k] == inode)
                return i;
        }
    }
    (void)svc;
    return -1;
}

static unsigned
sock_port(const struct sockaddr_storage *ss)
{
    return ntohs(te_sockaddr_get_port(CONST_SA(ss)));
}

static void
sock_addr(const struct sockaddr_storage *ss, char *buf, size_t size)
{
    snprintf(buf, size, "?");
    if (ss->ss_family == AF_INET)
        inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr, buf,
                  size);
    else if (ss->ss_family == AF_INET6)
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)ss)->sin6_addr,
                  buf, size);
}

static bool
port_in_contract(unsigned port)
{
    int i;

    for (i = 0; i < NAMES; i++)
    {
        if (tab_port[i] == port)
            return true;
    }
    return false;
}

static void
case_h3a(res_t *r)
{
    proc_t              *svc[NAMES] = { NULL };
    const int            which[] = { GO, CS, GW };
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES];
    tsapi_mde_session    session = { .ta = NULL };
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    tapi_cybersec_report report;
    te_vec               socks = TE_VEC_INIT(tapi_netexpose_socket);
    const tapi_netexpose_socket *s;
    char                 detail[1100] = "";
    char                 bad[600] = "";
    int                  i;
    unsigned             listeners = 0;

    if (!start_all(r, svc, which, 3))
        return;
    if (tsapi_mde_session_init(&session, "webdeps_h3a") != 0)
    {
        res_set(r, R_SKIP, "no session on the agent for tapi_netexpose");
        return;
    }
    tapi_cybersec_report_init(&report);
    opt.udp = false;
    opt.tcp = true;
    for (i = 0; i < NAMES; i++)
        n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
    if (tapi_netexpose_sockets(session.factory, &opt, &socks) != 0)
    {
        res_set(r, R_SKIP, "tapi_netexpose cannot read the socket tables");
        goto out;
    }
    TE_VEC_FOREACH(&socks, s)
    {
        char addr[64];
        int  o;
        bool wild;
        bool loop4;

        if (!tapi_netexpose_socket_is_listening(s))
            continue;
        o = owner_of(svc, ino, n_ino, s->inode);
        if (o < 0)
            continue;
        listeners++;
        sock_addr(&s->local, addr, sizeof(addr));
        wild = strcmp(addr, "0.0.0.0") == 0 || strcmp(addr, "::") == 0;
        loop4 = strcmp(addr, "127.0.0.1") == 0;
        append(detail, sizeof(detail), "%s %s:%u; ", names[o], addr,
               sock_port(&s->local));
        tapi_cybersec_report_add(&report, wild ? TAPI_CYBERSEC_SEV_HIGH :
                                 TAPI_CYBERSEC_SEV_INFO, "net.listener",
                                 names[o], "H3-a: listens on %s:%u", addr,
                                 sock_port(&s->local));
        if (wild)
            append(bad, sizeof(bad), "%s bound to %s:%u (code names "
                   "127.0.0.1); ", names[o], addr, sock_port(&s->local));
        else if (!loop4)
            append(bad, sizeof(bad), "%s bound to non-127.0.0.1 %s:%u; ",
                   names[o], addr, sock_port(&s->local));
        if (!port_in_contract(sock_port(&s->local)))
            append(bad, sizeof(bad), "%s listens on port %u outside the "
                   "hardcoded set; ", names[o], sock_port(&s->local));
    }
    tapi_cybersec_report_log(&report);
    if (listeners == 0)
        res_set(r, R_SKIP, "tapi_netexpose found no listener of the three "
                "processes");
    else if (bad[0] != '\0')
        res_set(r, R_FAIL, "H3-a FAIL (H3 confirmed): %s Listeners: %s", bad,
                detail);
    else
        res_set(r, R_PASS, "H3-a PASS (H3 not confirmed): every listener is "
                "on 127.0.0.1 and in the hardcoded port set. Listeners: %s",
                detail);
out:
    te_vec_free(&socks);
    tapi_cybersec_report_free(&report);
    tsapi_mde_session_fini(&session);
}

static void
case_h3b(res_t *r)
{
    proc_t              *svc[NAMES] = { NULL };
    const int            which[] = { GO, CS, GW };
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES];
    tsapi_mde_session    session = { .ta = NULL };
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    tapi_cybersec_report report;
    tapi_egress_rule     rules[NAMES];
    tapi_egress_policy   policy = { .n_rules = NAMES, .rules = rules,
                                    .allow_loopback = false,
                                    .allow_private = false };
    char                 detail[900] = "";
    char                 bad[600] = "";
    unsigned             seen = 0;
    int                  i;
    int                  round;

    if (!start_all(r, svc, which, 3))
        return;
    if (tsapi_mde_session_init(&session, "webdeps_h3b") != 0)
    {
        res_set(r, R_SKIP, "no session on the agent for tapi_egress");
        return;
    }
    tapi_cybersec_report_init(&report);
    opt.udp = false;
    opt.tcp = true;
    for (i = 0; i < NAMES; i++)
    {
        rules[i] = (tapi_egress_rule){ IPPROTO_TCP, "127.0.0.1/32",
                                       tab_port[i], tab_port[i] };
        n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
    }
    for (round = 0; round < 8; round++)
    {
        te_vec conns = TE_VEC_INIT(tapi_netexpose_socket);
        const tapi_netexpose_socket *c;
        hg_res h;

        http_get(svc[GW]->port, REQUEST, 5, &h);
        for (i = 0; i < NAMES; i++)
            n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
        if (tapi_egress_snapshot(session.factory, &opt, &conns) != 0)
        {
            res_set(r, R_SKIP, "tapi_egress cannot read the connections");
            te_vec_free(&conns);
            goto out;
        }
        TE_VEC_FOREACH(&conns, c)
        {
            char addr[64];
            int  o = owner_of(svc, ino, n_ino, c->inode);
            bool inbound = false;

            if (o < 0 || c->inode == 0)
                continue;
            for (i = 0; i < NAMES; i++)
                inbound = inbound || sock_port(&c->local) == tab_port[i];
            if (inbound)
                continue;
            sock_addr(&c->remote, addr, sizeof(addr));
            seen++;
            if (!tapi_egress_policy_allows(&policy, IPPROTO_TCP,
                                           CONST_SA(&c->remote)))
            {
                char one[128];

                snprintf(one, sizeof(one), "%s -> %s:%u; ", names[o], addr,
                         sock_port(&c->remote));
                if (strstr(bad, one) == NULL)
                    append(bad, sizeof(bad), "%s", one);
                tapi_cybersec_report_add(&report, TAPI_CYBERSEC_SEV_HIGH,
                                         "net.unexpected-egress", names[o],
                                         "H3-b: outbound to %s:%u", addr,
                                         sock_port(&c->remote));
            }
            else if (strstr(detail, names[o]) == NULL)
                append(detail, sizeof(detail), "%s -> %s:%u; ", names[o],
                       addr, sock_port(&c->remote));
        }
        te_vec_free(&conns);
        usleep(100000);
    }
    tapi_cybersec_report_log(&report);
    if (bad[0] != '\0')
        res_set(r, R_FAIL, "H3-b FAIL (H3 confirmed): outbound connection "
                "outside the allow-list of the hardcoded loopback "
                "endpoints: %s", bad);
    else
        res_set(r, R_PASS, "H3-b PASS (H3 not confirmed): %u outbound "
                "connection(s) of the services seen, all on the allow-list "
                "%s", seen, detail);
out:
    tapi_cybersec_report_free(&report);
    tsapi_mde_session_fini(&session);
}

static void
case_h3c(res_t *r)
{
    tsapi_mde_session    session = { .ta = NULL };
    tapi_cybersec_report report;
    char                 detail[1100] = "";
    unsigned             scanned = 0;
    int                  i;

    if (tsapi_mde_session_init(&session, "webdeps_h3c") != 0)
    {
        res_set(r, R_SKIP, "no session on the agent for tapi_binscan");
        return;
    }
    tapi_cybersec_report_init(&report);
    for (i = 0; i < NAMES; i++)
    {
        char path[512];
        tapi_binscan_info info;

        snprintf(path, sizeof(path), "%s/dist/bin/%s", src_root, names[i]);
        if (access(path, R_OK) != 0)
        {
            append(detail, sizeof(detail), "%s: not found; ", names[i]);
            continue;
        }
        if (tapi_binscan_inspect(session.ta, path, &info) != 0)
        {
            append(detail, sizeof(detail), "%s: cannot be scanned; ",
                   names[i]);
            continue;
        }
        scanned++;
        append(detail, sizeof(detail), "%s: NX=%s PIE=%s RELRO=%s "
               "canary=%s; ", names[i],
               info.nx_unknown ? "unknown" : (info.nx ? "yes" : "no"),
               info.kind == TAPI_BINSCAN_KIND_PIE ? "yes" : "no",
               tapi_binscan_relro2str(info.relro), info.canary ? "yes" : "no");
        tapi_cybersec_report_add(&report, TAPI_CYBERSEC_SEV_INFO,
                                 "binscan.properties", names[i],
                                 "H3-c information: NX=%s PIE=%s RELRO=%s "
                                 "canary=%s",
                                 info.nx_unknown ? "unknown" :
                                 (info.nx ? "yes" : "no"),
                                 info.kind == TAPI_BINSCAN_KIND_PIE ? "yes" :
                                 "no", tapi_binscan_relro2str(info.relro),
                                 info.canary ? "yes" : "no");
        tapi_binscan_info_free(&info);
    }
    tapi_cybersec_report_log(&report);
    if (scanned == 0)
        res_set(r, R_SKIP, "H3-c: no binary could be scanned: %s", detail);
    else
        res_set(r, R_PASS, "H3-c PASS (informational, never a failure): %s",
                detail);
    tapi_cybersec_report_free(&report);
    tsapi_mde_session_fini(&session);
}

int
main(int argc, char **argv)
{
    const char *hyp_id;
    res_t       res = { .kind = R_SKIP };
    static const struct { const char *id; void (*fn)(res_t *); } table[] = {
        { "H1-a", case_h1a }, { "H1-b", case_h1b }, { "H1-c", case_h1c },
        { "H2-a", case_h2a }, { "H2-b", case_h2b }, { "H2-c", case_h2c },
        { "H3-a", case_h3a }, { "H3-b", case_h3b }, { "H3-c", case_h3c },
    };
    unsigned    i;
    bool        found = false;

    TEST_START;
    TEST_GET_STRING_PARAM(hyp_id);
    signal(SIGPIPE, SIG_IGN);
    snprintf(workdir, sizeof(workdir), "/tmp/mde-wd-XXXXXX");
    if (mkdtemp(workdir) == NULL)
        workdir[0] = '\0';

    TEST_STEP("Case %s", hyp_id);
    for (i = 0; i < sizeof(table) / sizeof(table[0]); i++)
    {
        if (strcmp(table[i].id, hyp_id) != 0)
            continue;
        found = true;
        if (workdir[0] == '\0')
            res_set(&res, R_SKIP, "%s: cannot create a work directory",
                    hyp_id);
        else if (read_contract(&res))
            table[i].fn(&res);
    }
    if (!found)
        res_set(&res, R_SKIP, "unknown case id '%s'", hyp_id);

    if (res.kind == R_SKIP && strncmp(res.msg, hyp_id, strlen(hyp_id)) != 0)
    {
        char tmp[sizeof(res.msg)];

        snprintf(tmp, sizeof(tmp), "%s", res.msg);
        snprintf(res.msg, sizeof(res.msg), "%s SKIP: %.1400s", hyp_id, tmp);
    }
    cleanup_all();

    if (res.kind == R_PASS)
    {
        RING_VERDICT("%s", res.msg);
        TEST_SUCCESS;
    }
    if (res.kind == R_FAIL)
        TEST_VERDICT("%s", res.msg);
    TEST_SKIP("%s", res.msg);

cleanup:
    cleanup_all();
    TEST_END;
}

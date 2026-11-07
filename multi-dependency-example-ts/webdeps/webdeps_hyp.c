/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Webdeps Group
 *
 * One small test, run once per test name (the @c hyp_id parameter), so that
 * every run is independent. Every run ends with exactly one verdict whose
 * text names the test and carries the explicit hypothesis verdict
 * (H1:pass, H1:fail, H2:pass, H2:fail, H3:pass, H3:fail, H<n>:setup-error).
 * A missing binary, contract or port, or a service that dies while it
 * starts, is a distinct FAIL named setup_<component>, never a finding. The
 * exit code and the first 2 KB of stderr of every spawned process are
 * logged.
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
#define START_WAIT  5       /**< s to wait for a port to accept TCP. */
#define PROBE_TO    3       /**< s, client timeout of every probe. */
#define STALL_LIMIT 10      /**< s, H2 stall verdict limit. */

/** Service indexes, in contract order. */
enum { GW = 0, GO, CS };

static const char * const names[NAMES] = {
    "gateway-rs", "service-go", "service-cs",
};

/** Outcome of a case, turned into the verdict by main(). */
typedef struct res_t {
    enum { R_PASS, R_FAIL, R_SETUP } kind;   /**< R_SETUP: setup_<component>. */
    char msg[1536];
} res_t;

/** A child process. */
typedef struct proc_t {
    const char *name;
    pid_t       pid;
    bool        done;       /**< Reaped. */
    bool        stopped;    /**< Stopped by the test, not on its own. */
    bool        logged;     /**< Exit code and stderr already logged. */
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

/** Log exit code and the first 2 KB of stderr of a finished process. */
static void
proc_log(proc_t *p)
{
    char  head[2049] = "";
    FILE *f;
    size_t n = 0;

    if (p->logged)
        return;
    p->logged = true;
    if (p->err[0] != '\0' && (f = fopen(p->err, "r")) != NULL)
    {
        n = fread(head, 1, 2048, f);
        fclose(f);
    }
    head[n] = '\0';
    if (WIFSIGNALED(p->status))
        RING("webdeps: %s (pid %d) killed by signal %d%s; stderr[%zu B]: %s",
             p->name, (int)p->pid, WTERMSIG(p->status),
             p->stopped ? " (stopped by the test)" : "", n, head);
    else
        RING("webdeps: %s (pid %d) exit code %d%s; stderr[%zu B]: %s",
             p->name, (int)p->pid, WEXITSTATUS(p->status),
             p->stopped ? " (stopped by the test)" : "", n, head);
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
        proc_log(p);
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
    proc_log(p);
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
        res_set(r, R_SETUP, "TE_TS_MDE_SRC is not set: the example is not "
                "available");
        return false;
    }
    snprintf(path, sizeof(path), "%s/web/contract/services.tab", src_root);
    f = fopen(path, "r");
    if (f == NULL)
    {
        res_set(r, R_SETUP, "contract %s cannot be read", path);
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
        res_set(r, R_SETUP, "contract %s names only %d of 3 services", path,
                found);
        return false;
    }
    return true;
}

static bool port_accepts(unsigned port);

/** The setup_<component> name of the problem, set with an R_SETUP outcome. */
static char setup_name[64] = "setup";

/**
 * Start a service and wait up to START_WAIT s for its port (read from the
 * contract) to accept TCP. On any problem sets an R_SETUP outcome naming
 * setup_<component> and returns NULL.
 */
static proc_t *
svc_start(res_t *r, int idx)
{
    char     path[512];
    char     lib[600];
    proc_t  *p;
    double   end;
    char     why[900];
    pid_t    pid;

    snprintf(setup_name, sizeof(setup_name), "setup_%s", names[idx]);
    for (char *c = setup_name; *c != '\0'; c++)
    {
        if (*c == '-')
            *c = '_';
    }
    snprintf(path, sizeof(path), "%s/dist/bin/%s", src_root, names[idx]);
    if (access(path, X_OK) != 0)
    {
        res_set(r, R_SETUP, "binary %s not found or not executable", path);
        return NULL;
    }
    if (n_procs >= MAX_PROCS)
    {
        res_set(r, R_SETUP, "too many processes");
        return NULL;
    }
    if (port_accepts(tab_port[idx]))
    {
        res_set(r, R_SETUP, "port 127.0.0.1:%u of %s is busy before the "
                "start", tab_port[idx], names[idx]);
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
        res_set(r, R_SETUP, "fork failed: %s", strerror(errno));
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
    p->port = tab_port[idx];
    setpgid(pid, pid);
    n_procs++;

    end = now_s() + START_WAIT;
    while (now_s() < end)
    {
        if (proc_gone(p))
        {
            proc_describe(p, why, sizeof(why));
            p->stopped = true;
            ERROR("webdeps: %s", why);
            res_set(r, R_SETUP, "%s did not stay up while starting: %s",
                    names[idx], why);
            return NULL;
        }
        if (port_accepts(p->port))
            return p;
        usleep(100000);
    }
    res_set(r, R_SETUP, "%s: 127.0.0.1:%u does not accept TCP within %d s",
            names[idx], p->port, START_WAIT);
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
    char   body[2048];
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
    F_SILENT, F_GARBAGE, F_BADJSON, F_EMPTY, F_HUGE, F_HTTP500, F_RESET,
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
    snprintf(setup_name, sizeof(setup_name), "setup_fake_peer");
    if (ls < 0 || bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(ls, 16) != 0 || pipe(cp) != 0 || n_procs >= MAX_PROCS)
    {
        res_set(r, R_SETUP, "cannot listen on 127.0.0.1:%u for a fake peer: "
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
            if (mode != F_RESET && poll(&pfd, 1, 500) > 0)
            {
                if (read(c, req, sizeof(req)) < 0)
                    req[0] = '\0';
            }
            switch (mode)
            {
                case F_GARBAGE:
                {
                    int rf = open("/dev/urandom", O_RDONLY);

                    if (rf < 0 || read(rf, chunk, 256) != 256)
                        for (i = 0; i < 256; i++)
                            chunk[i] = (char)(i * 7 + 3);
                    if (rf >= 0)
                        close(rf);
                    if (write(c, chunk, 256) < 0)
                        break;
                    break;
                }
                case F_BADJSON:
                    /* Truncated JSON: the length promises more than is sent. */
                    dprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: "
                            "application/json\r\nContent-Length: 64\r\n"
                            "Connection: close\r\n\r\n{\"value\": [1, 2");
                    break;
                case F_RESET:
                {
                    struct linger lg = { .l_onoff = 1, .l_linger = 0 };

                    setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
                    break;      /* close() below sends RST. */
                }
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

/* ---- setup ---- */

/** Start one component from the built tree; setup_<component> on failure. */
static void
setup_one(res_t *r, int idx)
{
    proc_t *svc[NAMES] = { NULL };
    const int which[] = { idx };

    if (!start_all(r, svc, which, 1))
        return;
    res_set(r, R_PASS, "%s PASS: started from %s/dist/bin, pid %d, "
            "127.0.0.1:%u accepts TCP", setup_name, src_root,
            (int)svc[idx]->pid, svc[idx]->port);
}

static void case_setup_gateway_rs(res_t *r) { setup_one(r, GW); }
static void case_setup_service_go(res_t *r) { setup_one(r, GO); }
static void case_setup_service_cs(res_t *r) { setup_one(r, CS); }

/* ---- H1 ---- */

/** Tag for the explicit verdict of a hypothesis. */
#define HV(h, ok)   ((ok) ? "H" #h ":pass" : "H" #h ":fail")

/** Whether a response carries an error indication. */
static bool
reports_error(const hg_res *h)
{
    return h->how == HG_OK && (h->status >= 400 ||
        strstr(h->body, "unreachable") != NULL ||
        strstr(h->body, "error") != NULL ||
        strstr(h->body, "failed") != NULL ||
        strstr(h->body, "degraded") != NULL);
}

/**
 * Whether the gateway crashed: the process is gone (exit status described
 * in @p why, 101 and SIGABRT called out) or stderr shows a panic.
 */
static bool
gw_crashed(proc_t *gw, char *why, size_t size)
{
    bool panic = file_has(gw->err, "panicked");

    why[0] = '\0';
    if (proc_gone(gw))
    {
        proc_describe(gw, why, size);
        if (WIFSIGNALED(gw->status) && WTERMSIG(gw->status) == SIGABRT)
            append(why, size, " [SIGABRT]");
        if (WIFEXITED(gw->status) && WEXITSTATUS(gw->status) == 101)
            append(why, size, " [exit 101 = Rust panic]");
        return true;
    }
    if (panic)
        append(why, size, "'panicked' on stderr");
    return panic;
}

static void
case_h1_gateway_backends_absent(res_t *r)
{
    /* The gateway routes: /ring, with and without the hop budget that makes
     * it reach for the backend (main.rs:30-36). */
    static const char * const routes[] = {
        "/ring?value=1&hops=3", "/ring", "/ring?value=1&hops=1",
        "/ring?value=1&hops=0",
    };
    proc_t  *svc[NAMES] = { NULL };
    const int which[] = { GW };
    char     detail[1200] = "";
    bool     crashed = false;
    char     why[900] = "";
    unsigned i;

    if (!start_all(r, svc, which, 1))
        return;
    for (i = 0; i < sizeof(routes) / sizeof(routes[0]); i++)
    {
        hg_res h;
        bool   dead;
        char   w[900];

        http_get(svc[GW]->port, routes[i], PROBE_TO, &h);
        usleep(300000);
        dead = gw_crashed(svc[GW], w, sizeof(w));
        append(detail, sizeof(detail), "[GET %s: %s, HTTP %d in %.2f s, "
               "gateway %s%s%s] ", routes[i], hg_str(h.how), h.status,
               h.elapsed, dead ? "DEAD/panicked" : "alive",
               (h.status == 200 && !reports_error(&h)) ?
                   ", 200 without degraded body" : "",
               (h.how == HG_RESET || h.how == HG_NORESP) ?
                   ", CONNECTION LOST" : "");
        if (dead || h.how == HG_RESET || h.how == HG_NORESP)
        {
            crashed = true;
            snprintf(why, sizeof(why), "%s", w);
            break;
        }
    }
    if (crashed)
        res_set(r, R_FAIL, "h1_gateway_backends_absent %s (H1 confirmed): "
                "gateway with no backends crashed or dropped the "
                "connection. %s exit status: %s", HV(1, false), detail,
                why[0] != '\0' ? why : "(still running)");
    else
        res_set(r, R_PASS, "h1_gateway_backends_absent %s: gateway alive "
                "(exit status: none, still running), no panic, every "
                "request answered. %s", HV(1, true), detail);
}

static void
case_h1_gateway_backend_garbage(res_t *r)
{
    /* (a) empty body, (b) non-JSON bytes, (c) truncated JSON, (d) a 500. */
    static const struct { fake_t mode; const char *name; } cases[] = {
        { F_EMPTY, "(a) empty body" }, { F_GARBAGE, "(b) non-JSON bytes" },
        { F_BADJSON, "(c) truncated JSON" }, { F_HTTP500, "(d) HTTP 500" },
    };
    /* service-go address first, then service-cs (main.rs:33-36). */
    static const int backends[] = { GO, CS };
    char     detail[2000] = "";
    char     killers[400] = "";
    unsigned b;
    unsigned i;

    for (b = 0; b < 2; b++)
    {
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        {
            proc_t  *svc[NAMES] = { NULL };
            const int which[] = { GW };
            int      cfd;
            proc_t  *fake;
            hg_res   h;
            unsigned hits;
            bool     dead;
            char     why[900];

            if (!start_all(r, svc, which, 1))
                return;
            fake = fake_start(r, tab_port[backends[b]], cases[i].mode, &cfd);
            if (fake == NULL)
                return;
            http_get(svc[GW]->port, REQUEST, PROBE_TO, &h);
            usleep(300000);
            hits = fake_count(cfd);
            dead = gw_crashed(svc[GW], why, sizeof(why));
            close(cfd);
            proc_stop(fake);
            append(detail, sizeof(detail), "[backend %s, reply %s: gateway "
                   "%s, %s, HTTP %d, backend hits %u%s%s] ",
                   names[backends[b]], cases[i].name,
                   dead ? "DEAD" : "alive", hg_str(h.how), h.status, hits,
                   dead ? ", exit status: " : "", dead ? why : "");
            if (dead)
                append(killers, sizeof(killers), "%s on %s; ",
                       cases[i].name, names[backends[b]]);
            proc_stop(svc[GW]);
        }
    }
    if (killers[0] != '\0')
        res_set(r, R_FAIL, "h1_gateway_backend_garbage %s (H1 confirmed): "
                "reply kind(s) that killed the gateway: %s. %s", HV(1, false),
                killers, detail);
    else
        res_set(r, R_PASS, "h1_gateway_backend_garbage %s: gateway alive "
                "after every reply kind. %s", HV(1, true), detail);
}

static void
case_h1_gateway_startup_order(res_t *r)
{
    proc_t  *svc[NAMES] = { NULL };
    hg_res   early;
    hg_res   h;
    bool     dead;
    bool     ok;
    char     why[900];
    int      one[] = { GW };
    int      rest[] = { GO, CS };

    if (!start_all(r, svc, one, 1))
        return;
    http_get(svc[GW]->port, REQUEST, PROBE_TO, &early);
    sleep(2);
    if (!start_all(r, svc, rest, 2))
        return;
    http_get(svc[GW]->port, REQUEST, PROBE_TO, &h);
    dead = gw_crashed(svc[GW], why, sizeof(why));
    ok = !dead && h.how == HG_OK && h.status == 200 &&
         strstr(h.body, "value=") != NULL;
    if (ok)
        res_set(r, R_PASS, "h1_gateway_startup_order %s: gateway started "
                "2 s before the backends serves correctly afterwards "
                "(early request: %s HTTP %d; later: HTTP %d, gateway "
                "alive, exit status: none)", HV(1, true),
                hg_str(early.how), early.status, h.status);
    else
        res_set(r, R_FAIL, "h1_gateway_startup_order %s: after the backends "
                "came up the gateway gave %s HTTP %d, gateway %s %s "
                "(early request: %s HTTP %d)", HV(1, false), hg_str(h.how),
                h.status, dead ? "DEAD" : "alive", why, hg_str(early.how),
                early.status);
}

/* ---- H2 ---- */

/** A service with a peer on its dependency address that never answers. */
static void
stalled_peer(res_t *r, const char *id, int svc_idx, int peer_idx)
{
    proc_t   *svc[NAMES] = { NULL };
    const int which[] = { svc_idx };
    int       cfd;
    proc_t   *fake;
    hg_res    h;

    if (!start_all(r, svc, which, 1))
        return;
    fake = fake_start(r, tab_port[peer_idx], F_SILENT, &cfd);
    if (fake == NULL)
        return;
    /* The one probe allowed more than PROBE_TO: it measures the stall. */
    http_get(svc[svc_idx]->port, REQUEST, STALL_LIMIT, &h);
    if (h.how == HG_TIMEOUT || h.elapsed >= STALL_LIMIT)
        res_set(r, R_FAIL, "%s %s (H2 confirmed): %s gave no response "
                "within %d s (open %.1f s, process %s) with a peer on %u "
                "that accepts and never writes; peer contacted %u time(s)",
                id, HV(2, false), names[svc_idx], STALL_LIMIT, h.elapsed,
                proc_gone(svc[svc_idx]) ? "DEAD" : "alive", tab_port[peer_idx],
                fake_count(cfd));
    else
        res_set(r, R_PASS, "%s %s: %s %s after %.2f s (HTTP %d, process "
                "%s) with a peer on %u that accepts and never writes; peer "
                "contacted %u time(s)", id, HV(2, true), names[svc_idx],
                hg_str(h.how), h.elapsed, h.status,
                proc_gone(svc[svc_idx]) ? "DEAD" : "alive", tab_port[peer_idx],
                fake_count(cfd));
}

/* service-go depends on service-cs (main.go:46/51/87), service-cs on
 * gateway-rs (Program.cs:24/34/78). */
static void case_h2_go_stalled_peer(res_t *r)
{
    stalled_peer(r, "h2_go_stalled_peer", GO, CS);
}

static void case_h2_cs_stalled_peer(res_t *r)
{
    stalled_peer(r, "h2_cs_stalled_peer", CS, GW);
}

/** Peer returning 500, then closed, then garbage; is the failure masked? */
static void
failed_dep_masked(res_t *r, const char *id, int svc_idx, int peer_idx)
{
    static const struct { fake_t mode; const char *name; } peers[] = {
        { F_HTTP500, "HTTP 500" }, { F_SILENT, "port closed" },
        { F_GARBAGE, "garbage" },
    };
    proc_t   *svc[NAMES] = { NULL };
    const int which[] = { svc_idx };
    char      detail[1500] = "";
    bool      masked = false;
    unsigned  k;

    if (!start_all(r, svc, which, 1))
        return;
    for (k = 0; k < sizeof(peers) / sizeof(peers[0]); k++)
    {
        int     cfd = -1;
        proc_t *fake = NULL;
        hg_res  h;
        bool    err;
        bool    mask;

        /* "Port closed": nothing listens on the peer address. */
        if (k != 1)
        {
            fake = fake_start(r, tab_port[peer_idx], peers[k].mode, &cfd);
            if (fake == NULL)
                return;
        }
        http_get(svc[svc_idx]->port, REQUEST, PROBE_TO, &h);
        err = reports_error(&h);
        mask = h.how == HG_OK && h.status == 200 && !err;
        append(detail, sizeof(detail), "[peer %s: %s, HTTP %d%s%s, "
               "process %s] ", peers[k].name, hg_str(h.how), h.status,
               mask ? ", 200 with a success body = MASKED" : "",
               (err && h.status == 200) ? ", 200 but error/degraded body" : "",
               proc_gone(svc[svc_idx]) ? "DEAD" : "alive");
        masked = masked || mask;
        if (fake != NULL)
        {
            close(cfd);
            proc_stop(fake);
        }
    }
    if (masked)
        res_set(r, R_FAIL, "%s %s (H2 confirmed): %s masks a failed "
                "dependency as success. %s", id, HV(2, false),
                names[svc_idx], detail);
    else
        res_set(r, R_PASS, "%s %s: %s reports every dependency failure as "
                "a non-2xx status or an error/degraded body. %s", id,
                HV(2, true), names[svc_idx], detail);
}

static void case_h2_go_failed_dep_masked(res_t *r)
{
    failed_dep_masked(r, "h2_go_failed_dep_masked", GO, CS);
}

static void case_h2_cs_failed_dep_masked(res_t *r)
{
    failed_dep_masked(r, "h2_cs_failed_dep_masked", CS, GW);
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
case_h3_netexpose(res_t *r)
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
    if (tsapi_mde_session_init(&session, "h3_netexpose") != 0)
    {
        res_set(r, R_SETUP, "no session on the agent for tapi_netexpose");
        return;
    }
    tapi_cybersec_report_init(&report);
    opt.udp = false;
    opt.tcp = true;
    for (i = 0; i < NAMES; i++)
        n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
    if (tapi_netexpose_sockets(session.factory, &opt, &socks) != 0)
    {
        res_set(r, R_SETUP, "tapi_netexpose cannot read the socket tables");
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
        loop4 = strncmp(addr, "127.", 4) == 0;
        append(detail, sizeof(detail), "%s %s:%u; ", names[o], addr,
               sock_port(&s->local));
        tapi_cybersec_report_add(&report, wild ? TAPI_CYBERSEC_SEV_HIGH :
                                 TAPI_CYBERSEC_SEV_INFO, "net.listener",
                                 names[o], "H3: listens on %s:%u", addr,
                                 sock_port(&s->local));
        if (wild)
            append(bad, sizeof(bad), "%s bound to %s:%u (code names "
                   "127.0.0.1); ", names[o], addr, sock_port(&s->local));
        else if (!loop4)
            append(bad, sizeof(bad), "%s bound to %s:%u outside 127.0.0.0/8; ",
                   names[o], addr, sock_port(&s->local));
        if (!port_in_contract(sock_port(&s->local)))
            append(detail, sizeof(detail), "(port %u outside the hardcoded "
                   "set) ", sock_port(&s->local));
    }
    tapi_cybersec_report_log(&report);
    if (listeners == 0)
        res_set(r, R_SETUP, "tapi_netexpose found no listener of the three "
                "processes");
    else if (bad[0] != '\0')
        res_set(r, R_FAIL, "h3_netexpose H3:fail (H3 confirmed): %s Listeners: %s", bad,
                detail);
    else
        res_set(r, R_PASS, "h3_netexpose H3:pass: every listener is "
                "inside 127.0.0.0/8, none on 0.0.0.0 or ::. Listeners: %s",
                detail);
out:
    te_vec_free(&socks);
    tapi_cybersec_report_free(&report);
    tsapi_mde_session_fini(&session);
}

static void
case_h3_egress(res_t *r)
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
    if (tsapi_mde_session_init(&session, "h3_egress") != 0)
    {
        res_set(r, R_SETUP, "no session on the agent for tapi_egress");
        return;
    }
    tapi_cybersec_report_init(&report);
    opt.udp = false;
    opt.tcp = true;
    for (i = 0; i < NAMES; i++)
    {
        rules[i] = (tapi_egress_rule){ IPPROTO_TCP, "127.0.0.0/8", 1,
                                       65535 };
        n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
    }
    for (round = 0; round < 8; round++)
    {
        te_vec conns = TE_VEC_INIT(tapi_netexpose_socket);
        const tapi_netexpose_socket *c;
        hg_res h;

        for (i = 0; i < NAMES; i++)
            http_get(svc[i]->port, REQUEST, 5, &h);
        for (i = 0; i < NAMES; i++)
            n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
        if (tapi_egress_snapshot(session.factory, &opt, &conns) != 0)
        {
            res_set(r, R_SETUP, "tapi_egress cannot read the connections");
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
                                         "H3: outbound to %s:%u", addr,
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
        res_set(r, R_FAIL, "h3_egress H3:fail (H3 confirmed): outbound "
                "connection outside the allow-list 127.0.0.0/8: %s", bad);
    else
        res_set(r, R_PASS, "h3_egress H3:pass: %u outbound "
                "connection(s) of the services seen, all on the allow-list "
                "%s", seen, detail);
out:
    tapi_cybersec_report_free(&report);
    tsapi_mde_session_fini(&session);
}

/* ---- Iteration 1: T1..T6 (hypotheses H1..H6) ---- */

/** Loopback address, IPv4 or IPv6. */
static bool
is_loopback(const char *addr)
{
    return strncmp(addr, "127.", 4) == 0 || strcmp(addr, "::1") == 0;
}

/** Set a setup_<component> name from a free-form label. */
static void
setup_name_for(const char *label)
{
    char *c;

    snprintf(setup_name, sizeof(setup_name), "setup_%s", label);
    for (c = setup_name; *c != '\0'; c++)
    {
        if (*c == '-' || *c == '.')
            *c = '_';
    }
}

/** Send bytes to a port and drain what comes back for up to @p wait_ms. */
static void
raw_send(unsigned port, const char *data, size_t len, bool half_close,
         int wait_ms)
{
    struct timeval tv = { .tv_sec = 3 };
    char           buf[4096];
    double         end = now_s() + wait_ms / 1000.0;
    int            s = connect_loop(port);
    size_t         sent = 0;

    if (s < 0)
        return;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    while (sent < len)
    {
        ssize_t w = write(s, data + sent, len - sent);

        if (w <= 0)
            break;
        sent += w;
    }
    if (half_close)
        shutdown(s, SHUT_WR);
    for (;;)
    {
        struct pollfd pfd = { .fd = s, .events = POLLIN };
        double        left = end - now_s();

        if (left <= 0 || poll(&pfd, 1, (int)(left * 1000) + 1) <= 0)
            break;
        if (read(s, buf, sizeof(buf)) <= 0)
            break;
    }
    close(s);
}

/** Bad input of the gateway: kind name and what it sends. */
typedef struct bad_req {
    const char *name;
    const char *data;       /**< NULL: built by the test (oversized). */
    size_t      len;
    bool        half_close;
} bad_req;

#define BAD(n, s, hc)   { n, s, sizeof(s) - 1, hc }

static const bad_req bad_reqs[] = {
    BAD("malformed: random bytes", "\x00\xff\xfe\x80\x81garbage\x01\x02\r\n\r\n", false),
    BAD("malformed: no target", "GET\r\n\r\n", false),
    BAD("malformed: binary request line", "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n", false),
    BAD("malformed: bad numbers", "GET /ring?value=NaN&hops=-99999999999999999999 HTTP/1.1\r\n\r\n", false),
    BAD("malformed: huge hops", "GET /ring?value=1e999&hops=2147483647 HTTP/1.1\r\n\r\n", false),
    BAD("malformed: empty query pairs", "GET /ring?&&=&value&hops= HTTP/1.1\r\n\r\n", false),
    BAD("malformed: percent escapes", "GET /ring?value=%ff%00%zz&hops=%% HTTP/1.1\r\n\r\n", false),
    BAD("malformed: no line end", "GET /ring?value=1&hops=1", true),
    BAD("empty: connect and close", "", true),
    BAD("empty: bare line end", "\r\n", true),
    BAD("empty: zero-length path", "GET  HTTP/1.1\r\n\r\n", false),
};

#define OVERSIZE    (2u * 1024 * 1024)

/** Send one oversized request: a 2 MiB request line, then 2 MiB of headers. */
static void
send_oversized(unsigned port, bool in_header)
{
    char *buf = malloc(OVERSIZE + 128);
    int   n;

    if (buf == NULL)
        return;
    if (in_header)
    {
        n = snprintf(buf, 64, "GET /ring HTTP/1.1\r\nX-Big: ");
        memset(buf + n, 'B', OVERSIZE);
        memcpy(buf + n + OVERSIZE, "\r\n\r\n", 4);
        raw_send(port, buf, n + OVERSIZE + 4, false, 300);
    }
    else
    {
        n = snprintf(buf, 64, "GET /");
        memset(buf + n, 'A', OVERSIZE);
        memcpy(buf + n + OVERSIZE, " HTTP/1.1\r\n\r\n", 13);
        raw_send(port, buf, n + OVERSIZE + 13, false, 300);
    }
    free(buf);
}

/** Every bad input of T1, one connection each. */
static void
send_all_bad(unsigned port)
{
    unsigned i;

    for (i = 0; i < sizeof(bad_reqs) / sizeof(bad_reqs[0]); i++)
        raw_send(port, bad_reqs[i].data, bad_reqs[i].len,
                 bad_reqs[i].half_close, 300);
    send_oversized(port, false);
    send_oversized(port, true);
}

/** "none (still running)" or the exit code / signal of a process. */
static void
exit_code_str(proc_t *p, char *buf, size_t size)
{
    if (!proc_gone(p))
        snprintf(buf, size, "none (still running)");
    else if (WIFSIGNALED(p->status))
        snprintf(buf, size, "killed by signal %d", WTERMSIG(p->status));
    else
        snprintf(buf, size, "%d", WEXITSTATUS(p->status));
}

/** Start the three components, backends first. */
static bool
start_tier(res_t *r, proc_t **svc)
{
    const int which[] = { GO, CS, GW };

    return start_all(r, svc, which, 3);
}

static void
case_t1_h1_gateway_bad_input(res_t *r)
{
    proc_t  *svc[NAMES] = { NULL };
    char     detail[1500] = "";
    char     died[400] = "";
    char     code[96];
    char     why[900];
    unsigned i;
    unsigned n_panic = 0;
    hg_res   h;
    bool     answers;
    bool     alive;

    if (!start_tier(r, svc))
        return;
    for (i = 0; i < sizeof(bad_reqs) / sizeof(bad_reqs[0]) + 2; i++)
    {
        const char *name;

        if (i < sizeof(bad_reqs) / sizeof(bad_reqs[0]))
        {
            name = bad_reqs[i].name;
            raw_send(svc[GW]->port, bad_reqs[i].data, bad_reqs[i].len,
                     bad_reqs[i].half_close, 300);
        }
        else
        {
            name = i == sizeof(bad_reqs) / sizeof(bad_reqs[0]) ?
                   "oversized: 2 MiB request line" :
                   "oversized: 2 MiB header";
            send_oversized(svc[GW]->port,
                           i != sizeof(bad_reqs) / sizeof(bad_reqs[0]));
        }
        usleep(100000);
        if (proc_gone(svc[GW]) && died[0] == '\0')
        {
            proc_describe(svc[GW], why, sizeof(why));
            snprintf(died, sizeof(died), "exited after '%s'", name);
        }
        append(detail, sizeof(detail), "[%s] ", name);
    }
    if (file_has(svc[GW]->err, "panicked"))
        n_panic = 1;
    http_get(svc[GW]->port, REQUEST, 2, &h);
    answers = h.how == HG_OK && h.status == 200 && h.elapsed <= 2.0;
    alive = !proc_gone(svc[GW]);
    exit_code_str(svc[GW], code, sizeof(code));
    if (!alive)
        proc_describe(svc[GW], why, sizeof(why));
    RING("t1: gateway exit code: %s; thread panics on stderr: %s", code,
         n_panic != 0 ? "yes" : "no");
    if (!alive || !answers)
        res_set(r, R_FAIL, "t1_h1_gateway_bad_input %s (H1 confirmed): "
                "gateway %s; valid request afterwards: %s, HTTP %d in "
                "%.2f s; exit code: %s%s%s. Sent: %s", HV(1, false),
                alive ? "alive" : "EXITED", hg_str(h.how), h.status,
                h.elapsed, code, died[0] != '\0' ? "; " : "", died, detail);
    else
        res_set(r, R_PASS, "t1_h1_gateway_bad_input %s: gateway kept "
                "answering after malformed, oversized and empty requests; "
                "valid request answered HTTP %d in %.2f s; exit code: %s; "
                "panic text on stderr: %s. Sent: %s", HV(1, true), h.status,
                h.elapsed, code, n_panic != 0 ? "yes (thread only)" : "no",
                detail);
}

#define SLOW_OPEN_LIMIT 30      /**< s, T2 limit for a half-request socket. */
#define SLOW_SOCKETS    50

static const char slow_part[] =
    "GET /ring?value=1&hops=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: 1\r\n";

/** Half a request on a fresh socket; -1 when it cannot be opened. */
static int
slow_open(unsigned port)
{
    int s = connect_loop(port);

    if (s >= 0 && write(s, slow_part, sizeof(slow_part) - 1) < 0)
    {
        close(s);
        return -1;
    }
    return s;
}

static void
case_t2_h2_go_slow_client(res_t *r)
{
    proc_t  *svc[NAMES] = { NULL };
    int      socks[SLOW_SOCKETS];
    int      s;
    int      i;
    int      opened = 0;
    double   t0;
    double   closed_after = -1;
    double   end;
    hg_res   h;
    char     part2[300] = "";
    bool     lone_ok;
    bool     answers;

    if (!start_tier(r, svc))
        return;
    s = slow_open(svc[GO]->port);
    if (s < 0)
    {
        res_set(r, R_SETUP, "cannot open a socket to service-go");
        return;
    }
    t0 = now_s();
    end = t0 + SLOW_OPEN_LIMIT;
    for (;;)
    {
        struct pollfd pfd = { .fd = s, .events = POLLIN };
        double        left = end - now_s();
        char          b[512];
        ssize_t       n;

        if (left <= 0 || poll(&pfd, 1, (int)(left * 1000) + 1) == 0)
            break;
        n = read(s, b, sizeof(b));
        if (n <= 0)
        {
            closed_after = now_s() - t0;
            break;
        }
    }
    close(s);
    lone_ok = closed_after >= 0;

    for (i = 0; i < SLOW_SOCKETS; i++)
    {
        socks[i] = slow_open(svc[GO]->port);
        if (socks[i] >= 0)
            opened++;
    }
    http_get(svc[GO]->port, REQUEST, PROBE_TO, &h);
    answers = h.how == HG_OK && h.status == 200;
    snprintf(part2, sizeof(part2), "with %d half-open sockets: valid request "
             "%s, HTTP %d in %.2f s, process %s", opened, hg_str(h.how),
             h.status, h.elapsed, proc_gone(svc[GO]) ? "DEAD" : "alive");
    for (i = 0; i < SLOW_SOCKETS; i++)
    {
        if (socks[i] >= 0)
            close(socks[i]);
    }
    if (!lone_ok || !answers)
        res_set(r, R_FAIL, "t2_h2_go_slow_client %s (H2 confirmed): %s%s; "
                "%s", HV(2, false),
                lone_ok ? "" : "service-go kept a half-request socket open "
                               "for the whole 30 s limit",
                (!lone_ok && !answers) ? " and" : "", part2);
    else
        res_set(r, R_PASS, "t2_h2_go_slow_client %s: service-go closed the "
                "half-request socket after %.1f s (limit %d s); %s", HV(2, true),
                closed_after, SLOW_OPEN_LIMIT, part2);
}

/** Allow-list for T3: loopback, one rule per service port. */
static void
case_t3_h3_egress_run(res_t *r)
{
    proc_t              *svc[NAMES] = { NULL };
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES];
    tsapi_mde_session    session = { .ta = NULL };
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    tapi_cybersec_report report;
    tapi_egress_rule     rules[2 * NAMES];
    tapi_egress_policy   policy = { .n_rules = 2 * NAMES, .rules = rules,
                                    .allow_loopback = false,
                                    .allow_private = false };
    char                 detail[900] = "";
    char                 bad[900] = "";
    unsigned             seen = 0;
    int                  i;
    int                  round;

    if (!start_tier(r, svc))
        return;
    if (tsapi_mde_session_init(&session, "t3_egress") != 0)
    {
        res_set(r, R_SETUP, "no session on the agent for tapi_egress");
        return;
    }
    tapi_cybersec_report_init(&report);
    opt.udp = false;
    opt.tcp = true;
    for (i = 0; i < NAMES; i++)
    {
        rules[i] = (tapi_egress_rule){ IPPROTO_TCP, "127.0.0.0/8",
                                       tab_port[i], tab_port[i] };
        rules[NAMES + i] = (tapi_egress_rule){ IPPROTO_TCP, "::1/128",
                                               tab_port[i], tab_port[i] };
    }
    for (round = 0; round < 10; round++)
    {
        te_vec conns = TE_VEC_INIT(tapi_netexpose_socket);
        const tapi_netexpose_socket *c;
        hg_res h;

        /* Normal traffic on every component, and bad input every 3rd round. */
        for (i = 0; i < NAMES; i++)
            http_get(svc[i]->port, REQUEST, 5, &h);
        if (round % 3 == 0)
            send_all_bad(svc[GW]->port);
        for (i = 0; i < NAMES; i++)
            n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
        if (tapi_egress_snapshot(session.factory, &opt, &conns) != 0)
        {
            res_set(r, R_SETUP, "tapi_egress cannot read the connections");
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
                                         "H3: destination %s:%u", addr,
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
        res_set(r, R_FAIL, "t3_h3_egress_run %s (H3 confirmed): "
                "destination(s) outside loopback and the service ports "
                "%u/%u/%u: %s", HV(3, false), tab_port[0], tab_port[1],
                tab_port[2], bad);
    else
        res_set(r, R_PASS, "t3_h3_egress_run %s: %u outbound connection(s) "
                "seen over the run, all to loopback on a service port: %s",
                HV(3, true), seen, detail);
out:
    tapi_cybersec_report_free(&report);
    tsapi_mde_session_fini(&session);
}

static void
case_t4_h4_binscan(res_t *r)
{
    static const struct {
        const char *label;
        const char *rel;
        bool        c_family;   /**< Needs canary and fortify as well. */
    } bins[] = {
        { "gateway-rs", "dist/bin/gateway-rs", false },
        { "service-go", "dist/bin/service-go", false },
        { "service-cs", "dist/bin/service-cs", false },
        { "cpp-demo", "dist/bin/cpp-demo", true },
        { "libpycore.so", "dist/lib/libpycore.so", true },
    };
    tsapi_mde_session    session = { .ta = NULL };
    tapi_cybersec_report report;
    char                 missing[1200] = "";
    char                 detail[900] = "";
    unsigned             i;
    unsigned             n_missing = 0;

    if (tsapi_mde_session_init(&session, "t4_binscan") != 0)
    {
        res_set(r, R_SETUP, "no session on the agent for tapi_binscan");
        return;
    }
    tapi_cybersec_report_init(&report);
    for (i = 0; i < sizeof(bins) / sizeof(bins[0]); i++)
    {
        char              path[600];
        char              flags[160] = "";
        tapi_binscan_info info;
        bool              pie;
        bool              nx;
        const char       *label = bins[i].label;
        te_errno          rc;

        snprintf(path, sizeof(path), "%s/%s", src_root, bins[i].rel);
        if (access(path, R_OK) != 0)
        {
            setup_name_for(label);
            res_set(r, R_SETUP, "built artifact %s not found", path);
            goto out;
        }
        rc = tapi_binscan_inspect(session.ta, path, &info);
        if (rc != 0 || !info.elf)
        {
            setup_name_for(label);
            res_set(r, R_SETUP, "tapi_binscan cannot read %s as ELF "
                    "(rc %d)", path, (int)rc);
            goto out;
        }
        tapi_binscan_info_log(&info, path);
        pie = info.kind == TAPI_BINSCAN_KIND_PIE ||
              info.kind == TAPI_BINSCAN_KIND_SHARED;
        nx = info.nx && !info.nx_unknown;
        if (!nx)
            append(flags, sizeof(flags), "NX ");
        if (!pie)
            append(flags, sizeof(flags), "PIE ");
        if (info.relro == TAPI_BINSCAN_RELRO_NONE)
            append(flags, sizeof(flags), "RELRO ");
        if (bins[i].c_family && !info.canary)
            append(flags, sizeof(flags), "canary ");
        if (bins[i].c_family && !info.fortify)
            append(flags, sizeof(flags), "fortify ");
        if (!nx)
            tapi_cybersec_report_add(&report, TAPI_CYBERSEC_SEV_HIGH,
                                     "binary.no-nx", label, "H4: NX missing");
        if (!pie)
            tapi_cybersec_report_add(&report, TAPI_CYBERSEC_SEV_HIGH,
                                     "binary.no-pie", label,
                                     "H4: PIE missing (%s)",
                                     tapi_binscan_kind2str(info.kind));
        if (info.relro == TAPI_BINSCAN_RELRO_NONE)
            tapi_cybersec_report_add(&report, TAPI_CYBERSEC_SEV_HIGH,
                                     "binary.no-relro", label,
                                     "H4: RELRO missing");
        else if (info.relro == TAPI_BINSCAN_RELRO_PARTIAL)
            tapi_cybersec_report_add(&report, TAPI_CYBERSEC_SEV_LOW,
                                     "binary.partial-relro", label,
                                     "H4: only partial RELRO");
        if (!info.canary)
            tapi_cybersec_report_add(&report, bins[i].c_family ?
                                     TAPI_CYBERSEC_SEV_HIGH :
                                     TAPI_CYBERSEC_SEV_INFO,
                                     "binary.no-canary", label,
                                     "H4: stack canary missing");
        if (!info.fortify)
            tapi_cybersec_report_add(&report, bins[i].c_family ?
                                     TAPI_CYBERSEC_SEV_HIGH :
                                     TAPI_CYBERSEC_SEV_INFO,
                                     "binary.no-fortify", label,
                                     "H4: fortify missing");
        if (flags[0] != '\0')
        {
            n_missing++;
            append(missing, sizeof(missing), "%s lacks %s; ", label, flags);
        }
        append(detail, sizeof(detail), "%s [PIE=%s NX=%s RELRO=%s "
               "canary=%s fortify=%s] ", label, pie ? "yes" : "no",
               nx ? "yes" : "no", tapi_binscan_relro2str(info.relro),
               info.canary ? "yes" : "no", info.fortify ? "yes" : "no");
        tapi_binscan_info_free(&info);
    }
    tapi_cybersec_report_log(&report);
    if (n_missing > 0)
        res_set(r, R_FAIL, "t4_h4_binscan %s (H4 confirmed): missing "
                "hardening flags: %sScanned: %s", HV(4, false), missing,
                detail);
    else
        res_set(r, R_PASS, "t4_h4_binscan %s: NX, PIE and RELRO present on "
                "every binary, canary and fortify on the C and C++ ones: %s",
                HV(4, true), detail);
out:
    tapi_cybersec_report_free(&report);
    tsapi_mde_session_fini(&session);
}

static void
case_t5_h5_netexpose(res_t *r)
{
    proc_t              *svc[NAMES] = { NULL };
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES];
    tsapi_mde_session    session = { .ta = NULL };
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    tapi_cybersec_report report;
    te_vec               socks = TE_VEC_INIT(tapi_netexpose_socket);
    const tapi_netexpose_socket *s;
    char                 detail[900] = "";
    char                 bad[900] = "";
    unsigned             listeners = 0;
    int                  i;

    if (!start_tier(r, svc))
        return;
    if (tsapi_mde_session_init(&session, "t5_netexpose") != 0)
    {
        res_set(r, R_SETUP, "no session on the agent for tapi_netexpose");
        return;
    }
    tapi_cybersec_report_init(&report);
    opt.udp = false;
    opt.tcp = true;
    for (i = 0; i < NAMES; i++)
        n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
    if (tapi_netexpose_sockets(session.factory, &opt, &socks) != 0)
    {
        res_set(r, R_SETUP, "tapi_netexpose cannot read the socket tables");
        goto out;
    }
    TE_VEC_FOREACH(&socks, s)
    {
        char     addr[64];
        int      o;
        unsigned port;

        if (!tapi_netexpose_socket_is_listening(s))
            continue;
        o = owner_of(svc, ino, n_ino, s->inode);
        if (o < 0)
            continue;
        listeners++;
        sock_addr(&s->local, addr, sizeof(addr));
        port = sock_port(&s->local);
        append(detail, sizeof(detail), "%s %s:%u; ", names[o], addr, port);
        tapi_cybersec_report_add(&report, is_loopback(addr) &&
                                 port_in_contract(port) ?
                                 TAPI_CYBERSEC_SEV_INFO :
                                 TAPI_CYBERSEC_SEV_HIGH, "net.listener",
                                 names[o], "H5: listens on %s:%u", addr, port);
        if (!is_loopback(addr))
            append(bad, sizeof(bad), "%s listens on non-loopback %s:%u; ",
                   names[o], addr, port);
        if (!port_in_contract(port))
            append(bad, sizeof(bad), "%s listens on %s:%u, not in the "
                   "expected list %u/%u/%u; ", names[o], addr, port,
                   tab_port[0], tab_port[1], tab_port[2]);
    }
    tapi_cybersec_report_log(&report);
    if (listeners == 0)
        res_set(r, R_SETUP, "tapi_netexpose found no listener of the three "
                "processes");
    else if (bad[0] != '\0')
        res_set(r, R_FAIL, "t5_h5_netexpose %s (H5 confirmed): %sListeners: "
                "%s", HV(5, false), bad, detail);
    else
        res_set(r, R_PASS, "t5_h5_netexpose %s: every listener is on "
                "loopback and on an expected port. Listeners: %s", HV(5, true),
                detail);
out:
    te_vec_free(&socks);
    tapi_cybersec_report_free(&report);
    tsapi_mde_session_fini(&session);
}

static void
case_t6_h6_cs_failed_call(res_t *r)
{
    static const struct { fake_t mode; const char *name; } backends[] = {
        { F_SILENT, "gateway stopped" }, { F_HTTP500, "backend HTTP 500" },
        { F_GARBAGE, "backend garbage" }, { F_RESET, "backend reset" },
    };
    static const char * const inputs[] = {
        "/ring?value=1&hops=3", "/ring?value=1&hops=1",
    };
    proc_t  *svc[NAMES] = { NULL };
    char     detail[1500] = "";
    char     masked[600] = "";
    unsigned k;
    unsigned j;

    if (!start_tier(r, svc))
        return;
    /* service-cs calls the gateway: take that backend away. */
    proc_stop(svc[GW]);
    for (k = 0; k < sizeof(backends) / sizeof(backends[0]); k++)
    {
        int     cfd = -1;
        proc_t *fake = NULL;

        /* "Gateway stopped": nothing listens on the backend address. */
        if (k != 0)
        {
            fake = fake_start(r, tab_port[GW], backends[k].mode, &cfd);
            if (fake == NULL)
                return;
        }
        for (j = 0; j < sizeof(inputs) / sizeof(inputs[0]); j++)
        {
            hg_res h;
            bool   ok_status;

            http_get(svc[CS]->port, inputs[j], PROBE_TO, &h);
            ok_status = h.how == HG_OK &&
                        ((h.status >= 400 && h.status < 500) ||
                         (h.status >= 500 && h.status < 600));
            append(detail, sizeof(detail), "[%s, GET %s: %s, HTTP %d%s] ",
                   backends[k].name, inputs[j], hg_str(h.how), h.status,
                   (h.how == HG_OK && h.status >= 200 && h.status < 300) ?
                   " = 2xx on a failed call" : "");
            if (!ok_status)
                append(masked, sizeof(masked), "%s, GET %s: %s HTTP %d; ",
                       backends[k].name, inputs[j], hg_str(h.how), h.status);
        }
        if (fake != NULL)
        {
            close(cfd);
            proc_stop(fake);
        }
    }
    if (masked[0] != '\0')
        res_set(r, R_FAIL, "t6_h6_cs_failed_call %s (H6 confirmed): "
                "service-cs did not answer a failed backend call with 4xx "
                "or 5xx: %s. All: %s", HV(6, false), masked, detail);
    else
        res_set(r, R_PASS, "t6_h6_cs_failed_call %s: service-cs answered "
                "every failed backend call with 4xx or 5xx. %s", HV(6, true),
                detail);
}

int
main(int argc, char **argv)
{
    const char *hyp_id;
    res_t       res = { .kind = R_SETUP };
    static const struct {
        const char *id;
        int         hyp;
        void      (*fn)(res_t *);
    } table[] = {
        { "setup_gateway_rs", 0, case_setup_gateway_rs },
        { "setup_service_go", 0, case_setup_service_go },
        { "setup_service_cs", 0, case_setup_service_cs },
        { "h1_gateway_backends_absent", 1, case_h1_gateway_backends_absent },
        { "h1_gateway_backend_garbage", 1, case_h1_gateway_backend_garbage },
        { "h1_gateway_startup_order", 1, case_h1_gateway_startup_order },
        { "h2_go_stalled_peer", 2, case_h2_go_stalled_peer },
        { "h2_cs_stalled_peer", 2, case_h2_cs_stalled_peer },
        { "h2_go_failed_dep_masked", 2, case_h2_go_failed_dep_masked },
        { "h2_cs_failed_dep_masked", 2, case_h2_cs_failed_dep_masked },
        { "h3_netexpose", 3, case_h3_netexpose },
        { "h3_egress", 3, case_h3_egress },
        { "t1_h1_gateway_bad_input", 1, case_t1_h1_gateway_bad_input },
        { "t2_h2_go_slow_client", 2, case_t2_h2_go_slow_client },
        { "t3_h3_egress_run", 3, case_t3_h3_egress_run },
        { "t4_h4_binscan", 4, case_t4_h4_binscan },
        { "t5_h5_netexpose", 5, case_t5_h5_netexpose },
        { "t6_h6_cs_failed_call", 6, case_t6_h6_cs_failed_call },
    };
    unsigned    i;
    int         hyp = 0;
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
        hyp = table[i].hyp;
        if (workdir[0] == '\0')
            res_set(&res, R_SETUP, "cannot create a work directory");
        else if (read_contract(&res))
            table[i].fn(&res);
    }
    if (!found)
        res_set(&res, R_SETUP, "unknown case id '%s'", hyp_id);

    if (res.kind == R_SETUP)
    {
        char tmp[sizeof(res.msg)];

        snprintf(tmp, sizeof(tmp), "%s", res.msg);
        if (hyp != 0)
            snprintf(res.msg, sizeof(res.msg), "%s FAIL (not a finding): "
                     "%s cannot run (H%d:setup-error): %.1200s", setup_name,
                     hyp_id, hyp, tmp);
        else
            snprintf(res.msg, sizeof(res.msg), "%s FAIL (not a finding): "
                     "%.1400s", setup_name, tmp);
    }
    cleanup_all();

    if (res.kind == R_PASS)
    {
        RING_VERDICT("%s", res.msg);
        TEST_SUCCESS;
    }
    TEST_VERDICT("%s", res.msg);

cleanup:
    cleanup_all();
    TEST_END;
}

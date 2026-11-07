/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps standalone tests: shared static helpers
 *
 * Child processes for the three services, their ports from the contract,
 * a small HTTP client and the socket-owner lookup. Included by the
 * standalone t_h<n>_* tests, each of which is one executable.
 */

#ifndef MDE_WEBDEPS_LIB_H
#define MDE_WEBDEPS_LIB_H

#pragma GCC diagnostic ignored "-Wunused-function"

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
#define START_WAIT  10      /**< s to wait for a port to accept TCP. */
#define PROBE_TO    3       /**< s, client timeout of every probe. */
#define STALL_LIMIT 10      /**< s, H2 stall verdict limit. */

/** Service indexes, in contract order. */
enum { GW = 0, GO, CS };

static const char * const names[NAMES] = {
    "gateway-rs", "service-go", "service-cs",
};

/** Outcome of a case, turned into the verdict by main(). */
typedef struct res_t {
    enum {
        R_PASS, R_FAIL, R_SETUP,
        R_INCONCLUSIVE, /**< A scanner returned no data; names which one. */
    } kind;   /**< R_SETUP: setup_<component>. */
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

/** Service whose start failed, named in the SETUP verdict. */
static const char *setup_svc = "harness";

/**
 * Start a service and wait up to START_WAIT s for its port (read from the
 * contract) to accept TCP. On any problem sets an R_SETUP outcome naming
 * the service (setup_svc) and returns NULL.
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

    setup_svc = names[idx];
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

/**
 * Run a short-lived program in the current directory's dist/bin to
 * completion (a demo, not a service: no port to probe). Waits up to
 * @p timeout_s for it to exit. On any problem sets an R_SETUP outcome
 * naming @p label and returns NULL; otherwise returns the finished
 * process (reaped, @c proc_gone() already @c true).
 */
static proc_t *
run_once(res_t *r, const char *label, const char *path, char *const *argv,
        int timeout_s)
{
    proc_t  *p;
    double   end;
    pid_t    pid;

    setup_svc = label;
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
    p = &procs[n_procs];
    memset(p, 0, sizeof(*p));
    p->name = label;
    snprintf(p->out, sizeof(p->out), "%s/%s.out", workdir, label);
    snprintf(p->err, sizeof(p->err), "%s/%s.err", workdir, label);

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
        char lib[600];

        snprintf(lib, sizeof(lib), "%s/dist/lib", src_root);
        setpgid(0, 0);
        dup2(z, 0);
        dup2(o, 1);
        dup2(e, 2);
        setenv("LD_LIBRARY_PATH", lib, 1);
        execv(path, argv);
        dprintf(2, "exec %s: %s\n", path, strerror(errno));
        _exit(127);
    }
    p->pid = pid;
    setpgid(pid, pid);
    n_procs++;

    end = now_s() + timeout_s;
    while (now_s() < end)
    {
        if (proc_gone(p))
            return p;
        usleep(100000);
    }
    res_set(r, R_SETUP, "%s did not finish within %d s", label, timeout_s);
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
static bool
is_loopback(const char *addr)
{
    return strncmp(addr, "127.", 4) == 0 || strcmp(addr, "::1") == 0;
}

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

/**
 * The smoke shape shared by s_rust, s_go and s_cs: start the service, send
 * one valid request, check it is still running (no exit code) and the
 * response is 2xx with "value=" in the body, then stop it. @p r->kind is
 * left as R_PASS/R_FAIL/R_SETUP with a message naming @p test_name.
 */
static void
smoke_service(res_t *r, const char *test_name, int idx)
{
    proc_t *svc;
    hg_res  h;

    svc = svc_start(r, idx);
    if (svc == NULL)
        return;

    http_get(svc->port, REQUEST, PROBE_TO, &h);
    if (proc_gone(svc))
    {
        char why[900];

        proc_describe(svc, why, sizeof(why));
        svc->stopped = true;
        res_set(r, R_FAIL, "%s: %s exited instead of answering a valid "
                "request: %s", test_name, names[idx], why);
        return;
    }
    if (h.how != HG_OK)
    {
        res_set(r, R_FAIL, "%s: %s gave no reply to a valid request (%s)",
                test_name, names[idx], hg_str(h.how));
        return;
    }
    if (h.status < 200 || h.status >= 300 || strstr(h.body, "value=") == NULL)
    {
        res_set(r, R_FAIL, "%s: %s answered HTTP %d, body [%.200s], "
                "expected 2xx with \"value=\"", test_name, names[idx],
                h.status, h.body);
        return;
    }
    res_set(r, R_PASS, "%s: %s is running (no exit code) and answered the "
            "valid request %s with HTTP %d, body [%.200s]", test_name,
            names[idx], REQUEST, h.status, h.body);
}

/* ---- setup ---- */

/** Last non-empty line of a file, or "(none)". */
static void
last_line(const char *path, char *buf, size_t size)
{
    char   tail[1024];
    size_t n;

    file_tail(path, tail, sizeof(tail));
    n = strlen(tail);
    while (n > 0 && tail[n - 1] == '|')
        tail[--n] = '\0';
    snprintf(buf, size, "%s", n == 0 ? "(none)" :
             (strrchr(tail, '|') != NULL ? strrchr(tail, '|') + 1 : tail));
}

/** Send bytes on a fresh connection; the socket is closed after wait_ms. */
static void
send_once(unsigned port, const char *data, size_t len, bool half_close,
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

/** Prepare the run: ignore SIGPIPE, make the work dir, read the contract. */
static void
wd_init(res_t *r)
{
    signal(SIGPIPE, SIG_IGN);
    snprintf(workdir, sizeof(workdir), "/tmp/mde-wd-XXXXXX");
    if (mkdtemp(workdir) == NULL)
    {
        workdir[0] = '\0';
        res_set(r, R_SETUP, "cannot create a work directory");
    }
    else
    {
        read_contract(r);
    }
}

/**
 * Turn the outcome into the verdict: a setup fault is a failure that
 * starts with SETUP and the service name, never a finding; a scanner that
 * came back with nothing is a failure that starts with INCONCLUSIVE and
 * names the scanner, also never a finding.
 */
#define WD_VERDICT(_r) \
    do {                                                                    \
        if ((_r)->kind == R_SETUP)                                          \
        {                                                                   \
            char tmp_[sizeof((_r)->msg)];                                   \
                                                                            \
            snprintf(tmp_, sizeof(tmp_), "%s", (_r)->msg);                  \
            snprintf((_r)->msg, sizeof((_r)->msg), "SETUP %s: %.1400s",     \
                     setup_svc, tmp_);                                      \
        }                                                                   \
        else if ((_r)->kind == R_INCONCLUSIVE)                              \
        {                                                                   \
            char tmp_[sizeof((_r)->msg)];                                   \
                                                                            \
            snprintf(tmp_, sizeof(tmp_), "%s", (_r)->msg);                  \
            snprintf((_r)->msg, sizeof((_r)->msg), "INCONCLUSIVE: %.1480s", \
                     tmp_);                                                 \
        }                                                                   \
        cleanup_all();                                                      \
        if ((_r)->kind == R_PASS)                                           \
        {                                                                   \
            RING_VERDICT("%s", (_r)->msg);                                  \
            TEST_SUCCESS;                                                   \
        }                                                                   \
        TEST_VERDICT("%s", (_r)->msg);                                      \
    } while (0)

#endif /* MDE_WEBDEPS_LIB_H */

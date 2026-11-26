/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps ts_*: shared helpers of the TypeScript example tests
 *
 * Runs one shell command as a child in its own process group with stdin
 * from a file, stdout and stderr captured to files, a time limit and an
 * optional environment, and tells a clean exit from a signal or a hang.
 * Also: a stack-trace detector with its own known-bad control, and a
 * fake peer that accepts a TCP connection and never answers.
 */

#ifndef MDE_TS_LIB_H
#define MDE_TS_LIB_H

#include "webdeps_lib.h"

#define TS_CAP  65536   /**< Bytes of output kept per stream. */

typedef struct ts_run_t {
    int     code;       /**< Exit code, -1 when not exited. */
    int     sig;        /**< Terminating signal, 0 if none. */
    bool    hung;       /**< Killed by the test on the time limit. */
    double  secs;
    char    out[TS_CAP];
    char    err[TS_CAP];
    size_t  out_len;
    size_t  err_len;
} ts_run_t;

/** Read up to @p size - 1 bytes of a file; return the length. */
static size_t
ts_read(const char *path, char *buf, size_t size)
{
    FILE   *f = fopen(path, "r");
    size_t  n = 0;

    buf[0] = '\0';
    if (f == NULL)
        return 0;
    n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n;
}

/** First @p max bytes of @p s with newlines flattened, for a log line. */
static void
ts_flat(const char *s, size_t max, char *dst, size_t size)
{
    size_t i;

    for (i = 0; i < max && i + 1 < size && s[i] != '\0'; i++)
        dst[i] = (s[i] == '\n' || s[i] == '\r') ? '|' : s[i];
    dst[i] = '\0';
}

/**
 * Run `sh -c cmd` in @p cwd. @p env is a NULL-terminated list of
 * "NAME=value" strings added to the environment (may be NULL); @p stdin_path
 * is the file used as stdin (NULL: /dev/null). The whole process group is
 * killed after @p limit_s seconds.
 *
 * @return false when the child could not be started.
 */
static bool
ts_run(ts_run_t *r, const char *cwd, const char *cmd, const char *stdin_path,
       const char * const *env, const char *path_prefix, int limit_s,
       const char *tag)
{
    char    outp[200];
    char    errp[200];
    pid_t   pid;
    double  t0;
    double  end;
    int     status = 0;

    memset(r, 0, sizeof(*r));
    r->code = -1;
    snprintf(outp, sizeof(outp), "%s/%s.stdout", workdir, tag);
    snprintf(errp, sizeof(errp), "%s/%s.stderr", workdir, tag);
    t0 = now_s();
    pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0)
    {
        int  o = open(outp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int  e = open(errp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int  z = open(stdin_path != NULL ? stdin_path : "/dev/null",
                      O_RDONLY);
        int  k;
        char lib[700];

        setpgid(0, 0);
        dup2(z, 0);
        dup2(o, 1);
        dup2(e, 2);
        if (chdir(cwd) != 0)
            _exit(126);
        snprintf(lib, sizeof(lib), "%s/dist/lib", cwd);
        setenv("LD_LIBRARY_PATH", lib, 1);
        if (path_prefix != NULL)
        {
            char p[2048];

            snprintf(p, sizeof(p), "%s:%s", path_prefix,
                     getenv("PATH") != NULL ? getenv("PATH") : "/usr/bin");
            setenv("PATH", p, 1);
        }
        for (k = 0; env != NULL && env[k] != NULL; k++)
            putenv((char *)env[k]);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    end = t0 + limit_s;
    for (;;)
    {
        pid_t w = waitpid(pid, &status, WNOHANG);

        if (w == pid)
            break;
        if (now_s() >= end)
        {
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            r->hung = true;
            break;
        }
        usleep(50000);
    }
    /* Anything the command left behind in its group goes too. */
    kill(-pid, SIGKILL);
    r->secs = now_s() - t0;
    if (!r->hung)
    {
        if (WIFEXITED(status))
            r->code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status))
            r->sig = WTERMSIG(status);
    }
    r->out_len = ts_read(outp, r->out, sizeof(r->out));
    r->err_len = ts_read(errp, r->err, sizeof(r->err));
    return true;
}

/** One-line description of how a run ended. */
static void
ts_end_text(const ts_run_t *r, char *buf, size_t size)
{
    if (r->hung)
        snprintf(buf, size, "hung, killed after %.1f s", r->secs);
    else if (r->sig != 0)
        snprintf(buf, size, "killed by signal %d after %.1f s", r->sig,
                 r->secs);
    else
        snprintf(buf, size, "exit code %d after %.1f s", r->code, r->secs);
}

/** True when text looks like a Node/TypeScript crash and not a message. */
static bool
ts_has_trace(const char *s)
{
    static const char * const marks[] = {
        "\n    at ", "    at Object.", "    at Module.", "node:internal",
        "TypeError:", "ReferenceError:", "RangeError:", "SyntaxError:",
        "UnhandledPromiseRejection", "ERR_UNHANDLED_REJECTION",
        "Segmentation fault", "core dumped", "panicked at",
        "FATAL ERROR", "JavaScript heap out of memory", "TSError",
        "Unable to compile TypeScript",
    };
    size_t i;

    if (strncmp(s, "    at ", 7) == 0)
        return true;
    for (i = 0; i < sizeof(marks) / sizeof(marks[0]); i++)
    {
        if (strstr(s, marks[i]) != NULL)
            return true;
    }
    return false;
}

/**
 * Known-bad control for ts_has_trace(): a real Node trace must be flagged
 * and a plain error message must not. A detector failing this proves
 * nothing about the example.
 */
static bool
ts_trace_control_ok(char *why, size_t size)
{
    static const char bad[] =
        "/app/guess.ts:12\n    throw new Error(\"boom\");\n    ^\n\n"
        "Error: boom\n    at main (/app/guess.ts:12:11)\n"
        "    at Module._compile (node:internal/modules/cjs/loader:1)\n";
    static const char good[] = "guess: input is not a number: 'abc'\n";

    if (!ts_has_trace(bad))
    {
        snprintf(why, size, "stack-trace detector did not flag a planted "
                 "Node stack trace");
        return false;
    }
    if (ts_has_trace(good))
    {
        snprintf(why, size, "stack-trace detector flagged a plain error "
                 "message");
        return false;
    }
    return true;
}

/**
 * Known-bad control for the runner: a command that sleeps must be reported
 * as hung under a short limit, and a command that kills itself must be
 * reported as a signal.
 */
static bool
ts_runner_control_ok(const char *cwd, char *why, size_t size)
{
    ts_run_t r;

    if (!ts_run(&r, cwd, "sleep 30", NULL, NULL, NULL, 1, "ctl-hang") ||
        !r.hung || r.secs > 5.0)
    {
        snprintf(why, size, "runner did not report a planted 30 s sleep as "
                 "hung under a 1 s limit");
        return false;
    }
    if (!ts_run(&r, cwd, "kill -SEGV $$", NULL, NULL, NULL, 5, "ctl-sig") ||
        r.sig != SIGSEGV)
    {
        snprintf(why, size, "runner did not report a planted SIGSEGV as a "
                 "signal");
        return false;
    }
    return true;
}

/** A listening socket whose accepted connections are never answered. */
typedef struct ts_peer_t {
    int     lfd;
    pid_t   pid;
    unsigned port;
    char    count_path[200];
} ts_peer_t;

/** Start the silent peer on 127.0.0.1; return false on a setup fault. */
static bool
ts_peer_start(ts_peer_t *p, const char *dir)
{
    struct sockaddr_in a;
    socklen_t          l = sizeof(a);
    int                one = 1;

    memset(p, 0, sizeof(*p));
    p->lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (p->lfd < 0)
        return false;
    setsockopt(p->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(p->lfd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(p->lfd, 16) != 0 ||
        getsockname(p->lfd, (struct sockaddr *)&a, &l) != 0)
        return false;
    p->port = ntohs(a.sin_port);
    snprintf(p->count_path, sizeof(p->count_path), "%s/peer.count", dir);
    p->pid = fork();
    if (p->pid < 0)
        return false;
    if (p->pid == 0)
    {
        int n = 0;

        setpgid(0, 0);
        for (;;)
        {
            int c = accept(p->lfd, NULL, NULL);
            FILE *f;

            if (c < 0)
                continue;
            n++;
            f = fopen(p->count_path, "w");
            if (f != NULL)
            {
                fprintf(f, "%d\n", n);
                fclose(f);
            }
            /* Hold it open, read and discard, never write. */
            if (fork() == 0)
            {
                char b[4096];

                while (read(c, b, sizeof(b)) > 0)
                    ;
                pause();
                _exit(0);
            }
        }
    }
    return true;
}

/** How many connections the peer accepted so far. */
static int
ts_peer_count(const ts_peer_t *p)
{
    char b[32];

    if (ts_read(p->count_path, b, sizeof(b)) == 0)
        return 0;
    return atoi(b);
}

static void
ts_peer_stop(ts_peer_t *p)
{
    if (p->pid > 0)
    {
        kill(-p->pid, SIGKILL);
        kill(p->pid, SIGKILL);
        waitpid(p->pid, NULL, 0);
        p->pid = 0;
    }
    if (p->lfd > 0)
        close(p->lfd);
    p->lfd = -1;
}

/** Write @p n bytes of @p fill (then no newline) to a file. */
static bool
ts_write_fill(const char *path, char fill, size_t n)
{
    FILE *f = fopen(path, "w");
    size_t i;

    if (f == NULL)
        return false;
    for (i = 0; i < n; i++)
        fputc(fill, f);
    return fclose(f) == 0;
}

/**
 * A shim directory for the C compiler, as scripts/ensure-web-deps.sh makes
 * it: build.sh is written for macOS and its soname flag must be translated
 * for Linux. Returns the directory in @p dir.
 */
static bool
ts_cc_shim(const char *workdir_, char *dir, size_t size)
{
    char  path[512];
    FILE *f;

    snprintf(dir, size, "%.200s/shim", workdir_);
    if (mkdir(dir, 0700) != 0)
        return false;
    snprintf(path, sizeof(path), "%.400s/cc", dir);
    f = fopen(path, "w");
    if (f == NULL)
        return false;
    fputs("#!/bin/sh\n"
          "for a in \"$@\"; do\n  shift\n  case \"$a\" in\n"
          "    -Wl,-install_name,@rpath/*)\n"
          "      set -- \"$@\" \"-Wl,-soname,${a#-Wl,-install_name,@rpath/}\" ;;\n"
          "    *) set -- \"$@\" \"$a\" ;;\n  esac\ndone\n"
          "exec gcc -D_GNU_SOURCE \"$@\"\n", f);
    fclose(f);
    return chmod(path, 0755) == 0;
}

/**
 * Find the directory of the TypeScript example under @p root: the first of
 * the places the project has used that holds a package.json.
 */
static bool
ts_find_dir(const char *root, char *dir, size_t size)
{
    static const char * const cand[] = {
        "typescript", "src/typescript", "src/ts", "ts",
    };
    size_t i;

    for (i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
    {
        char p[1200];

        snprintf(p, sizeof(p), "%.500s/%s/package.json", root, cand[i]);
        if (access(p, R_OK) == 0)
        {
            snprintf(dir, size, "%.500s/%s", root, cand[i]);
            return true;
        }
    }
    /* Not in a place the project has used: any directory up to four levels
     * down that holds both a package.json and a tsconfig.json. */
    {
        char  cmd[1200];
        FILE *f;
        char  line[1100];
        bool  found = false;

        snprintf(cmd, sizeof(cmd), "find '%.500s' -maxdepth 4 -name "
                 "tsconfig.json -not -path '*/node_modules/*' 2>/dev/null",
                 root);
        f = popen(cmd, "r");
        if (f == NULL)
            return false;
        while (!found && fgets(line, sizeof(line), f) != NULL)
        {
            char *sl;
            char  p[1200];

            line[strcspn(line, "\n")] = '\0';
            sl = strrchr(line, '/');
            if (sl == NULL)
                continue;
            *sl = '\0';
            snprintf(p, sizeof(p), "%.1000s/package.json", line);
            if (access(p, R_OK) == 0)
            {
                snprintf(dir, size, "%s", line);
                found = true;
            }
        }
        pclose(f);
        return found;
    }
}

#endif /* MDE_TS_LIB_H */

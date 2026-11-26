/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: helpers shared by the four TypeScript example tests
 *
 * Builds on the process runner of webdeps/ts_lib.h and adds: the example
 * root and the TypeScript directory, a log of every step (command, exit
 * code, elapsed time, last 40 lines of stdout and of stderr), the service
 * chain the example talks to, and the numbers a demo prints.
 */

#ifndef MDE_TSX_LIB_H
#define MDE_TSX_LIB_H

#include "../webdeps/ts_lib.h"

#include <ctype.h>
#include <limits.h>
#include <glob.h>
#include <math.h>

#define TSX_TAIL    50      /**< Lines of the tail logged when a step fails. */

static void tsx_log_full(const char *label, const char *text);
static void tsx_crash(int sig);

/** Text of the TEST_STEP that is running, for the verdict of a failure. */
static char tsx_step[200] = "(before the first step)";

/** What the last command run through tsx_log_step() did. */
static struct tsx_last_t {
    bool    set;
    char    id[16];
    char    tag[64];
    char    cmd[500];
    char    cwd[300];
    int     code;
    int     sig;
    bool    hung;
    char    out[500];
    char    err[500];
} tsx_last;

/** TEST_STEP that also remembers its text as the current step name. */
#define TSX_STEP(_fs...) \
    do {                                                            \
        snprintf(tsx_step, sizeof(tsx_step), _fs);                  \
        TEST_STEP(_fs);                                             \
    } while (0)

/** Set up the work directory and the example root; false on a fault. */
static bool
tsx_init(res_t *res, const char *id)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGSEGV, tsx_crash);
    signal(SIGABRT, tsx_crash);
    src_root = getenv("TE_TS_MDE_SRC");
    if (src_root == NULL || src_root[0] == '\0')
    {
        res_set(res, R_FAIL, "%s NOT SETTLED: TE_TS_MDE_SRC is not set, so "
                "there is no project root to test", id);
        return false;
    }
    if (access(src_root, X_OK) != 0)
    {
        res_set(res, R_FAIL, "%s NOT SETTLED: project root %s does not "
                "exist", id, src_root);
        return false;
    }
    {
        static char absroot[PATH_MAX];

        if (realpath(src_root, absroot) != NULL)
            src_root = absroot;
        if (chdir(src_root) != 0)
        {
            res_set(res, R_FAIL, "%s NOT SETTLED: cannot change the working "
                    "directory to the project root %s: %s", id, src_root,
                    strerror(errno));
            return false;
        }
    }
    snprintf(workdir, sizeof(workdir), "/tmp/mde-wd-XXXXXX");
    if (mkdtemp(workdir) == NULL)
    {
        workdir[0] = '\0';
        res_set(res, R_FAIL, "%s NOT SETTLED: cannot create a work "
                "directory", id);
        return false;
    }
    {
        res_t ignore = { .kind = R_PASS };

        /* The ports of the services; a missing table only means the
         * service chain cannot be started. */
        read_contract(&ignore);
    }
    return true;
}

/** Last @p n lines of the file @p path, each logged on its own. */
static void
tsx_log_tail(const char *label, const char *path, int n)
{
    char    buf[16384];
    FILE   *f = fopen(path, "r");
    long    len;
    size_t  got;
    char   *p;
    char   *lines[TSX_TAIL + 1];
    int     cnt = 0;
    int     i;

    (void)n; /* the tail length is fixed at TSX_TAIL */
    if (f == NULL)
    {
        RING("%s: (no file %s)", label, path);
        return;
    }
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, len > (long)sizeof(buf) - 1 ? -((long)sizeof(buf) - 1) : 0,
          SEEK_SET);
    got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[got] = '\0';
    if (got == 0)
    {
        RING("%s: (empty)", label);
        return;
    }
    for (p = strtok(buf, "\n"); p != NULL; p = strtok(NULL, "\n"))
    {
        if (cnt == TSX_TAIL)
        {
            memmove(lines, lines + 1, (TSX_TAIL - 1) * sizeof(lines[0]));
            cnt--;
        }
        lines[cnt++] = p;
    }
    for (i = 0; i < cnt; i++)
    {
        char cut[400];

        snprintf(cut, sizeof(cut), "%s", lines[i]);
        RING("%s: %s", label, cut);
    }
}

/**
 * Log one step: command, working directory, exit code, elapsed time and
 * the whole of stdout and stderr; when the step failed, also the last
 * TSX_TAIL lines of both. The step is kept for tsx_evidence().
 */
static void
tsx_log_step(const char *id, const char *tag, const char *cmd,
             const ts_run_t *r)
{
    char what[200];
    char path[300];
    char label[120];
    bool failed = r->hung || r->sig != 0 || r->code != 0;

    ts_end_text(r, what, sizeof(what));
    RING("%s step %s: command [%s]; working directory [%s]; exit code %d; "
         "signal %d; elapsed %.2f s; %s", id, tag, cmd,
         src_root != NULL ? src_root : "", r->code, r->sig, r->secs, what);
    snprintf(label, sizeof(label), "%s %s stdout", id, tag);
    tsx_log_full(label, r->out);
    snprintf(label, sizeof(label), "%s %s stderr", id, tag);
    tsx_log_full(label, r->err);
    if (failed)
    {
        ERROR("%s step %s FAILED: %s; last %d lines of the output follow",
              id, tag, what, TSX_TAIL);
        snprintf(path, sizeof(path), "%s/%s.stdout", workdir, tag);
        snprintf(label, sizeof(label), "%s %s stdout(last %d lines)", id,
                 tag, TSX_TAIL);
        tsx_log_tail(label, path, TSX_TAIL);
        snprintf(path, sizeof(path), "%s/%s.stderr", workdir, tag);
        snprintf(label, sizeof(label), "%s %s stderr(last %d lines)", id,
                 tag, TSX_TAIL);
        tsx_log_tail(label, path, TSX_TAIL);
    }
    memset(&tsx_last, 0, sizeof(tsx_last));
    tsx_last.set = true;
    snprintf(tsx_last.id, sizeof(tsx_last.id), "%s", id);
    snprintf(tsx_last.tag, sizeof(tsx_last.tag), "%s", tag);
    snprintf(tsx_last.cmd, sizeof(tsx_last.cmd), "%s", cmd);
    snprintf(tsx_last.cwd, sizeof(tsx_last.cwd), "%s",
             src_root != NULL ? src_root : "");
    tsx_last.code = r->code;
    tsx_last.sig = r->sig;
    tsx_last.hung = r->hung;
    ts_flat(r->out + (r->out_len > 300 ? r->out_len - 300 : 0), 300,
            tsx_last.out, sizeof(tsx_last.out));
    ts_flat(r->err + (r->err_len > 300 ? r->err_len - 300 : 0), 300,
            tsx_last.err, sizeof(tsx_last.err));
}

/** Result of tsx_sh(): how a shell command ended and the end of its output. */
typedef struct tsx_sh_t {
    bool    started;        /**< The shell could be started at all. */
    int     code;           /**< Exit code, -1 when not exited. */
    int     sig;
    bool    hung;
    double  secs;
    size_t  len;            /**< Bytes of combined output. */
    char    tail[3600];     /**< Last TSX_TAIL lines, " | " between lines. */
    char    text[8192];     /**< The last bytes of the combined output. */
} tsx_sh_t;

/** Last @p n lines of @p s joined with " | " into @p dst. */
static void
tsx_last_lines(const char *s, int n, char *dst, size_t size)
{
    const char *e = s + strlen(s);
    const char *p;
    int         lines = 0;
    size_t      o = 0;

    while (e > s && (e[-1] == '\n' || e[-1] == '\r'))
        e--;
    p = e;
    while (p > s)
    {
        if (p[-1] == '\n' && ++lines >= n)
            break;
        p--;
    }
    if ((size_t)(e - p) >= size)
        p = e - (size - 1);
    for (; p < e && o + 4 < size; p++)
    {
        if (*p == '\n')
        {
            dst[o++] = ' ';
            dst[o++] = '|';
            dst[o++] = ' ';
        }
        else if (*p != '\r')
            dst[o++] = *p;
    }
    dst[o] = '\0';
}

/**
 * Step 0 helper of every test: run @p cmd through `sh -c` in @p cwd with
 * stdout and stderr captured together, write the whole text to the test log
 * and keep the exit code and the last TSX_TAIL lines for the verdict (see
 * tsx_sh_text()). Returns false only when the shell could not be started;
 * the reason is then in the log and the caller must still give a verdict.
 * @p env is a NULL-terminated list of NAME=value strings, may be NULL.
 */
static bool
tsx_sh(tsx_sh_t *o, const char *id, const char *tag, const char *cwd,
       const char *cmd, int limit_s, const char * const *env)
{
    ts_run_t *r = calloc(1, sizeof(*r));
    char     *wrapped = malloc(strlen(cmd) + 32);
    char      label[160];
    size_t    tl;

    memset(o, 0, sizeof(*o));
    o->code = -1;
    if (workdir[0] == '\0')
    {
        snprintf(workdir, sizeof(workdir), "/tmp/mde-wd-XXXXXX");
        if (mkdtemp(workdir) == NULL)
            workdir[0] = '\0';
    }
    if (r == NULL || wrapped == NULL || workdir[0] == '\0')
    {
        free(r);
        free(wrapped);
        ERROR("%s step %s: cannot allocate or create a work directory for "
              "[%s]", id, tag, cmd);
        return false;
    }
    sprintf(wrapped, "( %s\n) 2>&1", cmd);
    if (!ts_run(r, cwd, wrapped, NULL, env, NULL, limit_s, tag))
    {
        ERROR("%s step %s: cannot start sh for [%s] in [%s]", id, tag, cmd,
              cwd);
        free(r);
        free(wrapped);
        return false;
    }
    {
        /* ts_run keeps the first bytes; a long build needs its end. */
        char  path[300];
        FILE *f;

        snprintf(path, sizeof(path), "%s/%s.stdout", workdir, tag);
        f = fopen(path, "r");
        if (f != NULL)
        {
            long len;

            fseek(f, 0, SEEK_END);
            len = ftell(f);
            fseek(f, len > (long)(TS_CAP - 1) ? len - (TS_CAP - 1) : 0,
                  SEEK_SET);
            r->out_len = fread(r->out, 1, TS_CAP - 1, f);
            r->out[r->out_len] = '\0';
            fclose(f);
        }
    }
    o->started = true;
    o->code = r->code;
    o->sig = r->sig;
    o->hung = r->hung;
    o->secs = r->secs;
    o->len = r->out_len;
    RING("%s step %s: command [%s]; working directory [%s]; exit code %d; "
         "signal %d%s; elapsed %.2f s; %zu byte(s) of stdout and stderr "
         "together", id, tag, cmd, cwd, r->code, r->sig,
         r->hung ? "; killed on the time limit" : "", r->secs, r->out_len);
    snprintf(label, sizeof(label), "%s %s output", id, tag);
    tsx_log_full(label, r->out);
    tsx_last_lines(r->out, TSX_TAIL, o->tail, sizeof(o->tail));
    snprintf(o->text, sizeof(o->text), "%s", r->out_len > sizeof(o->text) - 1 ?
             r->out + r->out_len - (sizeof(o->text) - 1) : r->out);
    memset(&tsx_last, 0, sizeof(tsx_last));
    tsx_last.set = true;
    snprintf(tsx_last.id, sizeof(tsx_last.id), "%s", id);
    snprintf(tsx_last.tag, sizeof(tsx_last.tag), "%s", tag);
    snprintf(tsx_last.cmd, sizeof(tsx_last.cmd), "%s", cmd);
    snprintf(tsx_last.cwd, sizeof(tsx_last.cwd), "%s", cwd);
    tsx_last.code = r->code;
    tsx_last.sig = r->sig;
    tsx_last.hung = r->hung;
    tl = strlen(o->tail);
    ts_flat(o->tail + (tl > 300 ? tl - 300 : 0), 300, tsx_last.out,
            sizeof(tsx_last.out));
    free(r);
    free(wrapped);
    return true;
}

/** The verdict text of a tsx_sh() run: exit code and the last 50 lines. */
static void
tsx_sh_text(const tsx_sh_t *o, char *dst, size_t size)
{
    if (!o->started)
        snprintf(dst, size, "the shell could not be started");
    else
        snprintf(dst, size, "exit code %d%s%s; last %d lines of stdout and "
                 "stderr [%s]", o->code, o->sig != 0 ? ", killed by a "
                 "signal" : "", o->hung ? ", killed on the time limit" : "",
                 TSX_TAIL, o->tail[0] != '\0' ? o->tail : "(no output)");
}

/** True when the shell ran and exited 0 on its own. */
static bool
tsx_sh_ok(const tsx_sh_t *o)
{
    return o->started && !o->hung && o->sig == 0 && o->code == 0;
}

/** Marker a passing ts_build leaves for the tests that need the build. */
#define TSX_BUILD_MARK  "/tmp/mde-ts-build.passed"

/**
 * For the tests that run after ts_build: when the build did not pass, set
 * the result to a skip that names the reason and return false.
 */
static bool
tsx_need_build(res_t *res, const char *id)
{
    if (access(TSX_BUILD_MARK, R_OK) == 0)
        return true;
    res_set(res, R_SKIP, "%s SKIPPED: ts_build did not pass in this run "
            "(no %s), so there is no built TypeScript example to run; "
            "%s is not settled by this test", id, TSX_BUILD_MARK, id);
    return false;
}

/** After a crash of the test itself, say so before dying. */
static void
tsx_crash(int sig)
{
    static const char m[] = "ts_example: the test process itself received "
        "a fatal signal; it has no verdict because of it\n";

    if (write(2, m, sizeof(m) - 1) < 0)
        _exit(2);
    signal(sig, SIG_DFL);
    raise(sig);
}

/**
 * Record, and log in full, a command that was started by the test itself
 * (not through ts_run) and whose output went to @p outp and @p errp.
 */
static void
tsx_note_proc(const char *id, const char *tag, const char *cmd, int code,
              int sig, const char *outp, const char *errp)
{
    ts_run_t *r = calloc(1, sizeof(*r));

    if (r == NULL)
        return;
    r->code = code;
    r->sig = sig;
    r->out_len = ts_read(outp, r->out, sizeof(r->out));
    r->err_len = ts_read(errp, r->err, sizeof(r->err));
    {
        char path[300];

        /* tsx_log_step reads the tails of <workdir>/<tag>.* on a failure. */
        snprintf(path, sizeof(path), "%s/%s.stdout", workdir, tag);
        if (strcmp(path, outp) != 0)
            ts_write_fill(path, ' ', 0);
    }
    tsx_log_step(id, tag, cmd, r);
    free(r);
}

/**
 * Add to a failing result the evidence the verdict must carry: the step
 * that was running, the last command, its exit code and the end of stdout
 * and stderr. A passing or skipped result is left alone.
 */
static void
tsx_evidence(res_t *r)
{
    size_t n;

    if (r->kind == R_PASS || r->kind == R_SKIP)
        return;
    n = strlen(r->msg);
    snprintf(r->msg + n, sizeof(r->msg) - n, " | failing step [%s]",
             tsx_step);
    n = strlen(r->msg);
    if (tsx_last.set)
        snprintf(r->msg + n, sizeof(r->msg) - n, "; last command [%s] in "
                 "[%s] (%s): exit code %d, signal %d%s; stdout [%s]; "
                 "stderr [%s]", tsx_last.cmd, tsx_last.cwd, tsx_last.tag,
                 tsx_last.code, tsx_last.sig, tsx_last.hung ? ", killed on "
                 "the time limit" : "", tsx_last.out, tsx_last.err);
    else
        snprintf(r->msg + n, sizeof(r->msg) - n, "; no command had run yet");
}

/** The verdict of a test: the evidence first, then the usual verdict. */
#define TSX_VERDICT(_r, _id) \
    do {                                                                    \
        tsx_evidence(_r);                                                   \
        T_VERDICT(_r, _id);                                                 \
    } while (0)

/** The entry file of the TypeScript build, from "main" in package.json. */
static void
tsx_entry(const char *tsdir, char *entry, size_t size)
{
    char  path[700];
    char  json[8192];
    char *p;

    snprintf(entry, size, "dist/main.js");
    snprintf(path, sizeof(path), "%s/package.json", tsdir);
    if (ts_read(path, json, sizeof(json)) == 0)
        return;
    p = strstr(json, "\"main\"");
    if (p == NULL)
        return;
    p = strchr(p + 6, '"');
    if (p == NULL)
        return;
    {
        char *q = strchr(p + 1, '"');

        if (q != NULL && q > p + 1 && (size_t)(q - p - 1) < size)
        {
            memcpy(entry, p + 1, q - p - 1);
            entry[q - p - 1] = '\0';
        }
    }
}

/** True when the first existing TypeScript output is present. */
static bool
tsx_output_exists(const char *tsdir, char *found, size_t size)
{
    char entry[200];
    char p[1000];

    tsx_entry(tsdir, entry, sizeof(entry));
    snprintf(p, sizeof(p), "%.600s/%s", tsdir, entry);
    if (access(p, R_OK) == 0)
    {
        snprintf(found, size, "%s", p);
        return true;
    }
    snprintf(p, sizeof(p), "%.600s/dist", tsdir);
    if (access(p, X_OK) == 0)
    {
        snprintf(found, size, "%s", p);
        return true;
    }
    snprintf(found, size, "%.600s/%s (and no dist directory)", tsdir, entry);
    return false;
}

/**
 * Count the compiled JavaScript files the compiled files of <tsdir>/dist that were written
 * at or after @p since (a wall-clock second; 0 accepts any). The first one
 * is copied to @p found. Returns -1 when there is no such directory.
 */
static int
tsx_dist_js(const char *tsdir, time_t since, char *found, size_t size)
{
    glob_t  g;
    char    pat[900];
    int     n = 0;
    size_t  i;

    found[0] = '\0';
    snprintf(pat, sizeof(pat), "%.800s/dist/*.js", tsdir);
    if (glob(pat, 0, NULL, &g) != 0)
        return -1;
    for (i = 0; i < g.gl_pathc; i++)
    {
        struct stat st;

        if (stat(g.gl_pathv[i], &st) != 0 || st.st_mtime + 2 < since)
            continue;
        if (n++ == 0)
            snprintf(found, size, "%s", g.gl_pathv[i]);
    }
    globfree(&g);
    return n;
}

/** True when the two replies are the same bytes, length included. */
static bool
tsx_same_bytes(const char *a, size_t an, const char *b, size_t bn)
{
    return an == bn && memcmp(a, b, an) == 0;
}

/** Offset of the first byte in which the two replies differ. */
static size_t
tsx_first_diff(const char *a, size_t an, const char *b, size_t bn)
{
    size_t i;

    for (i = 0; i < an && i < bn && a[i] == b[i]; i++)
        ;
    return i;
}

/** The reply as one line: newlines shown as \n, at most @p max bytes. */
static void
tsx_escape(const char *s, size_t n, size_t max, char *dst, size_t size)
{
    size_t i;
    size_t o = 0;

    for (i = 0; i < n && i < max && o + 3 < size; i++)
    {
        if (s[i] == '\n')
        {
            dst[o++] = '\\';
            dst[o++] = 'n';
        }
        else if (s[i] == '\r')
        {
            dst[o++] = '\\';
            dst[o++] = 'r';
        }
        else
            dst[o++] = s[i];
    }
    dst[o] = '\0';
}

/** Known-bad control of tsx_same_bytes(): a one-byte, a length and a
 *  trailing-newline difference must all be told apart. */
static bool
tsx_bytes_control_ok(char *why, size_t size)
{
    static const char a[] = "value=47.5\n";

    if (!tsx_same_bytes(a, sizeof(a) - 1, "value=47.5\n", 11))
    {
        snprintf(why, size, "equal replies were called different");
        return false;
    }
    if (tsx_same_bytes(a, sizeof(a) - 1, "value=48.5\n", 11) ||
        tsx_same_bytes(a, sizeof(a) - 1, "value=47.5", 10) ||
        tsx_same_bytes(a, sizeof(a) - 1, "value=47.5\n\n", 12) ||
        tsx_same_bytes(a, sizeof(a) - 1, "", 0))
    {
        snprintf(why, size, "a planted one-byte, missing-newline, "
                 "extra-newline or empty difference was called equal");
        return false;
    }
    if (tsx_first_diff(a, sizeof(a) - 1, "value=48.5\n", 11) != 6)
    {
        snprintf(why, size, "the first differing byte was not found");
        return false;
    }
    return true;
}

/** Gateway URL the example is pointed at; filled by tsx_services_up(). */
static char tsx_url[100];

/**
 * Start the web services that exist, in contract order, and log which ones
 * stand. Returns how many are listening. The example reaches the gateway
 * only when the whole chain is up, so a chain that is not complete is
 * named in @p note.
 */
static int
tsx_services_up(const char *id, char *note, size_t size)
{
    int     idx;
    int     up = 0;
    res_t   r = { .kind = R_PASS };

    note[0] = '\0';
    for (idx = GW; idx <= CS; idx++)
    {
        if (tab_port[idx] == 0)
        {
            append(note, size, "%s has no port in the contract; ",
                   names[idx]);
            continue;
        }
        if (svc_start(&r, idx) != NULL)
        {
            up++;
            RING("%s: %s is listening on 127.0.0.1:%u", id, names[idx],
                 tab_port[idx]);
        }
        else
        {
            append(note, size, "%s not started (%.150s); ", names[idx],
                   r.msg);
            RING("%s: %s not started: %s", id, names[idx], r.msg);
        }
    }
    snprintf(tsx_url, sizeof(tsx_url), "http://127.0.0.1:%u",
             tab_port[GW]);
    return up;
}

/** The last decimal number printed after the word "result", or after all. */
static bool
tsx_result_number(const char *s, double *out)
{
    const char *p = s;
    const char *last = NULL;
    const char *q;
    bool        any = false;

    /* Prefer a number that follows the word "result" (any case). */
    for (q = s; *q != '\0'; q++)
    {
        if (strncasecmp(q, "result", 6) == 0)
            last = q + 6;
    }
    if (last != NULL)
    {
        while (*last != '\0' && !isdigit((unsigned char)*last) &&
               !(*last == '-' && isdigit((unsigned char)last[1])))
            last++;
        if (*last != '\0')
        {
            *out = strtod(last, NULL);
            return true;
        }
    }
    /* Otherwise the last number in the text. */
    while (*p != '\0')
    {
        char *end;

        if (isdigit((unsigned char)*p) ||
            (*p == '-' && isdigit((unsigned char)p[1])))
        {
            double v = strtod(p, &end);

            if (end > p)
            {
                *out = v;
                any = true;
                p = end;
                continue;
            }
        }
        p++;
    }
    return any;
}

/** Log every line of @p text (at most 200), each prefixed with @p label. */
static void
tsx_log_full(const char *label, const char *text)
{
    const char *p = text;
    int         n = 0;

    if (text[0] == '\0')
    {
        RING("%s: (empty)", label);
        return;
    }
    while (*p != '\0' && n < 2000)
    {
        size_t k = strcspn(p, "\n");

        RING("%s: %.*s", label, (int)(k > 390 ? 390 : k), p);
        p += k + (p[k] == '\n' ? 1 : 0);
        n++;
    }
    if (*p != '\0')
        RING("%s: (more lines not shown)", label);
}

/** The path of the built TypeScript entry file of @p root, or "" when
 *  there is no TypeScript directory. */
static bool
tsx_index_js(const char *root, char *tsdir, size_t dsize, char *index,
             size_t isize)
{
    tsdir[0] = '\0';
    if (!ts_find_dir(root, tsdir, dsize))
    {
        snprintf(index, isize, "%.500s/typescript/dist/index.js", root);
        return false;
    }
    snprintf(index, isize, "%.700s/dist/index.js", tsdir);
    return true;
}

/** The last line of @p text that starts with "value=", trimmed, in @p out;
 *  false when there is none. */
static bool
tsx_answer_line(const char *text, char *out, size_t size)
{
    const char *p = text;
    bool        any = false;

    out[0] = '\0';
    while (*p != '\0')
    {
        size_t k = strcspn(p, "\n");
        size_t e = k;

        if (strncmp(p, "value=", 6) == 0)
        {
            while (e > 0 && isspace((unsigned char)p[e - 1]))
                e--;
            if (e >= size)
                e = size - 1;
            memcpy(out, p, e);
            out[e] = '\0';
            any = true;
        }
        p += k + (p[k] == '\n' ? 1 : 0);
    }
    return any;
}

/**
 * The part of the output of ./scripts/run.sh guess that belongs to the
 * node @p svc: the lines after "== guess (TypeScript) -> <svc> " up to the
 * next "== " line. Copied to @p out; false when the node has no section.
 */
static bool
tsx_section(const char *text, const char *svc, char *out, size_t size)
{
    char        key[100];
    const char *p;
    const char *e;
    size_t      n;

    snprintf(key, sizeof(key), "-> %s :", svc);
    p = strstr(text, key);
    if (p == NULL)
        return false;
    p = strchr(p, '\n');
    if (p == NULL)
    {
        out[0] = '\0';
        return true;
    }
    p++;
    e = strstr(p, "\n== ");
    n = e != NULL ? (size_t)(e - p) + 1 : strlen(p);
    if (n >= size)
        n = size - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

/**
 * Log the TCP sockets of process @p pid as tapi_netexpose reports them and
 * count the ones that listen. Returns the number of listening sockets, or
 * -1 when the socket tables could not be read; @p total gets the number of
 * sockets the process holds.
 */
static int
tsx_expose_log(const char *id, tsapi_mde_session *session, pid_t pid,
               const char *what, unsigned *total, unsigned *port_of_first)
{
    unsigned long                ino[MAX_INO];
    tapi_netexpose_opt           opt = tapi_netexpose_default_opt;
    te_vec                       socks = TE_VEC_INIT(tapi_netexpose_socket);
    const tapi_netexpose_socket *s;
    size_t                       n = pid_inodes(pid, ino, MAX_INO);
    size_t                       k;
    int                          listening = 0;

    *total = 0;
    if (port_of_first != NULL)
        *port_of_first = 0;
    opt.udp = false;
    opt.tcp = true;
    if (tapi_netexpose_sockets(session->factory, &opt, &socks) != 0)
    {
        te_vec_free(&socks);
        return -1;
    }
    TE_VEC_FOREACH(&socks, s)
    {
        for (k = 0; k < n; k++)
        {
            char     la[64];
            char     ra[64];
            bool     l;

            if (ino[k] != s->inode)
                continue;
            l = tapi_netexpose_socket_is_listening(s);
            sock_addr(&s->local, la, sizeof(la));
            sock_addr(&s->remote, ra, sizeof(ra));
            RING("%s: %s pid %d holds %s socket local %s:%u remote %s:%u "
                 "state %u (tapi_netexpose)", id, what, (int)pid,
                 l ? "a LISTENING" : "a", la, sock_port(&s->local), ra,
                 sock_port(&s->remote), s->state);
            (*total)++;
            if (l)
            {
                listening++;
                if (port_of_first != NULL && *port_of_first == 0)
                    *port_of_first = sock_port(&s->local);
            }
        }
    }
    te_vec_free(&socks);
    RING("%s: %s pid %d: %u socket(s), %d listening", id, what, (int)pid,
         *total, listening);
    return listening;
}

/**
 * Start the built TypeScript example (node <index> 1 3) against
 * GUESS_ENDPOINT=@p endpoint in the background, wait until it holds a
 * socket (at most 3 s), log with tapi_netexpose what it listens on and
 * stop it. Returns the number of listening sockets of the process, or -1
 * when it could not be observed (the reason is logged).
 */
static int
tsx_ts_probe(const char *id, tsapi_mde_session *session, const char *index,
             const char *endpoint, unsigned *total)
{
    pid_t           pid;
    double          end;
    unsigned long   ino[MAX_INO];
    int             rc;

    *total = 0;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0)
    {
        int z = open("/dev/null", O_RDWR);

        setpgid(0, 0);
        dup2(z, 0);
        dup2(z, 1);
        dup2(z, 2);
        setenv("GUESS_ENDPOINT", endpoint, 1);
        execlp("node", "node", index, "1", "3", (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    end = now_s() + 3.0;
    while (now_s() < end && pid_inodes(pid, ino, MAX_INO) == 0)
        usleep(50000);
    usleep(200000);
    rc = tsx_expose_log(id, session, pid, "TypeScript process", total, NULL);
    kill(-pid, SIGKILL);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return rc;
}

/** What tapi_netexpose says about the listeners of one started example. */
typedef struct tsx_lp_t {
    bool        started;        /**< The process could be started. */
    bool        exited;         /**< It ended before it was observed. */
    int         n;              /**< Listening TCP sockets. */
    unsigned    port[8];
    char        addr[8][64];
    bool        wild;           /**< Some listener is on 0.0.0.0 or ::. */
} tsx_lp_t;

/** True when the textual address is the wildcard address. */
static bool
tsx_addr_is_wild(const char *a)
{
    return strcmp(a, "0.0.0.0") == 0 || strcmp(a, "::") == 0 ||
           a[0] == '\0';
}

/** Known-bad control of the address check: a wildcard is told from loopback. */
static bool
tsx_addr_control_ok(char *why, size_t size)
{
    if (!tsx_addr_is_wild("0.0.0.0") || !tsx_addr_is_wild("::") ||
        tsx_addr_is_wild("127.0.0.1") || tsx_addr_is_wild("::1"))
    {
        snprintf(why, size, "the wildcard address check did not tell "
                 "0.0.0.0 and :: from 127.0.0.1 and ::1");
        return false;
    }
    return true;
}

/**
 * Start `node <index>` with the address and port variables set to
 * 127.0.0.1 and @p port (@p port != 0), or with none of them set
 * (@p port == 0), wait up to @p wait_s for it to listen, record with
 * tapi_netexpose the local address and port of every listening socket of
 * the process, then stop it. Stdout and stderr of the example go to the
 * test log. Returns false when the process could not be started.
 */
static bool
tsx_listen_probe(const char *id, tsapi_mde_session *session,
                 const char *index, unsigned port, const char *tag,
                 double wait_s, tsx_lp_t *lp)
{
    static const char * const vars[] = {
        "PORT", "GUESS_PORT", "LISTEN_PORT", "GUESS_LISTEN", "GUESS_ADDR",
        "GUESS_ADDRESS", "GUESS_HOST", "LISTEN_ADDR", "LISTEN_HOST", "HOST",
        "GUESS_ENDPOINT",
    };
    char    outp[300];
    char    errp[300];
    char    cmd[600];
    pid_t   pid;
    double  end;
    int     st = 0;
    size_t  v;

    memset(lp, 0, sizeof(*lp));
    snprintf(outp, sizeof(outp), "%s/%s.stdout", workdir, tag);
    snprintf(errp, sizeof(errp), "%s/%s.stderr", workdir, tag);
    snprintf(cmd, sizeof(cmd), "node '%s' (%s)", index, port != 0 ?
             "address variables 127.0.0.1, port variables set" :
             "no address or port variable set");
    pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0)
    {
        int z = open("/dev/null", O_RDONLY);
        int o = open(outp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int e = open(errp, O_WRONLY | O_CREAT | O_TRUNC, 0600);

        setpgid(0, 0);
        dup2(z, 0);
        dup2(o, 1);
        dup2(e, 2);
        for (v = 0; v < sizeof(vars) / sizeof(vars[0]); v++)
            unsetenv(vars[v]);
        if (port != 0)
        {
            char val[32];
            char ep[64];

            snprintf(val, sizeof(val), "%u", port);
            snprintf(ep, sizeof(ep), "127.0.0.1:%u", port);
            setenv("PORT", val, 1);
            setenv("GUESS_PORT", val, 1);
            setenv("LISTEN_PORT", val, 1);
            setenv("GUESS_LISTEN", ep, 1);
            setenv("GUESS_ADDR", "127.0.0.1", 1);
            setenv("GUESS_ADDRESS", "127.0.0.1", 1);
            setenv("GUESS_HOST", "127.0.0.1", 1);
            setenv("LISTEN_ADDR", "127.0.0.1", 1);
            setenv("LISTEN_HOST", "127.0.0.1", 1);
            setenv("HOST", "127.0.0.1", 1);
        }
        execlp("node", "node", index, (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    lp->started = true;
    end = now_s() + wait_s;
    while (now_s() < end)
    {
        unsigned long                ino[MAX_INO];
        tapi_netexpose_opt           opt = tapi_netexpose_default_opt;
        te_vec                       socks = TE_VEC_INIT(tapi_netexpose_socket);
        const tapi_netexpose_socket *s;
        size_t                       ni;
        size_t                       k;

        if (waitpid(pid, &st, WNOHANG) == pid)
        {
            lp->exited = true;
            pid = 0;
            break;
        }
        ni = pid_inodes(pid, ino, MAX_INO);
        opt.udp = false;
        opt.tcp = true;
        lp->n = 0;
        lp->wild = false;
        if (tapi_netexpose_sockets(session->factory, &opt, &socks) == 0)
        {
            TE_VEC_FOREACH(&socks, s)
            {
                for (k = 0; k < ni; k++)
                {
                    if (ino[k] != s->inode ||
                        !tapi_netexpose_socket_is_listening(s) || lp->n >= 8)
                        continue;
                    sock_addr(&s->local, lp->addr[lp->n], sizeof(lp->addr[0]));
                    lp->port[lp->n] = sock_port(&s->local);
                    if (tsx_addr_is_wild(lp->addr[lp->n]))
                        lp->wild = true;
                    RING("%s: %s: pid %d listens on %s:%u (tapi_netexpose)",
                         id, tag, (int)pid, lp->addr[lp->n], lp->port[lp->n]);
                    lp->n++;
                }
            }
        }
        te_vec_free(&socks);
        if (lp->n > 0)
            break;
        usleep(250000);
    }
    if (pid > 0)
    {
        kill(-pid, SIGKILL);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    tsx_note_proc(id, tag, cmd, lp->exited ? (WIFEXITED(st) ?
                  WEXITSTATUS(st) : -1) : -1, lp->exited &&
                  WIFSIGNALED(st) ? WTERMSIG(st) : 0, outp, errp);
    return true;
}

/**
 * Judge a tsx_lp_t: empty when the example listens, on 127.0.0.1 only and
 * not on a wildcard address (and on @p port when it is not 0); otherwise a
 * sentence naming the fault in @p why.
 */
static bool
tsx_lp_loopback_only(const tsx_lp_t *lp, unsigned port, char *why,
                     size_t size)
{
    int i;

    if (!lp->started)
        snprintf(why, size, "the example could not be started");
    else if (lp->exited && lp->n == 0)
        snprintf(why, size, "the example exited before it listened");
    else if (lp->n == 0)
        snprintf(why, size, "the example listened on no TCP socket");
    else if (lp->wild)
        snprintf(why, size, "the example listens on a wildcard address "
                 "(0.0.0.0 or ::), not on 127.0.0.1 only");
    else
    {
        for (i = 0; i < lp->n; i++)
        {
            if (strcmp(lp->addr[i], "127.0.0.1") != 0)
            {
                snprintf(why, size, "the example listens on %s, not on "
                         "127.0.0.1", lp->addr[i]);
                return false;
            }
            if (port != 0 && lp->port[i] != port)
            {
                snprintf(why, size, "the example listens on port %u, "
                         "not on the configured port %u", lp->port[i], port);
                return false;
            }
        }
        return true;
    }
    return false;
}

#endif /* MDE_TSX_LIB_H */

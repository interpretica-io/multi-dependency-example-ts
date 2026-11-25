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
#include <math.h>

#define TSX_TAIL    40      /**< Lines of each stream kept in the log. */

/** Set up the work directory and the example root; false on a fault. */
static bool
tsx_init(res_t *res, const char *id)
{
    signal(SIGPIPE, SIG_IGN);
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

/** Log one step: command, exit code, elapsed time, tails of both streams. */
static void
tsx_log_step(const char *id, const char *tag, const char *cmd,
             const ts_run_t *r)
{
    char what[200];
    char path[300];
    char label[120];

    ts_end_text(r, what, sizeof(what));
    RING("%s step %s: command [%s]; exit code %d; signal %d; elapsed %.2f s; "
         "%s", id, tag, cmd, r->code, r->sig, r->secs, what);
    snprintf(path, sizeof(path), "%s/%s.stdout", workdir, tag);
    snprintf(label, sizeof(label), "%s %s stdout(last %d lines)", id, tag,
             TSX_TAIL);
    tsx_log_tail(label, path, TSX_TAIL);
    snprintf(path, sizeof(path), "%s/%s.stderr", workdir, tag);
    snprintf(label, sizeof(label), "%s %s stderr(last %d lines)", id, tag,
             TSX_TAIL);
    tsx_log_tail(label, path, TSX_TAIL);
}

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
    while (*p != '\0' && n < 200)
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
    n = e != NULL ? (size_t)(e - p) : strlen(p);
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

#endif /* MDE_TSX_LIB_H */

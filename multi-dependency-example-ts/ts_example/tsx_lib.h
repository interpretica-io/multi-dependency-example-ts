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

#endif /* MDE_TSX_LIB_H */

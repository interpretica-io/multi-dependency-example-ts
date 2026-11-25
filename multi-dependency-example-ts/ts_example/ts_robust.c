/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_robust, the TypeScript example reads its endpoint
 *        from GUESS_ENDPOINT, has no hardcoded URL and ends in time against
 *        a silent peer (settles H3)
 *
 * Three checks, each with its own message in the verdict:
 *  (a) the TypeScript source under src/ is scanned, comments removed, for a
 *      literal http:// or https:// or an IP address; any hit fails;
 *  (b) the example is started with GUESS_ENDPOINT set to a local port the
 *      test chose; it must connect to that port and to no other (a second
 *      listener on another port must stay unvisited);
 *  (c) GUESS_ENDPOINT points at a local listener that accepts and never
 *      answers; the example must end with a non-zero exit code in 10 s or
 *      less; a hang fails. The elapsed time and the exit code are logged.
 * A further check (d) keeps the earlier bad-input cases (empty, non-numeric,
 * oversize) with the same bounds: no hang, no signal, no stack trace.
 * Known-bad controls: a planted URL in a scanned file, a planted hang, a
 * planted trace and a connection to a counted listener.
 *
 * The example is run as node dist/index.js: ./scripts/run.sh sets
 * GUESS_ENDPOINT itself, so it cannot test the variable.
 *
 * @author midair <midair@localhost>
 */

#ifndef TE_TEST_NAME
#define TE_TEST_NAME    "ts_example/ts_robust"
#endif

#include "te_config.h"

#include <dirent.h>

#include "tsx_lib.h"

#define LIMIT_S     10
#define BIG_ARG     120000
#define BIG_STDIN   (1024 * 1024)

/** Scan state of the comment stripper. */
enum { S_CODE, S_LINE, S_BLOCK, S_STR };

/** True for the start of an IPv4 address at @p p (not inside a longer
 *  number or dotted name). */
static bool
ip_at(const char *s, size_t i, size_t n)
{
    int    part;
    size_t k = i;

    if (i > 0 && (isdigit((unsigned char)s[i - 1]) || s[i - 1] == '.'))
        return false;
    for (part = 0; part < 4; part++)
    {
        size_t d = 0;

        while (k < n && isdigit((unsigned char)s[k]) && d < 4)
        {
            k++;
            d++;
        }
        if (d < 1 || d > 3)
            return false;
        if (part < 3)
        {
            if (k >= n || s[k] != '.')
                return false;
            k++;
        }
    }
    return !(k < n && (isdigit((unsigned char)s[k]) || s[k] == '.'));
}

/**
 * Scan one source text without its comments; append "file:line [kind]" to
 * @p hits for each literal URL or IP address. Returns the number found.
 */
static int
scan_text(const char *file, const char *s, size_t n, char *hits,
          size_t hsize)
{
    int     state = S_CODE;
    char    quote = 0;
    int     line = 1;
    int     found = 0;
    size_t  i;

    for (i = 0; i < n; i++)
    {
        char c = s[i];

        if (c == '\n')
        {
            line++;
            if (state == S_LINE)
                state = S_CODE;
            continue;
        }
        switch (state)
        {
            case S_LINE:
                break;
            case S_BLOCK:
                if (c == '*' && i + 1 < n && s[i + 1] == '/')
                {
                    state = S_CODE;
                    i++;
                }
                break;
            case S_STR:
                if (c == '\\')
                {
                    i++;
                    break;
                }
                if (c == quote)
                {
                    state = S_CODE;
                    break;
                }
                /* A literal inside a string is code for the scan below. */
                /* fall through */
            default:
                if (state == S_CODE)
                {
                    if (c == '/' && i + 1 < n && s[i + 1] == '/')
                    {
                        state = S_LINE;
                        i++;
                        break;
                    }
                    if (c == '/' && i + 1 < n && s[i + 1] == '*')
                    {
                        state = S_BLOCK;
                        i++;
                        break;
                    }
                    if (c == '"' || c == '\'' || c == '`')
                    {
                        state = S_STR;
                        quote = c;
                        break;
                    }
                }
                if (strncmp(s + i, "http://", 7) == 0 ||
                    strncmp(s + i, "https://", 8) == 0)
                {
                    append(hits, hsize, "%s:%d [literal %s URL]; ", file,
                           line, s[i + 4] == 's' ? "https" : "http");
                    found++;
                    while (i + 1 < n && !isspace((unsigned char)s[i + 1]) &&
                           s[i + 1] != '"' && s[i + 1] != '\'' &&
                           s[i + 1] != '`' && s[i + 1] != ')')
                        i++;
                }
                else if (isdigit((unsigned char)c) && ip_at(s, i, n))
                {
                    append(hits, hsize, "%s:%d [literal IP address]; ", file,
                           line);
                    found++;
                    while (i + 1 < n && (isdigit((unsigned char)s[i + 1]) ||
                                         s[i + 1] == '.'))
                        i++;
                }
                break;
        }
    }
    return found;
}

/** Scan every .ts file under @p dir; returns hits, or -1 when @p dir
 *  cannot be read; @p files counts the files scanned. */
static int
scan_dir(const char *dir, char *hits, size_t hsize, int *files)
{
    DIR           *d = opendir(dir);
    struct dirent *e;
    int            found = 0;

    if (d == NULL)
        return -1;
    while ((e = readdir(d)) != NULL)
    {
        char        path[1200];
        struct stat st;

        if (e->d_name[0] == '.')
            continue;
        snprintf(path, sizeof(path), "%.700s/%.300s", dir, e->d_name);
        if (stat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode))
        {
            int k = scan_dir(path, hits, hsize, files);

            if (k > 0)
                found += k;
        }
        else if (S_ISREG(st.st_mode))
        {
            size_t len = strlen(e->d_name);
            FILE  *f;
            char  *buf;
            size_t got;

            if (len < 4 || strcmp(e->d_name + len - 3, ".ts") != 0)
                continue;
            f = fopen(path, "r");
            if (f == NULL)
                continue;
            buf = malloc(st.st_size + 1);
            if (buf == NULL)
            {
                fclose(f);
                continue;
            }
            got = fread(buf, 1, st.st_size, f);
            fclose(f);
            buf[got] = '\0';
            (*files)++;
            found += scan_text(path, buf, got, hits, hsize);
            free(buf);
        }
    }
    closedir(d);
    return found;
}

typedef struct tcase_t {
    const char *name;
    const char *a1;
    const char *a2;
    bool        big_arg;
    bool        big_stdin;
} tcase_t;

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *r = calloc(1, sizeof(*r));
    static const tcase_t cases[] = {
        { "empty-value", "", NULL, false, false },
        { "non-numeric-value", "abc-not-a-number", NULL, false, false },
        { "non-numeric-hops", "42", "x3", false, false },
        { "oversize-argument", NULL, NULL, true, false },
        { "oversize-stdin-1MiB", "42", "3", false, true },
    };
    const int   n_cases = (int)(sizeof(cases) / sizeof(cases[0]));
    ts_peer_t   pa;
    ts_peer_t   pb;
    bool        pa_up = false;
    bool        pb_up = false;
    char        tsdir[700];
    char        index[800];
    char        srcdir[800];
    char        why[400];
    char        hits[500];
    char        msg_a[2048] = "";
    char        msg_b[900] = "";
    char        msg_c[900] = "";
    char        msg_d[2048] = "";
    bool        ok_a = false;
    bool        ok_b = false;
    bool        ok_c = false;
    bool        ok_d = false;
    bool        built;
    char       *big = NULL;
    char        in_big[300];
    char        in_none[300];
    int         i;
    int         files = 0;
    int         found;

    TEST_START;
    t_report_begin();
    memset(&pa, 0, sizeof(pa));
    memset(&pb, 0, sizeof(pb));
    pa.lfd = pb.lfd = -1;
    if (r == NULL)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H3"))
        goto verdict;
    built = false;
    tsx_index_js(src_root, tsdir, sizeof(tsdir), index, sizeof(index));
    built = access(index, R_OK) == 0;

    TEST_STEP("Known-bad controls: trace detector and runner");
    why[0] = '\0';
    if (!ts_trace_control_ok(why, sizeof(why)) ||
        !ts_runner_control_ok(workdir, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }

    /* ---- (a) literal endpoints in the source ---- */
    TEST_STEP("(a) Scan the TypeScript source under src/ outside comments");
    {
        static const char ctl[] =
            "// http://in-a-comment.example/ and 10.9.9.9\n"
            "/* https://also-a-comment.example\n   192.168.0.1 */\n"
            "const ok = \"no endpoint here\";\n"
            "const bad = \"http://10.1.2.3:80/ring\";\n"
            "const ip = '172.16.0.5';\n"
            "const v = \"1.2.3\";\n";
        char ch[600] = "";
        int  cf;

        cf = scan_text("control.ts", ctl, strlen(ctl), ch, sizeof(ch));
        if (cf != 2 || strstr(ch, "control.ts:5 [literal http URL]") == NULL
            || strstr(ch, "control.ts:6 [literal IP address]") == NULL ||
            strstr(ch, "control.ts:1") != NULL ||
            strstr(ch, "control.ts:2") != NULL)
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: the "
                    "source scan found %d hit(s) [%s] in a planted file "
                    "(expected the URL and the IP outside comments only)",
                    cf, ch);
            goto verdict;
        }
    }
    snprintf(srcdir, sizeof(srcdir), "%.700s/src", tsdir[0] != '\0' ? tsdir :
             src_root);
    hits[0] = '\0';
    found = scan_dir(srcdir, hits, sizeof(hits), &files);
    if (found < 0)
        snprintf(msg_a, sizeof(msg_a), "(a) NOT SETTLED: cannot read %s",
                 srcdir);
    else if (files == 0)
        snprintf(msg_a, sizeof(msg_a), "(a) NOT SETTLED: no .ts file under "
                 "%s", srcdir);
    else if (found > 0)
        snprintf(msg_a, sizeof(msg_a), "(a) FAIL: %d literal URL or IP "
                 "address outside comments in the TypeScript source: %s",
                 found, hits);
    else
    {
        ok_a = true;
        snprintf(msg_a, sizeof(msg_a), "(a) ok: %d file(s) under %s have no "
                 "literal http://, https:// or IP address outside comments",
                 files, srcdir);
    }
    RING("H3 %s", msg_a);
    T_FINDING(ok_a ? TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_MEDIUM,
              "ts.hardcoded-endpoint", "typescript source", "%s", msg_a);

    if (!built)
    {
        snprintf(msg_b, sizeof(msg_b), "H1 build missing: %s does not "
                 "exist, so (b), (c) and (d) were not run", index);
        res_set(&res, R_FAIL, "%s", msg_b);
        goto verdict;
    }

    TEST_STEP("Start two local listeners: the chosen port and a decoy");
    if (!ts_peer_start(&pa, workdir))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the listener");
        goto verdict;
    }
    pa_up = true;
    snprintf(why, sizeof(why), "%s/peer-b", workdir);
    if (mkdir(why, 0700) != 0 || !ts_peer_start(&pb, why))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the decoy "
                "listener");
        goto verdict;
    }
    pb_up = true;
    RING("H3: chosen port %u, decoy port %u", pa.port, pb.port);

    /* ---- (b) the example uses the port from GUESS_ENDPOINT ---- */
    TEST_STEP("(b) Known-bad control: a counted listener sees a connection");
    {
        int before = ts_peer_count(&pa);

        if (!port_accepts(pa.port))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: the "
                    "listener does not accept");
            goto verdict;
        }
        usleep(400000);
        if (ts_peer_count(&pa) <= before)
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: a "
                    "planted connection to port %u was not counted",
                    pa.port);
            goto verdict;
        }
    }
    TEST_STEP("(b) Run the example with GUESS_ENDPOINT on the chosen port");
    {
        char        ep[120];
        char        cmd[1024];
        const char *env[2] = { ep, NULL };
        int         a0 = ts_peer_count(&pa);
        int         b0 = ts_peer_count(&pb);
        int         da;
        int         db;

        snprintf(ep, sizeof(ep), "GUESS_ENDPOINT=http://127.0.0.1:%u",
                 pa.port);
        snprintf(cmd, sizeof(cmd), "node '%s' 42 3", index);
        if (!ts_run(r, src_root, cmd, NULL, env, NULL,
                    LIMIT_S + 5, "endpoint"))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the "
                    "example");
            goto verdict;
        }
        tsx_log_step("H3", "endpoint", cmd, r);
        usleep(300000);
        da = ts_peer_count(&pa) - a0;
        db = ts_peer_count(&pb) - b0;
        if (da <= 0)
            snprintf(msg_b, sizeof(msg_b), "(b) FAIL: the example did not "
                     "connect to port %u set in GUESS_ENDPOINT (%d "
                     "connection(s); connection to the decoy port %u: %d); "
                     "exit code %d, stderr [%.200s]", pa.port, da, pb.port,
                     db, r->code, r->err);
        else if (db > 0)
            snprintf(msg_b, sizeof(msg_b), "(b) FAIL: the example connected "
                     "to the chosen port %u (%d) and also to another port "
                     "%u (%d)", pa.port, da, pb.port, db);
        else
        {
            ok_b = true;
            snprintf(msg_b, sizeof(msg_b), "(b) ok: the example connected to "
                     "the chosen port %u (%d connection(s)) and not to "
                     "another one (decoy port %u: 0)", pa.port, da, pb.port);
        }
        RING("H3 %s", msg_b);
        T_FINDING(ok_b ? TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH,
                  "ts.endpoint-variable", "GUESS_ENDPOINT", "%s", msg_b);
    }

    /* ---- (c) a peer that never answers ---- */
    TEST_STEP("(c) Run the example against a listener that never answers");
    {
        char        ep[120];
        char        cmd[1024];
        const char *env[2] = { ep, NULL };
        char        t[200];
        int         c0 = ts_peer_count(&pa);

        snprintf(ep, sizeof(ep), "GUESS_ENDPOINT=http://127.0.0.1:%u",
                 pa.port);
        snprintf(cmd, sizeof(cmd), "node '%s' 42 3", index);
        if (!ts_run(r, src_root, cmd, NULL, env, NULL, LIMIT_S + 5,
                    "silent"))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the "
                    "example against the silent peer");
            goto verdict;
        }
        tsx_log_step("H3", "silent", cmd, r);
        ts_end_text(r, t, sizeof(t));
        RING("H3 (c): elapsed %.2f s, exit code %d, signal %d, hung %d, "
             "connections to the silent peer %d", r->secs, r->code, r->sig,
             r->hung, ts_peer_count(&pa) - c0);
        if (r->hung || r->secs > LIMIT_S)
            snprintf(msg_c, sizeof(msg_c), "(c) FAIL: the example hangs "
                     "against a peer that never answers: %s after %.1f s "
                     "(limit %d s)", t, r->secs, LIMIT_S);
        else if (r->sig != 0)
            snprintf(msg_c, sizeof(msg_c), "(c) FAIL: the example was "
                     "killed by signal %d after %.1f s", r->sig, r->secs);
        else if (r->code == 0)
            snprintf(msg_c, sizeof(msg_c), "(c) FAIL: the example exited 0 "
                     "after %.1f s although the peer never answered",
                     r->secs);
        else if (ts_has_trace(r->err) || ts_has_trace(r->out))
            snprintf(msg_c, sizeof(msg_c), "(c) FAIL: the example ended with "
                     "exit code %d in %.1f s but printed a stack trace",
                     r->code, r->secs);
        else if (ts_peer_count(&pa) <= c0)
            snprintf(msg_c, sizeof(msg_c), "(c) NOT SETTLED: the example "
                     "exited %d in %.1f s but never connected to the silent "
                     "peer", r->code, r->secs);
        else
        {
            ok_c = true;
            snprintf(msg_c, sizeof(msg_c), "(c) ok: the example ended with "
                     "non-zero exit code %d in %.1f s (limit %d s) against "
                     "a peer that never answers", r->code, r->secs, LIMIT_S);
        }
        RING("H3 %s", msg_c);
        T_FINDING(ok_c ? TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH,
                  "ts.silent-peer", "GUESS_ENDPOINT", "%s", msg_c);
    }

    /* ---- (d) bad input ---- */
    TEST_STEP("(d) Bad input: empty, non-numeric and oversize");
    big = malloc(BIG_ARG + 1);
    snprintf(in_big, sizeof(in_big), "%s/in-big", workdir);
    snprintf(in_none, sizeof(in_none), "%s/in-none", workdir);
    if (big == NULL || !ts_write_fill(in_big, '9', BIG_STDIN) ||
        !ts_write_fill(in_none, ' ', 0))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot write the inputs");
        goto verdict;
    }
    memset(big, '9', BIG_ARG);
    big[BIG_ARG] = '\0';
    ok_d = true;
    for (i = 0; i < n_cases; i++)
    {
        const tcase_t *c = &cases[i];
        char        ep[120];
        char        a1[BIG_ARG + 32];
        const char *env[3] = { ep, a1, NULL };
        char        cmd[1024];
        char        t[200];
        bool        trace;
        bool        problem;

        snprintf(ep, sizeof(ep), "GUESS_ENDPOINT=http://127.0.0.1:%u",
                 pa.port);
        snprintf(a1, sizeof(a1), "TSX_A1=%s", c->big_arg ? big :
                 (c->a1 != NULL ? c->a1 : ""));
        snprintf(cmd, sizeof(cmd), "exec node '%s' %s%s%s%s", index,
                 (c->a1 != NULL || c->big_arg) ? "\"$TSX_A1\"" : "",
                 c->a2 != NULL ? " '" : "", c->a2 != NULL ? c->a2 : "",
                 c->a2 != NULL ? "'" : "");
        if (!ts_run(r, src_root, cmd, c->big_stdin ? in_big : in_none, env,
                    NULL, LIMIT_S, c->name))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the example "
                    "for case %s", c->name);
            goto verdict;
        }
        tsx_log_step("H3", c->name, cmd, r);
        ts_end_text(r, t, sizeof(t));
        trace = ts_has_trace(r->err) || ts_has_trace(r->out);
        problem = r->hung || r->sig != 0 || trace;
        if (problem)
        {
            ok_d = false;
            append(msg_d, sizeof(msg_d), "%s: %s%s; ", c->name, t,
                   trace ? ", stack trace" : "");
        }
    }
    if (ok_d)
        snprintf(msg_d, sizeof(msg_d), "(d) ok: %d bad-input cases ended "
                 "within %d s with no signal and no stack trace", n_cases,
                 LIMIT_S);
    else
    {
        char tmp[2048];

        snprintf(tmp, sizeof(tmp), "%s", msg_d);
        snprintf(msg_d, sizeof(msg_d), "(d) FAIL: %.2000s", tmp);
    }
    RING("H3 %s", msg_d);
    T_FINDING(ok_d ? TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH,
              "ts.robust", "bad input", "%s", msg_d);

verdict:
    if (pa_up)
        ts_peer_stop(&pa);
    if (pb_up)
        ts_peer_stop(&pb);
    free(big);
    free(r);
    if (res.kind == R_FAIL)
        ; /* a harness fault or a missing build, already worded */
    else if (ok_a && ok_b && ok_c && ok_d)
        res_set(&res, R_PASS, "H3 PASS: %s; %s; %s; %s", msg_a, msg_b,
                msg_c, msg_d);
    else
        res_set(&res, R_FAIL, "H3 FAIL: %s; %s; %s; %s", msg_a, msg_b,
                msg_c, msg_d);
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}

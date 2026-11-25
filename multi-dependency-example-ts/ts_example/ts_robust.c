/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_robust, the TypeScript example ends in bounded time
 *        on bad input and on a silent peer (settles H3)
 *
 * Runs ./scripts/run.sh guess with (a) an empty value, a non-numeric value,
 * a non-numeric hop count, a bad RING_TIMEOUT_MS, a 120000-byte argument (the
 * most one argument can hold) and 1 MiB on stdin, and (b) the gateway
 * address pointing at a local TCP peer on 127.0.0.1 that accepts the
 * connection and never replies. Every run must end within 10 s with no
 * signal and no stack trace; a clean non-zero exit with a message is fine.
 * A timeout kill or a trace fails the test. The silent-peer run is not
 * settled when the example never connected to the peer. Two known-bad
 * controls (trace detector, runner) run first.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_robust"

#include "te_config.h"

#include "tsx_lib.h"

#define LIMIT_S     10
#define BIG_ARG     120000
#define BIG_STDIN   (1024 * 1024)

typedef struct tcase_t {
    const char *name;
    const char *a1;         /**< First argument, NULL for none. */
    const char *a2;         /**< Second argument, NULL for none. */
    bool        big_arg;    /**< First argument is BIG_ARG digits. */
    bool        big_stdin;  /**< stdin is 1 MiB. */
    const char *extra_env;  /**< One more variable, or NULL. */
    bool        peer;       /**< Valid input; the peer is what is wrong. */
} tcase_t;

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *r = calloc(1, sizeof(*r));
    static const tcase_t cases[] = {
        { "empty-value", "", NULL, false, false, NULL, false },
        { "non-numeric-value", "abc-not-a-number", NULL, false, false, NULL,
          false },
        { "non-numeric-hops", "42", "x3", false, false, NULL, false },
        { "bad-timeout-env", "42", "3", false, false,
          "RING_TIMEOUT_MS=abc", false },
        { "oversize-argument", NULL, NULL, true, false, NULL, false },
        { "oversize-stdin-1MiB", "42", "3", false, true, NULL, true },
        { "silent-peer", "42", "3", false, false, NULL, true },
    };
    const int   n_cases = (int)(sizeof(cases) / sizeof(cases[0]));
    ts_peer_t   peer;
    char        why[400];
    char        bad[1400] = "";
    char        ok[600] = "";
    char        note[400] = "";
    char       *big = NULL;
    char        in_big[300];
    char        in_none[300];
    int         i;
    bool        peer_up = false;
    int         peer_hits = 0;

    TEST_START;
    t_report_begin();
    memset(&peer, 0, sizeof(peer));
    peer.lfd = -1;
    if (r == NULL)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H3"))
        goto verdict;

    TEST_STEP("Known-bad controls: trace detector and runner");
    why[0] = '\0';
    if (!ts_trace_control_ok(why, sizeof(why)) ||
        !ts_runner_control_ok(workdir, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }
    if (access("/bin/sh", X_OK) != 0 || src_root == NULL)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: no shell to run the example");
        goto verdict;
    }
    {
        char runsh[700];

        snprintf(runsh, sizeof(runsh), "%s/scripts/run.sh", src_root);
        if (access(runsh, X_OK) != 0)
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: step missing file: %s "
                    "does not exist or is not executable (run ts_build "
                    "first)", runsh);
            goto verdict;
        }
    }

    big = malloc(BIG_ARG + 1);
    if (big == NULL)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: out of memory");
        goto verdict;
    }
    memset(big, '9', BIG_ARG);
    big[BIG_ARG] = '\0';
    snprintf(in_big, sizeof(in_big), "%s/in-big", workdir);
    snprintf(in_none, sizeof(in_none), "%s/in-none", workdir);
    if (!ts_write_fill(in_big, '9', BIG_STDIN) ||
        !ts_write_fill(in_none, ' ', 0))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot write the inputs in "
                "%s", workdir);
        goto verdict;
    }

    TEST_STEP("Scan the TypeScript source for literal endpoints");
    {
        /* Literal http:// URLs and dotted IPv4 strings in .ts files, not in
         * tests, type files or dependencies, and not on the line of a
         * DEFAULT_ constant. */
        static const char scan_cmd[] =
            "find \"$TSX_ROOT\" \\( -name node_modules -o -name dist -o "
            "-name test -o -name tests -o -name __tests__ -o -name .git \\) "
            "-prune -o -type f -name '*.ts' ! -name '*.test.ts' "
            "! -name '*.spec.ts' ! -name '*.d.ts' -print0 | "
            "xargs -0 -r grep -nE "
            "'https?://|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}' "
            "| grep -vE 'DEFAULT_|[Dd]efault[A-Z_]'; true";
        char        ctl_dir[400];
        char        ctl_env[500];
        char        mk[1000];
        const char *cenv[2] = { ctl_env, NULL };
        const char *senv[2];
        char        root_env[800];
        char        hits[500];

        /* Known-bad control: a planted literal must be reported. */
        snprintf(ctl_dir, sizeof(ctl_dir), "%s/scan-ctl", workdir);
        snprintf(mk, sizeof(mk), "mkdir -p '%s' && printf "
                 "'const u = \"http://10.1.2.3:80\";\\n' > '%s/bad.ts'",
                 ctl_dir, ctl_dir);
        if (system(mk) != 0)
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot plant the scan "
                    "control");
            goto verdict;
        }
        snprintf(ctl_env, sizeof(ctl_env), "TSX_ROOT=%s", ctl_dir);
        if (!ts_run(r, workdir, scan_cmd, in_none, cenv, NULL, LIMIT_S,
                    "scan-ctl") || strstr(r->out, "10.1.2.3") == NULL)
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: the "
                    "source scan did not report a planted http:// literal");
            goto verdict;
        }
        snprintf(root_env, sizeof(root_env), "TSX_ROOT=%s", src_root);
        senv[0] = root_env;
        senv[1] = NULL;
        if (!ts_run(r, workdir, scan_cmd, in_none, senv, NULL, 30,
                    "scan-src"))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot run the source "
                    "scan");
            goto verdict;
        }
        ts_flat(r->out, 400, hits, sizeof(hits));
        T_FINDING(r->out_len > 0 ? TAPI_CYBERSEC_SEV_MEDIUM :
                  TAPI_CYBERSEC_SEV_INFO, "ts.hardcoded-endpoint",
                  "typescript source", "%s",
                  r->out_len > 0 ? hits : "no literal http:// or IP string");
        if (r->out_len > 0)
            append(bad, sizeof(bad), "hardcoded endpoint literal in the "
                   "TypeScript source: [%s]; ", hits);
        else
            append(ok, sizeof(ok), "no literal endpoint in the source; ");
    }

    TEST_STEP("Start the silent peer on 127.0.0.1");
    if (!ts_peer_start(&peer, workdir))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the silent peer");
        goto verdict;
    }
    peer_up = true;
    RING("H3: silent peer on 127.0.0.1:%u", peer.port);

    for (i = 0; i < n_cases; i++)
    {
        const tcase_t *c = &cases[i];
        char        url[100];
        char        in_arg[BIG_ARG + 32];
        const char *env[4];
        char        cmd[200];
        char        t[200];
        char        e[300];
        int         before = ts_peer_count(&peer);
        bool        trace;
        bool        problem;

        snprintf(url, sizeof(url), "RING_GATEWAY_URL=http://127.0.0.1:%u",
                 peer.port);
        snprintf(in_arg, sizeof(in_arg), "TSX_A1=%s",
                 c->big_arg ? big : (c->a1 != NULL ? c->a1 : ""));
        env[0] = url;
        env[1] = in_arg;
        env[2] = c->extra_env;
        env[3] = NULL;
        if (env[2] == NULL)
            env[2] = "TSX_NONE=1";
        {
            char a2[64] = "";

            if (c->a2 != NULL)
                snprintf(a2, sizeof(a2), " '%s'", c->a2);
            snprintf(cmd, sizeof(cmd), "exec ./scripts/run.sh guess %s%s",
                     (c->a1 != NULL || c->big_arg) ? "\"$TSX_A1\"" : "", a2);
        }
        TEST_STEP("Case %s", c->name);
        if (!ts_run(r, src_root, cmd, c->big_stdin ? in_big : in_none, env,
                    NULL, LIMIT_S, c->name))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the example "
                    "for case %s", c->name);
            goto verdict;
        }
        tsx_log_step("H3", c->name, cmd, r);
        ts_end_text(r, t, sizeof(t));
        ts_flat(r->err_len > 0 ? r->err : r->out, 200, e, sizeof(e));
        trace = ts_has_trace(r->err) || ts_has_trace(r->out);
        problem = r->hung || r->sig != 0 || trace;
        if (c->peer && ts_peer_count(&peer) > before)
            peer_hits++;
        T_FINDING(problem ? TAPI_CYBERSEC_SEV_HIGH :
                  (r->code == 0 && !c->peer) ? TAPI_CYBERSEC_SEV_LOW :
                  TAPI_CYBERSEC_SEV_INFO, "ts.robust", c->name, "%s%s%s", t,
                  trace ? "; stack trace in output" : "",
                  (r->code == 0 && !c->peer) ? "; exit 0 on bad input" : "");
        if (problem)
            append(bad, sizeof(bad), "%s: %s%s [%s]; ", c->name, t,
                   trace ? ", stack trace" : "", e);
        else
            append(ok, sizeof(ok), "%s: %s; ", c->name, t);
    }

    if (peer_hits == 0)
        snprintf(note, sizeof(note), "the example never connected to the "
                 "silent peer (RING_GATEWAY_URL was set to it), so the "
                 "silent-peer case proves nothing");

verdict:
    if (peer_up)
        ts_peer_stop(&peer);
    free(big);
    free(r);
    if (res.kind == R_FAIL)
        ; /* a harness fault already worded */
    else if (bad[0] != '\0')
        res_set(&res, R_FAIL, "H3 FAIL: %s%s", bad, note);
    else if (note[0] != '\0')
        res_set(&res, R_FAIL, "H3 NOT SETTLED: %s; clean so far: %s", note,
                ok);
    else
        res_set(&res, R_PASS, "H3 PASS: every case ended within %d s with no "
                "signal and no stack trace; %s", LIMIT_S, ok);
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}

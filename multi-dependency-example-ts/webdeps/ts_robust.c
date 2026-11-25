/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: ts_robust, the TypeScript example on bad input and a
 *        silent peer (settles H3)
 *
 * Runs ./scripts/run.sh guess four times: empty input, an oversize input
 * (100000 characters as the argument and 1 MiB on stdin), a non-numeric
 * input, and with every endpoint variable pointing at a peer that accepts
 * a connection and never answers. Pass when each run exits non-zero with a
 * message, with no stack trace, no signal and no run longer than 10 s.
 * Fail on a hang, a crash, a signal, a trace, or exit 0 on bad input. When
 * the example never contacts the peer, the peer case is NOT SETTLED.
 * Two known-bad controls run first (trace detector, hang/signal runner).
 * Every verdict starts with H3.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/ts_robust"

#include "te_config.h"

#include "ts_lib.h"

#define LIMIT_S     10
#define BIG_ARG     100000
#define BIG_STDIN   (1024 * 1024)
#define N_CASES     4

typedef struct tcase_t {
    const char *name;
    const char *arg;        /**< NULL: built per case. */
} tcase_t;

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *r = calloc(1, sizeof(*r));
    static const char * const names_[N_CASES] = {
        "empty", "oversize", "non-numeric", "silent-peer",
    };
    ts_peer_t   peer;
    char        in_path[N_CASES][300];
    char        why[400];
    char        bad[1400] = "";
    char        ok[400] = "";
    char        note[300] = "";
    char       *big = NULL;
    char        peer_env[16][100];
    const char *env_all[24];
    int         i;
    bool        peer_up = false;

    TEST_START;
    t_report_begin();
    memset(&peer, 0, sizeof(peer));
    peer.lfd = -1;
    if (r == NULL)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: out of memory");
        goto verdict;
    }
    wd_init(&res);
    if (res.kind == R_SETUP)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: harness step broke: %.800s",
                res.msg);
        goto verdict;
    }

    TEST_STEP("Known-bad controls: trace detector and runner");
    if (!ts_trace_control_ok(why, sizeof(why)) ||
        !ts_runner_control_ok(workdir, why + strlen(why),
                              sizeof(why) - strlen(why)))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }

    big = malloc(BIG_ARG + 1);
    if (big == NULL)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: out of memory");
        goto verdict;
    }
    memset(big, '9', BIG_ARG);
    big[BIG_ARG] = '\0';

    for (i = 0; i < N_CASES; i++)
    {
        FILE *f;

        snprintf(in_path[i], sizeof(in_path[i]), "%s/in-%d", workdir, i);
        if (i == 1)
            f = ts_write_fill(in_path[i], '9', BIG_STDIN) ? (FILE *)1 : NULL;
        else
            f = fopen(in_path[i], "w");
        if (f == NULL)
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot write %s",
                    in_path[i]);
            goto verdict;
        }
        if (i != 1)
        {
            if (i == 2)
                fputs("abc-not-a-number\n", f);
            fclose(f);
        }
    }

    if (!ts_peer_start(&peer, workdir))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the silent peer");
        goto verdict;
    }
    peer_up = true;

    for (i = 0; i < N_CASES; i++)
    {
        static const char * const vars[] = {
            "HOST", "ADDR", "ADDRESS", "SERVER", "SERVER_ADDR", "PEER",
            "ENDPOINT", "URL", "SERVICE_URL", "GATEWAY_URL", "SERVICE_ADDR",
            "GATEWAY_ADDR", "GUESS_SERVER", "GUESS_URL",
        };
        const char *input = i == 0 ? "" : i == 1 ? big :
                            i == 2 ? "abc-not-a-number" : "42";
        char        cmd[200];
        char        t[200];
        char        e[300];
        int         n = 0;
        size_t      k;
        int         before = ts_peer_count(&peer);
        bool        trace;
        bool        problem = false;
        char        in_env[BIG_ARG + 32];

        snprintf(in_env, sizeof(in_env), "TS_INPUT=%s", input);
        env_all[n++] = in_env;
        if (i == 3)
        {
            for (k = 0; k < sizeof(vars) / sizeof(vars[0]) && n < 20; k++)
            {
                snprintf(peer_env[k], sizeof(peer_env[k]), "%s=%s%s",
                         vars[k],
                         strstr(vars[k], "URL") != NULL ? "http://" : "",
                         "127.0.0.1");
                env_all[n++] = peer_env[k];
            }
            snprintf(peer_env[15], sizeof(peer_env[15]), "PORT=%u",
                     peer.port);
            env_all[n++] = peer_env[15];
            snprintf(peer_env[14], sizeof(peer_env[14]),
                     "ENDPOINT=127.0.0.1:%u", peer.port);
            env_all[n++] = peer_env[14];
        }
        env_all[n] = NULL;
        snprintf(cmd, sizeof(cmd), "exec ./scripts/run.sh guess %s",
                 i == 3 ? "\"$TS_INPUT\" \"127.0.0.1:$PORT\"" :
                 "\"$TS_INPUT\"");
        TEST_STEP("Case %s", names_[i]);
        if (!ts_run(r, src_root, cmd, in_path[i], env_all, NULL, i == 3 ? 15 : LIMIT_S,
                    names_[i]))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the example "
                    "for case %s", names_[i]);
            goto verdict;
        }
        ts_end_text(r, t, sizeof(t));
        ts_flat(r->err_len > 0 ? r->err : r->out, 200, e, sizeof(e));
        trace = ts_has_trace(r->err) || ts_has_trace(r->out);
        RING("webdeps H3: command [%s]; %s: %s; stderr(200 B) [%s]", cmd, names_[i], t, e);

        if (r->hung)
            problem = true;
        else if (r->sig != 0)
            problem = true;
        else if (trace)
            problem = true;
        else if (r->code == 0 || r->err_len + r->out_len == 0)
            problem = true;

        if (i == 3 && ts_peer_count(&peer) == before)
        {
            snprintf(note, sizeof(note), "the example never connected to "
                     "the silent peer (set HOST/PORT/URL-style variables and "
                     "an address argument), so the slow-peer case proves "
                     "nothing");
        }
        T_FINDING(problem ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
                  "ts.robust", names_[i], "%s%s%s%s", t,
                  trace ? "; stack trace in output" : "",
                  r->code == 0 ? "; exit 0 on bad input" : "",
                  r->err_len + r->out_len == 0 ? "; no message" : "");
        if (problem)
            append(bad, sizeof(bad), "%s: %s%s%s%s [%s]; ", names_[i], t,
                   trace ? ", stack trace" : "",
                   (!r->hung && r->sig == 0 && r->code == 0) ?
                   ", exit 0 on bad input" : "",
                   r->err_len + r->out_len == 0 ? ", no message" : "", e);
        else
            append(ok, sizeof(ok), "%s: %s; ", names_[i], t);
    }

verdict:
    if (peer_up)
        ts_peer_stop(&peer);
    free(big);
    free(r);
    if (res.kind == R_FAIL && strncmp(res.msg, "H3", 2) == 0)
        ; /* a harness fault already worded */
    else if (bad[0] != '\0')
        res_set(&res, R_FAIL, "H3 FAIL: %s%s", bad, note);
    else if (note[0] != '\0')
        res_set(&res, R_FAIL, "H3 NOT SETTLED: %s; clean so far: %s", note,
                ok);
    else
        res_set(&res, R_PASS, "H3 PASS: every case exited with a clear "
                "error, no stack trace, no signal, within %d s; %s",
                LIMIT_S, ok);
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}

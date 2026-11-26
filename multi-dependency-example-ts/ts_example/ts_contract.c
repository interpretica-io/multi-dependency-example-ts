/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_contract, the TypeScript example gives the same
 *        answer as the Go and C# examples (settles H3)
 *
 * Order of the checks, so that each fault has its own verdict:
 *  1. dist/index.js of the TypeScript example must exist; if not the test
 *     fails with "H2 build missing" and says nothing about H3.
 *  2. The web services are started. When the Go example cannot start the
 *     test is skipped with a message, not failed; a gateway that is not up
 *     is a "start-up fault".
 *  3. One fixed set of contract inputs (one valid guess first) is sent to
 *     the TypeScript example (scripts/run.sh guess <value> <hops>, absolute
 *     path, project root as working directory) and by curl to the Go and C#
 *     services. All replies are logged in full with their exit codes.
 *  4. The TypeScript reply is compared byte for byte with the Go reply: the
 *     test passes when they are equal for every input and prints both
 *     replies on a mismatch. A C# difference is logged as a warning.
 * tapi_netexpose logs what the TypeScript process listens on. Known-bad
 * controls check that the byte comparison tells replies apart.
 *
 * @author midair <midair@localhost>
 */

#ifndef TE_TEST_NAME
#define TE_TEST_NAME    "ts_example/ts_contract"
#endif

#include "te_config.h"

#include "tsx_lib.h"

/** The fixed contract inputs; the first is the valid guess. */
static const struct { const char *value; const char *hops; } inputs[] = {
    { "42", "3" }, { "1", "1" }, { "7", "2" }, { "100", "5" },
};
#define N_INPUTS    (sizeof(inputs) / sizeof(inputs[0]))
#define LIMIT_S     60
#define START_S     10

/** One example: how it ended and its answer line. */
typedef struct ex_t {
    const char *name;
    int         code;       /**< Exit code; -1 when none. */
    bool        ran;
    char        answer[200];
    bool        has_answer;
} ex_t;

/** Same answer line text and the same exit code. */
static bool
same_answer(const ex_t *a, const ex_t *b)
{
    return a->code == b->code && a->has_answer == b->has_answer &&
           strcmp(a->answer, b->answer) == 0;
}

/** Record the answer line and exit code of a finished run. */
static void
ex_set(ex_t *e, const char *name, const ts_run_t *r, const char *text)
{
    e->name = name;
    e->ran = true;
    e->code = r->hung ? -1 : (r->sig != 0 ? 128 + r->sig : r->code);
    e->has_answer = tsx_answer_line(text, e->answer, sizeof(e->answer));
}

/** Wait up to START_S s for @p port; true when it accepts. */
static bool
wait_port(unsigned port)
{
    double end = now_s() + START_S;

    while (port != 0)
    {
        if (port_accepts(port))
            return true;
        if (now_s() >= end)
            break;
        usleep(200000);
    }
    return false;
}

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *ts = calloc(1, sizeof(*ts));
    ts_run_t   *go = calloc(1, sizeof(*go));
    ts_run_t   *cs = calloc(1, sizeof(*cs));
    ex_t        ca = { "control-a", 0, true, "value=47.5", true };
    ex_t        cb = { "control-b", 0, true, "value=47.5", true };
    char        tsdir[700];
    char        index[800];
    char        note[900];
    char        bad[1400] = "";
    char        sec[8192];
    char        cmd[500];
    char        tscmd[800];
    char        cs_note[1400] = "";
    bool        go_up = false;
    bool        cs_up = false;
    size_t      k;
    int         same = 0;
    char        gw[200];
    const char *env[3];
    tsapi_mde_session session = { .ta = NULL };
    bool        have_session = false;
    ts_peer_t   peer;
    bool        peer_up = false;
    unsigned    total = 0;
    int         listening;
    int         up;

    TEST_START;
    t_report_begin();
    memset(&peer, 0, sizeof(peer));
    peer.lfd = -1;
    if (ts == NULL || go == NULL || cs == NULL)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H3"))
        goto verdict;

    TSX_STEP("Check that the TypeScript build exists (dist/index.js)");
    tsx_index_js(src_root, tsdir, sizeof(tsdir), index, sizeof(index));
    if (access(index, R_OK) != 0)
    {
        res_set(&res, R_FAIL, "H2 build missing: %s does not exist, so the "
                "TypeScript example was never built here; this is a build "
                "fault (see ts_build), the H3 comparison was not run", index);
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "ts.contract", "build",
                  "%s", res.msg);
        goto verdict;
    }
    RING("H3: TypeScript entry %s exists", index);

    TSX_STEP("Known-bad control: the comparison tells two answers apart");
    if (!same_answer(&ca, &cb))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: equal "
                "answers were called different");
        goto verdict;
    }
    snprintf(cb.answer, sizeof(cb.answer), "value=48.5");
    if (same_answer(&ca, &cb))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: a planted "
                "different answer line was called equal");
        goto verdict;
    }
    snprintf(cb.answer, sizeof(cb.answer), "value=47.5");
    cb.code = 3;
    if (same_answer(&ca, &cb))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: a planted "
                "different exit code was called equal");
        goto verdict;
    }
    {
        char a[100];

        if (!tsx_answer_line("trace\nvalue=1\nvalue=2\n\n", a, sizeof(a)) ||
            strcmp(a, "value=2") != 0 ||
            tsx_answer_line("no answer here\n", a, sizeof(a)))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: the "
                    "answer line is not extracted correctly");
            goto verdict;
        }
    }

    TSX_STEP("Known-bad control: the byte comparison tells replies apart");
    if (!tsx_bytes_control_ok(bad, sizeof(bad)))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: %s", bad);
        goto verdict;
    }

    TSX_STEP("Start the web services; ports must open within %d s", START_S);
    up = tsx_services_up("H3", note, sizeof(note));
    go_up = wait_port(tab_port[GO]);
    cs_up = wait_port(tab_port[CS]);
    if (!go_up)
    {
        res_set(&res, R_SKIP, "H3 SKIPPED: the Go example could not start "
                "(%d of 3 services started, go port %u NOT open within %d s)"
                ": %s, so there is no Go reply to compare the TypeScript "
                "reply with", up, tab_port[GO], START_S, note);
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "ts.contract", "start-up", "%s",
                  res.msg);
        goto verdict;
    }
    if (!port_accepts(tab_port[GW]))
    {
        res_set(&res, R_FAIL, "H3 start-up fault: the gateway the "
                "TypeScript example talks to is not up (%d of 3 services "
                "started): %s", up, note);
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "ts.contract", "start-up", "%s",
                  res.msg);
        goto verdict;
    }
    if (!cs_up)
        RING("H3: the C# example is not up (port %u): it is left out of the "
             "comparison: %s", tab_port[CS], note);

    TSX_STEP("Log what the TypeScript process listens on (tapi_netexpose)");
    if (tsapi_mde_session_init(&session, "ts_contract") != 0)
        RING("H3: no tapi_netexpose session on the agent; the listening "
             "sockets of the TypeScript process are not logged");
    else
    {
        have_session = true;
        if (ts_peer_start(&peer, workdir))
        {
            unsigned ctl_total = 0;
            unsigned ctl_port = 0;
            char     ep[100];

            peer_up = true;
            /* Known-bad control: the peer listens, and the scan sees it. */
            if (tsx_expose_log("H3 control", &session, peer.pid,
                               "silent peer", &ctl_total, &ctl_port) < 1 ||
                ctl_port != peer.port)
            {
                RING("H3: control of the listener scan failed: the planted "
                     "listener on port %u was not reported (saw port %u); "
                     "the listener log below is not trusted", peer.port,
                     ctl_port);
                T_FINDING(TAPI_CYBERSEC_SEV_LOW, "ts.listen", "control",
                          "the planted listener was not found");
            }
            else
            {
                snprintf(ep, sizeof(ep), "http://127.0.0.1:%u", peer.port);
                listening = tsx_ts_probe("H3", &session, index, ep, &total);
                if (listening < 0)
                    RING("H3: the TypeScript process could not be observed");
                else
                {
                    RING("H3: the TypeScript process holds %u socket(s) and "
                         "listens on %d", total, listening);
                    T_FINDING(listening > 0 ? TAPI_CYBERSEC_SEV_MEDIUM :
                              TAPI_CYBERSEC_SEV_INFO, "ts.listen",
                              "typescript process",
                              "%d listening socket(s), %u socket(s) in all",
                              listening, total);
                }
            }
            ts_peer_stop(&peer);
            peer_up = false;
        }
    }

    snprintf(gw, sizeof(gw), "RING_TIMEOUT_MS=20000");
    env[0] = gw;
    env[1] = NULL;
    for (k = 0; k < N_INPUTS; k++)
    {
        const char *v = inputs[k].value;
        const char *h = inputs[k].hops;
        const char *tsrep;
        size_t      tslen;
        char        ea[400];
        char        eb[400];

        TSX_STEP("Run guess for the TypeScript example (value %s hops %s)",
                 v, h);
        snprintf(tscmd, sizeof(tscmd), "'%s/scripts/run.sh' guess %s %s",
                 src_root, v, h);
        if (!ts_run(ts, src_root, tscmd, NULL, env, NULL, LIMIT_S, "ts"))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the "
                    "example");
            goto verdict;
        }
        tsx_log_step("H3", "ts", tscmd, ts);
        if (strstr(ts->err, "is not built") != NULL ||
            strstr(ts->err, "missing; run ./build.sh") != NULL)
        {
            char o[300];

            ts_flat(ts->err, 250, o, sizeof(o));
            res_set(&res, R_FAIL, "H2 build missing: scripts/run.sh "
                    "reports that something is not built [%s]; the H3 "
                    "comparison was not run", o);
            goto verdict;
        }
        if (ts->hung || strstr(ts->err, "nothing listens on port") != NULL)
        {
            char o[300];

            ts_flat(ts->err, 250, o, sizeof(o));
            res_set(&res, R_FAIL, "H3 start-up fault: scripts/run.sh guess "
                    "%s [%s]", ts->hung ? "did not finish within the time "
                    "limit" : "found a port not open within 10 s", o);
            goto verdict;
        }

        TSX_STEP("Send the same input to the Go and the C# service");
        snprintf(cmd, sizeof(cmd), "curl -sS --fail --max-time 20 "
                 "'http://127.0.0.1:%u/ring?value=%s&hops=%s'", tab_port[GO],
                 v, h);
        if (!ts_run(go, src_root, cmd, NULL, NULL, NULL, LIMIT_S, "ref-go"))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the Go run");
            goto verdict;
        }
        tsx_log_step("H3", "ref-go", cmd, go);
        if (go->code != 0 || go->hung)
        {
            res_set(&res, R_SKIP, "H3 SKIPPED: the Go example started but "
                    "did not answer value %s hops %s (curl exit code %d): "
                    "there is no Go reply to compare with", v, h, go->code);
            goto verdict;
        }
        cs->out_len = 0;
        cs->out[0] = '\0';
        cs->code = -1;
        if (cs_up)
        {
            snprintf(cmd, sizeof(cmd), "curl -sS --fail --max-time 20 "
                     "'http://127.0.0.1:%u/ring?value=%s&hops=%s'",
                     tab_port[CS], v, h);
            if (ts_run(cs, src_root, cmd, NULL, NULL, NULL, LIMIT_S,
                       "ref-cs"))
                tsx_log_step("H3", "ref-cs", cmd, cs);
        }

        TSX_STEP("Compare the replies byte for byte (value %s hops %s)", v,
                 h);
        tsrep = tsx_section(ts->out, "service-go", sec, sizeof(sec)) ?
                sec : ts->out;
        tslen = strlen(tsrep);
        tsx_escape(tsrep, tslen, 300, ea, sizeof(ea));
        tsx_escape(go->out, go->out_len, 300, eb, sizeof(eb));
        RING("H3: value %s hops %s: typescript reply (%zu bytes, exit %d) "
             "[%s]; go reply (%zu bytes) [%s]", v, h, tslen, ts->code, ea,
             go->out_len, eb);
        if (ts->hung || ts->sig != 0 || ts->code != 0)
            append(bad, sizeof(bad), "value %s hops %s: the TypeScript "
                   "example failed (exit code %d, signal %d), typescript "
                   "reply [%s], go reply [%s]; ", v, h, ts->code, ts->sig,
                   ea, eb);
        else if (!tsx_same_bytes(tsrep, tslen, go->out, go->out_len))
            append(bad, sizeof(bad), "value %s hops %s: typescript reply "
                   "(%zu bytes) [%s] differs from go reply (%zu bytes) [%s] "
                   "at byte %zu; ", v, h, tslen, ea, go->out_len, eb,
                   tsx_first_diff(tsrep, tslen, go->out, go->out_len));
        else
            same++;
        if (cs_up && cs->code == 0)
        {
            tsx_escape(cs->out, cs->out_len, 300, eb, sizeof(eb));
            if (!tsx_same_bytes(go->out, go->out_len, cs->out, cs->out_len))
                append(cs_note, sizeof(cs_note), "value %s hops %s: the C# "
                       "reply [%s] differs from the Go reply; ", v, h, eb);
        }
    }
    if (cs_note[0] != '\0')
    {
        WARN("H3: Go and C# differ (not a failure of the TypeScript "
             "example): %s", cs_note);
        T_FINDING(TAPI_CYBERSEC_SEV_MEDIUM, "ts.contract", "go vs csharp",
                  "%.1500s", cs_note);
    }
    if (bad[0] != '\0')
        res_set(&res, R_FAIL, "H3 FAIL: mismatch: the TypeScript reply is "
                "not the Go reply: %s", bad);
    else
        res_set(&res, R_PASS, "H3 PASS: the TypeScript reply equals the Go "
                "reply byte for byte for all %d fixed inputs; C# %s",
                same, !cs_up ? "was not up and was left out" :
                cs_note[0] != '\0' ? "differs from Go (logged as a warning)"
                : "equals them too");
    T_FINDING(res.kind == R_PASS ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_MEDIUM, "ts.contract", "guess", "%.1500s",
              res.msg);

verdict:
    if (peer_up)
        ts_peer_stop(&peer);
    if (have_session)
        tsapi_mde_session_fini(&session);
    free(ts);
    free(go);
    free(cs);
    TSX_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}

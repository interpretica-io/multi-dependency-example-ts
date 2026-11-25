/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_contract, the TypeScript example gives the same
 *        answer as the Go and C# examples (settles H2)
 *
 * Order of the checks, so that each fault has its own verdict:
 *  1. dist/index.js of the TypeScript example must exist; if not the test
 *     fails with "H1 build missing" and says nothing about H2.
 *  2. The web services are started and the Go and C# ports must open
 *     within 10 s; if not the test fails with "start-up fault".
 *  3. ./scripts/run.sh guess 42 3 (TypeScript), and the same input sent to
 *     the Go service and to the C# service. All three outputs are logged in
 *     full, with their exit codes.
 *  4. The answer line (the last "value=" line) and the exit code of the
 *     three are compared; both values are printed on a mismatch.
 * tapi_netexpose logs what the TypeScript process listens on. A known-bad
 * control checks that the comparison tells two answers apart.
 *
 * @author midair <midair@localhost>
 */

#ifndef TE_TEST_NAME
#define TE_TEST_NAME    "ts_example/ts_contract"
#endif

#include "te_config.h"

#include "tsx_lib.h"

#define INPUT_VALUE "42"
#define INPUT_HOPS  "3"
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
    ex_t        e_ts_go = { .name = "typescript->service-go" };
    ex_t        e_ts_cs = { .name = "typescript->service-cs" };
    ex_t        e_go = { .name = "go" };
    ex_t        e_cs = { .name = "csharp" };
    ex_t        ca = { "control-a", 0, true, "value=47.5", true };
    ex_t        cb = { "control-b", 0, true, "value=47.5", true };
    char        tsdir[700];
    char        index[800];
    char        note[900];
    char        bad[1400] = "";
    char        sec[8192];
    char        cmd[500];
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
        res_set(&res, R_FAIL, "H2 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H2"))
        goto verdict;

    TEST_STEP("Check that the TypeScript build exists (dist/index.js)");
    tsx_index_js(src_root, tsdir, sizeof(tsdir), index, sizeof(index));
    if (access(index, R_OK) != 0)
    {
        res_set(&res, R_FAIL, "H1 build missing: %s does not exist, so the "
                "TypeScript example was never built here; this is a build "
                "fault (see ts_build), the H2 comparison was not run", index);
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "ts.contract", "build",
                  "%s", res.msg);
        goto verdict;
    }
    RING("H2: TypeScript entry %s exists", index);

    TEST_STEP("Known-bad control: the comparison tells two answers apart");
    if (!same_answer(&ca, &cb))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: equal "
                "answers were called different");
        goto verdict;
    }
    snprintf(cb.answer, sizeof(cb.answer), "value=48.5");
    if (same_answer(&ca, &cb))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: a planted "
                "different answer line was called equal");
        goto verdict;
    }
    snprintf(cb.answer, sizeof(cb.answer), "value=47.5");
    cb.code = 3;
    if (same_answer(&ca, &cb))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: a planted "
                "different exit code was called equal");
        goto verdict;
    }
    {
        char a[100];

        if (!tsx_answer_line("trace\nvalue=1\nvalue=2\n\n", a, sizeof(a)) ||
            strcmp(a, "value=2") != 0 ||
            tsx_answer_line("no answer here\n", a, sizeof(a)))
        {
            res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: the "
                    "answer line is not extracted correctly");
            goto verdict;
        }
    }

    TEST_STEP("Start the web services; ports must open within %d s", START_S);
    up = tsx_services_up("H2", note, sizeof(note));
    if (up < 3 || !wait_port(tab_port[GO]) || !wait_port(tab_port[CS]))
    {
        res_set(&res, R_FAIL, "H2 start-up fault: the services were not "
                "up (%d of 3 started, go port %u %s, csharp port %u %s, "
                "limit %d s): %s", up, tab_port[GO],
                port_accepts(tab_port[GO]) ? "open" : "NOT open",
                tab_port[CS], port_accepts(tab_port[CS]) ? "open" :
                "NOT open", START_S, note);
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "ts.contract", "start-up", "%s",
                  res.msg);
        goto verdict;
    }

    TEST_STEP("Log what the TypeScript process listens on (tapi_netexpose)");
    if (tsapi_mde_session_init(&session, "ts_contract") != 0)
        RING("H2: no tapi_netexpose session on the agent; the listening "
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
            if (tsx_expose_log("H2 control", &session, peer.pid,
                               "silent peer", &ctl_total, &ctl_port) < 1 ||
                ctl_port != peer.port)
            {
                RING("H2: control of the listener scan failed: the planted "
                     "listener on port %u was not reported (saw port %u); "
                     "the listener log below is not trusted", peer.port,
                     ctl_port);
                T_FINDING(TAPI_CYBERSEC_SEV_LOW, "ts.listen", "control",
                          "the planted listener was not found");
            }
            else
            {
                snprintf(ep, sizeof(ep), "http://127.0.0.1:%u", peer.port);
                listening = tsx_ts_probe("H2", &session, index, ep, &total);
                if (listening < 0)
                    RING("H2: the TypeScript process could not be observed");
                else
                {
                    RING("H2: the TypeScript process holds %u socket(s) and "
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

    TEST_STEP("Run guess for the TypeScript example");
    snprintf(gw, sizeof(gw), "RING_TIMEOUT_MS=20000");
    env[0] = gw;
    env[1] = NULL;
    if (!ts_run(ts, src_root, "./scripts/run.sh guess " INPUT_VALUE " "
                INPUT_HOPS, NULL, env, NULL, LIMIT_S, "ts"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start the example");
        goto verdict;
    }
    tsx_log_step("H2", "ts", "./scripts/run.sh guess " INPUT_VALUE " "
                 INPUT_HOPS, ts);
    tsx_log_full("H2 ts stdout", ts->out);
    tsx_log_full("H2 ts stderr", ts->err);
    if (strstr(ts->err, "is not built") != NULL ||
        strstr(ts->err, "missing; run ./build.sh") != NULL)
    {
        char o[300];

        ts_flat(ts->err, 250, o, sizeof(o));
        res_set(&res, R_FAIL, "H1 build missing: ./scripts/run.sh reports "
                "that something is not built [%s]; the H2 comparison was "
                "not run", o);
        goto verdict;
    }
    if (ts->hung || strstr(ts->err, "nothing listens on port") != NULL)
    {
        char o[300];

        ts_flat(ts->err, 250, o, sizeof(o));
        res_set(&res, R_FAIL, "H2 start-up fault: ./scripts/run.sh guess %s "
                "[%s]", ts->hung ? "did not finish within the time limit" :
                "found a port not open within 10 s", o);
        goto verdict;
    }

    TEST_STEP("Run the same input against the Go and the C# service");
    snprintf(cmd, sizeof(cmd), "curl -sS --fail --max-time 20 "
             "'http://127.0.0.1:%u/ring?value=" INPUT_VALUE "&hops="
             INPUT_HOPS "'", tab_port[GO]);
    if (!ts_run(go, src_root, cmd, NULL, NULL, NULL, LIMIT_S, "ref-go"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start the Go run");
        goto verdict;
    }
    tsx_log_step("H2", "ref-go", cmd, go);
    tsx_log_full("H2 go stdout", go->out);
    snprintf(cmd, sizeof(cmd), "curl -sS --fail --max-time 20 "
             "'http://127.0.0.1:%u/ring?value=" INPUT_VALUE "&hops="
             INPUT_HOPS "'", tab_port[CS]);
    if (!ts_run(cs, src_root, cmd, NULL, NULL, NULL, LIMIT_S, "ref-cs"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start the C# run");
        goto verdict;
    }
    tsx_log_step("H2", "ref-cs", cmd, cs);
    tsx_log_full("H2 csharp stdout", cs->out);

    TEST_STEP("Compare the answer lines and the exit codes");
    ex_set(&e_go, "go", go, go->out);
    ex_set(&e_cs, "csharp", cs, cs->out);
    ex_set(&e_ts_go, "typescript->service-go", ts, "");
    ex_set(&e_ts_cs, "typescript->service-cs", ts, "");
    e_ts_go.has_answer = tsx_section(ts->out, "service-go", sec, sizeof(sec))
                         && tsx_answer_line(sec, e_ts_go.answer,
                                            sizeof(e_ts_go.answer));
    e_ts_cs.has_answer = tsx_section(ts->out, "service-cs", sec, sizeof(sec))
                         && tsx_answer_line(sec, e_ts_cs.answer,
                                            sizeof(e_ts_cs.answer));
    RING("H2: answer lines: typescript->go [%s] (exit %d), go [%s] (exit "
         "%d), typescript->csharp [%s] (exit %d), csharp [%s] (exit %d)",
         e_ts_go.answer, e_ts_go.code, e_go.answer, e_go.code,
         e_ts_cs.answer, e_ts_cs.code, e_cs.answer, e_cs.code);
    if (!e_go.has_answer || !e_cs.has_answer)
        append(bad, sizeof(bad), "the %s service printed no value= line "
               "(exit %d); ", !e_go.has_answer ? "Go" : "C#",
               !e_go.has_answer ? e_go.code : e_cs.code);
    if (!e_ts_go.has_answer || !e_ts_cs.has_answer)
        append(bad, sizeof(bad), "the TypeScript example printed no value= "
               "line for %s (exit %d); ", !e_ts_go.has_answer ?
               "service-go" : "service-cs", ts->code);
    if (bad[0] == '\0')
    {
        if (!same_answer(&e_ts_go, &e_go))
            append(bad, sizeof(bad), "typescript vs go: [%s] exit %d vs [%s] "
                   "exit %d; ", e_ts_go.answer, e_ts_go.code, e_go.answer,
                   e_go.code);
        if (!same_answer(&e_ts_cs, &e_cs))
            append(bad, sizeof(bad), "typescript vs csharp: [%s] exit %d vs "
                   "[%s] exit %d; ", e_ts_cs.answer, e_ts_cs.code,
                   e_cs.answer, e_cs.code);
        if (!same_answer(&e_go, &e_cs))
            append(bad, sizeof(bad), "go vs csharp: [%s] exit %d vs [%s] "
                   "exit %d; ", e_go.answer, e_go.code, e_cs.answer,
                   e_cs.code);
    }
    if (bad[0] != '\0')
        res_set(&res, R_FAIL, "H2 FAIL: mismatch: %s", bad);
    else
        res_set(&res, R_PASS, "H2 PASS: the TypeScript, Go and C# examples "
                "give the same answer line [%s] and the same exit code %d",
                e_go.answer, e_go.code);
    T_FINDING(res.kind == R_PASS ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_MEDIUM, "ts.contract", "guess", "%s",
              res.msg);

verdict:
    if (peer_up)
        ts_peer_stop(&peer);
    if (have_session)
        tsapi_mde_session_fini(&session);
    free(ts);
    free(go);
    free(cs);
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}

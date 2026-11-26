/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h3_same_output, the TypeScript example and the Go
 *        service give the same output for the same input (settles H3)
 *
 * Starts the web services, runs the built TypeScript example (node
 * dist/index.js 42 3) and sends the same value and hop count to the Go
 * service. Both outputs are logged in full. The answer line (the last
 * "value=" line) and the exit code must be equal; any difference fails and
 * both values are printed. A missing build is "H1 build missing" and a
 * service that is not up is "start-up fault", neither says anything about H3.
 * Known-bad control: the comparison separates a planted different line, a
 * planted different exit code and a planted missing line.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h3_same_output"

#include "te_config.h"

#include "tsx_lib.h"

#define VALUE       "42"
#define HOPS        "3"
#define LIMIT_S     60

typedef struct out_t {
    int     code;
    bool    has;
    char    line[200];
} out_t;

static bool
out_same(const out_t *a, const out_t *b)
{
    return a->code == b->code && a->has == b->has &&
           strcmp(a->line, b->line) == 0;
}

static bool
control_ok(char *why, size_t size)
{
    out_t a = { 0, true, "value=47.5" };
    out_t b = a;

    if (!out_same(&a, &b))
    {
        snprintf(why, size, "equal outputs were called different");
        return false;
    }
    snprintf(b.line, sizeof(b.line), "value=48.5");
    if (out_same(&a, &b))
    {
        snprintf(why, size, "a planted different answer was called equal");
        return false;
    }
    b = a;
    b.code = 1;
    if (out_same(&a, &b))
    {
        snprintf(why, size, "a planted different exit code was called "
                 "equal");
        return false;
    }
    b = a;
    b.has = false;
    b.line[0] = '\0';
    if (out_same(&a, &b))
    {
        snprintf(why, size, "a planted missing answer was called equal");
        return false;
    }
    return true;
}

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *ts = calloc(1, sizeof(*ts));
    ts_run_t   *go = calloc(1, sizeof(*go));
    out_t       ots = { 0 };
    out_t       ogo = { 0 };
    char        tsdir[700];
    char        index[800];
    char        cmd[1000];
    char        note[900];
    char        why[400];
    char        ep[200];
    char        sec[8192];
    const char *env[3];
    int         up;

    TEST_START;
    t_report_begin();
    if (ts == NULL || go == NULL)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H3"))
        goto verdict;

    TEST_STEP("Known-bad control: the comparison tells outputs apart");
    if (!control_ok(why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }

    TEST_STEP("Check that the TypeScript build exists");
    tsx_index_js(src_root, tsdir, sizeof(tsdir), index, sizeof(index));
    if (access(index, R_OK) != 0)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: H1 build missing: %s does "
                "not exist, so there is no TypeScript example to compare",
                index);
        goto verdict;
    }

    TEST_STEP("Start the web services");
    up = tsx_services_up("H3", note, sizeof(note));
    if (up < 3 || !port_accepts(tab_port[GO]) || !port_accepts(tab_port[GW]))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: start-up fault: %d of 3 "
                "services up: %s", up, note);
        goto verdict;
    }

    TEST_STEP("Run the TypeScript example with value " VALUE " hops " HOPS);
    snprintf(ep, sizeof(ep), "GUESS_ENDPOINT=%s", tsx_url);
    env[0] = ep;
    env[1] = "RING_TIMEOUT_MS=20000";
    env[2] = NULL;
    snprintf(cmd, sizeof(cmd), "node '%s' " VALUE " " HOPS, index);
    if (!ts_run(ts, src_root, cmd, NULL, env, NULL, LIMIT_S, "ts"))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the example");
        goto verdict;
    }
    tsx_log_step("H3", "ts", cmd, ts);
    tsx_log_full("H3 typescript stdout", ts->out);

    TEST_STEP("Send the same input to the Go service");
    snprintf(cmd, sizeof(cmd), "curl -sS --fail --max-time 20 "
             "'http://127.0.0.1:%u/ring?value=" VALUE "&hops=" HOPS "'",
             tab_port[GO]);
    if (!ts_run(go, src_root, cmd, NULL, NULL, NULL, LIMIT_S, "go"))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the Go run");
        goto verdict;
    }
    tsx_log_step("H3", "go", cmd, go);
    tsx_log_full("H3 go stdout", go->out);

    TEST_STEP("Compare the answer lines and the exit codes");
    ots.code = ts->hung ? -1 : ts->sig != 0 ? 128 + ts->sig : ts->code;
    ogo.code = go->hung ? -1 : go->sig != 0 ? 128 + go->sig : go->code;
    /* Prefer the part of the output that names the Go service. */
    if (tsx_section(ts->out, "service-go", sec, sizeof(sec)))
        ots.has = tsx_answer_line(sec, ots.line, sizeof(ots.line));
    else
        ots.has = tsx_answer_line(ts->out, ots.line, sizeof(ots.line));
    ogo.has = tsx_answer_line(go->out, ogo.line, sizeof(ogo.line));
    RING("H3: typescript [%s] exit %d; go [%s] exit %d", ots.line, ots.code,
         ogo.line, ogo.code);
    if (!ots.has || !ogo.has)
        res_set(&res, R_FAIL, "H3 FAIL: no answer line: typescript %s "
                "(exit %d), go %s (exit %d)", ots.has ? "has one" :
                "has none", ots.code, ogo.has ? "has one" : "has none",
                ogo.code);
    else if (!out_same(&ots, &ogo))
        res_set(&res, R_FAIL, "H3 FAIL: the outputs differ: typescript [%s] "
                "exit %d, go [%s] exit %d", ots.line, ots.code, ogo.line,
                ogo.code);
    else
        res_set(&res, R_PASS, "H3 PASS: the TypeScript example and the Go "
                "service give the same answer [%s] and exit code %d for "
                "value " VALUE " hops " HOPS, ots.line, ots.code);
    T_FINDING(res.kind == R_PASS ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_MEDIUM, "ts.same-output", "typescript vs go",
              "%s", res.msg);

verdict:
    free(ts);
    free(go);
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}

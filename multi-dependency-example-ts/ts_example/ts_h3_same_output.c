/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h3_same_output, the TypeScript example and the Go
 *        service give the same output for the same input (settles H3)
 *
 * Starts the web services, then sends one fixed set of contract inputs (one
 * valid guess first, then three more valid ones) to the built TypeScript
 * example (node dist/index.js <value> <hops>) and to the Go service. The
 * replies are logged in full and compared byte for byte: the test passes
 * when the TypeScript reply equals the Go reply for every input, and prints
 * both replies on a mismatch. When the Go example cannot start the test is
 * skipped, not failed. A missing build is "H2 build missing" and a
 * service that is not up is "start-up fault", neither says anything about H3.
 * Known-bad control: the byte comparison separates a planted one-byte
 * difference, a missing and an extra newline and an empty reply.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h3_same_output"

#include "te_config.h"

#include "tsx_lib.h"

#define LIMIT_S     60

/** The fixed contract inputs; the first is the valid guess. */
static const struct { const char *value; const char *hops; } inputs[] = {
    { "42", "3" }, { "1", "1" }, { "7", "2" }, { "100", "5" },
};
#define N_INPUTS    (sizeof(inputs) / sizeof(inputs[0]))

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *ts = calloc(1, sizeof(*ts));
    ts_run_t   *go = calloc(1, sizeof(*go));
    char        tsdir[700];
    char        index[800];
    char        cmd[1000];
    char        note[900];
    char        why[400];
    char        ep[200];
    char        sec[8192];
    char        a[400];
    char        b[400];
    char        bad[2400] = "";
    const char *env[3];
    size_t      i;
    int         up;
    int         same = 0;

    TEST_START;
    t_report_begin();
    if (ts == NULL || go == NULL)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H3"))
        goto verdict;
    if (!tsx_need_build(&res, "H3"))
        goto verdict;

    TSX_STEP("Known-bad control: the byte comparison tells replies apart");
    if (!tsx_bytes_control_ok(why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }

    TSX_STEP("Check that the TypeScript build exists");
    tsx_index_js(src_root, tsdir, sizeof(tsdir), index, sizeof(index));
    if (access(index, R_OK) != 0)
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: H2 build missing: %s does "
                "not exist, so there is no TypeScript example to compare",
                index);
        goto verdict;
    }

    TSX_STEP("Start the web services");
    up = tsx_services_up("H3", note, sizeof(note));
    if (tab_port[GO] == 0 || !port_accepts(tab_port[GO]))
    {
        res_set(&res, R_SKIP, "H3 SKIPPED: the Go example could not start "
                "(%d of 3 services up; go port %u is not open): %s, so there "
                "is no Go reply to compare the TypeScript reply with", up,
                tab_port[GO], note);
        goto verdict;
    }
    if (tab_port[GW] == 0 || !port_accepts(tab_port[GW]))
    {
        res_set(&res, R_FAIL, "H3 NOT SETTLED: start-up fault: the gateway "
                "the TypeScript example talks to is not up (%d of 3 "
                "services up): %s", up, note);
        goto verdict;
    }

    snprintf(ep, sizeof(ep), "GUESS_ENDPOINT=%s", tsx_url);
    env[0] = ep;
    env[1] = "RING_TIMEOUT_MS=20000";
    env[2] = NULL;
    for (i = 0; i < N_INPUTS; i++)
    {
        const char *tsrep;
        size_t      tslen;
        const char *gorep = go->out;
        size_t      golen;

        TSX_STEP("Send value %s hops %s to the TypeScript example",
                 inputs[i].value, inputs[i].hops);
        snprintf(cmd, sizeof(cmd), "node '%s' %s %s", index,
                 inputs[i].value, inputs[i].hops);
        if (!ts_run(ts, src_root, cmd, NULL, env, NULL, LIMIT_S, "ts"))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the "
                    "example");
            goto verdict;
        }
        tsx_log_step("H3", "ts", cmd, ts);

        TSX_STEP("Send value %s hops %s to the Go service",
                 inputs[i].value, inputs[i].hops);
        snprintf(cmd, sizeof(cmd), "curl -sS --fail --max-time 20 "
                 "'http://127.0.0.1:%u/ring?value=%s&hops=%s'",
                 tab_port[GO], inputs[i].value, inputs[i].hops);
        if (!ts_run(go, src_root, cmd, NULL, NULL, NULL, LIMIT_S, "go"))
        {
            res_set(&res, R_FAIL, "H3 NOT SETTLED: cannot start the Go "
                    "run");
            goto verdict;
        }
        tsx_log_step("H3", "go", cmd, go);
        if (go->code != 0 || go->hung)
        {
            res_set(&res, R_SKIP, "H3 SKIPPED: the Go example started but "
                    "did not answer value %s hops %s (curl exit code %d): "
                    "there is no Go reply to compare with", inputs[i].value,
                    inputs[i].hops, go->code);
            goto verdict;
        }

        TSX_STEP("Compare the replies byte for byte (value %s hops %s)",
                 inputs[i].value, inputs[i].hops);
        /* The part of the output that names the Go service, else all. */
        if (tsx_section(ts->out, "service-go", sec, sizeof(sec)))
            tsrep = sec;
        else
            tsrep = ts->out;
        tslen = strlen(tsrep);
        golen = go->out_len;
        gorep = go->out;
        tsx_escape(tsrep, tslen, 300, a, sizeof(a));
        tsx_escape(gorep, golen, 300, b, sizeof(b));
        RING("H3: value %s hops %s: typescript reply (%zu bytes, exit %d) "
             "[%s]; go reply (%zu bytes) [%s]", inputs[i].value,
             inputs[i].hops, tslen, ts->code, a, golen, b);
        if (ts->hung || ts->sig != 0 || ts->code != 0)
            append(bad, sizeof(bad), "value %s hops %s: the TypeScript "
                   "example %s (exit code %d, signal %d), typescript reply "
                   "[%s], go reply [%s]; ", inputs[i].value, inputs[i].hops,
                   ts->hung ? "was killed on the time limit" : "failed",
                   ts->code, ts->sig, a, b);
        else if (!tsx_same_bytes(tsrep, tslen, gorep, golen))
            append(bad, sizeof(bad), "value %s hops %s: typescript reply "
                   "(%zu bytes) [%s] differs from go reply (%zu bytes) [%s] "
                   "at byte %zu; ", inputs[i].value, inputs[i].hops, tslen,
                   a, golen, b, tsx_first_diff(tsrep, tslen, gorep, golen));
        else
            same++;
    }
    if (bad[0] != '\0')
        res_set(&res, R_FAIL, "H3 FAIL: the TypeScript reply is not the Go "
                "reply: %s", bad);
    else
        res_set(&res, R_PASS, "H3 PASS: the TypeScript reply equals the Go "
                "reply byte for byte for all %d fixed inputs (first: value "
                "%s hops %s, reply [%s])", same, inputs[0].value,
                inputs[0].hops, a);
    T_FINDING(res.kind == R_PASS ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_MEDIUM, "ts.same-output", "typescript vs go",
              "%.1500s", res.msg);

verdict:
    free(ts);
    free(go);
    TSX_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}

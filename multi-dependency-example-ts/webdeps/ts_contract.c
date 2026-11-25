/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: ts_contract, the TypeScript example and an existing one
 *        answer alike (settles H2)
 *
 * Runs the TypeScript example (./scripts/run.sh guess) and the Rust
 * example (dist/bin/rust-demo; the Go build is the fallback) with the same
 * fixed input, as the first argument and on stdin, and compares stdout and
 * the exit code. Pass when both match. A known-bad control checks that the
 * comparison tells two different outputs apart. Every verdict starts with H2.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/ts_contract"

#include "te_config.h"

#include "ts_lib.h"

#define FIXED_INPUT "42"
#define LIMIT_S     30

/** Compare two runs; fills @p why with the first difference. */
static bool
same(const ts_run_t *a, const ts_run_t *b, char *why, size_t size)
{
    char x[200];
    char y[200];

    if (a->code != b->code || a->sig != b->sig || a->hung != b->hung)
    {
        snprintf(why, size, "exit code differs (ts: code %d sig %d hung %d; "
                 "reference: code %d sig %d hung %d)", a->code, a->sig,
                 a->hung, b->code, b->sig, b->hung);
        return false;
    }
    if (a->out_len != b->out_len || memcmp(a->out, b->out, a->out_len) != 0)
    {
        ts_flat(a->out, 150, x, sizeof(x));
        ts_flat(b->out, 150, y, sizeof(y));
        snprintf(why, size, "stdout differs (ts, %zu B: [%s]; reference, "
                 "%zu B: [%s])", a->out_len, x, b->out_len, y);
        return false;
    }
    return true;
}

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *ts = calloc(1, sizeof(*ts));
    ts_run_t   *ref = calloc(1, sizeof(*ref));
    char        in_path[300];
    char        cmd[700];
    char        bin[600];
    char        why[700] = "";
    char        t1[200];
    char        t2[200];
    const char *refname = "rust-demo";
    FILE       *f;
    const char *env[] = { "TS_INPUT=" FIXED_INPUT, NULL };

    TEST_START;
    t_report_begin();
    if (ts == NULL || ref == NULL)
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: out of memory");
        goto verdict;
    }
    wd_init(&res);
    if (res.kind == R_SETUP)
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: harness step broke: %.800s",
                res.msg);
        goto verdict;
    }
    snprintf(in_path, sizeof(in_path), "%s/input", workdir);
    f = fopen(in_path, "w");
    if (f == NULL)
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot write %s", in_path);
        goto verdict;
    }
    fputs(FIXED_INPUT "\n", f);
    fclose(f);

    TEST_STEP("Known-bad control: two different outputs are told apart");
    ts->out_len = snprintf(ts->out, sizeof(ts->out), "guess: 42\n");
    ref->out_len = snprintf(ref->out, sizeof(ref->out), "result = 42\n");
    if (same(ts, ref, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: the "
                "comparison called two different outputs equal");
        goto verdict;
    }
    ref->code = 3;
    ref->out_len = ts->out_len;
    memcpy(ref->out, ts->out, ts->out_len + 1);
    if (same(ts, ref, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: the "
                "comparison called two different exit codes equal");
        goto verdict;
    }

    snprintf(bin, sizeof(bin), "%s/dist/bin/rust-demo", src_root);
    if (access(bin, X_OK) != 0)
    {
        refname = "service-go";
        snprintf(bin, sizeof(bin), "%s/dist/bin/service-go", src_root);
    }
    if (access(bin, X_OK) != 0)
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: neither dist/bin/rust-demo "
                "nor dist/bin/service-go exists in %s (build failure?)",
                src_root);
        goto verdict;
    }

    TEST_STEP("Run the TypeScript example with input %s", FIXED_INPUT);
    snprintf(cmd, sizeof(cmd), "exec ./scripts/run.sh guess \"$TS_INPUT\"");
    if (!ts_run(ts, src_root, cmd, in_path, env, NULL, LIMIT_S, "ts"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start the example");
        goto verdict;
    }
    TEST_STEP("Run %s with the same input", refname);
    snprintf(cmd, sizeof(cmd), "exec '%s' \"$TS_INPUT\"", bin);
    if (!ts_run(ref, src_root, cmd, in_path, env, NULL, LIMIT_S, "ref"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start %s", refname);
        goto verdict;
    }
    ts_end_text(ts, t1, sizeof(t1));
    ts_end_text(ref, t2, sizeof(t2));
    {
        char o1[200];
        char o2[200];

        ts_flat(ts->out, 150, o1, sizeof(o1));
        ts_flat(ref->out, 150, o2, sizeof(o2));
        RING("webdeps H2: ts: %s stdout [%s]; %s: %s stdout [%s]", t1, o1,
             refname, t2, o2);
    }
    if (same(ts, ref, why, sizeof(why)))
    {
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "ts.contract", refname,
                  "match: %s", t1);
        res_set(&res, R_PASS, "H2 PASS: the TypeScript example and %s gave "
                "the same stdout (%zu B) and exit code (%d) for input '%s'",
                refname, ts->out_len, ts->code, FIXED_INPUT);
    }
    else
    {
        T_FINDING(TAPI_CYBERSEC_SEV_MEDIUM, "ts.contract", refname, "%s",
                  why);
        res_set(&res, R_FAIL, "H2 FAIL: against %s for input '%s': %s",
                refname, FIXED_INPUT, why);
    }

verdict:
    free(ts);
    free(ref);
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}

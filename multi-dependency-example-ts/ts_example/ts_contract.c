/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_contract, the TypeScript example follows the same
 *        contract as the Go, Rust and C++ examples (settles H2)
 *
 * Runs guess for the TypeScript example (./scripts/run.sh guess 42 3) and
 * the same input for the Rust demo (dist/bin/rust-demo), the C++ demo
 * (dist/bin/cpp-demo) and Go (dist/bin/go-demo when it exists, otherwise
 * the /ring endpoint of service-go, which is Go's entry to the ring), and
 * compares stdout and the exit code. Every run is logged. On a difference
 * both outputs are logged side by side.
 *
 * Pass: the TypeScript stdout (blank lines and edge blanks ignored) and exit
 * code equal those of every reference found. Demos that print their own
 * program name cannot be equal to each other; when the references already
 * differ among themselves in that way, the contract is the exit code and the
 * final result number, and the verdict says so. Fail when the TypeScript
 * example differs. Not settled when no reference could be run.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_contract"

#include "te_config.h"

#include "tsx_lib.h"

#define INPUT_VALUE "42"
#define INPUT_HOPS  "3"
#define LIMIT_S     30
#define N_REF       3

/** Normalise stdout: trim every line, drop blank ones. */
static void
norm(const char *in, char *out, size_t size)
{
    size_t o = 0;
    const char *p = in;

    while (*p != '\0' && o + 2 < size)
    {
        size_t n = strcspn(p, "\n");
        size_t s = 0;
        size_t e = n;

        while (s < e && isspace((unsigned char)p[s]))
            s++;
        while (e > s && isspace((unsigned char)p[e - 1]))
            e--;
        if (e > s)
        {
            size_t k = e - s;

            if (o + k + 2 >= size)
                k = size - o - 2;
            memcpy(out + o, p + s, k);
            o += k;
            out[o++] = '\n';
        }
        p += n + (p[n] == '\n' ? 1 : 0);
    }
    out[o] = '\0';
}

/** Equal exit status and normalised stdout. */
static bool
strict_equal(const ts_run_t *a, const ts_run_t *b)
{
    static char na[TS_CAP];
    static char nb[TS_CAP];

    if (a->code != b->code || a->sig != b->sig || a->hung != b->hung)
        return false;
    norm(a->out, na, sizeof(na));
    norm(b->out, nb, sizeof(nb));
    return strcmp(na, nb) == 0;
}

/** Same exit status and the same final number. */
static bool
result_equal(const ts_run_t *a, const ts_run_t *b)
{
    double x;
    double y;
    double tol;

    if (a->code != b->code || a->sig != b->sig || a->hung != b->hung)
        return false;
    if (!tsx_result_number(a->out, &x) || !tsx_result_number(b->out, &y))
        return false;
    tol = 1e-3 * (fabs(x) > 1.0 ? fabs(x) : 1.0);
    return fabs(x - y) <= tol;
}

/** Log two outputs line by line, side by side. */
static void
side_by_side(const char *ref, const ts_run_t *ts, const ts_run_t *r)
{
    char la[TS_CAP];
    char lb[TS_CAP];
    char *pa;
    char *pb;
    char *sa = NULL;
    char *sb = NULL;
    int   ln;

    snprintf(la, sizeof(la), "%s", ts->out);
    snprintf(lb, sizeof(lb), "%s", r->out);
    pa = strtok_r(la, "\n", &sa);
    pb = strtok_r(lb, "\n", &sb);
    RING("H2 side by side (exit code ts %d | %s %d)", ts->code, ref, r->code);
    for (ln = 0; ln < TSX_TAIL && (pa != NULL || pb != NULL); ln++)
    {
        RING("H2 %-2d ts [%.100s] | %s [%.100s]", ln + 1,
             pa != NULL ? pa : "", ref, pb != NULL ? pb : "");
        pa = pa != NULL ? strtok_r(NULL, "\n", &sa) : NULL;
        pb = pb != NULL ? strtok_r(NULL, "\n", &sb) : NULL;
    }
}

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *ts = calloc(1, sizeof(*ts));
    ts_run_t   *ref = calloc(N_REF, sizeof(*ref));
    static const char * const lang[N_REF] = { "go", "rust", "cpp" };
    bool        have[N_REF] = { false, false, false };
    char        cmd[N_REF][700];
    char        tag[N_REF][16];
    char        note[900];
    char        missing[400] = "";
    char        bad[1200] = "";
    char        gw[200];
    char        path[600];
    char        why[300];
    const char *env[3];
    int         n_have = 0;
    int         i;
    int         j;
    bool        refs_agree = true;
    bool        all_strict = true;
    bool        all_result = true;
    ts_run_t    ca;
    ts_run_t    cb;

    TEST_START;
    t_report_begin();
    if (ts == NULL || ref == NULL)
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H2"))
        goto verdict;

    TEST_STEP("Known-bad control: the comparison tells two outputs apart");
    memset(&ca, 0, sizeof(ca));
    memset(&cb, 0, sizeof(cb));
    snprintf(ca.out, sizeof(ca.out), "ts-demo: result = 42.5\n");
    snprintf(cb.out, sizeof(cb.out), "  ts-demo:   result = 42.5  \n\n");
    if (!strict_equal(&ca, &cb))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: blank and "
                "edge-space differences were called a difference");
        goto verdict;
    }
    snprintf(cb.out, sizeof(cb.out), "ts-demo: result = 43.5\n");
    if (strict_equal(&ca, &cb) || result_equal(&ca, &cb))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: a planted "
                "different result was called equal");
        goto verdict;
    }
    snprintf(cb.out, sizeof(cb.out), "ts-demo: result = 42.5\n");
    cb.code = 3;
    if (strict_equal(&ca, &cb) || result_equal(&ca, &cb))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: a planted "
                "different exit code was called equal");
        goto verdict;
    }
    (void)why;

    TEST_STEP("Start the web services");
    tsx_services_up("H2", note, sizeof(note));
    snprintf(gw, sizeof(gw), "RING_GATEWAY_URL=%s", tsx_url);
    env[0] = gw;
    env[1] = "RING_TIMEOUT_MS=20000";
    env[2] = NULL;

    TEST_STEP("Run guess for the TypeScript example");
    if (!ts_run(ts, src_root, "./scripts/run.sh guess " INPUT_VALUE " "
                INPUT_HOPS, NULL, env, NULL, LIMIT_S, "ts"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start the example");
        goto verdict;
    }
    tsx_log_step("H2", "ts", "./scripts/run.sh guess " INPUT_VALUE " "
                 INPUT_HOPS, ts);

    for (i = 0; i < N_REF; i++)
    {
        snprintf(tag[i], sizeof(tag[i]), "ref-%s", lang[i]);
        cmd[i][0] = '\0';
        if (i == 0)
        {
            snprintf(path, sizeof(path), "%s/dist/bin/go-demo", src_root);
            if (access(path, X_OK) == 0)
                snprintf(cmd[i], sizeof(cmd[i]), "'%s' " INPUT_VALUE " "
                         INPUT_HOPS, path);
            else if (tab_port[GO] != 0 && port_accepts(tab_port[GO]))
                snprintf(cmd[i], sizeof(cmd[i]), "curl -sS --max-time 20 "
                         "'http://127.0.0.1:%u/ring?value=" INPUT_VALUE
                         "&hops=" INPUT_HOPS "'", tab_port[GO]);
        }
        else
        {
            snprintf(path, sizeof(path), "%s/dist/bin/%s-demo", src_root,
                     lang[i]);
            if (access(path, X_OK) == 0)
                snprintf(cmd[i], sizeof(cmd[i]), "'%s' " INPUT_VALUE " "
                         INPUT_HOPS, path);
        }
        TEST_STEP("Run the %s reference with the same input", lang[i]);
        if (cmd[i][0] == '\0')
        {
            if (i == 0)
                append(missing, sizeof(missing), "go: no go-demo binary and "
                       "service-go is not listening; ");
            else
                append(missing, sizeof(missing), "%s: dist/bin/%s-demo is "
                       "absent; ", lang[i], lang[i]);
            RING("H2: %s reference not available", lang[i]);
            continue;
        }
        if (!ts_run(&ref[i], src_root, cmd[i], NULL, NULL, NULL, LIMIT_S,
                    tag[i]))
        {
            append(missing, sizeof(missing), "%s: cannot start; ", lang[i]);
            continue;
        }
        have[i] = true;
        n_have++;
        tsx_log_step("H2", tag[i], cmd[i], &ref[i]);
    }

    if (n_have == 0)
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: no reference example could "
                "be run: %s", missing);
        goto verdict;
    }

    TEST_STEP("Compare stdout and exit code");
    for (i = 0; i < N_REF; i++)
    {
        if (!have[i])
            continue;
        for (j = i + 1; j < N_REF; j++)
        {
            if (have[j] && !strict_equal(&ref[i], &ref[j]))
                refs_agree = false;
        }
    }
    for (i = 0; i < N_REF; i++)
    {
        bool s;
        bool v;

        if (!have[i])
            continue;
        s = strict_equal(ts, &ref[i]);
        v = result_equal(ts, &ref[i]);
        RING("H2: ts vs %s: strict %s, exit code and result %s", lang[i],
             s ? "equal" : "DIFFERENT", v ? "equal" : "DIFFERENT");
        if (!s)
        {
            all_strict = false;
            side_by_side(lang[i], ts, &ref[i]);
        }
        if (!v)
        {
            all_result = false;
            append(bad, sizeof(bad), "%s: exit code ts %d vs %d, ", lang[i],
                   ts->code, ref[i].code);
        }
    }

    if (all_strict)
        res_set(&res, R_PASS, "H2 PASS: the TypeScript stdout and exit code "
                "(%d) equal those of %d reference(s); not run: [%s]",
                ts->code, n_have, missing);
    else if (!refs_agree && all_result)
        res_set(&res, R_PASS, "H2 PASS: exit code and result number equal "
                "those of %d reference(s); the printed text differs (each "
                "demo prints its own name, and the references differ among "
                "themselves too), see the side-by-side log; not run: [%s]",
                n_have, missing);
    else
    {
        char o[300];

        ts_flat(ts->out, 150, o, sizeof(o));
        res_set(&res, R_FAIL, "H2 FAIL: the TypeScript output differs from "
                "the references: %s%s; ts exit code %d stdout [%s]; see the "
                "side-by-side log; not run: [%s]", bad,
                all_result ? "result and exit code equal but text differs "
                "while the references agree" : "result or exit code differ",
                ts->code, o, missing);
    }
    T_FINDING(res.kind == R_PASS ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_MEDIUM, "ts.contract", "guess", "%s",
              res.msg);

verdict:
    free(ts);
    free(ref);
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}

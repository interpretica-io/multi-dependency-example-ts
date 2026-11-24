/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: gateway_startup_panic, gateway-rs started three times
 *        (settles H1)
 *
 * Hypothesis H1: gateway-rs panics at start-up on bad input or config
 * (panic! at main.rs:30 and main.rs:34).
 *
 * The upstream setting is a row of web/contract/services.tab compiled into
 * the gateway. Three runs, each for up to 5 s, exit code and stderr logged:
 *  1. normal: the installed dist/bin/gateway-rs;
 *  2. empty: a build from a copy of web/ whose gateway-rs upstream is empty;
 *  3. malformed: a build whose gateway-rs port is not a number.
 * The sources of the example are not changed; the copies live in the
 * work directory.
 *
 * Verdicts (every one starts with H1):
 *  - "H1 CONFIRMED panic-in-RUN" (fail): a run exited with 101 or SIGABRT
 *    (134), or printed a Rust panic message.
 *  - "H1 DISPROVED" (pass): every run kept running or exited with an error
 *    message and no panic.
 *  - "H1 NOT SETTLED config-not-changeable" (fail): a bad-config variant
 *    could not be built; only the runs that took place are judged.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/gateway_startup_panic"

#include "te_config.h"

#include "webdeps_lib.h"

#define RUN_S   5

static const struct {
    const char *name;
    const char *sed;        /**< NULL: the installed binary. */
} runs[] = {
    { "normal", NULL },
    { "empty", "s/^\\(gateway-rs[ \\t]*[0-9]*[ \\t]*\\)[^ \\t]*/\\1/" },
    { "malformed", "s/^\\(gateway-rs[ \\t]*\\)[0-9]*/\\1notaport/" },
};

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    char     panics[300] = "";
    char     summary[900] = "";
    unsigned n_done = 0;
    unsigned n_unset = 0;
    size_t   i;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;

    for (i = 0; i < TE_ARRAY_LEN(runs); i++)
    {
        char    cmd[1800];
        char    outtail[300];
        char    errtail[400];
        char    label[64];
        proc_t *p;
        int     code = -1;
        char   *e;
        bool    panic;

        TEST_STEP("Start gateway-rs: %s configuration", runs[i].name);
        snprintf(label, sizeof(label), "gateway-rs-%s", runs[i].name);
        if (runs[i].sed == NULL)
            snprintf(cmd, sizeof(cmd),
                     "LD_LIBRARY_PATH='%s/dist/lib' timeout %d "
                     "dist/bin/gateway-rs 2>%s/%s.stderr; echo \"exit=$?\"",
                     src_root, RUN_S, workdir, label);
        else
            snprintf(cmd, sizeof(cmd),
                     "T=%s/%s && rm -rf $T && mkdir -p $T/web && "
                     "cp -r web/contract web/gateway-rs $T/web/ && "
                     "sed -i '%s' $T/web/contract/services.tab && "
                     "CARGO_TARGET_DIR=$T/target cargo build --release "
                     "--offline --manifest-path $T/web/gateway-rs/Cargo.toml "
                     ">$T/build.log 2>&1 || { tail -5 $T/build.log; "
                     "echo build-failed; exit 0; }; "
                     "LD_LIBRARY_PATH='%s/dist/lib' timeout %d "
                     "$T/target/release/gateway-rs 2>%s/%s.stderr; "
                     "echo \"exit=$?\"",
                     workdir, label, runs[i].sed, src_root, RUN_S, workdir,
                     label);
        p = run_sh(&res, label, cmd, 300);
        if (p == NULL)
        {
            char orig[sizeof(res.msg)];

            snprintf(orig, sizeof(orig), "%s", res.msg);
            res_set(&res, R_SETUP, "H1 setup-run-%s-failed: %.1400s",
                    runs[i].name, orig);
            goto verdict;
        }
        file_tail(p->out, outtail, sizeof(outtail));
        {
            char errpath[200];

            snprintf(errpath, sizeof(errpath), "%s/%s.stderr", workdir, label);
            file_tail(errpath, errtail, sizeof(errtail));
            panic = file_has(errpath, "panicked at");
        }
        if (strstr(outtail, "build-failed") != NULL)
        {
            n_unset++;
            RING("webdeps H1: the %s variant could not be built: %s",
                 runs[i].name, outtail);
            T_FINDING(TAPI_CYBERSEC_SEV_LOW, "gateway.config-unchanged",
                      runs[i].name, "variant not built: %s", outtail);
            append(summary, sizeof(summary), "%s: not built; ", runs[i].name);
            continue;
        }
        e = strstr(outtail, "exit=");
        if (e != NULL)
            code = atoi(e + 5);
        n_done++;
        RING("webdeps H1: run %s: exit code %d (124 = still running after "
             "%d s); stderr [%s]", runs[i].name, code, RUN_S, errtail);
        panic = panic || code == 101 || code == 134;
        T_FINDING(panic ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
                  "gateway.startup", runs[i].name, "exit code %d; stderr "
                  "[%s]", code, errtail);
        append(summary, sizeof(summary), "%s: exit %d, stderr [%.120s]; ",
               runs[i].name, code, errtail);
        if (panic)
            append(panics, sizeof(panics), "%s(%d) ", runs[i].name, code);
    }

    if (panics[0] != '\0')
        res_set(&res, R_FAIL, "H1 CONFIRMED panic-in-%s: gateway-rs "
                "panicked at start-up (exit 101 or SIGABRT, or a Rust panic "
                "message); %s", panics, summary);
    else if (n_unset > 0)
        res_set(&res, R_FAIL, "H1 NOT SETTLED config-not-changeable: %u of "
                "3 runs could not be made (the setting is compiled in and "
                "the variant did not build); no panic in the %u that ran; "
                "%s", n_unset, n_done, summary);
    else
        res_set(&res, R_PASS, "H1 DISPROVED: no run panicked (kept running "
                "or exited with an error message); %s", summary);

verdict:
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}

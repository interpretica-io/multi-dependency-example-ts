/** @file
 * @brief Kernel Group
 *
 * Trace sched:sched_process_exec while the ring demos run, and check that
 * the kernel saw every one of them start: an independent, kernel-side
 * view of what the suite believes it ran. /bin/true is run first as the
 * known-bad control of the tracer itself: a trace that does not show it
 * is blind. A tracefs instance of tsf-kernel is used when the agent can
 * create one; otherwise the same instance is driven through sudo; when
 * neither works (a container without tracefs) the test skips.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "kernel/ktrace"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_ktrace.h"
#include "kernel_common.h"

/** The event traced. */
#define KT_EVENT        "sched/sched_process_exec"
/** Name of the instance driven through sudo. */
#define KT_SUDO_INST    "mde-ktrace-exec"

/** Programs whose exec must be in the trace; [0] is the control. */
static const char *kt_expected[] = {
    "true", "cpp-demo", "rust-demo", "python3",
};

/** Count exec events per program basename in a trace. */
static unsigned int
kt_count(const char *trace, double counts[TE_ARRAY_LEN(kt_expected)])
{
    const char  *p = trace;
    unsigned int total = 0;
    unsigned int i;

    while ((p = strstr(p, "sched_process_exec:")) != NULL)
    {
        const char *f = strstr(p, "filename=");
        const char *eol = strchr(p, '\n');
        const char *end;
        const char *base;
        size_t      len;

        p += strlen("sched_process_exec:");
        if (f == NULL || (eol != NULL && f > eol))
            continue;
        f += strlen("filename=");
        for (end = f; *end != '\0' && *end != ' ' && *end != '\n'; end++)
            ;
        for (base = end; base > f && base[-1] != '/'; base--)
            ;
        len = (size_t)(end - base);
        total++;
        for (i = 0; i < TE_ARRAY_LEN(kt_expected); i++)
        {
            if (strlen(kt_expected[i]) == len &&
                strncmp(base, kt_expected[i], len) == 0)
                counts[i]++;
        }
    }

    return total;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tsapi_mde_report    report;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string           root = TE_STRING_INIT;
    te_string           text = TE_STRING_INIT;
    tapi_ktrace        *trace = NULL;
    bool                use_sudo = false;
    bool                sudo_inst = false;
    bool                lost = false;
    double              counts[TE_ARRAY_LEN(kt_expected)];
    unsigned int        total;
    unsigned int        ok_runs;
    unsigned int        i;
    double              t0;

    TEST_START;
    tsapi_mde_report_init(&report);
    memset(&dut, 0, sizeof(dut));
    memset(counts, 0, sizeof(counts));

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "ktrace", dut, session_up);

    TEST_STEP("Find tracefs and a way to create an instance in it");
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh,
                          "for d in /sys/kernel/tracing "
                          "/sys/kernel/debug/tracing; do "
                          "if [ -w \"$d/instances\" ]; then "
                          "echo \"user $d\"; exit 0; fi; done; "
                          "for d in /sys/kernel/tracing "
                          "/sys/kernel/debug/tracing; do "
                          "if sudo -n test -w \"$d/instances\" 2>/dev/null; "
                          "then echo \"sudo $d\"; exit 0; fi; done; exit 1"));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_SKIP("tracefs is not available to the agent, not even with "
                  "sudo");
    use_sudo = strncmp(te_string_value(&sh.out), "sudo ", 5) == 0;
    te_string_append(&root, "%s", te_string_value(&sh.out) + 5);
    while (root.len > 0 && root.ptr[root.len - 1] == '\n')
        te_string_cut(&root, 1);
    TEST_ARTIFACT("tracefs: %s (%s)", root.ptr,
                  use_sudo ? "through sudo" : "tsf-kernel instance");

    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh, "%stest -e '%s/events/%s'",
                          use_sudo ? "sudo -n " : "", root.ptr, KT_EVENT));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_SKIP("The kernel has no " KT_EVENT " tracepoint");

    TEST_STEP("Start tracing " KT_EVENT);
    if (!use_sudo)
    {
        CHECK_RC(tapi_ktrace_open(session.factory, "mde-exec", 0, &trace));
        CHECK_RC(tapi_ktrace_enable(trace, KT_EVENT, NULL));
        CHECK_RC(tapi_ktrace_start(trace));
    }
    else
    {
        CHECK_RC(tsapi_mde_sh(&session, 20000, &sh,
                              "sudo -n rmdir '%s/instances/" KT_SUDO_INST
                              "' 2>/dev/null; "
                              "sudo -n sh -c 'mkdir \"$1\" && "
                              "echo 1 > \"$1/events/" KT_EVENT "/enable\" && "
                              "echo 1 > \"$1/tracing_on\"' sh "
                              "'%s/instances/" KT_SUDO_INST "'",
                              root.ptr, root.ptr));
        if (!tsapi_mde_sh_ok(&sh))
        {
            RING("sudo could not set the instance up: %s",
                 te_string_value(&sh.err));
            TEST_SKIP("A tracefs instance cannot be set up through sudo");
        }
        sudo_inst = true;
    }

    TEST_STEP("Run the control (/bin/true) and the ring demos");
    t0 = tsapi_mde_now();
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh, "/bin/true"));
    ok_runs = kernel_run_ring(&session, &dut);
    TEST_ARTIFACT("ring demos that exited 0: %u of 3", ok_runs);
    tsapi_mde_mi_point("kernel/ktrace", "Traced workload duration",
                       TE_MI_MEAS_TIME, "workload_s", tsapi_mde_now() - t0,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Stop tracing and read the trace");
    if (!use_sudo)
    {
        CHECK_RC(tapi_ktrace_stop(trace));
        CHECK_RC(tapi_ktrace_read(trace, &text, &lost));
    }
    else
    {
        CHECK_RC(tsapi_mde_sh(&session, 60000, &sh,
                              "sudo -n sh -c 'echo 0 > \"$1/tracing_on\"; "
                              "cat \"$1/trace\"' sh "
                              "'%s/instances/" KT_SUDO_INST "'", root.ptr));
        te_string_append(&text, "%s", te_string_value(&sh.out));
        lost = false;
    }
    RING("Trace:\n%s", te_string_value(&text));

    TEST_STEP("Count the execs the kernel saw");
    total = kt_count(te_string_value(&text), counts);
    TEST_ARTIFACT("exec events traced: %u%s", total,
                  lost ? " (the buffer lost events)" : "");
    tsapi_mde_mi_bars("kernel/ktrace", "Exec events per program",
                      TE_MI_MEAS_UNITLESS_VALUE, "execs",
                      TE_ARRAY_LEN(kt_expected), kt_expected, counts,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("kernel/ktrace", "Exec events in the trace",
                       TE_MI_MEAS_UNITLESS_VALUE, "execs", total,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (lost)
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                 "kernel.ktrace.lost", KT_EVENT,
                                 "the trace buffer lost events");

    for (i = 0; i < TE_ARRAY_LEN(kt_expected); i++)
    {
        TEST_ARTIFACT("exec of %s: %.0f", kt_expected[i], counts[i]);
        if (counts[i] > 0)
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                     "kernel.ktrace.exec", kt_expected[i],
                                     "%.0f exec event(s)", counts[i]);
        else if (i > 0)
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "kernel.ktrace.exec-missing",
                                     kt_expected[i],
                                     "the kernel never saw it start");
    }

    TEST_STEP("The control's exec must be in the trace");
    tsapi_mde_report_expect(&report, "kernel.ktrace.exec", kt_expected[0]);
    tsapi_mde_report_drop_subject(&report, kt_expected[0]);

    TEST_STEP("Decide over the trace");
    TSAPI_MDE_REPORT_GATE(&report, "kernel", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    if (trace != NULL)
        CLEANUP_CHECK_RC(tapi_ktrace_close(trace));
    if (sudo_inst)
    {
        (void)tsapi_mde_sh(&session, 20000, &sh,
                           "sudo -n sh -c 'echo 0 > \"$1/events/" KT_EVENT
                           "/enable\"; echo 0 > \"$1/tracing_on\"; "
                           "rmdir \"$1\"' sh '%s/instances/" KT_SUDO_INST "'",
                           root.ptr);
    }
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&root);
    te_string_free(&text);
    if (session_up)
    {
        tsapi_mde_dut_free(&dut);
        tsapi_mde_session_fini(&session);
    }

    TEST_END;
}

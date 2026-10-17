/** @file
 * @brief Kernel Group
 *
 * Watch the kernel log while the example runs. A window is opened on the
 * log (a tsf-kernel marker when /dev/kmsg is writable, the last line of
 * the log otherwise), the ring demos or the web tier are driven, a
 * deliberately crashing program is run as the known-bad control, and the
 * window is closed. Every user-space fault line ("segfault at",
 * "traps:", "general protection") that names a binary of the example is
 * the critical finding kernel.dut-crash; the control's own fault must be
 * seen, or the window is blind. Kernel events in the window (oops, BUG,
 * WARNING, ...) are classified by tsf-kernel and ranked as medium: the
 * kernel is shared with the host and is not the DUT.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "kernel/kmsg_window"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_kernel.h"
#include "tapi_kmsg.h"
#include "kernel_common.h"

/** Where the control crasher is built on the agent. */
#define KMSG_CTL_DIR    "/tmp/mde-kernel-kmsg-ctl"

/** Fragments of a kernel line reporting a user-space fault. */
static const char *kmsg_fault_marks[] = {
    "segfault at", "traps:", "general protection", "trap invalid opcode",
    "trap divide error", "trap int3", "Unhandled", "unhandled",
};

/** Names of the priorities, index = priority. */
static const char *kmsg_prio_names[] = {
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
};

/**
 * Skip "<N>" and "[ timestamp]" in front of a raw dmesg line.
 *
 * @param line      Line.
 * @param prio      Where to save the priority, or -1 if none.
 *
 * @return The message.
 */
static const char *
kmsg_skip(const char *line, int *prio)
{
    const char *p = line;

    *prio = -1;
    if (*p == '<')
    {
        char *end;
        long  v = strtol(p + 1, &end, 10);

        if (*end == '>')
        {
            *prio = (int)(v & 7);
            p = end + 1;
        }
    }
    if (*p == '[')
    {
        const char *close = strchr(p, ']');

        if (close != NULL)
            p = close + 1;
    }
    while (*p == ' ')
        p++;

    return p;
}

/**
 * Extract the command name from a fault message:
 * "comm[pid]: segfault at ..." or "traps: comm[pid] ...".
 *
 * @param msg       Message.
 * @param comm      String to append the name to.
 *
 * @return @c true if a name was found.
 */
static bool
kmsg_fault_comm(const char *msg, te_string *comm)
{
    const char *p = msg;
    const char *br;
    size_t      len;

    if (strncmp(p, "traps: ", 7) == 0)
        p += 7;
    br = strchr(p, '[');
    if (br == NULL || br == p)
        return false;
    len = (size_t)(br - p);
    if (len > 16 || memchr(p, ' ', len) != NULL)
        return false;

    te_string_append_buf(comm, p, len);
    return true;
}

/** Whether a name is a binary of the example. */
static bool
kmsg_is_dut(const char *comm)
{
    unsigned int i;

    for (i = 0; i < tsapi_mde_dut_n_bins; i++)
    {
        if (strcmp(comm, tsapi_mde_dut_bins[i]) == 0)
            return true;
    }

    return false;
}

int
main(int argc, char **argv)
{
    kernel_workload        workload;
    tapi_cybersec_severity min_sev;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_web          web;
    tsapi_mde_report       report;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    const char            *dmesg;
    te_string              anchor = TE_STRING_INIT;
    te_string              clean = TE_STRING_INIT;
    te_string              ctl_comm = TE_STRING_INIT;
    tapi_kmsg_window       window;
    bool                   window_open = false;
    te_vec                 events = TE_VEC_INIT(tapi_kmsg_event);
    tapi_kernel_issues     kissues;
    const char            *klog;
    const char            *start;
    const char            *p;
    double                 prio_counts[TE_ARRAY_LEN(kmsg_prio_names)];
    unsigned int           n_lines = 0;
    unsigned int           n_faults = 0;
    unsigned int           n_dut_faults = 0;
    unsigned int           ok_runs = 0;
    unsigned int           answered = 0;
    bool                   truncated = false;
    bool                   have_gcc;
    double                 t0;
    double                 workload_s;
    unsigned int           i;
    const tapi_kmsg_event *ev;

    TEST_START;
    tsapi_mde_report_init(&report);
    tapi_kernel_issues_init(&kissues);
    memset(&web, 0, sizeof(web));
    memset(&dut, 0, sizeof(dut));
    memset(prio_counts, 0, sizeof(prio_counts));

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(workload, KERNEL_WORKLOAD_LIST);
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "kmsg", dut, session_up);

    TEST_STEP("Find a way to read the kernel log");
    dmesg = kernel_dmesg_cmd(&session);
    if (dmesg == NULL)
        TEST_SKIP("The kernel log is not readable on the agent, not even "
                  "with sudo (EPERM: no CAP_SYSLOG in the container)");
    TEST_ARTIFACT("kernel log read with: %s -r", dmesg);

    TEST_STEP("Check that the kernel logs user-space faults at all");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh,
                          "cat /proc/sys/debug/exception-trace 2>/dev/null "
                          "|| echo absent"));
    TEST_ARTIFACT("debug.exception-trace: %s", te_string_value(&sh.out));
    if (strncmp(te_string_value(&sh.out), "0", 1) == 0)
        TEST_SKIP("The kernel does not log user-space faults "
                  "(debug.exception-trace = 0)");

    TEST_STEP("Prepare the known-bad control: a program that segfaults");
    have_gcc = tsapi_mde_have(&session, "gcc");
    if (have_gcc)
    {
        CHECK_RC(tsapi_mde_sh(&session, 60000, &sh,
                              "rm -rf " KMSG_CTL_DIR " && mkdir -p "
                              KMSG_CTL_DIR " && printf '%%s\\n' "
                              "'int main(void) { volatile int *p = (int *)0; "
                              "return *p; }' > " KMSG_CTL_DIR "/crash.c && "
                              "gcc -O0 -o " KMSG_CTL_DIR "/mde-crashme "
                              KMSG_CTL_DIR "/crash.c"));
        have_gcc = tsapi_mde_sh_ok(&sh);
        if (!have_gcc)
            RING("gcc could not build the crasher: %s",
                 te_string_value(&sh.err));
    }
    if (have_gcc)
    {
        te_string_append(&ctl_comm, "mde-crashme");
    }
    else
    {
        if (!tsapi_mde_have(&session, "python3"))
            TEST_SKIP("Neither gcc nor python3 is there to crash on purpose");
        te_string_append(&ctl_comm, "python3");
    }
    TEST_ARTIFACT("control crasher: %s", ctl_comm.ptr);

    TEST_STEP("Skip unless the workload can be driven");
    if (workload == KERNEL_WORKLOAD_WEB)
    {
        if (!tsapi_mde_web_built(&session, &dut))
            TEST_SKIP("The web tier is not built");
        if (!tsapi_mde_have(&session, "curl"))
            TEST_SKIP("curl is not available on the agent");
    }

    TEST_STEP("Open the window on the kernel log");
    if (tsapi_mde_sh(&session, 10000, &sh, "test -w /dev/kmsg") == 0 &&
        tsapi_mde_sh_ok(&sh))
    {
        rc = tapi_kmsg_window_open(session.factory, &window);
        window_open = (rc == 0);
        if (rc != 0)
            RING("tsf-kernel window could not be opened: %r", rc);
    }
    else
    {
        RING("/dev/kmsg is not writable by the agent: the window is "
             "delimited by the last line of the log instead of a marker");
    }
    TEST_ARTIFACT("window: %s", window_open ? "tsf-kernel marker" :
                                              "last log line");
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "%s -r | tail -n 1", dmesg));
    te_string_append(&anchor, "%s", te_string_value(&sh.out));
    while (anchor.len > 0 && anchor.ptr[anchor.len - 1] == '\n')
        te_string_cut(&anchor, 1);

    TEST_STEP("Drive the workload");
    t0 = tsapi_mde_now();
    if (workload == KERNEL_WORKLOAD_RING)
    {
        ok_runs = kernel_run_ring(&session, &dut);
        TEST_ARTIFACT("ring demos that exited 0: %u of 3", ok_runs);
    }
    else
    {
        rc = tsapi_mde_web_start(&session, &dut, &web);
        if (rc != 0)
            TEST_VERDICT("The web tier did not start");
        answered = kernel_web_requests(&session, 20);
        tsapi_mde_web_stop(&web);
        TEST_ARTIFACT("web requests answered with 200: %u of 20", answered);
    }
    workload_s = tsapi_mde_now() - t0;
    tsapi_mde_mi_point("kernel/kmsg_window", "Workload duration",
                       TE_MI_MEAS_TIME, "workload_s", workload_s,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Run the known-bad control inside the window");
    if (have_gcc)
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                              KMSG_CTL_DIR "/mde-crashme; echo \"status=$?\""));
    else
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                              "python3 -c 'import ctypes; "
                              "ctypes.string_at(0)'; echo \"status=$?\""));
    TEST_ARTIFACT("control exit: %s", te_string_value(&sh.out));
    if (strstr(te_string_value(&sh.out), "status=139") == NULL)
        TEST_VERDICT("The control program did not die of SIGSEGV");

    TEST_STEP("Close the window and take what the kernel logged");
    CHECK_RC(tsapi_mde_sh(&session, 60000, &sh, "%s -r", dmesg));
    klog = te_string_value(&sh.out);
    start = NULL;
    if (anchor.len == 0)
    {
        start = klog;
    }
    else
    {
        for (p = klog; (p = strstr(p, anchor.ptr)) != NULL; p++)
            start = p;
        if (start != NULL)
        {
            start = strchr(start, '\n');
            start = start != NULL ? start + 1 : "";
        }
        else
        {
            truncated = true;
            start = klog;
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                     "kernel.kmsg-truncated", "window",
                                     "the log wrapped past the start of the "
                                     "window; older lines are counted too");
        }
    }

    for (p = start; *p != '\0'; )
    {
        const char *eol = strchr(p, '\n');
        size_t      len = eol != NULL ? (size_t)(eol - p) : strlen(p);
        te_string   line = TE_STRING_INIT;
        const char *msg;
        int         prio;

        te_string_append_buf(&line, p, len);
        p += len + (eol != NULL ? 1 : 0);
        if (line.len == 0)
        {
            te_string_free(&line);
            continue;
        }

        n_lines++;
        msg = kmsg_skip(line.ptr, &prio);
        if (prio >= 0)
            prio_counts[prio]++;
        te_string_append(&clean, "%s\n", msg);

        for (i = 0; i < TE_ARRAY_LEN(kmsg_fault_marks); i++)
        {
            te_string comm = TE_STRING_INIT;

            if (strstr(msg, kmsg_fault_marks[i]) == NULL)
                continue;
            if (kmsg_fault_comm(msg, &comm))
            {
                n_faults++;
                RING("User-space fault in the window: %s", msg);
                if (kmsg_is_dut(comm.ptr))
                {
                    n_dut_faults++;
                    tapi_cybersec_report_add(&report.cyber,
                                             TAPI_CYBERSEC_SEV_CRITICAL,
                                             "kernel.dut-crash", comm.ptr,
                                             "%s", msg);
                }
                else
                {
                    tapi_cybersec_report_add(&report.cyber,
                                             TAPI_CYBERSEC_SEV_INFO,
                                             "kernel.user-fault", comm.ptr,
                                             "%s", msg);
                }
            }
            te_string_free(&comm);
            break;
        }
        te_string_free(&line);
    }
    RING("Kernel log of the window (%u line(s)):\n%s", n_lines,
         te_string_value(&clean));

    TEST_STEP("Classify the kernel events of the window");
    if (window_open)
    {
        rc = tapi_kmsg_window_close(&window, &events);
        window_open = false;
        if (rc != 0)
        {
            RING("tsf-kernel could not close its window (%r); parsing the "
                 "log taken above instead", rc);
            CHECK_RC(tapi_kmsg_parse(te_string_value(&clean), &events));
        }
        else
        {
            tapi_kmsg_window_check(&window, &kissues);
        }
    }
    else
    {
        CHECK_RC(tapi_kmsg_parse(te_string_value(&clean), &events));
    }
    tapi_kmsg_events_log(&events);
    TE_VEC_FOREACH(&events, ev)
    {
        te_string check = TE_STRING_INIT;

        te_string_append(&check, "kernel.kmsg.%s",
                         tapi_kmsg_kind2str(ev->kind));
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 check.ptr, ev->signature,
                                 "the kernel logged it during the window");
        te_string_free(&check);
    }
    kernel_issues_to_cyber(&kissues, &report, TAPI_CYBERSEC_SEV_MEDIUM);

    TEST_STEP("Chart the window");
    tsapi_mde_mi_bars("kernel/kmsg_window", "Window lines per priority",
                      TE_MI_MEAS_UNITLESS_VALUE, "lines",
                      TE_ARRAY_LEN(kmsg_prio_names), kmsg_prio_names,
                      prio_counts, TE_MI_MEAS_MULTIPLIER_PLAIN);
    {
        static const char *labels[] = {
            "lines", "user_faults", "dut_faults", "kernel_events",
        };
        double vals[TE_ARRAY_LEN(labels)];

        vals[0] = n_lines;
        vals[1] = n_faults;
        vals[2] = n_dut_faults;
        vals[3] = te_vec_size(&events);
        tsapi_mde_mi_bars("kernel/kmsg_window", "What the window holds",
                          TE_MI_MEAS_UNITLESS_VALUE, "count",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    TEST_ARTIFACT("window: %u line(s), %u user fault(s), %u in the example, "
                  "%zu kernel event(s)%s", n_lines, n_faults, n_dut_faults,
                  te_vec_size(&events), truncated ? ", log wrapped" : "");

    TEST_STEP("The control's fault must be in the window");
    tsapi_mde_report_expect(&report, "kernel.user-fault", ctl_comm.ptr);
    tsapi_mde_report_drop_subject(&report, ctl_comm.ptr);

    TEST_STEP("Decide over the window");
    TSAPI_MDE_REPORT_GATE(&report, "kernel", min_sev);

    TEST_SUCCESS;

cleanup:

    if (window_open)
    {
        te_vec rest = TE_VEC_INIT(tapi_kmsg_event);

        (void)tapi_kmsg_window_close(&window, &rest);
        tapi_kmsg_events_free(&rest);
    }
    tsapi_mde_web_stop(&web);
    if (session_up)
    {
        (void)tsapi_mde_sh(&session, 10000, &sh, "rm -rf " KMSG_CTL_DIR);
        tsapi_mde_dut_free(&dut);
    }
    tapi_kmsg_events_free(&events);
    tapi_kernel_issues_free(&kissues);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&anchor);
    te_string_free(&clean);
    te_string_free(&ctl_comm);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

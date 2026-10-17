/** @file
 * @brief Kernel Group
 *
 * Resources the web tier holds before, during and after a burst of
 * requests: resident memory, open descriptors and threads of each
 * service, sampled from /proc of the agent, and the system-wide view of
 * tsf-kernel (open files, TCP sockets, tasks, unreclaimable memory)
 * around it. A service that ends the burst with more descriptors than it
 * started with, beyond a small slack for connection pools, leaks them
 * (kernel.fd-leak); one whose RSS grew by more than the bound of the
 * iteration is kernel.rss-growth; one that died or restarted is
 * kernel.service-died.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "kernel/resources"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_kres.h"
#include "kernel_common.h"

/** Request chunks of the burst; a sample is taken after each. */
#define RES_CHUNKS      5
/** Samples: before, after every chunk, after settling. */
#define RES_SAMPLES     (RES_CHUNKS + 2)
/** Descriptors a service may gain over the burst (pooled connections). */
#define RES_FD_SLACK    8
/** Warm-up requests before the first sample: pools are filled by then. */
#define RES_WARMUP      5

/** The services sampled, in contract order. */
static const char *res_services[TSAPI_MDE_WEB_N] = {
    "gateway-rs", "service-go", "service-cs",
};

/** What one sample of one service read. */
typedef struct res_point {
    unsigned int pid;       /**< 0 when the process was not found. */
    unsigned long rss_kb;   /**< VmRSS, kB. */
    unsigned long fds;      /**< Entries of /proc/PID/fd. */
    unsigned long threads;  /**< Threads. */
} res_point;

/** Take one sample of every service. */
static te_errno
res_sample(tsapi_mde_session *session,
           res_point pts[TSAPI_MDE_WEB_N][RES_SAMPLES], unsigned int s)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const char         *out;
    unsigned int        i;
    te_errno            rc;

    rc = tsapi_mde_sh(session, 30000, &res,
                      "for n in %s %s %s; do p=$(pgrep -n -x \"$n\"); "
                      "if [ -n \"$p\" ]; then "
                      "r=$(awk '/^VmRSS:/{print $2}' /proc/$p/status); "
                      "t=$(awk '/^Threads:/{print $2}' /proc/$p/status); "
                      "f=$(ls /proc/$p/fd | wc -l); "
                      "echo \"$n $p $r $f $t\"; "
                      "else echo \"$n 0 0 0 0\"; fi; done",
                      res_services[0], res_services[1], res_services[2]);
    if (rc != 0)
        goto out;

    out = te_string_value(&res.out);
    RING("Sample %u:\n%s", s, out);
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        const char   *line = strstr(out, res_services[i]);
        unsigned int  pid = 0;
        unsigned long rss = 0;
        unsigned long fds = 0;
        unsigned long thr = 0;

        memset(&pts[i][s], 0, sizeof(pts[i][s]));
        if (line == NULL)
            continue;
        line += strlen(res_services[i]);
        if (sscanf(line, " %u %lu %lu %lu", &pid, &rss, &fds, &thr) == 4)
        {
            pts[i][s].pid = pid;
            pts[i][s].rss_kb = rss;
            pts[i][s].fds = fds;
            pts[i][s].threads = thr;
        }
    }

out:
    tsapi_mde_sh_result_free(&res);
    return rc;
}

/** Log a system-wide value of two snapshots and return its change. */
static double
res_kres_delta(const tapi_kres_snapshot *before,
               const tapi_kres_snapshot *after, const char *name)
{
    intmax_t a = 0;
    intmax_t b = 0;

    if (!tapi_kres_snapshot_get(before, name, &a) ||
        !tapi_kres_snapshot_get(after, name, &b))
    {
        RING("%s is not in the snapshots", name);
        return 0;
    }
    TEST_ARTIFACT("system %s: %jd -> %jd", name, a, b);

    return (double)(b - a);
}

int
main(int argc, char **argv)
{
    static const tapi_kres_rule released_rules[] = {
        { "fs.file-nr.allocated", 512 },
        { "sockstat.TCP.inuse",   32 },
        { "tasks.total",          32 },
        { "meminfo.SUnreclaim",   16384 },
    };
    static const char *kres_names[] = {
        "fs.file-nr.allocated", "sockstat.TCP.inuse", "tasks.total",
        "meminfo.SUnreclaim",
    };
    kernel_workload      workload;
    unsigned int         load;
    unsigned int         rss_growth_mb;
    tsapi_mde_session    session;
    bool                 session_up = false;
    tsapi_mde_dut        dut;
    tsapi_mde_web        web;
    tsapi_mde_report     report;
    tapi_kres_snapshot   kbefore;
    tapi_kres_snapshot   kafter;
    bool                 kbefore_up = false;
    bool                 kafter_up = false;
    tapi_kernel_issues   kissues;
    res_point            pts[TSAPI_MDE_WEB_N][RES_SAMPLES];
    double               rps[RES_CHUNKS];
    double               kdelta[TE_ARRAY_LEN(kres_names)];
    unsigned int         per_chunk;
    unsigned int         answered = 0;
    unsigned int         sent = 0;
    unsigned int         i;
    unsigned int         s;

    TEST_START;
    tsapi_mde_report_init(&report);
    tapi_kernel_issues_init(&kissues);
    memset(&web, 0, sizeof(web));
    memset(&dut, 0, sizeof(dut));
    memset(pts, 0, sizeof(pts));
    memset(rps, 0, sizeof(rps));

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(workload, KERNEL_WORKLOAD_LIST);
    TEST_GET_UINT_PARAM(load);
    TEST_GET_UINT_PARAM(rss_growth_mb);
    if (workload != KERNEL_WORKLOAD_WEB)
        TEST_FAIL("Only the web workload has long-lived processes to sample");
    per_chunk = load / RES_CHUNKS;
    if (per_chunk == 0)
        per_chunk = 1;

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "kres", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built");
    if (!tsapi_mde_have(&session, "curl"))
        TEST_SKIP("curl is not available on the agent");
    if (!tsapi_mde_exists(&session, "/proc/self/status"))
        TEST_SKIP("The agent has no /proc to sample processes from");

    TEST_STEP("Start the web tier and warm its connection pools up");
    if (tsapi_mde_web_start(&session, &dut, &web) != 0)
        TEST_VERDICT("The web tier did not start");
    (void)kernel_web_requests(&session, RES_WARMUP);

    TEST_STEP("Take the system-wide snapshot and the first sample");
    CHECK_RC(tapi_kres_snapshot_take(session.factory,
                                     TAPI_KRES_SRC_FS | TAPI_KRES_SRC_SOCKSTAT |
                                     TAPI_KRES_SRC_MEMINFO, &kbefore));
    kbefore_up = true;
    CHECK_RC(res_sample(&session, pts, 0));
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        if (pts[i][0].pid == 0)
            TEST_VERDICT("A service of the web tier is not running after "
                         "start");
    }

    TEST_STEP("Send the burst in chunks, sampling after each");
    for (s = 0; s < RES_CHUNKS; s++)
    {
        double t0 = tsapi_mde_now();
        double dt;

        answered += kernel_web_requests(&session, per_chunk);
        sent += per_chunk;
        dt = tsapi_mde_now() - t0;
        rps[s] = dt > 0 ? per_chunk / dt : 0;
        CHECK_RC(res_sample(&session, pts, s + 1));
    }
    TEST_ARTIFACT("burst: %u request(s) sent, %u answered with 200",
                  sent, answered);
    if (answered != sent)
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "kernel.web-unanswered", "gateway-rs",
                                 "%u of %u requests were not answered "
                                 "with 200", sent - answered, sent);
    tsapi_mde_mi_series("kernel/resources", "Requests per second per chunk",
                        TE_MI_MEAS_RPS, "rps", RES_CHUNKS, rps,
                        TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Let the tier settle and take the last sample");
    {
        tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;

        (void)tsapi_mde_sh(&session, 10000, &sh, "sleep 2");
        tsapi_mde_sh_result_free(&sh);
    }
    CHECK_RC(res_sample(&session, pts, RES_SAMPLES - 1));
    CHECK_RC(tapi_kres_snapshot_take(session.factory,
                                     TAPI_KRES_SRC_FS | TAPI_KRES_SRC_SOCKSTAT |
                                     TAPI_KRES_SRC_MEMINFO, &kafter));
    kafter_up = true;

    TEST_STEP("Chart every service over the samples");
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        te_mi_logger *lg;
        te_string     title = TE_STRING_INIT;

        if (tsapi_mde_mi_create(res_services[i], &lg) != 0)
            continue;
        for (s = 0; s < RES_SAMPLES; s++)
        {
            te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "sample", TE_MI_MEAS_AGGR_SINGLE, s,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_MEMORY, "rss",
                                  TE_MI_MEAS_AGGR_SINGLE, pts[i][s].rss_kb,
                                  TE_MI_MEAS_MULTIPLIER_KIBI);
            te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_UNITLESS_VALUE, "fds",
                                  TE_MI_MEAS_AGGR_SINGLE, pts[i][s].fds,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "threads", TE_MI_MEAS_AGGR_SINGLE,
                                  pts[i][s].threads,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        te_mi_logger_add_meas_key(lg, NULL, "service", "%s", res_services[i]);
        te_mi_logger_add_meas_key(lg, NULL, "load", "%u", load);
        te_mi_logger_add_meas_key(lg, NULL, "samples", "%s",
                                  "0=before 1..5=after each chunk "
                                  "6=after settling");
        te_string_append(&title, "%s: RSS over the burst of %u",
                         res_services[i], load);
        tsapi_mde_mi_line(lg, "rss", title.ptr, "sample", "rss", NULL);
        te_string_reset(&title);
        te_string_append(&title, "%s: descriptors and threads over the "
                         "burst of %u", res_services[i], load);
        tsapi_mde_mi_line(lg, "fds", title.ptr, "sample", "fds", "threads",
                          NULL);
        te_mi_logger_destroy(lg);
        te_string_free(&title);
    }

    TEST_STEP("Check every service: alive, no descriptor leak, bounded RSS");
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        const res_point *first = &pts[i][0];
        const res_point *last = &pts[i][RES_SAMPLES - 1];
        unsigned long    peak = 0;
        bool             died = false;

        for (s = 0; s < RES_SAMPLES; s++)
        {
            if (pts[i][s].pid == 0 || pts[i][s].pid != first->pid)
                died = true;
            if (pts[i][s].rss_kb > peak)
                peak = pts[i][s].rss_kb;
        }
        TEST_ARTIFACT("%s: rss %lu -> %lu kB (peak %lu), fds %lu -> %lu, "
                      "threads %lu -> %lu", res_services[i], first->rss_kb,
                      last->rss_kb, peak, first->fds, last->fds,
                      first->threads, last->threads);

        if (died)
        {
            tapi_cybersec_report_add(&report.cyber,
                                     TAPI_CYBERSEC_SEV_CRITICAL,
                                     "kernel.service-died", res_services[i],
                                     "the process disappeared or was "
                                     "replaced during the burst");
            continue;
        }
        if (last->fds > first->fds + RES_FD_SLACK)
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "kernel.fd-leak", res_services[i],
                                     "%lu descriptors before the burst of "
                                     "%u, %lu after settling (slack %u)",
                                     first->fds, load, last->fds,
                                     RES_FD_SLACK);
        if (last->rss_kb > first->rss_kb + rss_growth_mb * 1024UL)
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "kernel.rss-growth", res_services[i],
                                     "RSS grew from %lu to %lu kB over a "
                                     "burst of %u (bound %u MB)",
                                     first->rss_kb, last->rss_kb, load,
                                     rss_growth_mb);
    }

    TEST_STEP("Compare the system-wide view around the burst");
    for (i = 0; i < TE_ARRAY_LEN(kres_names); i++)
        kdelta[i] = res_kres_delta(&kbefore, &kafter, kres_names[i]);
    tsapi_mde_mi_bars("kernel/resources", "System-wide change over the burst",
                      TE_MI_MEAS_UNITLESS_VALUE, "delta",
                      TE_ARRAY_LEN(kres_names), kres_names, kdelta,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    CHECK_RC(tapi_kres_check_released(&kbefore, &kafter, released_rules,
                                      TE_ARRAY_LEN(released_rules),
                                      &kissues));
    CHECK_RC(tapi_kres_check_headroom(&kafter, &kissues));
    /* The host kernel is shared with everything else: context, not DUT. */
    kernel_issues_to_cyber(&kissues, &report, TAPI_CYBERSEC_SEV_INFO);

    TEST_STEP("Decide over the resources");
    TSAPI_MDE_REPORT_GATE(&report, "kernel", TAPI_CYBERSEC_SEV_MEDIUM);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_web_stop(&web);
    if (kbefore_up)
        tapi_kres_snapshot_free(&kbefore);
    if (kafter_up)
        tapi_kres_snapshot_free(&kafter);
    tapi_kernel_issues_free(&kissues);
    tsapi_mde_report_free(&report);
    if (session_up)
    {
        tsapi_mde_dut_free(&dut);
        tsapi_mde_session_fini(&session);
    }

    TEST_END;
}

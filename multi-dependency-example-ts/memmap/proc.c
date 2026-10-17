/** @file
 * @brief Memory Map Group
 *
 * The live memory map of one service of the web tier: the tier is started,
 * one walk is sent through it so that every runtime has done its start-up
 * work (the Go scheduler, the NativeAOT GC heap, the Rust allocator), and
 * the mappings of the service are read by tsf-memorymap from /proc. They
 * are charted by what backs them (file, heap, stack, anonymous, vDSO), the
 * resident total is cross-checked with VmRSS and the mapping count with
 * /proc/PID/maps, the main binary must be mapped executable, and the map
 * is audited for writable+executable mappings. The audit gets a known-bad
 * control: a python3 process that maps an RWX page on purpose.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "memmap/proc"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_job.h"
#include "tapi_memmap.h"
#include "tapi_memmap_proc.h"
#include "tapi_memmap_audit.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"
#include "memmap_common.h"

/** Number of backing kinds, TAPI_MEMMAP_BACK_FILE..ANON. */
#define PROC_N_KINDS    5

/** The control's own marker, found by pgrep -f with a [t] trick. */
#define PROC_CTL_MARK   "mde-memmap-rwx-ctl"
/** The pattern that finds it but not the shell that looks for it. */
#define PROC_CTL_RE     "mde-memmap-rwx-c[t]l"

/** Get the PID of the newest process named @p name, or 0. */
static unsigned int
proc_pid_of(tsapi_mde_session *session, const char *how, const char *name)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    unsigned int        pid = 0;

    if (tsapi_mde_sh(session, 20000, &res,
                     "i=0; while [ $i -lt 20 ]; do "
                     "p=$(pgrep -n %s '%s') && { echo \"$p\"; exit 0; }; "
                     "sleep 0.25; i=$((i+1)); done; exit 1",
                     how, name) == 0 && tsapi_mde_sh_ok(&res))
        pid = (unsigned int)strtoul(te_string_value(&res.out), NULL, 10);
    tsapi_mde_sh_result_free(&res);

    return pid;
}

int
main(int argc, char **argv)
{
    const char            *service;
    tapi_cybersec_severity min_sev;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_web          web;
    tsapi_mde_report       report;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    te_vec                 maps = TE_VEC_INIT(tapi_memmap_mapping);
    te_vec                 ctl_maps = TE_VEC_INIT(tapi_memmap_mapping);
    te_string              url = TE_STRING_INIT;
    tapi_job_t            *ctl_job = NULL;
    const tapi_memmap_mapping *m;
    const char            *kind_labels[PROC_N_KINDS];
    double                 kind_bytes[PROC_N_KINDS];
    double                 kind_count[PROC_N_KINDS];
    double                 kind_rss[PROC_N_KINDS];
    uint64_t               total = 0;
    uint64_t               resident = 0;
    unsigned long          vmrss_kb = 0;
    unsigned long          n_maps_file = 0;
    unsigned int           pid;
    unsigned int           ctl_pid;
    unsigned int           n_rwx = 0;
    unsigned int           n_exec = 0;
    bool                   main_mapped = false;
    unsigned int           i;

    TEST_START;
    tsapi_mde_report_init(&report);
    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));
    memset(kind_bytes, 0, sizeof(kind_bytes));
    memset(kind_count, 0, sizeof(kind_count));
    memset(kind_rss, 0, sizeof(kind_rss));

    TEST_STEP("Parse test parameters");
    TEST_GET_STRING_PARAM(service);
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "mmproc", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built");
    if (!tsapi_mde_exists(&session, "/proc/self/maps"))
        TEST_SKIP("The agent has no /proc to read mappings from");

    TEST_STEP("Start the web tier and send one walk through it");
    if (tsapi_mde_web_start(&session, &dut, &web) != 0)
        TEST_VERDICT("The web tier did not start");
    tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1, 7, &url);
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "curl -s -o /dev/null -m 10 -w '%%{http_code}' '%s'",
                          url.ptr));
    TEST_ARTIFACT("walk through the tier: HTTP %s", te_string_value(&sh.out));

    TEST_STEP("Find the service and read its mappings");
    pid = proc_pid_of(&session, "-x", service);
    if (pid == 0)
        TEST_VERDICT("The service is not running after start");
    CHECK_RC(tapi_memmap_proc_read(session.pco, (pid_t)pid,
                                   TAPI_MEMMAP_TIMEOUT_MS, &maps));
    tapi_memmap_mappings_log(&maps);
    if (te_vec_size(&maps) == 0)
        TEST_VERDICT("The service has no mappings");

    TEST_STEP("Sort the mappings by what backs them");
    for (i = 0; i < PROC_N_KINDS; i++)
        kind_labels[i] = tapi_memmap_backing2str((tapi_memmap_backing)i);
    TE_VEC_FOREACH(&maps, m)
    {
        unsigned int k = (unsigned int)m->backing;
        bool         w = (m->perms & TAPI_MEMMAP_W) != 0;
        bool         x = (m->perms & TAPI_MEMMAP_X) != 0;

        if (k < PROC_N_KINDS)
        {
            kind_bytes[k] += (double)(m->end - m->start);
            kind_count[k]++;
            if (m->rss >= 0)
                kind_rss[k] += (double)m->rss;
        }
        if (x)
            n_exec++;
        if (w && x)
            n_rwx++;
        if (x && m->backing == TAPI_MEMMAP_BACK_FILE && m->path != NULL)
        {
            const char *base = strrchr(m->path, '/');

            if (base != NULL && strcmp(base + 1, service) == 0)
                main_mapped = true;
        }
    }
    tapi_memmap_proc_totals(&maps, &total, &resident);
    TEST_ARTIFACT("%s: %zu mapping(s), %" PRIu64 " bytes mapped, %" PRIu64
                  " resident, %u executable, %u writable+executable",
                  service, te_vec_size(&maps), total, resident, n_exec,
                  n_rwx);
    for (i = 0; i < PROC_N_KINDS; i++)
        TEST_ARTIFACT("%s %s: %.0f mapping(s), %.0f bytes, %.0f resident",
                      service, kind_labels[i], kind_count[i], kind_bytes[i],
                      kind_rss[i]);

    TEST_STEP("Chart the mappings by kind");
    tsapi_mde_mi_bars("memmap/proc", "Mapped bytes per kind",
                      TE_MI_MEAS_MEMORY, "mapped", PROC_N_KINDS,
                      kind_labels, kind_bytes, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("memmap/proc", "Resident bytes per kind",
                      TE_MI_MEAS_MEMORY, "resident", PROC_N_KINDS,
                      kind_labels, kind_rss, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("memmap/proc", "Mappings per kind",
                      TE_MI_MEAS_UNITLESS_VALUE, "mappings", PROC_N_KINDS,
                      kind_labels, kind_count, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("memmap/proc", "Writable and executable mappings",
                       TE_MI_MEAS_UNITLESS_VALUE, "rwx_mappings", n_rwx,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Two views: resident total against VmRSS, count against maps");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh,
                          "awk '/^VmRSS:/{print $2}' /proc/%u/status; "
                          "wc -l < /proc/%u/maps", pid, pid));
    if (sscanf(te_string_value(&sh.out), "%lu %lu", &vmrss_kb,
               &n_maps_file) != 2)
        TEST_VERDICT("VmRSS and the maps line count cannot be read");
    TEST_ARTIFACT("%s: smaps resident %" PRIu64 " kB, VmRSS %lu kB; %zu "
                  "mapping(s) parsed, %lu line(s) in maps", service,
                  resident / 1024, vmrss_kb, te_vec_size(&maps), n_maps_file);
    {
        double a = (double)resident / 1024.0;
        double b = (double)vmrss_kb;
        double c = (double)te_vec_size(&maps);
        double d = (double)n_maps_file;

        /* Read a moment apart from a live process: 20% or 8 MB. */
        if (resident > 0 &&
            (a > b ? a - b : b - a) > (b * 0.2 > 8192 ? b * 0.2 : 8192))
            TEST_VERDICT("The resident total of the mappings and VmRSS "
                         "disagree");
        if ((c > d ? c - d : d - c) > d * 0.1 + 4)
            TEST_VERDICT("The parsed mappings and /proc/PID/maps disagree "
                         "on the count");
    }
    if (!main_mapped)
        TEST_VERDICT("The service's own binary is not mapped executable");

    TEST_STEP("W^X audit of the live process");
    CHECK_RC(tapi_memmap_audit_proc(&maps, service, &report.cyber));

    TEST_STEP("Known-bad control: a process with an RWX mapping");
    if (tsapi_mde_have(&session, "python3"))
    {
        const char *argv_ctl[] = {
            "python3", "-c",
            "import mmap, time  # " PROC_CTL_MARK "\n"
            "m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE"
            " | mmap.PROT_EXEC)\n"
            "time.sleep(60)\n",
            NULL,
        };

        CHECK_RC(tapi_job_create(session.factory, NULL, "python3", argv_ctl,
                                 NULL, &ctl_job));
        CHECK_RC(tapi_job_start(ctl_job));
        ctl_pid = proc_pid_of(&session, "-f", PROC_CTL_RE);
        if (ctl_pid == 0)
            TEST_VERDICT("The control process could not be found");
        /* Let it map the page before reading. */
        CHECK_RC(tsapi_mde_sh(&session, 10000, &sh, "sleep 1"));
        CHECK_RC(tapi_memmap_proc_read(session.pco, (pid_t)ctl_pid,
                                       TAPI_MEMMAP_TIMEOUT_MS, &ctl_maps));
        CHECK_RC(tapi_memmap_audit_proc(&ctl_maps, "control",
                                        &report.cyber));
        tsapi_mde_report_expect(&report, "memmap.wx-mapping", "control");
        tsapi_mde_report_drop_subject(&report, "control");
    }
    else
    {
        WARN("python3 is not on the agent: the live W^X audit runs without "
             "its control");
    }

    TEST_STEP("Decide over the live W^X findings");
    TSAPI_MDE_REPORT_GATE(&report, "memmap", min_sev);

    TEST_SUCCESS;

cleanup:

    if (ctl_job != NULL)
        tapi_job_destroy(ctl_job, -1);
    tsapi_mde_web_stop(&web);
    if (session_up)
        tsapi_mde_dut_free(&dut);
    tapi_memmap_mappings_free(&maps);
    tapi_memmap_mappings_free(&ctl_maps);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&url);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

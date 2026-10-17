/** @file
 * @brief Filesystem Group
 *
 * Health of the filesystems under the example: space and inode usage of
 * every mount that holds files (charted as percentages, the one holding
 * the example cross-checked with df), filesystem error counters, and
 * deleted files held open - taken while the web tier runs, so that a
 * service of the example keeping a deleted file alive shows. The space
 * check gets a known-bad control: at a 0% threshold every filesystem in
 * use must be reported.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "fs/health"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_fs.h"
#include "tapi_fs_health.h"
#include "fs_common.h"

/** Most mounts charted. */
#define HEALTH_MAX_MOUNTS   16
/** Smallest deleted-but-open file worth reporting, bytes. */
#define HEALTH_DELETED_MIN  (1024 * 1024)

int
main(int argc, char **argv)
{
    unsigned int         threshold;
    tsapi_mde_session    session;
    bool                 session_up = false;
    tsapi_mde_dut        dut;
    tsapi_mde_web        web;
    tsapi_mde_report     report;
    tapi_kernel_issues   issues;
    tsapi_mde_sh_result  sh = TSAPI_MDE_SH_RESULT_INIT;
    te_vec               mounts = TE_VEC_INIT(tapi_fs_mount);
    te_vec               deleted = TE_VEC_INIT(tapi_fs_deleted);
    tapi_fs_usage        usage;
    const tapi_fs_mount *m;
    const tapi_fs_deleted *d;
    const char          *labels[HEALTH_MAX_MOUNTS];
    double               space_pct[HEALTH_MAX_MOUNTS];
    double               inode_pct[HEALTH_MAX_MOUNTS];
    unsigned int         n = 0;
    unsigned long long   df_kb = 0;
    unsigned int         n_space;
    unsigned int         n_errors;
    unsigned int         n_deleted;
    bool                 web_up = false;
    unsigned int         i;

    TEST_START;
    tsapi_mde_report_init(&report);
    tapi_kernel_issues_init(&issues);
    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));

    TEST_STEP("Parse test parameters");
    TEST_GET_UINT_PARAM(threshold);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "fshealth", dut, session_up);
    CHECK_RC(tapi_fs_mounts(session.factory, &mounts));

    TEST_STEP("Known-bad control: at 0%% every filesystem in use is full");
    CHECK_RC(tapi_fs_space_check(session.factory, &mounts, 0, &issues));
    (void)fs_issues_to_report(&issues, &report);
    tsapi_mde_report_expect(&report, "fs.space", NULL);
    /* Only the control's findings are in the list so far. */
    tapi_cybersec_report_free(&report.cyber);
    tapi_cybersec_report_init(&report.cyber);

    TEST_STEP("Usage of the filesystem holding the example, two views");
    CHECK_RC(tapi_fs_usage_get(session.factory, dut.root, &usage));
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh,
                          "df -Pk '%s' | tail -n 1 | awk '{print $2}'",
                          dut.root));
    df_kb = strtoull(te_string_value(&sh.out), NULL, 10);
    TEST_ARTIFACT("example filesystem: %" PRIu64 " bytes total, %" PRIu64
                  " available, %" PRIu64 " inodes (%" PRIu64 " free); "
                  "df: %llu kB", usage.total, usage.avail, usage.inodes,
                  usage.inodes_free, df_kb);
    {
        double a = (double)usage.total / 1024.0;
        double b = (double)df_kb;

        if (b <= 0 || (a > b ? a - b : b - a) > b / 100 + 4)
            TEST_VERDICT("tsf-fs and df disagree on the size of the "
                         "example's filesystem");
    }

    TEST_STEP("Usage of every mount that holds files");
    TE_VEC_FOREACH(&mounts, m)
    {
        tapi_fs_usage u;

        if (n >= HEALTH_MAX_MOUNTS || tapi_fs_type_is_virtual(m->fstype) ||
            tapi_fs_mount_of(&mounts, m->mountpoint) != m)
            continue;
        if (tapi_fs_usage_get(session.factory, m->mountpoint, &u) != 0 ||
            u.total == 0)
            continue;
        labels[n] = m->mountpoint;
        space_pct[n] = 100.0 * (double)(u.total - u.avail) / (double)u.total;
        inode_pct[n] = u.inodes > 0 ?
            100.0 * (double)(u.inodes - u.inodes_free) / (double)u.inodes : 0;
        TEST_ARTIFACT("%s (%s): %.1f%% space, %.1f%% inodes used",
                      m->mountpoint, m->fstype, space_pct[n], inode_pct[n]);
        n++;
    }
    tsapi_mde_mi_bars("fs/health", "Space used per mount, %",
                      TE_MI_MEAS_PERCENTAGE, "space_used", n, labels,
                      space_pct, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("fs/health", "Inodes used per mount, %",
                      TE_MI_MEAS_PERCENTAGE, "inodes_used", n, labels,
                      inode_pct, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Report filesystems above the threshold, and errors");
    CHECK_RC(tapi_fs_space_check(session.factory, &mounts, threshold,
                                 &issues));
    n_space = fs_issues_to_report(&issues, &report);
    CHECK_RC(tapi_fs_errors_check(session.factory, &issues));
    n_errors = fs_issues_to_report(&issues, &report);

    TEST_STEP("Deleted files held open, with the web tier running");
    if (tsapi_mde_web_built(&session, &dut))
    {
        if (tsapi_mde_web_start(&session, &dut, &web) != 0)
            TEST_VERDICT("The web tier did not start");
        web_up = true;
        (void)fs_web_requests(&session, 5);
    }
    else
    {
        RING("The web tier is not built: deleted files are listed without "
             "it");
    }
    CHECK_RC(tapi_fs_deleted_open(session.factory, &deleted));
    TE_VEC_FOREACH(&deleted, d)
    {
        for (i = 0; i < tsapi_mde_dut_n_bins; i++)
        {
            if (strcmp(d->comm, tsapi_mde_dut_bins[i]) == 0)
                RING("%s holds deleted %s (%" PRIu64 " bytes)", d->comm,
                     d->path, d->size);
        }
    }
    CHECK_RC(tapi_fs_deleted_open_check(&deleted, HEALTH_DELETED_MIN,
                                        &issues));
    n_deleted = fs_issues_to_report(&issues, &report);
    if (web_up)
    {
        tsapi_mde_web_stop(&web);
        web_up = false;
    }
    TEST_ARTIFACT("findings: %u above %u%%, %u with errors, %u deleted file(s) "
                  "held open of %zu listed", n_space, threshold, n_errors,
                  n_deleted, te_vec_size(&deleted));
    {
        static const char *flabels[] = {
            "space_or_inodes", "fs_errors", "deleted_open", "deleted_listed",
        };
        double vals[TE_ARRAY_LEN(flabels)];

        vals[0] = n_space;
        vals[1] = n_errors;
        vals[2] = n_deleted;
        vals[3] = te_vec_size(&deleted);
        tsapi_mde_mi_bars("fs/health", "Health findings per check",
                          TE_MI_MEAS_UNITLESS_VALUE, "count",
                          TE_ARRAY_LEN(flabels), flabels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide over the health findings");
    TSAPI_MDE_REPORT_GATE(&report, "fs", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_web_stop(&web);
    if (session_up)
        tsapi_mde_dut_free(&dut);
    tapi_fs_mounts_free(&mounts);
    tapi_fs_deleted_free(&deleted);
    tapi_kernel_issues_free(&issues);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

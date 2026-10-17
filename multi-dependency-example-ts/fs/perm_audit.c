/** @file
 * @brief Filesystem Group
 *
 * Permission audit of the example on disk: the built tree (dist/) and the
 * source tree around it are walked with tsf-fs and checked for setuid and
 * setgid programs, files anyone can write, shared directories without the
 * sticky bit, device nodes and file capabilities. Next to it, a known-bad
 * control: a directory planted on the agent with a world-writable file, a
 * directory anyone can write and a setuid copy of /bin/true, which the
 * same audit must flag. Two views of one fact are compared: the mode of
 * cpp-demo as the walk read it and as stat prints it.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "fs/perm_audit"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_fs.h"
#include "tapi_fs_perm.h"
#include "fs_common.h"

/** The control directory on the agent. */
#define PERM_CTL        "/tmp/mde-fs-perm-ctl"
#define PERM_CTL_WW     PERM_CTL "/world-writable.txt"
#define PERM_CTL_DIR    PERM_CTL "/open-dir"
#define PERM_CTL_SUID   PERM_CTL "/suid-true"

/** Walk some roots and check them; return the walk time. */
static double
perm_walk_check(tsapi_mde_session *session, const char **roots,
                size_t n_roots, const char **prune, size_t n_prune,
                te_vec *entries, tapi_kernel_issues *issues)
{
    tapi_fs_walk_opt wopt = tapi_fs_walk_default_opt;
    double           t0 = tsapi_mde_now();
    te_errno         rc;

    wopt.roots = roots;
    wopt.n_roots = n_roots;
    wopt.prune = prune;
    wopt.n_prune = n_prune;
    wopt.cross_mounts = true;

    rc = tapi_fs_walk(session->factory, &wopt, entries);
    if (rc != 0)
        TEST_FAIL("Walking %s failed: %r", roots[0], rc);
    rc = tapi_fs_perm_check(entries, NULL, issues);
    if (rc != 0)
        TEST_FAIL("Checking the permissions of %s failed: %r", roots[0], rc);

    return tsapi_mde_now() - t0;
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity min_sev;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    tapi_kernel_issues     issues;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    te_vec                 dist_entries = TE_VEC_INIT(tapi_fs_entry);
    te_vec                 src_entries = TE_VEC_INIT(tapi_fs_entry);
    te_vec                 ctl_entries = TE_VEC_INIT(tapi_fs_entry);
    te_vec                 caps = TE_VEC_INIT(tapi_fs_filecap);
    te_string              dist = TE_STRING_INIT;
    te_string              prune_dist = TE_STRING_INIT;
    te_string              demo = TE_STRING_INIT;
    const char            *dist_roots[1];
    const char            *src_roots[1];
    const char            *ctl_roots[] = { PERM_CTL };
    const char            *src_prune[6];
    const tapi_fs_entry   *e;
    double                 walk_s[3];
    double                 types[4] = { 0, 0, 0, 0 };
    bool                   have_caps = false;
    bool                   suid_planted = false;
    unsigned int           n_dist;
    unsigned int           n_src;
    unsigned int           i;

    TEST_START;
    tsapi_mde_report_init(&report);
    tapi_kernel_issues_init(&issues);
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "fsperm", dut, session_up);
    te_string_append(&dist, "%s/dist", dut.root);
    te_string_append(&prune_dist, "%s/dist", dut.root);
    dist_roots[0] = dist.ptr;
    src_roots[0] = dut.root;
    src_prune[0] = prune_dist.ptr;
    src_prune[1] = "*/.git";
    src_prune[2] = "*/target";
    src_prune[3] = "*/obj";
    src_prune[4] = "*/node_modules";
    src_prune[5] = "*/__pycache__";

    TEST_STEP("Audit the built tree");
    walk_s[0] = perm_walk_check(&session, dist_roots, 1, NULL, 0,
                                &dist_entries, &issues);
    n_dist = fs_issues_to_report(&issues, &report);
    TEST_ARTIFACT("dist: %zu entries walked in %.2f s, %u finding(s)",
                  te_vec_size(&dist_entries), walk_s[0], n_dist);

    TEST_STEP("Audit the source tree around it");
    walk_s[1] = perm_walk_check(&session, src_roots, 1, src_prune,
                                TE_ARRAY_LEN(src_prune), &src_entries,
                                &issues);
    n_src = fs_issues_to_report(&issues, &report);
    TEST_ARTIFACT("source: %zu entries walked in %.2f s, %u finding(s)",
                  te_vec_size(&src_entries), walk_s[1], n_src);

    TEST_STEP("List file capabilities of the built programs");
    CHECK_RC(tapi_fs_filecaps(session.factory, dist_roots, 1, &caps,
                              &have_caps));
    if (have_caps)
    {
        CHECK_RC(tapi_fs_filecaps_check(&caps, NULL, 0, &issues));
        (void)fs_issues_to_report(&issues, &report);
        TEST_ARTIFACT("dist: %zu program(s) with file capabilities",
                      te_vec_size(&caps));
    }
    else
    {
        RING("getcap is not on the agent: file capabilities not listed");
    }

    TEST_STEP("Two views: the mode of cpp-demo by the walk and by stat");
    te_string_append(&demo, "%s/cpp-demo", dut.bin);
    e = tapi_fs_entries_find(&dist_entries, demo.ptr);
    if (e == NULL)
        TEST_VERDICT("The walk of dist did not find cpp-demo");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh, "stat -L -c %%a '%s'",
                          demo.ptr));
    if (strtoul(te_string_value(&sh.out), NULL, 8) !=
        (unsigned long)TAPI_FS_PERM(e->mode))
    {
        ERROR("walk: %04o, stat: %s", TAPI_FS_PERM(e->mode),
              te_string_value(&sh.out));
        TEST_VERDICT("The walk and stat disagree on the mode of cpp-demo");
    }
    TEST_ARTIFACT("cpp-demo mode: %04o (walk) = %s (stat)",
                  TAPI_FS_PERM(e->mode), te_string_value(&sh.out));

    TEST_STEP("Every built binary must be there and executable");
    for (i = 0; i < tsapi_mde_dut_n_bins; i++)
    {
        te_string path = TE_STRING_INIT;

        te_string_append(&path, "%s/%s", dut.bin, tsapi_mde_dut_bins[i]);
        e = tapi_fs_entries_find(&dist_entries, path.ptr);
        if (e != NULL && (TAPI_FS_PERM(e->mode) & 0111) == 0)
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "fs.not-executable", path.ptr,
                                     "a built program without execute bits");
        else if (e == NULL)
            RING("%s is not in the built tree", path.ptr);
        te_string_free(&path);
    }

    TEST_STEP("Chart the trees");
    TE_VEC_FOREACH(&dist_entries, e)
    {
        switch (TAPI_FS_TYPE(e->mode))
        {
            case TAPI_FS_TYPE_REG: types[0]++; break;
            case TAPI_FS_TYPE_DIR: types[1]++; break;
            case TAPI_FS_TYPE_LNK: types[2]++; break;
            default:               types[3]++; break;
        }
    }
    {
        static const char *labels[] = { "files", "dirs", "links", "other" };

        tsapi_mde_mi_bars("fs/perm_audit", "dist entries per type",
                          TE_MI_MEAS_UNITLESS_VALUE, "entries",
                          TE_ARRAY_LEN(labels), labels, types,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    fs_chart_by_dir(&report, dut.root, "fs/perm_audit",
                    "Permission findings per directory of the example");

    TEST_STEP("Plant the known-bad control");
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh,
                          "rm -rf " PERM_CTL " && mkdir -p " PERM_CTL_DIR
                          " && echo planted > " PERM_CTL_WW
                          " && chmod 0666 " PERM_CTL_WW
                          " && chmod 0777 " PERM_CTL_DIR
                          " && cp /bin/true " PERM_CTL_SUID
                          " && chmod 4755 " PERM_CTL_SUID
                          "; stat -c %%a " PERM_CTL_SUID));
    suid_planted = strncmp(te_string_value(&sh.out), "4755", 4) == 0;
    TEST_ARTIFACT("control planted: world-writable file, open directory%s",
                  suid_planted ? ", setuid program" :
                                 " (setuid not allowed here)");

    TEST_STEP("Audit the control with the same audit");
    walk_s[2] = perm_walk_check(&session, ctl_roots, 1, NULL, 0,
                                &ctl_entries, &issues);
    (void)fs_issues_to_report(&issues, &report);
    tsapi_mde_report_expect(&report, "fs.world-writable", PERM_CTL_WW);
    tsapi_mde_report_expect(&report, "fs.no-sticky", PERM_CTL_DIR);
    if (suid_planted)
        tsapi_mde_report_expect(&report, "fs.setuid", PERM_CTL_SUID);
    tsapi_mde_report_drop_subject(&report, PERM_CTL_WW);
    tsapi_mde_report_drop_subject(&report, PERM_CTL_DIR);
    tsapi_mde_report_drop_subject(&report, PERM_CTL_SUID);

    {
        static const char *labels[] = { "dist", "source", "control" };

        tsapi_mde_mi_bars("fs/perm_audit", "Walk time per tree",
                          TE_MI_MEAS_TIME, "walk_s", TE_ARRAY_LEN(labels),
                          labels, walk_s, TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide over the permission findings");
    TSAPI_MDE_REPORT_GATE(&report, "fs", min_sev);

    TEST_SUCCESS;

cleanup:

    if (session_up)
    {
        (void)tsapi_mde_sh(&session, 20000, &sh, "rm -rf " PERM_CTL);
        tsapi_mde_dut_free(&dut);
    }
    tapi_fs_entries_free(&dist_entries);
    tapi_fs_entries_free(&src_entries);
    tapi_fs_entries_free(&ctl_entries);
    tapi_fs_filecaps_free(&caps);
    tapi_kernel_issues_free(&issues);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&dist);
    te_string_free(&prune_dist);
    te_string_free(&demo);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

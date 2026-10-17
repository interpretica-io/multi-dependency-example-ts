/** @file
 * @brief Filesystem Group
 *
 * How the filesystem under the example is mounted: the mount the example
 * tree is on (found by tsf-fs, cross-checked with df), its options charted
 * as flags (it must not be noexec - the example runs from there), the
 * mount options the usual mount points must have (nosuid, nodev, noexec
 * on /tmp, /dev/shm, /proc, ...), whether the kernel enforces noexec and
 * read-only where they are claimed, and the link and dump protections.
 * The mount rules get a known-bad control: a synthetic mount table with a
 * removable-media mount that has none of the options must be reported.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "fs/mounts"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_fs.h"
#include "tapi_fs_mount.h"
#include "fs_common.h"

/** The synthetic mount of the control. */
#define MNT_CTL         "/media/mde-ctl"
/** Its line of /proc/self/mountinfo: no nosuid, nodev or noexec. */
#define MNT_CTL_LINE \
    "900 1 0:99 / " MNT_CTL " rw,relatime shared:1 - vfat /dev/sdz1 rw\n"

int
main(int argc, char **argv)
{
    static const char *flags[] = { "rw", "nosuid", "nodev", "noexec" };
    tapi_cybersec_severity min_sev;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    tapi_kernel_issues     issues;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    te_vec                 mounts = TE_VEC_INIT(tapi_fs_mount);
    te_vec                 ctl_mounts = TE_VEC_INIT(tapi_fs_mount);
    te_string              df_mp = TE_STRING_INIT;
    const tapi_fs_mount   *dm;
    const tapi_fs_mount   *m;
    double                 flag_vals[TE_ARRAY_LEN(flags)];
    double                 opt_counts[TE_ARRAY_LEN(flags)];
    double                 kinds[2] = { 0, 0 };
    unsigned int           n_rules;
    unsigned int           n_probe;
    unsigned int           n_posture;
    unsigned int           i;

    TEST_START;
    tsapi_mde_report_init(&report);
    tapi_kernel_issues_init(&issues);
    memset(&dut, 0, sizeof(dut));
    memset(opt_counts, 0, sizeof(opt_counts));

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "fsmount", dut, session_up);

    TEST_STEP("Read the mount table");
    CHECK_RC(tapi_fs_mounts(session.factory, &mounts));
    TE_VEC_FOREACH(&mounts, m)
    {
        kinds[tapi_fs_type_is_virtual(m->fstype) ? 1 : 0]++;
        for (i = 0; i < TE_ARRAY_LEN(flags); i++)
        {
            if (tapi_fs_mount_has(m, flags[i]))
                opt_counts[i]++;
        }
    }
    TEST_ARTIFACT("mounts: %zu (%.0f holding files, %.0f virtual)",
                  te_vec_size(&mounts), kinds[0], kinds[1]);
    {
        static const char *labels[] = { "holding_files", "virtual" };

        tsapi_mde_mi_bars("fs/mounts", "Mounts by kind",
                          TE_MI_MEAS_UNITLESS_VALUE, "mounts",
                          TE_ARRAY_LEN(labels), labels, kinds,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    tsapi_mde_mi_bars("fs/mounts", "Mounts carrying each option",
                      TE_MI_MEAS_UNITLESS_VALUE, "mounts",
                      TE_ARRAY_LEN(flags), flags, opt_counts,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Find the mount of the example and cross-check it with df");
    dm = tapi_fs_mount_of(&mounts, dut.root);
    if (dm == NULL)
        TEST_VERDICT("No mount holds the example tree");
    TEST_ARTIFACT("example tree on %s (%s from %s), options %s / %s",
                  dm->mountpoint, dm->fstype, dm->source, dm->options,
                  dm->super_options);
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh,
                          "df -P '%s' | tail -n 1 | awk '{print $NF}'",
                          dut.root));
    te_string_append(&df_mp, "%s", te_string_value(&sh.out));
    while (df_mp.len > 0 && df_mp.ptr[df_mp.len - 1] == '\n')
        te_string_cut(&df_mp, 1);
    TEST_ARTIFACT("mount point by df: %s", te_string_value(&df_mp));
    if (strcmp(te_string_value(&df_mp), dm->mountpoint) != 0)
        TEST_VERDICT("tsf-fs and df disagree on the mount of the example");

    for (i = 0; i < TE_ARRAY_LEN(flags); i++)
        flag_vals[i] = tapi_fs_mount_has(dm, flags[i]) ? 1 : 0;
    tsapi_mde_mi_bars("fs/mounts", "Options of the example's mount (1 = set)",
                      TE_MI_MEAS_UNITLESS_VALUE, "set", TE_ARRAY_LEN(flags),
                      flags, flag_vals, TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (tapi_fs_mount_has(dm, "noexec"))
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "fs.dut-noexec", dm->mountpoint,
                                 "the example runs from a noexec mount");
    if (!tapi_fs_mount_has(dm, "nosuid"))
        RING("The example's mount allows setuid programs (no nosuid): "
             "expected for a build tree, noted");

    TEST_STEP("Check the mount options of the usual mount points");
    CHECK_RC(tapi_fs_mount_check(&mounts, NULL, 0, &issues));
    n_rules = fs_issues_to_report(&issues, &report);

    TEST_STEP("Probe that noexec and read-only are enforced");
    CHECK_RC(tapi_fs_mount_verify(session.factory, &mounts, &issues));
    n_probe = fs_issues_to_report(&issues, &report);

    TEST_STEP("Check the link and dump protections");
    CHECK_RC(tapi_fs_posture_check(session.factory, &issues));
    n_posture = fs_issues_to_report(&issues, &report);
    TEST_ARTIFACT("findings: %u mount option(s), %u probe(s), %u "
                  "protection(s)", n_rules, n_probe, n_posture);
    {
        static const char *labels[] = {
            "mount_options", "enforcement", "protections",
        };
        double vals[TE_ARRAY_LEN(labels)];

        vals[0] = n_rules;
        vals[1] = n_probe;
        vals[2] = n_posture;
        tsapi_mde_mi_bars("fs/mounts", "Mount findings per check",
                          TE_MI_MEAS_UNITLESS_VALUE, "findings",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Known-bad control: a mount table with a bare media mount");
    CHECK_RC(tapi_fs_mounts_parse(MNT_CTL_LINE, &ctl_mounts));
    if (te_vec_size(&ctl_mounts) != 1)
        TEST_VERDICT("The synthetic mount line was not parsed");
    CHECK_RC(tapi_fs_mount_check(&ctl_mounts, NULL, 0, &issues));
    (void)fs_issues_to_report(&issues, &report);
    tsapi_mde_report_expect(&report, "fs.mount-option", MNT_CTL " nosuid");
    tsapi_mde_report_expect(&report, "fs.mount-option", MNT_CTL " nodev");
    tsapi_mde_report_expect(&report, "fs.mount-option", MNT_CTL " noexec");
    tsapi_mde_report_drop_subject(&report, MNT_CTL " nosuid");
    tsapi_mde_report_drop_subject(&report, MNT_CTL " nodev");
    tsapi_mde_report_drop_subject(&report, MNT_CTL " noexec");

    TEST_STEP("Decide over the mount findings");
    TSAPI_MDE_REPORT_GATE(&report, "fs", min_sev);

    TEST_SUCCESS;

cleanup:

    if (session_up)
        tsapi_mde_dut_free(&dut);
    tapi_fs_mounts_free(&mounts);
    tapi_fs_mounts_free(&ctl_mounts);
    tapi_kernel_issues_free(&issues);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&df_mp);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

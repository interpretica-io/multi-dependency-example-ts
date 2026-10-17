/** @file
 * @brief Filesystem Group
 *
 * Integrity of the built example across a run: a manifest of dist/ (every
 * path, mode, owner, size, SHA-256) is taken, the ring demos or the web
 * tier are driven, and a second manifest is compared with the first.
 * Nothing in dist/ may change - a run that rewrites its own binaries or
 * libraries is a finding. The manifest is checked three more ways: its
 * text form round-trips to an identical manifest, the digest of cpp-demo
 * agrees with sha256sum on the agent, and a known-bad control (a copy of
 * a library with one byte changed after its baseline) must be reported as
 * modified.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "fs/integrity"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_fs.h"
#include "tapi_fs_integrity.h"
#include "fs_common.h"

/** The control directory on the agent. */
#define INT_CTL         "/tmp/mde-fs-integrity-ctl"

/** Take a manifest of one root; return the time it took. */
static double
int_take(tsapi_mde_session *session, const char *root,
         tapi_fs_manifest *manifest)
{
    tapi_fs_walk_opt wopt = tapi_fs_walk_default_opt;
    const char      *roots[1];
    double           t0 = tsapi_mde_now();
    te_errno         rc;

    roots[0] = root;
    wopt.roots = roots;
    wopt.n_roots = 1;
    wopt.cross_mounts = true;

    rc = tapi_fs_manifest_take(session->factory, &wopt, manifest);
    if (rc != 0)
        TEST_FAIL("Cannot take the manifest of %s: %r", root, rc);

    return tsapi_mde_now() - t0;
}

/** Count regular files and their bytes in a manifest. */
static void
int_count(const tapi_fs_manifest *manifest, double *files, double *bytes)
{
    const tapi_fs_manifest_item *it;

    *files = 0;
    *bytes = 0;
    TE_VEC_FOREACH(&manifest->items, it)
    {
        if (it->digest != NULL)
        {
            (*files)++;
            *bytes += (double)it->size;
        }
    }
}

int
main(int argc, char **argv)
{
    fs_workload          workload;
    tsapi_mde_session    session;
    bool                 session_up = false;
    tsapi_mde_dut        dut;
    tsapi_mde_web        web;
    tsapi_mde_report     report;
    tapi_kernel_issues   issues;
    tsapi_mde_sh_result  sh = TSAPI_MDE_SH_RESULT_INIT;
    tapi_fs_manifest     before;
    tapi_fs_manifest     after;
    tapi_fs_manifest     copy;
    tapi_fs_manifest     ctl_before;
    tapi_fs_manifest     ctl_after;
    te_string            dist = TE_STRING_INIT;
    te_string            text = TE_STRING_INIT;
    te_string            demo = TE_STRING_INIT;
    te_string            lib = TE_STRING_INIT;
    te_string            ctl_file = TE_STRING_INIT;
    te_string            saved = TE_STRING_INIT;
    const tapi_fs_manifest_item *it;
    double               files[3];
    double               bytes[3];
    double               secs[3];
    unsigned int         n_changes;
    unsigned int         ok_runs = 0;
    unsigned int         answered = 0;
    const char          *tmp;

    TEST_START;
    tsapi_mde_report_init(&report);
    tapi_kernel_issues_init(&issues);
    tapi_fs_manifest_init(&before);
    tapi_fs_manifest_init(&after);
    tapi_fs_manifest_init(&copy);
    tapi_fs_manifest_init(&ctl_before);
    tapi_fs_manifest_init(&ctl_after);
    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(workload, FS_WORKLOAD_LIST);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "fsint", dut, session_up);
    if (workload == FS_WORKLOAD_WEB)
    {
        if (!tsapi_mde_web_built(&session, &dut))
            TEST_SKIP("The web tier is not built");
        if (!tsapi_mde_have(&session, "curl"))
            TEST_SKIP("curl is not available on the agent");
    }
    te_string_append(&dist, "%s/dist", dut.root);

    TEST_STEP("Take the baseline manifest of dist");
    secs[0] = int_take(&session, dist.ptr, &before);
    int_count(&before, &files[0], &bytes[0]);
    TEST_ARTIFACT("baseline: %zu path(s), %.0f file(s), %.0f byte(s) hashed "
                  "in %.2f s", te_vec_size(&before.items), files[0],
                  bytes[0], secs[0]);

    TEST_STEP("The manifest round-trips through its text form");
    tapi_fs_manifest_to_string(&before, &text);
    CHECK_RC(tapi_fs_manifest_from_string(text.ptr, &copy));
    CHECK_RC(tapi_fs_manifest_diff(&before, &copy, NULL, 0, &issues));
    if (tapi_kernel_issues_count(&issues) != 0 ||
        te_vec_size(&copy.items) != te_vec_size(&before.items))
    {
        tapi_kernel_issues_log(&issues);
        TEST_VERDICT("The manifest does not survive its own text form");
    }
    tmp = getenv("TE_TMP");
    te_string_append(&saved, "%s/mde-fs-integrity-%s.manifest",
                     tmp != NULL ? tmp : "/tmp",
                     workload == FS_WORKLOAD_RING ? "ring" : "web");
    rc = tapi_fs_manifest_save(&before, saved.ptr);
    if (rc == 0)
        TEST_ARTIFACT("baseline saved on the engine: %s (%zu bytes)",
                      saved.ptr, text.len);
    else
        RING("The baseline could not be saved to %s: %r", saved.ptr, rc);

    TEST_STEP("Two views: the digest of cpp-demo and sha256sum");
    te_string_append(&demo, "%s/cpp-demo", dut.bin);
    it = tapi_fs_manifest_find(&before, demo.ptr);
    if (it == NULL || it->digest == NULL)
        TEST_VERDICT("The manifest of dist has no digest for cpp-demo");
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "sha256sum '%s'", demo.ptr));
    if (strncmp(te_string_value(&sh.out), it->digest, 64) != 0)
    {
        ERROR("manifest: %s; sha256sum: %s", it->digest,
              te_string_value(&sh.out));
        TEST_VERDICT("The manifest and sha256sum disagree on cpp-demo");
    }
    TEST_ARTIFACT("cpp-demo sha256: %s", it->digest);

    TEST_STEP("Drive the workload");
    if (workload == FS_WORKLOAD_RING)
    {
        ok_runs = fs_run_ring(&session, &dut);
        TEST_ARTIFACT("ring demos that exited 0: %u of 3", ok_runs);
    }
    else
    {
        if (tsapi_mde_web_start(&session, &dut, &web) != 0)
            TEST_VERDICT("The web tier did not start");
        answered = fs_web_requests(&session, 20);
        tsapi_mde_web_stop(&web);
        TEST_ARTIFACT("web requests answered with 200: %u of 20", answered);
    }

    TEST_STEP("Take the manifest again and compare");
    secs[1] = int_take(&session, dist.ptr, &after);
    int_count(&after, &files[1], &bytes[1]);
    CHECK_RC(tapi_fs_manifest_diff(&before, &after, NULL, 0, &issues));
    n_changes = fs_issues_to_report(&issues, &report);
    TEST_ARTIFACT("after the run: %u change(s) in dist", n_changes);

    TEST_STEP("Known-bad control: change one byte of a baselined copy");
    te_string_append(&lib, "%s/libcppcore.%s", dut.lib, dut.dylib_ext);
    te_string_append(&ctl_file, INT_CTL "/libcppcore.%s", dut.dylib_ext);
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh,
                          "rm -rf " INT_CTL " && mkdir -p " INT_CTL
                          " && cp '%s' '%s'", lib.ptr, ctl_file.ptr));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("The control copy could not be made");
    secs[2] = int_take(&session, INT_CTL, &ctl_before);
    int_count(&ctl_before, &files[2], &bytes[2]);
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh,
                          "printf 'Z' | dd of='%s' bs=1 seek=0 count=1 "
                          "conv=notrunc 2>/dev/null", ctl_file.ptr));
    (void)int_take(&session, INT_CTL, &ctl_after);
    CHECK_RC(tapi_fs_manifest_diff(&ctl_before, &ctl_after, NULL, 0,
                                   &issues));
    (void)fs_issues_to_report(&issues, &report);
    tsapi_mde_report_expect(&report, "fs.modified", ctl_file.ptr);
    tsapi_mde_report_drop_subject(&report, ctl_file.ptr);

    TEST_STEP("Chart what was hashed");
    {
        te_mi_logger *lg;
        unsigned int  i;

        if (tsapi_mde_mi_create("fs/integrity", &lg) == 0)
        {
            for (i = 0; i < 3; i++)
            {
                te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                      "pass", TE_MI_MEAS_AGGR_SINGLE, i,
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                      "files", TE_MI_MEAS_AGGR_SINGLE,
                                      files[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_MEMORY, "bytes",
                                      TE_MI_MEAS_AGGR_SINGLE, bytes[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_TIME, "seconds",
                                      TE_MI_MEAS_AGGR_SINGLE, secs[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
            }
            te_mi_logger_add_meas_key(lg, NULL, "passes", "%s",
                                      "0=baseline 1=after the run "
                                      "2=control");
            tsapi_mde_mi_line(lg, "files", "Files hashed per manifest",
                              "pass", "files", NULL);
            tsapi_mde_mi_line(lg, "bytes", "Bytes hashed per manifest",
                              "pass", "bytes", NULL);
            tsapi_mde_mi_line(lg, "seconds", "Time per manifest",
                              "pass", "seconds", NULL);
            te_mi_logger_destroy(lg);
        }
    }

    TEST_STEP("Decide: nothing in dist may change");
    TSAPI_MDE_REPORT_GATE(&report, "fs", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_web_stop(&web);
    if (session_up)
    {
        (void)tsapi_mde_sh(&session, 20000, &sh, "rm -rf " INT_CTL);
        tsapi_mde_dut_free(&dut);
    }
    tapi_fs_manifest_free(&before);
    tapi_fs_manifest_free(&after);
    tapi_fs_manifest_free(&copy);
    tapi_fs_manifest_free(&ctl_before);
    tapi_fs_manifest_free(&ctl_after);
    tapi_kernel_issues_free(&issues);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&dist);
    te_string_free(&text);
    te_string_free(&demo);
    te_string_free(&lib);
    te_string_free(&ctl_file);
    te_string_free(&saved);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

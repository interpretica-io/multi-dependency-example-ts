/** @file
 * @brief Container Group
 *
 * Copy every ring library into a container and back out again, and hash
 * it three times: on the agent, inside the container, and after the
 * round trip. All three must be equal. A known-bad control overwrites
 * the first bytes of one copy inside the container before it comes out,
 * and the comparison must catch it.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "container/copy_roundtrip"

#include "te_config.h"
#include "tapi_test.h"
#include "container_common.h"

/** Where the copies go inside the container. */
#define RT_INSIDE_DIR   "/opt/mde-rt"
/** Where they come back to on the agent. */
#define RT_AGENT_DIR    "/tmp/mde-container-rt"
/** Subject of the control's finding. */
#define RT_CONTROL      "control"

/** Most libraries the test handles (the ring has five). */
#define RT_MAX_LIBS     8

/**
 * Compare the three hashes of one file and report a mismatch.
 *
 * @return @c true if all three agree.
 */
static bool
rt_compare(tsapi_mde_report *report, const char *subject, const char *host,
           const char *inside, const char *back)
{
    if (strcmp(host, inside) == 0 && strcmp(host, back) == 0 &&
        host[0] != '\0')
        return true;

    tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                             "container.copy-mismatch", subject,
                             "sha256 agent %s, inside %s, back %s", host,
                             inside, back);
    return false;
}

int
main(int argc, char **argv)
{
    const char         *image;
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tsapi_mde_report    report;
    tapi_container_opt  opt;
    const char *platform_args[] = { MDE_CT_PLATFORM_ARGS };
    tapi_container     *container = NULL;
    const char         *command[] = { "sleep", "infinity" };
    te_string           name = TE_STRING_INIT;
    te_string           slug = TE_STRING_INIT;
    te_string           src = TE_STRING_INIT;
    te_string           in_path = TE_STRING_INIT;
    te_string           back = TE_STRING_INIT;
    te_string           h_host = TE_STRING_INIT;
    te_string           h_in = TE_STRING_INIT;
    te_string           h_back = TE_STRING_INIT;
    te_string           cmd = TE_STRING_INIT;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    const char         *labels[RT_MAX_LIBS] = { NULL };
    double              sizes[RT_MAX_LIBS] = { 0 };
    double              t_in[RT_MAX_LIBS] = { 0 };
    double              t_out[RT_MAX_LIBS] = { 0 };
    double              mbps_in[RT_MAX_LIBS] = { 0 };
    double              mbps_out[RT_MAX_LIBS] = { 0 };
    unsigned int        n = 0;
    unsigned int        n_ok = 0;
    unsigned int        i;
    int                 code = -1;
    double              t0;

    TEST_START;
    tsapi_mde_report_init(&report);
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_STRING_PARAM(image);
    mde_ct_image_slug(image, &slug);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "ct_copy", dut, session_up);

    if (!mde_ct_docker(&session, &opt))
        TEST_SKIP("No container runtime with file copy on the agent");
    opt.image = image;
    if (tapi_container_pull(session.factory, &opt,
                            MDE_CT_PULL_TIMEOUT_MS) != 0)
        TEST_SKIP("Cannot pull the image - no registry access");

    TEST_STEP("Start the container");
    te_string_append(&name, "mde-copy-%s", slug.ptr);
    mde_ct_forget(&session, name.ptr);
    opt.name = name.ptr;
    opt.command = command;
    opt.n_command = TE_ARRAY_LEN(command);
    opt.extra_args = platform_args;
    opt.n_extra_args = TE_ARRAY_LEN(platform_args);
    CHECK_RC(tapi_container_run(session.factory, &opt, MDE_CT_TIMEOUT_MS,
                                &container));
    CHECK_RC(mde_ct_sh(container, "mkdir -p " RT_INSIDE_DIR, NULL, &code));
    if (code != 0)
        TEST_VERDICT("Cannot create a directory inside the container");
    CHECK_RC(tsapi_mde_sh(&session, MDE_CT_TIMEOUT_MS, &sh,
                          "rm -rf " RT_AGENT_DIR "; mkdir -p " RT_AGENT_DIR));

    TEST_STEP("Copy every ring library in and back out, hashing each copy");
    for (i = 0; i < tsapi_mde_dut_n_libs && n < RT_MAX_LIBS; i++)
    {
        const char *lib = tsapi_mde_dut_libs[i];

        te_string_reset(&src);
        te_string_reset(&in_path);
        te_string_reset(&back);
        te_string_reset(&h_host);
        te_string_reset(&h_in);
        te_string_reset(&h_back);

        tsapi_mde_dut_lib_path(&dut, lib, &src);
        if (!tsapi_mde_exists(&session, src.ptr))
        {
            TEST_ARTIFACT("%s: not built, skipped", lib);
            continue;
        }
        te_string_append(&in_path, RT_INSIDE_DIR "/%s.%s", lib,
                         dut.dylib_ext);
        te_string_append(&back, RT_AGENT_DIR "/%s.%s", lib, dut.dylib_ext);

        labels[n] = lib;
        sizes[n] = mde_ct_size_agent(&session, src.ptr);
        CHECK_RC(mde_ct_sha256_agent(&session, src.ptr, &h_host));

        t0 = tsapi_mde_now();
        CHECK_RC(tapi_container_copy_in(container, src.ptr, in_path.ptr,
                                        MDE_CT_COPY_TIMEOUT_MS));
        t_in[n] = tsapi_mde_now() - t0;
        (void)mde_ct_sha256_inside(container, in_path.ptr, &h_in);

        t0 = tsapi_mde_now();
        CHECK_RC(tapi_container_copy_out(container, in_path.ptr, back.ptr,
                                         MDE_CT_COPY_TIMEOUT_MS));
        t_out[n] = tsapi_mde_now() - t0;
        (void)mde_ct_sha256_agent(&session, back.ptr, &h_back);

        mbps_in[n] = t_in[n] > 0 ? sizes[n] / t_in[n] / 1e6 : 0;
        mbps_out[n] = t_out[n] > 0 ? sizes[n] / t_out[n] / 1e6 : 0;
        TEST_ARTIFACT("%s: %.0f bytes, sha256 %s; in %.3f s, out %.3f s",
                      lib, sizes[n], te_string_value(&h_host), t_in[n],
                      t_out[n]);
        if (rt_compare(&report, lib, te_string_value(&h_host),
                       te_string_value(&h_in), te_string_value(&h_back)))
            n_ok++;
        n++;
    }
    if (n == 0)
        TEST_SKIP("No ring library is built");

    TEST_STEP("Known-bad control: corrupt a copy inside, the hashes must "
              "catch it");
    te_string_reset(&src);
    te_string_reset(&h_host);
    te_string_reset(&h_in);
    te_string_reset(&h_back);
    tsapi_mde_dut_lib_path(&dut, labels[0], &src);
    CHECK_RC(mde_ct_sha256_agent(&session, src.ptr, &h_host));
    te_string_append(&cmd, "cp " RT_INSIDE_DIR "/%s.%s " RT_INSIDE_DIR
                     "/control.bin && printf MDE | dd of=" RT_INSIDE_DIR
                     "/control.bin bs=1 seek=0 conv=notrunc 2>/dev/null",
                     labels[0], dut.dylib_ext);
    CHECK_RC(mde_ct_sh(container, cmd.ptr, NULL, &code));
    if (code != 0)
        TEST_VERDICT("Cannot plant the corrupted copy inside the container");
    (void)mde_ct_sha256_inside(container, RT_INSIDE_DIR "/control.bin",
                               &h_in);
    CHECK_RC(tapi_container_copy_out(container, RT_INSIDE_DIR "/control.bin",
                                     RT_AGENT_DIR "/control.bin",
                                     MDE_CT_COPY_TIMEOUT_MS));
    (void)mde_ct_sha256_agent(&session, RT_AGENT_DIR "/control.bin",
                              &h_back);
    (void)rt_compare(&report, RT_CONTROL, te_string_value(&h_host),
                     te_string_value(&h_in), te_string_value(&h_back));
    tsapi_mde_report_expect(&report, "container.copy-mismatch", RT_CONTROL);
    tsapi_mde_report_drop_subject(&report, RT_CONTROL);
    if (strcmp(te_string_value(&h_in), te_string_value(&h_back)) != 0)
        TEST_VERDICT("The corrupted copy changed again on its way out");

    TEST_STEP("Chart sizes, copy times and throughput");
    TEST_ARTIFACT("round trips intact: %u of %u", n_ok, n);
    tsapi_mde_mi_bars("container/copy_roundtrip", "Library sizes",
                      TE_MI_MEAS_MEMORY, "bytes", n, labels, sizes,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    mde_ct_bars2("container/copy_roundtrip", "copy_time",
                 "Copy time per library: in vs out", TE_MI_MEAS_TIME,
                 "copy_in_s", "copy_out_s", n, labels, t_in, t_out);
    mde_ct_bars2("container/copy_roundtrip", "copy_rate",
                 "Copy throughput per library, MB/s",
                 TE_MI_MEAS_UNITLESS_VALUE, "in_MBps", "out_MBps", n,
                 labels, mbps_in, mbps_out);

    TEST_STEP("Decide on the report");
    TSAPI_MDE_REPORT_GATE(&report, "container", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_container_remove(container, MDE_CT_TIMEOUT_MS));
    if (session_up)
    {
        (void)tsapi_mde_sh(&session, MDE_CT_TIMEOUT_MS, &sh,
                           "rm -rf " RT_AGENT_DIR);
    }
    tsapi_mde_sh_result_free(&sh);
    tsapi_mde_report_free(&report);
    te_string_free(&name);
    te_string_free(&slug);
    te_string_free(&src);
    te_string_free(&in_path);
    te_string_free(&back);
    te_string_free(&h_host);
    te_string_free(&h_in);
    te_string_free(&h_back);
    te_string_free(&cmd);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

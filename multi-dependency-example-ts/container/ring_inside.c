/** @file
 * @brief Container Group
 *
 * Ship the built example into a container image it was not built for and
 * walk the ring there. The libraries and python/ go in at the same
 * absolute paths they have on the agent (libpycore has the path of
 * ring_stage.py compiled in); whatever shared library the image lacks is
 * a finding, named from ldd run inside. When cpp-demo runs, its trace is
 * compared byte for byte with the agent's own run, and both are compared
 * with the ring model: the same defect has to reproduce inside.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "container/ring_inside"

#include "te_config.h"
#include "tapi_test.h"
#include "tsapi_mde_ring.h"
#include "container_common.h"

/**
 * Collect the libraries ldd reported as "not found", without repeats.
 *
 * @param text      ldd output.
 * @param names     Comma-separated list to append to.
 *
 * @return Number of distinct names found.
 */
static unsigned int
ring_missing_libs(const char *text, te_string *names)
{
    const char  *line = text;
    unsigned int n = 0;

    while (line != NULL && *line != '\0')
    {
        const char *eol = strchr(line, '\n');
        size_t      len = (eol == NULL) ? strlen(line) : (size_t)(eol - line);
        te_string   cur = TE_STRING_INIT;

        te_string_append(&cur, "%.*s", (int)len, line);
        if (strstr(cur.ptr, "=> not found") != NULL)
        {
            te_string name = TE_STRING_INIT;

            mde_ct_first_word(cur.ptr, &name);
            if (name.len > 0 &&
                strstr(te_string_value(names), name.ptr) == NULL)
            {
                te_string_append(names, "%s%s", names->len > 0 ? "," : "",
                                 name.ptr);
                n++;
            }
            te_string_free(&name);
        }
        te_string_free(&cur);

        line = (eol == NULL) ? NULL : eol + 1;
    }

    return n;
}

int
main(int argc, char **argv)
{
    const char          *image;
    int                  hops;
    tsapi_mde_session    session;
    bool                 session_up = false;
    tsapi_mde_dut        dut;
    tsapi_mde_report     report;
    tapi_container_opt   opt;
    const char *platform_args[] = { MDE_CT_PLATFORM_ARGS };
    tapi_container      *container = NULL;
    const char          *command[] = { "sleep", "infinity" };
    tsapi_mde_sh_result  sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string            host_out = TE_STRING_INIT;
    te_string            in_out = TE_STRING_INIT;
    te_string            ldd_out = TE_STRING_INIT;
    te_string            missing = TE_STRING_INIT;
    te_string            cmd = TE_STRING_INIT;
    te_string            dist = TE_STRING_INIT;
    te_string            slug = TE_STRING_INIT;
    te_string            ct_name = TE_STRING_INIT;
    te_string            subject = TE_STRING_INIT;
    te_vec               expected = TE_VEC_INIT(tsapi_mde_step);
    te_vec               obs_host = TE_VEC_INIT(tsapi_mde_step);
    te_vec               obs_in = TE_VEC_INIT(tsapi_mde_step);
    tapi_cybersec_report host_rep;
    bool                 host_rep_up = false;
    unsigned int         n_missing;
    unsigned int         n_host_findings = 0;
    unsigned int         n_in_findings = 0;
    double               exp_result;
    double               host_result = 0.0;
    double               in_result = 0.0;
    bool                 have_host_result;
    bool                 have_in_result = false;
    bool                 ran_inside = false;
    int                  code = -1;
    double               t0;
    double               t_pull;
    double               t_host;
    double               t_in = 0.0;
    double               t_copy_dist;
    double               t_copy_py;
    double               img_size;
    char                 hops_str[16];

    TEST_START;
    TSAPI_MDE_PROLOGUE_GATE("container");
    tsapi_mde_report_init(&report);
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_STRING_PARAM(image);
    TEST_GET_INT_PARAM(hops);
    TE_SPRINTF(hops_str, "%d", hops);
    mde_ct_image_slug(image, &slug);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "ct_ring", dut, session_up);

    TEST_STEP("Check that Docker answers and can copy files");
    if (!mde_ct_docker(&session, &opt))
        TEST_SKIP("No container runtime with file copy on the agent");

    TEST_STEP("Pull the image");
    opt.image = image;
    t0 = tsapi_mde_now();
    rc = tapi_container_pull(session.factory, &opt, MDE_CT_PULL_TIMEOUT_MS);
    if (rc != 0)
        TEST_SKIP("Cannot pull the image - no registry access");
    t_pull = tsapi_mde_now() - t0;
    img_size = mde_ct_image_size(&session, image);
    TEST_ARTIFACT("image %s: %.0f bytes, pulled in %.3f s", image, img_size,
                  t_pull);
    tsapi_mde_mi_point("container/ring_inside", "Image size",
                       TE_MI_MEAS_MEMORY, "image_bytes", img_size,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("container/ring_inside", "Image pull time",
                       TE_MI_MEAS_TIME, "pull_s", t_pull,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Run cpp-demo on the agent itself as the reference");
    t0 = tsapi_mde_now();
    CHECK_RC(tsapi_mde_sh(&session, 60000, &sh, "'%s/cpp-demo' 1 %d",
                          dut.bin, hops));
    t_host = tsapi_mde_now() - t0;
    if (!tsapi_mde_sh_ok(&sh))
        TEST_VERDICT("cpp-demo does not run on the agent itself");
    te_string_append(&host_out, "%s", te_string_value(&sh.out));
    RING("cpp-demo on the agent:\n%s", te_string_value(&host_out));

    TEST_STEP("Start the container with a stable name");
    te_string_append(&ct_name, "mde-ring-inside-%s-h%d", slug.ptr, hops);
    mde_ct_forget(&session, ct_name.ptr);
    opt.name = ct_name.ptr;
    opt.command = command;
    opt.n_command = TE_ARRAY_LEN(command);
    opt.extra_args = platform_args;
    opt.n_extra_args = TE_ARRAY_LEN(platform_args);
    CHECK_RC(tapi_container_run(session.factory, &opt, MDE_CT_TIMEOUT_MS,
                                &container));

    TEST_STEP("Copy dist/ and python/ in at the agent's absolute paths");
    te_string_reset(&cmd);
    te_string_append(&cmd, "mkdir -p '%s'", dut.root);
    CHECK_RC(mde_ct_sh(container, cmd.ptr, NULL, &code));
    if (code != 0)
        TEST_VERDICT("Cannot create the example root inside the container");

    te_string_append(&dist, "%s/dist", dut.root);
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_container_copy_in(container, dist.ptr, dist.ptr,
                                    MDE_CT_COPY_TIMEOUT_MS));
    t_copy_dist = tsapi_mde_now() - t0;
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_container_copy_in(container, dut.python, dut.python,
                                    MDE_CT_COPY_TIMEOUT_MS));
    t_copy_py = tsapi_mde_now() - t0;
    TEST_ARTIFACT("copy in: dist/ %.3f s, python/ %.3f s", t_copy_dist,
                  t_copy_py);

    TEST_STEP("Check which shared libraries the image lacks (ldd inside)");
    te_string_reset(&cmd);
    te_string_append(&cmd, "ldd '%s/cpp-demo' '%s'/*.%s 2>&1", dut.bin,
                     dut.lib, dut.dylib_ext);
    CHECK_RC(mde_ct_sh(container, cmd.ptr, &ldd_out, &code));
    RING("ldd inside %s:\n%s", image, te_string_value(&ldd_out));
    n_missing = ring_missing_libs(te_string_value(&ldd_out), &missing);
    TEST_ARTIFACT("libraries missing in %s: %u (%s)", image, n_missing,
                  missing.len > 0 ? missing.ptr : "none");
    tsapi_mde_mi_point("container/ring_inside", "Libraries missing inside",
                       TE_MI_MEAS_UNITLESS_VALUE, "missing", n_missing,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (n_missing > 0)
    {
        char *list = strdup(missing.ptr);
        char *save = NULL;
        char *name;

        for (name = strtok_r(list, ",", &save); name != NULL;
             name = strtok_r(NULL, ",", &save))
        {
            te_string_reset(&subject);
            te_string_append(&subject, "%s:%s", image, name);
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "container.missing-runtime",
                                     subject.ptr,
                                     "the image has no %s, which the ring "
                                     "needs (ldd inside)", name);
        }
        free(list);
    }

    TEST_STEP("Run cpp-demo inside the container");
    {
        te_string   prog = TE_STRING_INIT;
        const char *args[3];

        te_string_append(&prog, "%s/cpp-demo", dut.bin);
        args[0] = prog.ptr;
        args[1] = "1";
        args[2] = hops_str;
        t0 = tsapi_mde_now();
        rc = tapi_container_exec(container, args, TE_ARRAY_LEN(args),
                                 MDE_CT_TIMEOUT_MS, &in_out, &code);
        t_in = tsapi_mde_now() - t0;
        te_string_free(&prog);
        CHECK_RC(rc);
    }
    RING("cpp-demo inside %s (exit %d):\n%s", image, code,
         te_string_value(&in_out));
    ran_inside = (code == 0);
    TEST_ARTIFACT("cpp-demo 1 %d: agent %.4f s, container %.4f s, exit "
                  "inside %d", hops, t_host, t_in, code);

    {
        const char *labels[] = { "agent", "container" };
        double      times[] = { t_host, t_in };
        const char *clabels[] = { "dist", "python" };
        double      ctimes[] = { t_copy_dist, t_copy_py };

        tsapi_mde_mi_bars("container/ring_inside",
                          "cpp-demo run time: agent vs container",
                          TE_MI_MEAS_TIME, "run_s", TE_ARRAY_LEN(times),
                          labels, times, TE_MI_MEAS_MULTIPLIER_PLAIN);
        tsapi_mde_mi_bars("container/ring_inside",
                          "Copy-in time per tree", TE_MI_MEAS_TIME,
                          "copy_s", TE_ARRAY_LEN(ctimes), clabels, ctimes,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Compare the traces with each other and with the model");
    exp_result = tsapi_mde_ring_predict(TSAPI_MDE_STAGE_RUST, 1.0, hops,
                                        &expected);
    tsapi_mde_ring_parse(te_string_value(&host_out), &obs_host);
    have_host_result = tsapi_mde_ring_parse_result(te_string_value(&host_out),
                                                   &host_result);
    tapi_cybersec_report_init(&host_rep);
    host_rep_up = true;
    n_host_findings = tsapi_mde_ring_compare(TSAPI_MDE_STAGE_RUST,
                                             &expected, &obs_host,
                                             have_host_result, exp_result,
                                             host_result, 1e-3, &host_rep);

    te_string_reset(&subject);
    te_string_append(&subject, "%s", image);
    if (ran_inside)
    {
        tsapi_mde_ring_parse(te_string_value(&in_out), &obs_in);
        have_in_result = tsapi_mde_ring_parse_result(
                                te_string_value(&in_out), &in_result);

        if (strcmp(te_string_value(&host_out), te_string_value(&in_out)) != 0)
        {
            size_t i = 0;
            const char *a = te_string_value(&host_out);
            const char *b = te_string_value(&in_out);

            while (a[i] != '\0' && a[i] == b[i])
                i++;
            TEST_ARTIFACT("traces diverge at byte %zu (agent %zu bytes, "
                          "container %zu bytes)", i, strlen(a), strlen(b));
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "container.trace-diverged", subject.ptr,
                                     "cpp-demo prints a different trace "
                                     "inside the container from byte %zu",
                                     i);
        }
        else
        {
            TEST_ARTIFACT("trace inside %s is identical to the agent's "
                          "(%zu bytes)", image, host_out.len);
        }

        n_in_findings = tsapi_mde_ring_compare(TSAPI_MDE_STAGE_RUST,
                                               &expected, &obs_in,
                                               have_in_result, exp_result,
                                               in_result, 1e-3,
                                               &report.cyber);
        if (n_in_findings != n_host_findings)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "container.defect-diverged",
                                     subject.ptr,
                                     "the model finds %u deviation(s) on "
                                     "the agent and %u inside",
                                     n_host_findings, n_in_findings);
        }

        {
            te_mi_logger *logger;

            if (tsapi_mde_mi_create("container/ring_inside", &logger) == 0)
            {
                tsapi_mde_ring_chart(logger, "inside", &expected, &obs_in);
                te_mi_logger_destroy(logger);
            }
        }
    }
    else if (n_missing == 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "container.run-failed", subject.ptr,
                                 "cpp-demo exited %d inside although ldd "
                                 "found every library", code);
    }

    TEST_ARTIFACT("model deviations: agent %u, container %u%s (expected "
                  "%u steps, result %.4f)", n_host_findings, n_in_findings,
                  ran_inside ? "" : " (did not run)",
                  (unsigned int)te_vec_size(&expected), exp_result);
    {
        const char *labels[] = { "agent", "container" };
        double      steps[] = { (double)te_vec_size(&obs_host),
                                (double)te_vec_size(&obs_in) };

        tsapi_mde_mi_bars("container/ring_inside",
                          "Stage steps traced: agent vs container",
                          TE_MI_MEAS_UNITLESS_VALUE, "steps",
                          TE_ARRAY_LEN(steps), labels, steps,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide on the report");
    TSAPI_MDE_REPORT_GATE(&report, "container", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_container_remove(container, MDE_CT_TIMEOUT_MS));
    if (host_rep_up)
        tapi_cybersec_report_free(&host_rep);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_vec_free(&expected);
    te_vec_free(&obs_host);
    te_vec_free(&obs_in);
    te_string_free(&host_out);
    te_string_free(&in_out);
    te_string_free(&ldd_out);
    te_string_free(&missing);
    te_string_free(&cmd);
    te_string_free(&dist);
    te_string_free(&slug);
    te_string_free(&ct_name);
    te_string_free(&subject);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

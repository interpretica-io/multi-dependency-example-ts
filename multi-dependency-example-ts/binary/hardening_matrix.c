/** @file
 * @brief Binary Group
 *
 * All ten artifacts of the example in one pass: every one is read by
 * tapi_binscan, checked against its default policy and summarised in
 * one chart - a line per hardening property over the artifact index -
 * and one compact table, so a build can be compared with the previous
 * one at a glance.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "binary/hardening_matrix"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "binary_common.h"

/** Lines of the matrix chart. */
static const char * const matrix_lines[] = {
    "pie", "relro", "bindnow", "nx", "canary", "fortify",
};
#define MATRIX_N_LINES TE_ARRAY_LEN(matrix_lines)

int
main(int argc, char **argv)
{
    tapi_cybersec_severity  min_sev;
    tsapi_mde_session       session = { .ta = NULL };
    tsapi_mde_dut           dut = { .root = NULL };
    bool                    session_up = false;
    tsapi_mde_report        report;
    bool                    report_up = false;
    bool                    have_readelf;
    const char             *names[BINARY_N_ARTIFACTS];
    double                  vals[MATRIX_N_LINES * BINARY_N_ARTIFACTS];
    double                  findings[BINARY_N_ARTIFACTS];
    double                  times[BINARY_N_ARTIFACTS];
    double                  sev_high[BINARY_N_ARTIFACTS];
    unsigned int            n = 0;
    unsigned int            n_missing = 0;
    unsigned int            n_mismatch = 0;
    unsigned int            i;
    unsigned int            j;
    te_string               log = TE_STRING_INIT;
    bool                    control_built = false;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "binary_matrix", dut, session_up);
    have_readelf = tsapi_mde_have(&session, "readelf");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_ARTIFACT("%-12s %-4s %-8s %-7s %-7s %-6s %-7s %s", "artifact",
                  "pie", "relro", "bindnow", "nx", "canary", "fortify",
                  "needed");

    TEST_STEP("Scan every artifact of the example");
    for (i = 0; i < binary_n_artifacts() && i < BINARY_N_ARTIFACTS; i++)
    {
        const char        *name = binary_artifact_name(i);
        te_string          path = TE_STRING_INIT;
        tapi_binscan_info  info;
        binary_props       scan;
        binary_props       elf;
        size_t             before;
        size_t             k;
        double             t0;
        te_errno           err;

        TEST_SUBSTEP("Scan %s", name);
        binary_artifact_path(&dut, name, &path);
        if (!tsapi_mde_exists(&session, path.ptr))
        {
            RING("%s is not built in this configuration", name);
            TEST_ARTIFACT("%-12s not built", name);
            n_missing++;
            te_string_free(&path);
            continue;
        }

        t0 = tsapi_mde_now();
        err = tapi_binscan_inspect(session.ta, path.ptr, &info);
        if (err != 0)
        {
            te_string_free(&path);
            TEST_FAIL("tapi_binscan cannot read %s: %r", name, err);
        }
        binary_props_from_info(&info, &scan);

        before = te_vec_size(&report.cyber.findings);
        err = tapi_binscan_check(session.ta, path.ptr, NULL, &report.cyber);
        times[n] = tsapi_mde_now() - t0;
        if (err != 0)
        {
            tapi_binscan_info_free(&info);
            te_string_free(&path);
            TEST_FAIL("tapi_binscan cannot check %s: %r", name, err);
        }

        /* BIND_NOW without RELRO is invisible to binscan; ask readelf. */
        memset(&elf, 0, sizeof(elf));
        if (have_readelf &&
            binary_readelf(&session, path.ptr, &elf, NULL) == 0)
        {
            n_mismatch += binary_compare_views(&report, name, &scan, &elf);
        }
        else
        {
            elf = scan;
        }

        names[n] = name;
        vals[0 * BINARY_N_ARTIFACTS + n] = scan.dyn ? 1 : 0;
        vals[1 * BINARY_N_ARTIFACTS + n] = scan.relro;
        vals[2 * BINARY_N_ARTIFACTS + n] = elf.bindnow ? 1 : 0;
        vals[3 * BINARY_N_ARTIFACTS + n] =
            (scan.nx && !scan.nx_unknown) ? 1 : 0;
        vals[4 * BINARY_N_ARTIFACTS + n] = scan.canary ? 1 : 0;
        vals[5 * BINARY_N_ARTIFACTS + n] = scan.fortify ? 1 : 0;

        findings[n] = (double)(te_vec_size(&report.cyber.findings) - before);
        sev_high[n] = 0;
        for (k = before; k < te_vec_size(&report.cyber.findings); k++)
        {
            const tapi_cybersec_finding *f =
                te_vec_get(&report.cyber.findings, k);

            if (f->severity >= TAPI_CYBERSEC_SEV_HIGH)
                sev_high[n] += 1;
        }

        TEST_ARTIFACT("%-12s %-4s %-8s %-7s %-7s %-6s %-7s %zu", name,
                      BINARY_YN(scan.dyn),
                      tapi_binscan_relro2str(info.relro),
                      BINARY_YN(elf.bindnow),
                      scan.nx_unknown ? "unknown" : BINARY_YN(scan.nx),
                      BINARY_YN(scan.canary), BINARY_YN(scan.fortify),
                      info.n_needed);

        tapi_binscan_info_free(&info);
        te_string_free(&path);
        n++;
    }

    if (n == 0)
        TEST_VERDICT("None of the artifacts is built");

    TEST_STEP("Chart the matrix");
    /* The rows were laid out for BINARY_N_ARTIFACTS columns; pack them. */
    for (j = 1; j < MATRIX_N_LINES; j++)
    {
        for (i = 0; i < n; i++)
            vals[j * n + i] = vals[j * BINARY_N_ARTIFACTS + i];
    }
    binary_mi_matrix("binscan", "matrix",
                     "Hardening matrix: property per artifact "
                     "(1/0, relro 0/1/2)",
                     n, names, MATRIX_N_LINES, matrix_lines, vals);

    {
        const char *lines[] = { "findings", "high_or_worse" };
        double      fv[2 * BINARY_N_ARTIFACTS];

        for (i = 0; i < n; i++)
        {
            fv[i] = findings[i];
            fv[n + i] = sev_high[i];
        }
        binary_mi_matrix("binscan", "findings",
                         "binscan findings per artifact", n, names,
                         TE_ARRAY_LEN(lines), lines, fv);
    }

    tsapi_mde_mi_bars("binscan", "Time to scan each artifact",
                      TE_MI_MEAS_TIME, "time", n, names, times,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_ARTIFACT("Scanned %u artifact(s), %u not built, %u view "
                  "mismatch(es)", n, n_missing, n_mismatch);

    TEST_STEP("Known-bad control: a binary built without any defence");
    control_built = binary_build_control(&session, &log);
    if (!control_built)
    {
        RING("Control build output:\n%s", te_string_value(&log));
        if (binary_compiler(&session) == NULL)
            WARN("There is no C compiler on the agent: no control");
        else
            TEST_VERDICT("Cannot build the known-bad control binary");
    }
    else
    {
        CHECK_RC(tapi_binscan_check(session.ta, BINARY_CONTROL_BIN, NULL,
                                    &report.cyber));
        tsapi_mde_report_expect(&report, "binary.not-pie",
                                BINARY_CONTROL_BIN);
        tsapi_mde_report_expect(&report, "binary.no-nx", BINARY_CONTROL_BIN);
        tsapi_mde_report_expect(&report, "binary.no-relro",
                                BINARY_CONTROL_BIN);
        tsapi_mde_report_expect(&report, "binary.no-canary",
                                BINARY_CONTROL_BIN);
        tsapi_mde_report_drop_subject(&report, BINARY_CONTROL_BIN);
    }

    TEST_STEP("Decide");
    TSAPI_MDE_REPORT_GATE(&report, "binary", min_sev);

    TEST_SUCCESS;

cleanup:

    if (control_built)
        binary_rm(&session, BINARY_CONTROL_SRC " " BINARY_CONTROL_BIN);
    if (report_up)
        tsapi_mde_report_free(&report);
    te_string_free(&log);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

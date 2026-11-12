/** @file
 * @brief Binary Group
 *
 * How one artifact of the example was built: the defences a compiler and
 * a linker were asked for, read from the ELF by tapi_binscan and checked
 * against its default policy. Two more things make it more than a scan:
 *
 * - a known-bad control, a binary built on the agent with every defence
 *   turned off, must come back with the matching @c binary.* findings;
 * - an independent view, @c readelf on the agent, must agree with
 *   binscan on PIE, interpreter, NX, RELRO, canary, fortify and the
 *   number of NEEDED entries (@c binary.view-mismatch otherwise).
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "binary/hardening"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "binary_common.h"

/** Properties both views know, in chart order. */
static const char * const hardening_props[] = {
    "pie", "interp", "nx", "relro", "bindnow", "canary", "fortify",
};
#define HARDENING_N_PROPS TE_ARRAY_LEN(hardening_props)

/** Fill a property row of the chart from a view. */
static void
hardening_row(const binary_props *p, double *row)
{
    row[0] = p->dyn ? 1 : 0;
    row[1] = p->interp ? 1 : 0;
    row[2] = (p->nx && !p->nx_unknown) ? 1 : 0;
    row[3] = p->relro;
    row[4] = p->bindnow ? 1 : 0;
    row[5] = p->canary ? 1 : 0;
    row[6] = p->fortify ? 1 : 0;
}

/** Defences only binscan reports, in chart order. */
static const char * const hardening_extra[] = {
    "no-textrel", "no-wx-segment", "no-rpath", "no-runpath", "not-stripped",
    "dynamic",
};
#define HARDENING_N_EXTRA TE_ARRAY_LEN(hardening_extra)

int
main(int argc, char **argv)
{
    const char             *artifact;
    tapi_cybersec_severity  min_sev;
    tsapi_mde_session       session = { .ta = NULL };
    tsapi_mde_dut           dut = { .root = NULL };
    bool                    session_up = false;
    tsapi_mde_report        report;
    bool                    report_up = false;
    tapi_binscan_info       info;
    bool                    info_up = false;
    binary_props            scan;
    binary_props            elf;
    bool                    have_readelf;
    te_string               path = TE_STRING_INIT;
    te_string               sha = TE_STRING_INIT;
    te_string               raw = TE_STRING_INIT;
    te_string               log = TE_STRING_INIT;
    unsigned long           size = 0;
    double                  rows[2 * HARDENING_N_PROPS];
    double                  extra[HARDENING_N_EXTRA];
    const char             *rows_names[] = { "binscan", "readelf" };
    double                  t_scan;
    double                  t_elf = 0;
    double                  t0;
    unsigned int            n_mismatch = 0;
    unsigned int            n_findings;
    bool                    control_built = false;
    unsigned int            i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_STRING_PARAM(artifact);
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "binary_hardening", dut, session_up);

    binary_artifact_path(&dut, artifact, &path);
    if (!tsapi_mde_exists(&session, path.ptr))
        TEST_VERDICT("%s is not built in this configuration", artifact);

    have_readelf = tsapi_mde_have(&session, "readelf");
    if (!have_readelf)
        WARN("There is no readelf on the agent: the second view is skipped");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Record what is scanned");
    binary_file_digest(&session, path.ptr, &size, &sha);
    TEST_ARTIFACT("%s: %lu bytes, sha256 %s", artifact, size, sha.ptr);
    tsapi_mde_mi_point("binscan", "Artifact size", TE_MI_MEAS_MEMORY,
                       "size", (double)size, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Read how the artifact was built (tapi_binscan)");
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_binscan_inspect(session.ta, path.ptr, &info));
    t_scan = tsapi_mde_now() - t0;
    info_up = true;
    tapi_binscan_info_log(&info, path.ptr);
    if (!info.elf)
        TEST_VERDICT("The artifact is not an ELF object");
    binary_props_from_info(&info, &scan);

    TEST_ARTIFACT("%s: kind=%s PIE=%s NX=%s RELRO=%s canary=%s fortify=%s "
                  "stripped=%s textrel=%s wx=%s rpath=%s runpath=%s "
                  "needed=%zu",
                  artifact, tapi_binscan_kind2str(info.kind),
                  BINARY_YN(scan.dyn),
                  info.nx_unknown ? "unknown" : BINARY_YN(info.nx),
                  tapi_binscan_relro2str(info.relro),
                  BINARY_YN(info.canary), BINARY_YN(info.fortify),
                  BINARY_YN(info.stripped), BINARY_YN(info.textrel),
                  BINARY_YN(info.wx_segment),
                  info.rpath != NULL ? info.rpath : "-",
                  info.runpath != NULL ? info.runpath : "-",
                  info.n_needed);

    TEST_STEP("Check it against the default policy");
    CHECK_RC(tapi_binscan_check(session.ta, path.ptr, NULL,
                                &report.cyber));

    TEST_STEP("Cross-check with readelf on the agent");
    memset(&elf, 0, sizeof(elf));
    if (have_readelf)
    {
        t0 = tsapi_mde_now();
        CHECK_RC(binary_readelf(&session, path.ptr, &elf, &raw));
        t_elf = tsapi_mde_now() - t0;
        RING("readelf view of %s:\n%s", path.ptr, raw.ptr);
        n_mismatch = binary_compare_views(&report, artifact, &scan, &elf);
        TEST_ARTIFACT("%s: binscan and readelf disagree on %u property(ies)",
                      artifact, n_mismatch);
    }

    TEST_STEP("Chart the hardening of the artifact");
    hardening_row(&scan, rows);
    if (have_readelf)
        hardening_row(&elf, rows + HARDENING_N_PROPS);
    else
        memcpy(rows + HARDENING_N_PROPS, rows,
               HARDENING_N_PROPS * sizeof(rows[0]));
    binary_mi_matrix("binscan", "hardening",
                     "Hardening per property (1 present / 0 absent; "
                     "relro 0/1/2)",
                     HARDENING_N_PROPS, hardening_props,
                     TE_ARRAY_LEN(rows_names), rows_names, rows);

    extra[0] = info.textrel ? 0 : 1;
    extra[1] = info.wx_segment ? 0 : 1;
    extra[2] = info.rpath == NULL ? 1 : 0;
    extra[3] = info.runpath == NULL ? 1 : 0;
    extra[4] = info.stripped ? 0 : 1;
    extra[5] = info.static_linked ? 0 : 1;
    tsapi_mde_mi_bars("binscan", "Other properties (1 good / 0 not)",
                      TE_MI_MEAS_UNITLESS_VALUE, "property",
                      HARDENING_N_EXTRA, hardening_extra, extra,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    {
        const char *labels[] = { "binscan", "readelf" };
        double      vals[] = { t_scan, t_elf };

        tsapi_mde_mi_bars("binscan", "Time to read the artifact, per view",
                          TE_MI_MEAS_TIME, "time", TE_ARRAY_LEN(labels),
                          labels, vals, TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

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
        binary_props cscan;
        binary_props celf;
        tapi_binscan_info cinfo;

        CHECK_RC(tapi_binscan_check(session.ta, BINARY_CONTROL_BIN, NULL,
                                    &report.cyber));
        tsapi_mde_report_expect(&report, "binary.not-pie",
                                BINARY_CONTROL_BIN);
        tsapi_mde_report_expect(&report, "binary.no-nx", BINARY_CONTROL_BIN);
        tsapi_mde_report_expect(&report, "binary.no-relro",
                                BINARY_CONTROL_BIN);
        tsapi_mde_report_expect(&report, "binary.no-canary",
                                BINARY_CONTROL_BIN);

        /* The two views have to agree on the control too. */
        if (have_readelf &&
            tapi_binscan_inspect(session.ta, BINARY_CONTROL_BIN,
                                 &cinfo) == 0)
        {
            binary_props_from_info(&cinfo, &cscan);
            tapi_binscan_info_free(&cinfo);
            CHECK_RC(binary_readelf(&session, BINARY_CONTROL_BIN, &celf,
                                    NULL));
            i = binary_compare_views(&report, BINARY_CONTROL_NAME, &cscan,
                                     &celf);
            TEST_ARTIFACT("control: binscan and readelf disagree on %u "
                          "property(ies)", i);
            if (celf.dyn || celf.relro != 0 || celf.canary ||
                (celf.nx && !celf.nx_unknown))
            {
                WARN("readelf sees a defence in the control that its flags "
                     "turned off: the toolchain overrides them");
            }
        }

        tsapi_mde_report_drop_subject(&report, BINARY_CONTROL_BIN);
    }

    TEST_STEP("Decide");
    n_findings = (unsigned int)te_vec_size(&report.cyber.findings);
    TEST_ARTIFACT("%s: %u finding(s) after the controls were dropped",
                  artifact, n_findings);
    TSAPI_MDE_REPORT_GATE(&report, "binary", min_sev);

    TEST_SUCCESS;

cleanup:

    if (control_built)
        binary_rm(&session, BINARY_CONTROL_SRC " " BINARY_CONTROL_BIN);
    if (info_up)
        tapi_binscan_info_free(&info);
    if (report_up)
        tsapi_mde_report_free(&report);
    te_string_free(&path);
    te_string_free(&sha);
    te_string_free(&raw);
    te_string_free(&log);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

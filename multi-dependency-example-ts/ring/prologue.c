/** @file
 * @brief ring Group
 *
 * ring group prologue: record what the group is about to drive - the ring
 * libraries and their sizes, which demos can run, the Python that will host
 * the Python demo, and whether the C# stage is the NativeAOT library or the
 * C stand-in. Nothing here fails the group: the tests skip on their own.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ring/prologue"

#include "ring_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut = { .root = NULL };
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    double              sizes[16];
    double              avail[RING_DEMO_N + 1];
    const char         *avail_labels[RING_DEMO_N + 1];
    unsigned int        i;
    te_errno            err;

    TEST_START;

    TEST_STEP("Prepare the ring group");
    CHECK_RC(tsapi_mde_session_init(&session, "ring_prologue"));
    session_up = true;

    err = tsapi_mde_dut_open(&session, &dut);
    if (err != 0)
    {
        TEST_ARTIFACT("The example is not built here (%s): the ring tests "
                      "will skip", tsapi_mde_src() != NULL ?
                      "TE_TS_MDE_SRC is set" : "TE_TS_MDE_SRC is unset");
        TEST_SUCCESS;
    }

    TEST_STEP("Record the host and the library format");
    if (tsapi_mde_sh(&session, 10000, &res, "uname -sm") == 0 &&
        tsapi_mde_sh_ok(&res))
    {
        TEST_ARTIFACT("Agent: %s; libraries: .%s", ring_str(&res.out),
                      dut.dylib_ext);
    }

    TEST_STEP("Record the ring libraries and their sizes");
    for (i = 0; i < tsapi_mde_dut_n_libs && i < TE_ARRAY_LEN(sizes); i++)
    {
        te_string path = TE_STRING_INIT;

        tsapi_mde_dut_lib_path(&dut, tsapi_mde_dut_libs[i], &path);
        sizes[i] = 0;
        if (tsapi_mde_sh(&session, 10000, &res, "wc -c < '%s'",
                         path.ptr) == 0 && tsapi_mde_sh_ok(&res))
            sizes[i] = strtod(ring_str(&res.out), NULL);
        TEST_ARTIFACT("%s: %.0f byte(s)%s", tsapi_mde_dut_libs[i], sizes[i],
                      sizes[i] > 0 ? "" : " (missing)");
        te_string_free(&path);
    }
    tsapi_mde_mi_bars("ring", "Ring library sizes", TE_MI_MEAS_MEMORY, "size",
                      i, (const char * const *)tsapi_mde_dut_libs, sizes,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Tell the C# stage from its C stand-in");
    {
        te_string path = TE_STRING_INIT;

        tsapi_mde_dut_lib_path(&dut, "libcscore", &path);
        if (tsapi_mde_sh(&session, 10000, &res,
                         "grep -a -c 'cs\\* \\]' '%s'", path.ptr) == 0 &&
            res.started)
        {
            TEST_ARTIFACT("C# stage: %s",
                          atoi(ring_str(&res.out)) > 0 ?
                          "C stand-in (RING_SKIP_CSHARP build)" :
                          "NativeAOT library");
        }
        te_string_free(&path);
    }

    TEST_STEP("Record which demos can run");
    for (i = 0; i < RING_DEMO_N; i++)
    {
        const char *why = ring_demo_unavailable(&session, &dut, i);

        avail[i] = why == NULL ? 1 : 0;
        avail_labels[i] = ring_demo2str(i);
        TEST_ARTIFACT("Demo %s: %s", ring_demo2str(i),
                      why == NULL ? "available" : why);
    }

    TEST_STEP("Record the Python that hosts the Python demo");
    avail_labels[RING_DEMO_N] = "python3+ctypes";
    avail[RING_DEMO_N] = 0;
    if (tsapi_mde_sh(&session, 20000, &res,
                     "python3 -c 'import ctypes, sys; "
                     "print(sys.version.split()[0])'") == 0 &&
        tsapi_mde_sh_ok(&res))
    {
        avail[RING_DEMO_N] = 1;
        TEST_ARTIFACT("python3 %s with ctypes", ring_str(&res.out));
    }
    else
    {
        TEST_ARTIFACT("python3 with ctypes is not available");
    }
    tsapi_mde_mi_bars("ring", "Availability (1 = can run)",
                      TE_MI_MEAS_UNITLESS_VALUE, "available",
                      RING_DEMO_N + 1, avail_labels, avail,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&res);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

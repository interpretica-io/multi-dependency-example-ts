/** @file
 * @brief graph Group
 *
 * graph group prologue: record the binary format of the ring libraries,
 * the tools the group reads them with (readelf, nm, otool, strings, ldd)
 * and each library's size and NEEDED count. Nothing here fails the group:
 * the tests skip on their own.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "graph/prologue"

#include "graph_common.h"

int
main(int argc, char **argv)
{
    static const char *tools[] = { "readelf", "nm", "otool", "strings",
                                   "ldd" };

    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut = { .root = NULL };
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    double              have[TE_ARRAY_LEN(tools)];
    double              sizes[TSAPI_MDE_STAGE_N];
    const char         *labels[TSAPI_MDE_STAGE_N];
    char                names[TSAPI_MDE_STAGE_N][32];
    unsigned int        i;
    te_errno            err;

    TEST_START;

    TEST_STEP("Prepare the graph group");
    CHECK_RC(tsapi_mde_session_init(&session, "graph_prologue"));
    session_up = true;

    TEST_STEP("Install what the group needs on the agent and check it");
    TSAPI_MDE_ENSURE(session, "base build");

    TEST_STEP("Record the tools the group reads binaries with");
    for (i = 0; i < TE_ARRAY_LEN(tools); i++)
    {
        have[i] = tsapi_mde_have(&session, tools[i]) ? 1 : 0;
        TEST_ARTIFACT("%s: %s", tools[i], have[i] > 0 ? "available" :
                      "missing");
    }
    tsapi_mde_mi_bars("graph", "Binary tools (1 = available)",
                      TE_MI_MEAS_UNITLESS_VALUE, "available",
                      TE_ARRAY_LEN(tools), tools, have,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    err = tsapi_mde_dut_open(&session, &dut);
    if (err != 0)
    {
        TEST_ARTIFACT("The example is not built here: the graph tests will "
                      "skip");
        TEST_SUCCESS;
    }

    TEST_STEP("Record the ring libraries: format and size");
    TEST_ARTIFACT("Ring libraries are %s (.%s)",
                  strcmp(dut.dylib_ext, "dylib") == 0 ? "Mach-O" : "ELF",
                  dut.dylib_ext);
    for (i = 0; i < TSAPI_MDE_STAGE_N; i++)
    {
        te_string path = TE_STRING_INIT;

        graph_lib_name(i, names[i], sizeof(names[i]));
        labels[i] = names[i];
        sizes[i] = 0;
        tsapi_mde_dut_lib_path(&dut, names[i], &path);
        if (tsapi_mde_sh(&session, 10000, &res, "wc -c < '%s'",
                         path.ptr) == 0 && tsapi_mde_sh_ok(&res))
            sizes[i] = strtod(graph_str(&res.out), NULL);
        if (sizes[i] > 0 &&
            tsapi_mde_sh(&session, 10000, &res, "file -b '%s'",
                         path.ptr) == 0 && tsapi_mde_sh_ok(&res))
            TEST_ARTIFACT("%s: %s", names[i], graph_str(&res.out));
        TEST_ARTIFACT("%s: %.0f byte(s)%s", names[i], sizes[i],
                      sizes[i] > 0 ? "" : " (missing)");
        te_string_free(&path);
    }
    tsapi_mde_mi_bars("graph", "Ring library sizes", TE_MI_MEAS_MEMORY,
                      "size", TSAPI_MDE_STAGE_N, labels, sizes,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&res);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

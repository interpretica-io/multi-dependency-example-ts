/** @file
 * @brief Test Suite
 *
 * Test Suite prologue: report where the example under test is, whether it
 * has been built, what it is made of and which of the tools the groups
 * drive the agent has - so the per-group skips later in the run are easy to
 * read, and the run opens with charts of what it found.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "prologue"

#include "te_config.h"

#include <stdlib.h>

#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/* The tools the groups drive. */
static const char *tools[] = {
    "python3", "python3-config", "curl", "readelf", "nm", "objdump",
    "strings", "ldd", "dpkg", "sha256sum", "clang", "gcc", "tcc", "make",
    "llvm-symbolizer", "docker", "node", "npx", "lsof", "ss", "tcpdump",
    "frida",
};

/* Size of a file on the agent in bytes, or -1. */
static double
agent_file_size(tsapi_mde_session *session, const char *path)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    double              size = -1;

    if (tsapi_mde_sh(session, 10000, &res, "stat -c %%s '%s' 2>/dev/null || "
                     "stat -f %%z '%s'", path, path) == 0 &&
        tsapi_mde_sh_ok(&res))
        size = strtod(res.out.ptr, NULL);
    tsapi_mde_sh_result_free(&res);

    return size;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session session;
    tsapi_mde_dut     dut;
    bool              session_up = false;
    bool              built = false;
    double            have[TE_ARRAY_LEN(tools)];
    unsigned int      n_have = 0;
    const char       *labels[16];
    double            sizes[16];
    te_string         path = TE_STRING_INIT;
    unsigned int      n = 0;
    unsigned int      i;

    TEST_START;

    tsapi_evo_analysis_hint(
        "multi-dependency-example suite. Drives the built example's demos and "
        "HTTP services as programs on the agent, checks that a value still "
        "propagates through every stage of each dependency cycle, and audits "
        "how it is built, linked, laid out and exposed.");

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "prologue"));
    session_up = true;

    TEST_STEP("Report the example under test");
    rc = tsapi_mde_dut_open(&session, &dut);
    if (rc == 0)
    {
        built = true;
        RING("Example under test: %s (libraries: .%s)", dut.root,
             dut.dylib_ext);
        TEST_ARTIFACT("Example under test: %s", dut.root);
    }
    else if (tsapi_mde_src() == NULL)
    {
        RING("TE_TS_MDE_SRC is not set: the suite has no example to test and "
             "the groups that need it will skip.");
    }
    else
    {
        RING("No built example under %s: build it (./build.sh) or the groups "
             "that need it will skip.", tsapi_mde_src());
    }

    if (built)
    {
        TEST_STEP("Chart what the example is made of");
        for (i = 0; i < tsapi_mde_dut_n_bins && n < TE_ARRAY_LEN(labels); i++)
        {
            te_string_reset(&path);
            te_string_append(&path, "%s/%s", dut.bin, tsapi_mde_dut_bins[i]);
            labels[n] = tsapi_mde_dut_bins[i];
            sizes[n++] = agent_file_size(&session, path.ptr);
        }
        for (i = 0; i < tsapi_mde_dut_n_libs && n < TE_ARRAY_LEN(labels); i++)
        {
            te_string_reset(&path);
            tsapi_mde_dut_lib_path(&dut, tsapi_mde_dut_libs[i], &path);
            labels[n] = tsapi_mde_dut_libs[i];
            sizes[n++] = agent_file_size(&session, path.ptr);
        }
        for (i = 0; i < n; i++)
            TEST_ARTIFACT("%s: %.0f bytes", labels[i], sizes[i]);
        tsapi_mde_mi_bars("dut", "Size of every built artifact",
                          TE_MI_MEAS_MEMORY, "size", n, labels, sizes,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
        tsapi_mde_dut_free(&dut);
    }

    TEST_STEP("Chart which tools the modules drive are on the agent");
    for (i = 0; i < TE_ARRAY_LEN(tools); i++)
    {
        have[i] = tsapi_mde_have(&session, tools[i]) ? 1 : 0;
        n_have += have[i] > 0;
        RING("%-20s %s", tools[i], have[i] > 0 ? "present" : "absent");
    }
    tsapi_mde_mi_bars("agent", "Tools present on the agent (1 = present)",
                      TE_MI_MEAS_UNITLESS_VALUE, "present",
                      TE_ARRAY_LEN(tools), tools, have,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("agent", "Tool coverage", TE_MI_MEAS_PERCENTAGE,
                       "coverage", 100.0 * n_have / TE_ARRAY_LEN(tools),
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("%u of %zu tools present on the agent", n_have,
                  TE_ARRAY_LEN(tools));

    TEST_SUCCESS;

cleanup:

    te_string_free(&path);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

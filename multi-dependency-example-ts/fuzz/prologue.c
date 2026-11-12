/** @file
 * @brief Fuzz Group
 *
 * Fuzz group prologue: can the agent's clang build a libFuzzer + ASan
 * target, which clang it is, and how many regression seeds earlier runs
 * left. Installs clang and its fuzzer runtime when they are missing. When
 * that fails, the reason is logged and recorded, and ring_abi and replay
 * SKIP naming this prologue instead of failing.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "fuzz/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "fuzz_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string           dir = TE_STRING_INIT;
    const char         *labels[MDE_FUZZ_N_TARGETS];
    double              seeds[MDE_FUZZ_N_TARGETS] = { 0 };
    unsigned int        count = 0;
    unsigned int        i;
    bool                clang;
    bool                supported = false;
    bool                symbolizer;
    double              t0;
    double              t_probe = 0;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "fuzz_prologue"));
    session_up = true;

    tsapi_mde_prologue_clear("fuzz");

    TEST_STEP("Install what the group needs on the agent and check it");
    TSAPI_MDE_ENSURE_GATED(session, "fuzz", "fuzz");

    TEST_STEP("Record the clang the group would build with");
    clang = tsapi_mde_have(&session, "clang");
    if (clang)
    {
        CHECK_RC(tsapi_mde_sh(&session, MDE_FUZZ_TIMEOUT_MS, &sh,
                              "clang --version | head -n 1"));
        TEST_ARTIFACT("clang: %s", te_string_value(&sh.out));
    }
    else
    {
        TEST_ARTIFACT("clang: absent (the fuzz tests will skip)");
    }
    symbolizer = tsapi_mde_have(&session, "llvm-symbolizer");
    TEST_ARTIFACT("llvm-symbolizer: %s", symbolizer ?
                  "present (crash stacks get function names)" :
                  "absent (crash signatures fall back to raw frames)");

    TEST_STEP("Probe -fsanitize=fuzzer,address");
    if (clang)
    {
        t0 = tsapi_mde_now();
        supported = mde_fuzz_supported(&session);
        t_probe = tsapi_mde_now() - t0;
    }
    TEST_ARTIFACT("libFuzzer + ASan: %s", supported ? "supported" :
                  "not supported");
    if (!supported)
        TSAPI_MDE_PROLOGUE_FAIL("fuzz", "clang cannot build with "
                                "-fsanitize=fuzzer,address after the "
                                "install (clang %s)", clang ? "present" :
                                "absent");
    tsapi_mde_mi_point("fuzz/prologue", "libFuzzer + ASan supported (1/0)",
                       TE_MI_MEAS_UNITLESS_VALUE, "supported",
                       supported ? 1 : 0, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("fuzz/prologue", "Compiler probe time",
                       TE_MI_MEAS_TIME, "probe_s", t_probe,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Count the regression seeds earlier runs kept");
    for (i = 0; i < MDE_FUZZ_N_TARGETS; i++)
    {
        labels[i] = mde_fuzz_target(i);
        te_string_reset(&dir);
        te_string_append(&dir, MDE_FUZZ_SEEDS_DIR "/%s", labels[i]);
        CHECK_RC(mde_fuzz_count_files(&session, dir.ptr, &count));
        seeds[i] = count;
        TEST_ARTIFACT("%s: %u regression seed(s)", labels[i], count);
    }
    tsapi_mde_mi_bars("fuzz/prologue", "Regression seeds per target",
                      TE_MI_MEAS_UNITLESS_VALUE, "seeds", MDE_FUZZ_N_TARGETS,
                      labels, seeds, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Create the group's directories");
    CHECK_RC(tsapi_mde_sh(&session, MDE_FUZZ_TIMEOUT_MS, &sh,
                          "mkdir -p " MDE_FUZZ_BUILD_DIR " "
                          MDE_FUZZ_SEEDS_DIR));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot create the fuzz directories on the agent");

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    te_string_free(&dir);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

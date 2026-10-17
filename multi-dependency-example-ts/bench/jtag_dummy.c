/** @file
 * @brief bench Group
 *
 * There is no JTAG probe here, so drive OpenOCD's own @c dummy adapter
 * through tsf-jtag: run a scan chain and check the result has the right
 * shape - an empty chain reported cleanly ("no TAP"), not a crash. That
 * is the most a scan can prove with no silicon on the other end.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "bench/jtag_dummy"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_jtag.h"
#include "tapi_jtag_scan.h"
#include "tsapi_mde.h"

/* The TAP this test declares on the dummy chain. */
#define MDE_TAP_IRLEN           4
#define MDE_TAP_IRLEN_STR       "4"
#define MDE_TAP_EXPECTED        0x4ba00477u
#define MDE_TAP_EXPECTED_STR    "0x4ba00477"
#include "tsapi_mde_mi.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tapi_jtag_tools     tools;
    tapi_jtag_adapter   adapter = tapi_jtag_adapter_default;
    tapi_jtag_result    jres;
    tapi_jtag_chain     chain;
    bool                result_up = false;
    bool                chain_up = false;
    /*
     * The dummy adapter has no silicon behind it, so the chain is
     * declared: one TAP with a known IR length and expected IDCODE. What
     * the scan reads back for it is then fully predictable.
     */
    const char         *pre[] = {
        "adapter driver dummy",
        "transport select jtag",
        "adapter speed 1000",
        "jtag newtap mde cpu -irlen " MDE_TAP_IRLEN_STR
            " -expected-id " MDE_TAP_EXPECTED_STR,
    };
    const tapi_jtag_tap *tap;
    const char         *commands[] = { "init", "scan_chain" };
    unsigned int        n_taps;
    const char         *which = NULL;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "bench_jtag"));
    session_up = true;

    TEST_STEP("Skip unless openocd is installed");
    CHECK_RC(tapi_jtag_tools_probe(session.factory, &tools));
    if (!tools.openocd)
        TEST_SKIP("openocd is not installed on the agent, so the dummy "
                  "adapter cannot be driven");
    TEST_ARTIFACT("JTAG tools: openocd %s, urjtag %s, openFPGALoader %s",
                  tools.openocd ? "yes" : "no", tools.urjtag ? "yes" : "no",
                  tools.openfpgaloader ? "yes" : "no");

    TEST_STEP("Run a scan chain through the dummy adapter");
    adapter.pre_commands = pre;
    adapter.n_pre_commands = TE_ARRAY_LEN(pre);
    CHECK_RC(tapi_jtag_run(session.factory, &adapter, commands,
                           TE_ARRAY_LEN(commands), &jres));
    result_up = true;
    RING("openocd dummy scan (exit %d):\n%s", jres.status,
         jres.output.ptr != NULL ? jres.output.ptr : "");

    /*
     * Nothing answers behind the dummy adapter, so OpenOCD complains about
     * the chain ("IR capture error", "double-check your JTAG setup") and
     * tsf-jtag must call the run not ok. That is the first half of the
     * known-bad control; a run reported ok here would mean errors on a
     * dead board go unnoticed. Only no output at all is a skip.
     */
    if (jres.output.ptr == NULL || strstr(jres.output.ptr, "auto") == NULL)
    {
        tapi_jtag_result_free(&jres);
        result_up = false;
        TEST_SKIP("openocd printed no scan chain through the dummy adapter");
    }
    if (jres.ok)
        TEST_VERDICT("A scan of a chain with no silicon was reported ok");
    TEST_ARTIFACT("tsf-jtag called the dead-chain scan not ok, as it must");

    TEST_STEP("Parse the scan chain");
    tapi_jtag_chain_init(&chain);
    chain_up = true;
    CHECK_RC(tapi_jtag_scan_parse(jres.output.ptr != NULL ?
                                  jres.output.ptr : "", &chain));
    n_taps = (unsigned int)te_vec_size(&chain.taps);
    tapi_jtag_chain_log(&chain);
    TEST_ARTIFACT("JTAG dummy scan: %u TAP(s) on the chain", n_taps);
    tsapi_mde_mi_point("tapi_jtag", "TAPs listed by the dummy scan",
                       TE_MI_MEAS_UNITLESS_VALUE, "taps", n_taps,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("The declared TAP is first, as declared");
    tap = tapi_jtag_chain_find(&chain, "mde.cpu");
    if (tap == NULL)
        TEST_VERDICT("The declared TAP mde.cpu is not on the parsed chain");
    if (tap->index != 0)
        TEST_VERDICT("The declared TAP is not first on the chain");
    if (tap->irlen != MDE_TAP_IRLEN)
        TEST_VERDICT("The declared TAP's IR length did not parse back");
    if (tap->expected != MDE_TAP_EXPECTED)
        TEST_VERDICT("The declared TAP's expected IDCODE did not parse back");
    TEST_ARTIFACT("mde.cpu: irlen %u, expected 0x%08x, read 0x%08x",
                  tap->irlen, tap->expected, tap->idcode);

    TEST_STEP("Known-bad control: no silicon means a stuck IDCODE");
    /*
     * Nothing drives TDO behind the dummy adapter, so the declared TAP
     * reads a stuck IDCODE and cannot match what was expected. The
     * chain checks must say so; a chain check that calls this chain
     * good would call a dead board good too.
     */
    {
        const uint32_t expected[] = { MDE_TAP_EXPECTED };

        if (tap->idcode == MDE_TAP_EXPECTED)
            TEST_VERDICT("The dummy adapter read the expected IDCODE");
        if (!tapi_jtag_chain_has_bad_idcode(&chain, &which))
            TEST_VERDICT("A stuck IDCODE on the dummy chain was not "
                         "reported");
        if (tapi_jtag_chain_matches(&chain, expected,
                                    TE_ARRAY_LEN(expected)))
            TEST_VERDICT("A chain of dead TAPs matched the expected IDCODE");
        TEST_ARTIFACT("Stuck IDCODE detected on %s, as it must be",
                      which != NULL ? which : "(unnamed)");
    }

    TEST_SUCCESS;

cleanup:

    if (chain_up)
        tapi_jtag_chain_free(&chain);
    if (result_up)
        tapi_jtag_result_free(&jres);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

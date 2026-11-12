/** @file
 * @brief Browser Group
 *
 * A ready 'playwright test' project, run on the agent through
 * tapi_playwright_run_spec(): a project a web developer would keep next
 * to the services, driven from TE. Two tests: the gateway answers for
 * itself (hops=0) and must pass; a control test holds a deliberately
 * wrong expectation and must fail. The test passes when the runner
 * reports exactly that outcome - one pass, one failure, and the failure
 * is the control - so it proves both that the project runs against the
 * tier and that the runner's failures reach TE. The walk with hops > 0
 * is checked by walk_page; it is kept out of here, since with the
 * injected defect it would make the outcome depend on the DUT.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "browser/pw_project"

#include "te_config.h"

#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_web.h"
#include "browser_common.h"

/* The project on the agent. */
#define PROJECT_DIR     "/tmp/mde-browser-pw-project"

/* Number of tests the spec declares. */
#define PROJECT_N_TESTS 2

/* Spec file of the project. */
#define PROJECT_SPEC    "walk.spec.cjs"

/* Title of the test that must pass. */
#define PROJECT_PASS    "gateway answers for itself"

/* Title of the control test that must fail. */
#define PROJECT_CONTROL "control: a deliberately wrong expectation fails"

/* How the runner names the failed control: "<spec file> > <title>". */
#define PROJECT_CONTROL_FAILURE PROJECT_SPEC " > " PROJECT_CONTROL

static const char project_spec[] =
    "// Written by multi-dependency-example-ts browser/pw_project.\n"
    "const { test, expect } = require('@playwright/test');\n"
    "\n"
    "const nodeLines = (text) => text.split('\\n')\n"
    "    .filter((l) => /^\\s*\\[(gateway-rs|service-go|service-cs)\\]"
    "\\s+hops=/.test(l)).length;\n"
    "\n"
    "test('" PROJECT_PASS "', async ({ page }) => {\n"
    "    await page.goto('http://127.0.0.1:8081/ring?value=1&hops=0');\n"
    "    await expect(page.locator('body'))"
    ".toContainText('[gateway-rs] hops=0');\n"
    "    expect(nodeLines(await page.locator('body').innerText()))"
    ".toBe(1);\n"
    "});\n"
    "\n"
    "// Control: the gateway page always has one node line for hops=0,\n"
    "// so expecting none fails whatever the web tier does.\n"
    "test('" PROJECT_CONTROL "', async ({ page }) => {\n"
    "    await page.goto('http://127.0.0.1:8081/ring?value=1&hops=0');\n"
    "    expect(nodeLines(await page.locator('body').innerText()))"
    ".toBe(0);\n"
    "});\n";

static const char project_config[] =
    "// Written by multi-dependency-example-ts browser/pw_project.\n"
    "module.exports = {\n"
    "    testDir: '.',\n"
    "    testMatch: /.*\\.spec\\.cjs$/,\n"
    "    retries: 0,\n"
    "    workers: 1,\n"
    "    use: { headless: true },\n"
    "};\n";

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tsapi_mde_web       web;
    bool                web_started = false;
    bool                project_made = false;
    tapi_playwright    *pw = NULL;
    tapi_playwright_spec_result spec;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    unsigned int        total;
    double              t0;
    double              t_run;

    TEST_START;
    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));
    memset(&spec, 0, sizeof(spec));
    spec.failures = (te_string)TE_STRING_INIT;

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "browser_pwproj", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_VERDICT("The web tier is not built - build the example first");
    browser_skip_unless_ready(&session);
    if (!tsapi_mde_exists(&session,
                          BROWSER_PW_DIR "/node_modules/@playwright/test"))
    {
        TEST_VERDICT("@playwright/test is not installed in " BROWSER_PW_DIR
                  ", 'playwright test' cannot run");
    }
    if (!tsapi_mde_have(&session, "npx"))
        TEST_VERDICT("npx is not installed on the agent");

    TEST_STEP("Write the project to " PROJECT_DIR);
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "rm -rf '" PROJECT_DIR "' && "
                          "mkdir -p '" PROJECT_DIR "' && "
                          "ln -s '" BROWSER_PW_DIR "/node_modules' '"
                          PROJECT_DIR "/node_modules'"));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot prepare " PROJECT_DIR ": %s", sh.err.ptr);
    project_made = true;
    CHECK_RC(tapi_file_create_ta(session.ta,
                                 PROJECT_DIR "/playwright.config.cjs", "%s",
                                 project_config));
    CHECK_RC(tapi_file_create_ta(session.ta, PROJECT_DIR "/" PROJECT_SPEC,
                                 "%s", project_spec));

    TEST_STEP("Start the web tier and the Playwright runner");
    web_started = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    browser_open(&session, false, false, false, &pw);

    TEST_STEP("Run 'playwright test' in the project");
    t0 = tsapi_mde_now();
    rc = tapi_playwright_run_spec(pw, PROJECT_DIR, NULL, NULL, &spec);
    t_run = tsapi_mde_now() - t0;
    /* The control fails, so TE_EFAIL is the expected status. */
    if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_EFAIL)
        TEST_VERDICT("'playwright test' did not produce a report");
    rc = 0;

    total = spec.passed + spec.failed + spec.skipped + spec.flaky;
    TEST_ARTIFACT("playwright test: %u passed, %u failed, %u skipped, "
                  "%u flaky in %.1f s; failed: %s", spec.passed,
                  spec.failed, spec.skipped, spec.flaky, t_run,
                  spec.failures.ptr != NULL ? spec.failures.ptr : "-");
    {
        const char *labels[] = { "passed", "failed", "skipped", "flaky" };
        double      vals[4];

        vals[0] = spec.passed;
        vals[1] = spec.failed;
        vals[2] = spec.skipped;
        vals[3] = spec.flaky;
        tsapi_mde_mi_bars("browser", "playwright test outcomes",
                          TE_MI_MEAS_UNITLESS_VALUE, "tests",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    tsapi_mde_mi_point("browser", "playwright test run time", TE_MI_MEAS_TIME,
                       "run", t_run, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Check the outcome against the one expected");
    if (total != PROJECT_N_TESTS)
    {
        TEST_VERDICT("playwright test reported %u test(s), the project has "
                     "%u", total, PROJECT_N_TESTS);
    }
    if (spec.failed == 0)
        TEST_VERDICT("The control test did not fail");
    if (spec.skipped != 0 || spec.flaky != 0)
    {
        TEST_VERDICT("playwright test: %u skipped, %u flaky, expected none",
                     spec.skipped, spec.flaky);
    }
    if (spec.passed != 1 || spec.failed != 1)
    {
        TEST_VERDICT("playwright test: %u passed, %u failed, expected 1 "
                     "passed (the gateway test), 1 failed (the control)",
                     spec.passed, spec.failed);
    }
    if (strcmp(te_string_value(&spec.failures),
               PROJECT_CONTROL_FAILURE) != 0)
    {
        ERROR("Failed tests: '%s', expected only '%s'",
              te_string_value(&spec.failures), PROJECT_CONTROL_FAILURE);
        TEST_VERDICT("The failed test is not the control: the gateway test "
                     "failed and the control passed");
    }
    TEST_ARTIFACT("Outcome as expected: '%s' passed, '%s' failed",
                  PROJECT_PASS, PROJECT_CONTROL);

    TEST_SUCCESS;

cleanup:

    tapi_playwright_destroy(pw);
    if (web_started)
        tsapi_mde_web_stop(&web);
    if (project_made)
    {
        CLEANUP_CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                                      "rm -rf '" PROJECT_DIR "'"));
    }
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&spec.failures);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

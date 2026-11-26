/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example Group
 *
 * ts_example group prologue: check that the tools the four tests need are on
 * the agent (they are installed by scripts/midair-setup.sh, never here) and
 * report the project root. It builds nothing and installs nothing: the build
 * is the first test of the group, which logs it step by step. When a tool is
 * missing the prologue fails and names it.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/prologue"

#include "te_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"

int
main(int argc, char **argv)
{
    static const char * const need[] = {
        "bash", "node", "npm", "npx", "tsc", "find", "gcc", "curl", "tar",
    };
    const char *root;
    char        missing[256] = "";
    size_t      i;

    TEST_START;

    TEST_STEP("Report the project under test");
    root = getenv("TE_TS_MDE_SRC");
    if (root == NULL || root[0] == '\0')
        TEST_VERDICT("H1 NOT SETTLED: TE_TS_MDE_SRC is not set, so the "
                     "ts_example group has no project root");
    RING("ts_example: project root %s", root);

    TEST_STEP("Check the tools of the group");
    for (i = 0; i < sizeof(need) / sizeof(need[0]); i++)
    {
        char cmd[128];

        snprintf(cmd, sizeof(cmd), "command -v %s >/dev/null 2>&1", need[i]);
        if (system(cmd) != 0)
        {
            ERROR("%s is not on the agent", need[i]);
            strncat(missing, need[i], sizeof(missing) - strlen(missing) - 2);
            strncat(missing, " ", sizeof(missing) - strlen(missing) - 1);
        }
    }
    TEST_STEP("Check that scripts/midair-setup.sh ran on this machine");
    if (access("/var/tmp/midair-setup.done", R_OK) != 0)
    {
        ERROR("/var/tmp/midair-setup.done is missing: scripts/midair-setup.sh "
              "was not copied to this agent or did not run before the tests");
        if (missing[0] != '\0')
            TEST_VERDICT("H2 NOT SETTLED: %sis missing on the agent and "
                         "/var/tmp/midair-setup.done is absent: "
                         "scripts/midair-setup.sh did not run here before the "
                         "tests", missing);
    }
    else
        system("cat /var/tmp/midair-setup.done");
    if (missing[0] != '\0')
        TEST_VERDICT("H2 NOT SETTLED: %sis missing on the agent: "
                     "scripts/midair-setup.sh did not install it", missing);

    TEST_SUCCESS;

cleanup:
    TEST_END;
}

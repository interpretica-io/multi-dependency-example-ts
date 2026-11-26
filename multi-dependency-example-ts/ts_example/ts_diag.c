/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_diag, the plain diagnostic (settles H5)
 *
 * Uses no helper and no skip logic. Runs eight commands with system(),
 * stdout and stderr redirected to /tmp/ts_diag_<n>.log, reads each file
 * back and puts the first 400 bytes and the exit code into a verdict. A
 * verdict that does not end the test is used (RING_VERDICT): TEST_VERDICT
 * stops the test at once, so only the first command would be seen. The
 * test ends with TEST_SUCCESS and passes whenever it runs. When it shows
 * verdicts, H5 is false: the suite does report results, and the fault of
 * the other tests is elsewhere.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_diag"

#include "te_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "tsd.h"

int
main(int argc, char **argv)
{
    static const char * const cmds[] = {
        "id",
        "pwd",
        "ls -la /work /work/src",
        "node -v",
        "npm -v",
        "npx tsc -v",
        "find /work/src -name \"*.ts\" -not -path \"*/node_modules/*\"",
        "ls /work/src/ts",
    };
    unsigned i;

    TEST_START;
    tsd_say("H5 start");

    for (i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
    {
        char    path[64];
        char    full[512];
        char    head[401];
        FILE   *f;
        size_t  got = 0;
        int     st;
        int     code;

        snprintf(path, sizeof(path), "/tmp/ts_diag_%u.log", i + 1);
        snprintf(full, sizeof(full), "%s > %s 2>&1", cmds[i], path);
        TEST_STEP("Run %s", cmds[i]);
        st = system(full);
        if (st == -1)
            code = -1;
        else if (WIFEXITED(st))
            code = WEXITSTATUS(st);
        else
            code = 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
        head[0] = '\0';
        f = fopen(path, "r");
        if (f != NULL)
        {
            got = fread(head, 1, sizeof(head) - 1, f);
            fclose(f);
            head[got] = '\0';
        }
        RING_VERDICT("H5 ts_diag command %u [%s] exit code %d, %s, first "
                     "%zu bytes of %s: [%s]", i + 1, cmds[i], code,
                     f != NULL ? "log read" : "log NOT readable", got, path,
                     head);
    }

    {
        static const char *const vc[] = { "node --version", "npm --version",
                                          "tsc --version",
                                          "ls /work/src" };
        char     all[1500] = "";
        char     bad[200] = "";
        char     one[401];
        unsigned k;

        for (k = 0; k < 4; k++)
        {
            char log[48];
            int  c;

            snprintf(log, sizeof(log), "/tmp/ts_diag_v%u.log", k + 1);
            TEST_STEP("Run %s", vc[k]);
            c = tsd_sh("/", vc[k], 60, log);
            tsd_head(log, one, sizeof(one));
            if (c != 0)
                snprintf(bad + strlen(bad), sizeof(bad) - strlen(bad),
                         "%s ", vc[k]);
            snprintf(all + strlen(all), sizeof(all) - strlen(all),
                     "[%s exit=%d: %.300s] ", vc[k], c, one);
        }
        if (bad[0] != '\0')
            tsd_say("H5 versions: FAILED commands: %s; %s", bad, all);
        else
            tsd_say("H5 versions: all commands ran; %s", all);
    }

    TEST_SUCCESS;

cleanup:
    TEST_END;
}

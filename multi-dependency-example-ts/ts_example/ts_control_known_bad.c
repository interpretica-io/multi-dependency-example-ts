/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_control_known_bad, a check on the suite itself
 *        (H2, H3 and H4)
 *
 * Runs `sh -c 'echo bad >&2; exit 3'` through the shell helper that every
 * test of the group uses and requires that the verdict text it produces
 * carries exit code 3 and the text "bad" that went to stderr. A planted
 * good command (exit 0, text on stdout) must read as exit code 0 with its
 * text, so the helper is checked in both directions. When the verdict text
 * is empty, the log capture does not work and none of the H2, H3 and H4
 * verdicts of the group can be trusted; the test fails and says so.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_control_known_bad"

#include "te_config.h"

#include "tsx_lib.h"

#define IDS "H2 H3 H4"

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    tsx_sh_t   *bad = calloc(1, sizeof(*bad));
    tsx_sh_t   *good = calloc(1, sizeof(*good));
    char       *vtext = malloc(4200);

    TEST_START;
    t_report_begin();
    signal(SIGPIPE, SIG_IGN);
    if (bad == NULL || good == NULL || vtext == NULL)
    {
        res_set(&res, R_FAIL, IDS " NOT SETTLED: out of memory");
        goto verdict;
    }

    TSX_STEP("Run a command that writes bad to stderr and exits with 3");
    if (!tsx_sh(bad, "CTL", "ctl-bad", "/",
                "sh -c 'echo bad >&2; exit 3'", 30, NULL))
    {
        res_set(&res, R_FAIL, IDS " FAIL: the shell helper could not run "
                "the planted command, so its log capture does not work");
        goto verdict;
    }
    tsx_sh_text(bad, vtext, 4200);
    RING(IDS ": verdict text of the planted bad command: %s", vtext);
    if (vtext[0] == '\0')
    {
        res_set(&res, R_FAIL, IDS " FAIL: the verdict text is empty: the "
                "log capture does not work");
        goto verdict;
    }
    if (bad->code != 3 || strstr(vtext, "exit code 3") == NULL)
    {
        res_set(&res, R_FAIL, IDS " FAIL: the planted exit code 3 was read "
                "as %d; verdict text [%s]", bad->code, vtext);
        goto verdict;
    }
    if (strstr(vtext, "bad") == NULL || strstr(bad->text, "bad") == NULL)
    {
        res_set(&res, R_FAIL, IDS " FAIL: the text bad written to stderr is "
                "not in the captured output or the verdict; verdict text "
                "[%s]", vtext);
        goto verdict;
    }
    if (tsx_sh_ok(bad))
    {
        res_set(&res, R_FAIL, IDS " FAIL: a command that exits 3 was "
                "reported as a success");
        goto verdict;
    }

    TSX_STEP("Run a good command: stdout text, exit code 0");
    if (!tsx_sh(good, "CTL", "ctl-good", "/",
                "echo fine; echo noise >&2", 30, NULL) ||
        !tsx_sh_ok(good) || strstr(good->text, "fine") == NULL ||
        strstr(good->text, "noise") == NULL)
    {
        tsx_sh_text(good, vtext, 4200);
        res_set(&res, R_FAIL, IDS " FAIL: a planted good command was not "
                "read as exit code 0 with both of its streams: %s", vtext);
        goto verdict;
    }

    TSX_STEP("Run a command that never ends: the time limit must be seen");
    if (!tsx_sh(good, "CTL", "ctl-hang", "/", "echo start; sleep 30", 2,
                NULL) || !good->hung || strstr(good->text, "start") == NULL)
    {
        tsx_sh_text(good, vtext, 4200);
        res_set(&res, R_FAIL, IDS " FAIL: a planted hang was not reported "
                "as killed on the time limit with its output: %s", vtext);
        goto verdict;
    }

    res_set(&res, R_PASS, IDS " PASS: the shell helper reads exit code 3 and "
            "the stderr text bad of a planted failing command into the "
            "verdict [%s], a good command as exit code 0 and a hang as "
            "killed on the time limit; the log capture works", vtext);
    T_FINDING(TAPI_CYBERSEC_SEV_INFO, "ts.control", "shell helper", "%s",
              res.msg);
    RING("%s", res.msg);
    res_set(&res, R_PASS, IDS " PASS: the shell helper control tripped");

verdict:
    free(bad);
    free(good);
    free(vtext);
    TSX_VERDICT(&res, IDS);

cleanup:
    cleanup_all();
    TEST_END;
}

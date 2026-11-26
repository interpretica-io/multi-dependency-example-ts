/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_bad_input, bad input gives a short error and no
 *        hardcoded address (settles H2 and backs H3)
 *
 * Starts the TypeScript example through ./scripts/run.sh guess with empty,
 * non-numeric, very long non-numeric and very long numeric input, each under
 * a 10 s timeout. Every run must exit non-zero (not by the timeout, not by
 * a signal), print a short error and no stack trace. A planted stack trace
 * checks the detector. Then the TypeScript sources are searched, outside
 * whole-line comments, for a literal IP address or http(s) URL.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_bad_input"

#include "tsd.h"

#define MAX_ERR_BYTES   400

/** Literal IPv4 address or http(s) URL in ts/src, loopback included. */
#define SCAN "grep -rnE --include='*.ts' --exclude-dir=node_modules " \
             "-e '[0-9]{1,3}(\\.[0-9]{1,3}){3}' -e 'https?://' ts/src " \
             "| grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\\*|/\\*)'"

/** A stack trace or a crash dump in text. */
static bool
has_trace(const char *t)
{
    return strstr(t, "\n    at ") != NULL || strstr(t, "node:internal") != NULL ||
           strstr(t, "Uncaught") != NULL || strstr(t, "Traceback") != NULL ||
           strstr(t, "panicked") != NULL || strstr(t, "    at ") == t;
}

static void
one_case(const char *name, const char *prep, const char *arg_expr)
{
    char        cmd[1024];
    char        log[64];
    char        text[MAX_ERR_BYTES + 200];
    char        shown[401];
    char        word[64];
    int         code;
    size_t      n;
    long long   t0 = tsd_ms();

    snprintf(log, sizeof(log), "/tmp/ts_bi_%s.log", name);
    snprintf(cmd, sizeof(cmd), "%s timeout -k 2 10 ./scripts/run.sh guess "
             "%s", prep, arg_expr);
    code = tsd_sh(tsd_src(), cmd, 20, log);
    n = tsd_head(log, text, sizeof(text));
    tsd_clean(text, shown, sizeof(shown));
    snprintf(word, sizeof(word), "%s", name);
    if (code == 124 || code == 137 || code == 143 || tsd_ms() - t0 > 10500)
        tsd_bad("H3", word, "killed by the 10 s timeout (exit %d): [%s]",
                code, shown);
    else if (code == 0)
        tsd_bad("H3", word, "exit 0 on bad input: [%s]", shown);
    else if (code > 128)
        tsd_bad("H3", word, "killed by signal %d: [%s]", code - 128, shown);
    else if (has_trace(text))
        tsd_bad("H3", word, "prints a stack trace, exit %d: [%s]", code,
                shown);
    else if (n == 0 || n > MAX_ERR_BYTES)
        tsd_bad("H3", word, "message is %zu bytes (want 1 to %d), exit %d: "
                "[%s]", n, MAX_ERR_BYTES, code, shown);
    else
        tsd_say("H3 %s ok: exit=%d after %lld ms, message [%s]", word, code,
                tsd_ms() - t0, shown);
}

int
main(int argc, char **argv)
{
    const char *src = tsd_src();
    char        out[801];
    int         code;

    TEST_START;

    TEST_STEP("Control: the trace detector sees a planted trace");
    if (!has_trace("Error: boom\n    at f (x.js:1:1)\n") ||
        has_trace("ts-demo: error: usage: demo [value] [hops]\n"))
        TEST_FAIL("H3 NOT SETTLED: the stack trace detector is wrong");

    TEST_STEP("Control: the address scan sees planted literals");
    system("rm -rf /tmp/ts_bi_plant; mkdir -p /tmp/ts_bi_plant/ts/src");
    tsd_put("/tmp/ts_bi_plant/ts/src/a.ts", "const u = \"http://x\";\n");
    tsd_put("/tmp/ts_bi_plant/ts/src/b.ts", "const h = \"127.0.0.1\";\n");
    tsd_put("/tmp/ts_bi_plant/ts/src/c.ts", "// 10.0.0.1 in a comment\nconst k = 1;\n");
    if (tsd_sh("/tmp/ts_bi_plant", SCAN, 30, "/tmp/ts_bi_ctl.log") != 0)
        TEST_FAIL("H2 NOT SETTLED: the address scan found no planted literal");
    else
    {
        char c[801];

        tsd_head("/tmp/ts_bi_ctl.log", c, sizeof(c));
        if (strstr(c, "a.ts") == NULL || strstr(c, "b.ts") == NULL ||
            strstr(c, "c.ts") != NULL)
            TEST_FAIL("H2 NOT SETTLED: the address scan is wrong on planted "
                      "files: [%.300s]", c);
    }

    TEST_STEP("The project root and the build");
    if (src[0] == '\0' || access(src, X_OK) != 0)
        TEST_FAIL("H3 FAIL: TE_TS_MDE_SRC is [%s], not a directory", src);
    if (!tsd_have_main(out, sizeof(out)))
        TEST_FAIL("H3 blocked by H1: %s is missing, ./build.sh did not make "
                  "the TypeScript example", out);

    TEST_STEP("Empty input");
    one_case("empty", "", "''");
    TEST_STEP("Non-numeric input");
    one_case("nonnumeric", "", "abc");
    TEST_STEP("Very long non-numeric input");
    one_case("long_text", "A=$(head -c 100000 /dev/zero | tr '\\0' a);",
             "\"$A\"");
    TEST_STEP("Very long numeric input");
    one_case("long_digits", "A=$(head -c 100000 /dev/zero | tr '\\0' 9);",
             "\"$A\" 3");

    TEST_STEP("Search the TypeScript sources for a literal address or URL");
    code = tsd_sh(src, SCAN, 30, "/tmp/ts_bi_scan.log");
    tsd_head("/tmp/ts_bi_scan.log", out, sizeof(out));
    if (code == 0)
        tsd_bad("H2", "address", "literal IP address or URL in ts/src: [%.600s]",
                out);
    else if (code == 1)
        tsd_say("H2 address ok: no literal IP address or URL in ts/src");
    else
        tsd_bad("H2", "address", "search failed, exit %d: [%s]", code, out);

    TSD_PASS("H2 H3", "no literal address in ts/src; bad input gives a "
             "short error and a non-zero exit");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}

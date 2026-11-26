/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_bad_input, the TypeScript demo exits at once with one
 *        error line when RING_HOST or RING_PORT is unset or bad, the README
 *        matches, and the source holds no literal address (settles H3)
 *
 * The demo (node dist/demo.js) is started directly (no listener is started
 * first and none is waited for) with RING_HOST unset, RING_PORT unset and
 * both bad. Each must
 * exit with code 1 in under 2 s with one error line and no stack trace. A
 * text check requires the README to name RING_HOST and RING_PORT as required and not to
 * contain 127.0.0.1:9100.
 * Scan: searches ts/src and web/service-ts/src for a literal IPv4 address,
 * "localhost" and "http://" or "https://". A line that holds only a comment
 * is excluded and the test logs each such exclusion. Every hit is printed as
 * file:line, or "scan: 0 hits"; any hit fails.
 * Exit cases: runs the HTTP variant (node dist/main.js and run.sh guess serve) and
 * service-ts with RING_HOST and RING_PORT unset, with one of them unset and
 * with a non-numeric or out-of-range RING_PORT. Each run must exit
 * within 2 s, non-zero, with exactly one output line and no stack trace and
 * name the variable. The demo with bad arguments (empty, non-numeric, very
 * long) must also exit non-zero in 10 s with a short error and no trace.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_bad_input"

#include "tsd.h"

#define MAX_ERR_BYTES   400

/** Directories scanned, when they exist. */
#define SCAN_DIRS   "ts/src web/service-ts/src"

/**
 * Every hit of a literal IPv4 address, "localhost" or http(s):// in the
 * TypeScript source, comments included, as file:line:text.
 */
#define SCAN_ALL \
    "d=; for x in " SCAN_DIRS "; do [ -d $x ] && d=\"$d $x\"; done; " \
    "[ -n \"$d\" ] || exit 2; " \
    "grep -rnEi --include='*.ts' --exclude-dir=node_modules " \
    "-e '[0-9]{1,3}(\\.[0-9]{1,3}){3}' -e 'localhost' -e 'https?://' $d"

/** A hit on a line that holds only a comment. */
#define COMMENT_RE  "^[^:]+:[0-9]+:[[:space:]]*(//|\\*|/\\*)"

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
    snprintf(cmd, sizeof(cmd), "export RING_HOST=127.0.0.1 RING_PORT=9; "
             "%s timeout -k 2 10 ./scripts/run.sh guess "
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

/** Lines of a log with text, and whether it holds a stack trace. */
static int
count_lines(const char *t)
{
    int  n = 0;
    bool text = false;

    for (; *t != '\0'; t++)
    {
        if (*t == '\n')
        {
            n += text;
            text = false;
        }
        else if (*t != '\r' && *t != ' ')
            text = true;
    }
    return n + text;
}

/**
 * Scan @p root: print every hit as file:line (comment-only lines are
 * excluded and each exclusion is printed), return the number of hits, or -1
 * when the scan itself failed. @p first gets the first hits for a verdict.
 */
static int
scan_source(const char *root, char *first, size_t fsize)
{
    char   all[8192];
    char   line[1024];
    char  *p;
    int    code;
    int    hits = 0;
    int    shown = 0;

    first[0] = '\0';
    code = tsd_sh(root, SCAN_ALL, 30, "/tmp/ts_bi_scan.log");
    tsd_tail("/tmp/ts_bi_scan.log", all, sizeof(all));
    if (code == 1)
    {
        tsd_say("scan: 0 hits");
        return 0;
    }
    if (code != 0)
    {
        tsd_head("/tmp/ts_bi_scan.log", all, 301);
        tsd_say("scan failed, exit %d: [%s]", code, all);
        return -1;
    }
    tsd_head("/tmp/ts_bi_scan.log", all, sizeof(all));
    for (p = all; *p != '\0'; )
    {
        char *e = strchr(p, '\n');
        size_t n = e != NULL ? (size_t)(e - p) : strlen(p);
        char  ref[256];
        char *c1;
        char *c2;

        snprintf(line, sizeof(line), "%.*s", (int)(n < 600 ? n : 600), p);
        p += n + (e != NULL);
        if (line[0] == '\0')
            continue;
        c1 = strchr(line, ':');
        c2 = c1 != NULL ? strchr(c1 + 1, ':') : NULL;
        snprintf(ref, sizeof(ref), "%.*s", c2 != NULL ? (int)(c2 - line) :
                 (int)strlen(line) > 200 ? 200 : (int)strlen(line), line);
        if (c2 != NULL && c1 != NULL)
        {
            const char *t = c2 + 1;

            while (*t == ' ' || *t == '\t')
                t++;
            if (strncmp(t, "//", 2) == 0 || strncmp(t, "*", 1) == 0 ||
                strncmp(t, "/*", 2) == 0)
            {
                tsd_say("scan: excluded, comment only: %s [%.120s]", ref, t);
                continue;
            }
        }
        hits++;
        tsd_say("scan: hit %s [%.120s]", ref, c2 != NULL ? c2 + 1 : line);
        if (shown++ < 6)
        {
            size_t l = strlen(first);

            snprintf(first + l, fsize - l, "%s; ", ref);
        }
    }
    return hits;
}

/**
 * The README of the project names RING_HOST and RING_PORT and no README
 * holds the default 127.0.0.1:9100. Returns true when so; @p why gets the
 * reason otherwise.
 */
static bool
readme_ok(const char *root, char *why, size_t size)
{
    int code = tsd_sh(root,
        "[ -s README.md ] || { echo 'README.md is missing or empty'; exit 1; }; "
        "grep -q RING_HOST README.md || { echo 'README.md does not name "
        "RING_HOST'; exit 1; }; "
        "grep -q RING_PORT README.md || { echo 'README.md does not name "
        "RING_PORT'; exit 1; }; "
        "for v in RING_HOST RING_PORT; do grep -A2 -E \"$v\" README.md | "
        "grep -qi required || { echo \"README.md does not say $v is "
        "required\"; exit 1; }; done; "
        "f=$(grep -lF '127.0.0.1:9100' README.md ts/README.md "
        "web/service-ts/README.md 2>/dev/null); "
        "[ -z \"$f\" ] || { echo \"default 127.0.0.1:9100 stated in $f\"; "
        "exit 1; }", 10, "/tmp/ts_bi_readme.log");

    tsd_head("/tmp/ts_bi_readme.log", why, size);
    why[strcspn(why, "\n")] = '\0';
    return code == 0;
}

/**
 * Run the TypeScript program @p cmd (from @p cwd) with the environment
 * @p envp in front, and check H3: exit within 2 s, non-zero, one line, no
 * trace, and @p must (a variable name) in the line.
 */
static void
env_case(const char *name, const char *cwd, const char *envp, const char *cmd,
         const char *must)
{
    char      full[1024];
    char      log[96];
    char      text[1201];
    char      shown[401];
    long long t0;
    long long ms;
    int       code;
    int       lines;

    snprintf(log, sizeof(log), "/tmp/ts_bi_env_%s.log", name);
    snprintf(full, sizeof(full), "%s timeout -k 2 10 %s", envp, cmd);
    t0 = tsd_ms();
    code = tsd_sh(cwd, full, 20, log);
    ms = tsd_ms() - t0;
    tsd_head(log, text, sizeof(text));
    tsd_clean(text, shown, sizeof(shown));
    lines = count_lines(text);
    if (code == 124 || code == 137 || code == 143)
        tsd_bad("H3", name, "no exit before the 10 s limit (exit %d, %lld "
                "ms): [%s]", code, ms, shown);
    else if (ms > 2000)
        tsd_bad("H3", name, "took %lld ms to exit (limit 2000), exit %d: "
                "[%s]", ms, code, shown);
    else if (code == 0)
        tsd_bad("H3", name, "exit 0 with a missing or bad variable: [%s]",
                shown);
    else if (code > 128)
        tsd_bad("H3", name, "killed by signal %d: [%s]", code - 128, shown);
    else if (code != 1)
        tsd_bad("H3", name, "exit code %d, want 1: [%s]", code, shown);
    else if (has_trace(text))
        tsd_bad("H3", name, "prints a stack trace, exit %d: [%s]", code,
                shown);
    else if (lines != 1)
        tsd_bad("H3", name, "%d output lines (want 1), exit %d: [%s]", lines,
                code, shown);
    else if (must != NULL && strstr(text, must) == NULL)
        tsd_bad("H3", name, "the line does not name %s: [%s]", must, shown);
    else
        tsd_say("H3 %s ok: exit=%d after %lld ms, one line [%s]", name, code,
                ms, shown);
}

int
main(int argc, char **argv)
{
    const char *src = tsd_src();
    char        out[801];
    char        ts[PATH_MAX];
    char        svc[PATH_MAX];
    char        envp[160];
    char        first[400];
    unsigned    port;
    int         hits;

    TEST_START;

    TEST_STEP("Control: the trace detector sees a planted trace");
    if (!has_trace("Error: boom\n    at f (x.js:1:1)\n") ||
        has_trace("ts-demo: error: usage: demo [value] [hops]\n"))
        TEST_FAIL("H3 NOT SETTLED: the stack trace detector is wrong");
    if (count_lines("a\nb\n") != 2 || count_lines("one\n") != 1 ||
        count_lines("") != 0 || count_lines("one") != 1)
        TEST_FAIL("H3 NOT SETTLED: the line counter is wrong");

    TEST_STEP("Control: the address scan sees planted literals");
    system("rm -rf /tmp/ts_bi_plant; mkdir -p /tmp/ts_bi_plant/ts/src");
    tsd_put("/tmp/ts_bi_plant/ts/src/a.ts", "const u = \"http://x\";\n");
    tsd_put("/tmp/ts_bi_plant/ts/src/b.ts", "const h = \"127.0.0.1\";\n");
    tsd_put("/tmp/ts_bi_plant/ts/src/d.ts", "const l = \"LocalHost\";\n");
    tsd_put("/tmp/ts_bi_plant/ts/src/e.ts", "const s = \"https://y\";\n");
    tsd_put("/tmp/ts_bi_plant/ts/src/c.ts", "// 10.0.0.1 in a comment\nconst k = 1;\n");
    hits = scan_source("/tmp/ts_bi_plant", first, sizeof(first));
    if (hits != 4 || strstr(first, "a.ts") == NULL ||
        strstr(first, "b.ts") == NULL || strstr(first, "d.ts") == NULL ||
        strstr(first, "e.ts") == NULL || strstr(first, "c.ts") != NULL)
        TEST_FAIL("H3 NOT SETTLED: the scan found %d hit(s) in the planted "
                  "files, want 4 (a.ts b.ts d.ts e.ts, not the comment in "
                  "c.ts): [%.200s]", hits, first);
    tsd_say("H3 control: the scan sees every planted literal and excludes "
            "only the listed comment");

    TEST_STEP("Control: the README text check sees planted READMEs");
    {
        char why[200];

        system("rm -rf /tmp/ts_bi_rd; mkdir -p /tmp/ts_bi_rd");
        tsd_put("/tmp/ts_bi_rd/README.md", "RING_HOST and RING_PORT are both required.\n");
        if (!readme_ok("/tmp/ts_bi_rd", why, sizeof(why)))
            TEST_FAIL("H3 NOT SETTLED: a good planted README was rejected: "
                      "[%s]", why);
        tsd_put("/tmp/ts_bi_rd/README.md", "RING_HOST RING_PORT required, default "
                "127.0.0.1:9100\n");
        if (readme_ok("/tmp/ts_bi_rd", why, sizeof(why)))
            TEST_FAIL("H3 NOT SETTLED: a README with 127.0.0.1:9100 was "
                      "accepted");
        tsd_put("/tmp/ts_bi_rd/README.md", "Set RING_HOST and RING_PORT.\n");
        if (readme_ok("/tmp/ts_bi_rd", why, sizeof(why)))
            TEST_FAIL("H3 NOT SETTLED: a README that does not say the "
                      "variables are required was accepted");
        tsd_put("/tmp/ts_bi_rd/README.md", "RING_HOST is required.\n");
        if (readme_ok("/tmp/ts_bi_rd", why, sizeof(why)))
            TEST_FAIL("H3 NOT SETTLED: a README without RING_PORT was "
                      "accepted");
        tsd_say("H3 control: planted READMEs are judged as expected");
    }

    TEST_STEP("The project root and the build");
    if (src[0] == '\0' || access(src, X_OK) != 0)
        TEST_FAIL("H3 FAIL: TE_TS_MDE_SRC is [%s], not a directory", src);

    TEST_STEP("H3: search the TypeScript source for a literal address");
    hits = scan_source(src, first, sizeof(first));
    if (hits > 0)
        tsd_bad("H3", "address", "%d literal IPv4 address, localhost or URL "
                "hit(s): %s", hits, first);
    else if (hits < 0)
        tsd_bad("H3", "address", "the scan could not run in %s", src);
    else
        tsd_say("H3 address ok: scan: 0 hits");

    TEST_STEP("H3: the build");
    if (!tsd_have_main(out, sizeof(out)))
        TEST_FAIL("H3 blocked by H1: %s is missing, ./build.sh did not make "
                  "the TypeScript example", out);

    snprintf(ts, sizeof(ts), "%s/ts", src);
    snprintf(svc, sizeof(svc), "%s/dist/bin/service-ts", src);
    port = tsd_free_port();

    TEST_STEP("H3: the README names RING_HOST and RING_PORT, no 127.0.0.1:9100");
    if (!readme_ok(src, out, 300))
        tsd_bad("H3", "README", "%s", out);
    else
        tsd_say("H3 README names RING_HOST and RING_PORT and states no "
                "127.0.0.1:9100 default");

    TEST_STEP("H3: node dist/demo.js started directly, RING_HOST unset and "
              "RING_PORT unset");
    env_case("demo_both_unset", ts, "env -u RING_HOST -u RING_PORT",
             "node dist/demo.js", "RING_");
    TEST_STEP("H3: node dist/demo.js started directly, RING_HOST unset");
    env_case("demo_host_unset", ts, "env -u RING_HOST RING_PORT=9",
             "node dist/demo.js 42 3", "RING_HOST");
    TEST_STEP("H3: node dist/demo.js started directly, RING_PORT unset");
    env_case("demo_port_unset", ts, "env -u RING_PORT RING_HOST=127.0.0.1",
             "node dist/demo.js 42 3", "RING_PORT");
    TEST_STEP("H3: node dist/demo.js started directly, both bad");
    env_case("demo_both_bad", ts, "env RING_HOST= RING_PORT=abc",
             "node dist/demo.js 42 3", "RING_");

    TEST_STEP("H3: dist/main.js started directly, RING_HOST unset, exit time");
    env_case("direct_host_unset", ts, "env -u RING_HOST RING_PORT=9",
             "node dist/main.js", "RING_HOST");
    TEST_STEP("H3: demo started directly, RING_PORT unset, exit time");
    env_case("direct_port_unset", ts, "env -u RING_PORT RING_HOST=127.0.0.1",
             "node dist/main.js", "RING_PORT");
    TEST_STEP("H3: demo started directly, both bad, exit time");
    env_case("direct_both_bad", ts, "env RING_HOST= RING_PORT=abc",
             "node dist/main.js", "RING_");

    TEST_STEP("H3: HTTP variant, RING_HOST and RING_PORT unset");
    env_case("main_both_unset", ts, "env -u RING_HOST -u RING_PORT",
             "node dist/main.js", "RING_");
    TEST_STEP("H3: HTTP variant, RING_HOST unset only");
    snprintf(envp, sizeof(envp), "env -u RING_HOST RING_PORT=%u", port);
    env_case("main_host_unset", ts, envp, "node dist/main.js", "RING_HOST");
    TEST_STEP("H3: HTTP variant, RING_PORT unset only");
    env_case("main_port_unset", ts, "env -u RING_PORT RING_HOST=127.0.0.1",
             "node dist/main.js", "RING_PORT");
    TEST_STEP("H3: HTTP variant, RING_PORT not a number");
    env_case("main_port_abc", ts, "env RING_HOST=127.0.0.1 RING_PORT=abc",
             "node dist/main.js", "RING_PORT");
    TEST_STEP("H3: HTTP variant, RING_PORT out of range");
    env_case("main_port_big", ts, "env RING_HOST=127.0.0.1 RING_PORT=70000",
             "node dist/main.js", "RING_PORT");

    TEST_STEP("H3: run.sh guess serve, RING_HOST and RING_PORT unset");
    env_case("runsh_both_unset", src, "env -u RING_HOST -u RING_PORT",
             "./scripts/run.sh guess serve", "RING_");
    TEST_STEP("H3: run.sh guess serve, RING_HOST unset only");
    snprintf(envp, sizeof(envp), "env -u RING_HOST RING_PORT=%u", port);
    env_case("runsh_host_unset", src, envp, "./scripts/run.sh guess serve",
             "RING_HOST");

    if (access(svc, X_OK) == 0)
    {
        TEST_STEP("H3: service-ts, RING_HOST and RING_PORT unset");
        env_case("svc_both_unset", src, "env -u RING_HOST -u RING_PORT", svc,
                 "RING_");
        TEST_STEP("H3: service-ts, RING_HOST unset only");
        snprintf(envp, sizeof(envp), "env -u RING_HOST RING_PORT=%u", port);
        env_case("svc_host_unset", src, envp, svc, "RING_HOST");
        TEST_STEP("H3: service-ts, RING_PORT unset only");
        env_case("svc_port_unset", src, "env -u RING_PORT RING_HOST=127.0.0.1",
                 svc, "RING_PORT");
        TEST_STEP("H3: service-ts, RING_PORT not a number");
        env_case("svc_port_abc", src, "env RING_HOST=127.0.0.1 RING_PORT=abc",
                 svc, "RING_PORT");
    }
    else
        tsd_bad("H3", "service-ts", "%s does not exist: build.sh did not "
                "make the TypeScript web node", svc);

    TEST_STEP("H3: what the documentation says about a default");
    tsd_sh(src, "grep -n -e 9100 -e 'RING_HOST' README.md | head -n 8", 10,
           "/tmp/ts_bi_doc.log");
    tsd_head("/tmp/ts_bi_doc.log", out, 500);
    tsd_say("H3 info: README lines on RING_HOST and port 9100: [%s]", out);
    tsd_sh(ts, "env -u RING_HOST -u RING_PORT node dist/demo.js 42 3 "
           ">/dev/null 2>&1; echo demo exit $?", 30, "/tmp/ts_bi_demo.log");
    tsd_head("/tmp/ts_bi_demo.log", out, 100);
    tsd_say("H3 info: node dist/demo.js with both unset: %s (code 1 is the "
            "documented behaviour)", out);

    TEST_STEP("H3: the demo with bad arguments");
    one_case("empty", "", "''");
    one_case("nonnumeric", "", "abc");
    one_case("long_text", "A=$(head -c 100000 /dev/zero | tr '\\0' a);",
             "\"$A\"");
    one_case("long_digits", "A=$(head -c 100000 /dev/zero | tr '\\0' 9);",
             "\"$A\" 3");

    TSD_PASS("H3", "scan: 0 hits in the TypeScript source; an unset or "
             "bad RING_HOST or RING_PORT exits with code 1 within 2 s with "
             "one line and no trace; the README matches");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}

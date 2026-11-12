/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps t10_build_*: one language built with its own tool (H4)
 *
 * Shared body of t10_build_rust, t10_build_go, t10_build_cs, t10_build_cpp,
 * t10_build_c and t10_build_python. A test builds one language with the
 * compile lines of the project's build.sh, runs the demo it produced once
 * and checks exit code 0 and one expected line of output. The outputs go to
 * H3_OUT so that t4_binscan can scan them.
 *
 * Every command is logged with its exit code and the first 40 lines of its
 * output. A build that fails fails the test with the compiler text; a tool
 * that is not on the agent after the prologue is a SKIP naming the tool.
 * The number of compiler warnings and the hardcoded endpoints of the
 * language's service are added to the report as findings; they settle
 * nothing by themselves.
 */

#ifndef MDE_T10_BUILD_H
#define MDE_T10_BUILD_H

#include "webdeps_lib.h"

#define BUILD_TO    1500    /**< s, longest build. */
#define RUN_TO      60      /**< s, longest demo. */
#define N_ERR       20      /**< error lines put in the verdict. */

#define GO_ENV \
    "CGO_LDFLAGS_ALLOW='-Wl,-(U|install_name|rpath),.*|" \
    "-Wl,--unresolved-symbols=.*' "

/** A C driver: loads the ring, then libpycore, and calls py_weight() once. */
#define C_DRIVER \
    "#include <dlfcn.h>\n#include <stdio.h>\n#include <math.h>\n" \
    "int main(void){\n" \
    "void*h;double(*f)(void);double v;\n" \
    "if(!dlopen(\"dist/lib/libcppcore.so\",RTLD_NOW|RTLD_GLOBAL)||\n" \
    "   !dlopen(\"dist/lib/libgocore.so\",RTLD_NOW|RTLD_GLOBAL)){\n" \
    "printf(\"dlopen of the ring failed: %s\\n\",dlerror());return 1;}\n" \
    "h=dlopen(\"" H3_OUT "/libpycore.so\",RTLD_NOW|RTLD_GLOBAL);\n" \
    "if(!h){printf(\"dlopen failed: %s\\n\",dlerror());return 1;}\n" \
    "f=(double(*)(void))dlsym(h,\"py_weight\");\n" \
    "if(!f){printf(\"dlsym failed: %s\\n\",dlerror());return 1;}\n" \
    "v=f();printf(\"py_weight() = %.6f\\n\",v);return isfinite(v)?0:1;}\n"

/** One build command, run in the example root. */
typedef struct t10_step {
    const char *name;
    const char *src;        /**< What is built, for the log. */
    const char *cmd;
} t10_step;

/** A source file and the lines of it that name an endpoint. */
typedef struct t10_endpoints {
    const char *file;
    unsigned    lines[3];
} t10_endpoints;

typedef struct t10_lang {
    const char *id;             /**< "rust", "go", ... */
    const char *tools[4];       /**< What must be on the agent. */
    const t10_step *steps;
    size_t      n_steps;
    const char *demo;           /**< Name of the demo, for the log. */
    const char *demo_cmd;       /**< Run in the example root, or NULL. */
    const char *service;        /**< Built service to run as the demo. */
    int         port_idx;       /**< Contract index of that service. */
    const char *expect;         /**< Line the demo output must carry. */
    const t10_endpoints *ep;    /**< Hardcoded endpoints to report. */
} t10_lang;

/** Version of the compiler and its path, the first thing every test logs. */
static bool
t10_tools(res_t *r, const t10_lang *l)
{
    size_t i;

    for (i = 0; i < TE_ARRAY_LEN(l->tools) && l->tools[i] != NULL; i++)
    {
        char    cmd[300];
        proc_t *p;

        TEST_STEP("Compiler path and version of %s", l->tools[i]);
        snprintf(cmd, sizeof(cmd), "command -v %s && { %s --version 2>&1 || "
                 "%s version 2>&1 || %s --prefix 2>&1; } | head -n 3",
                 l->tools[i], l->tools[i], l->tools[i], l->tools[i]);
        p = run_sh(r, "tool", cmd, 60);
        if (p == NULL)
            return false;
        log_command("tool", cmd, p);
        if (!WIFEXITED(p->status) || WEXITSTATUS(p->status) != 0)
        {
            res_set(r, R_SKIP, "H4 SKIP: tool %s is not on the agent",
                    l->tools[i]);
            T_FINDING(TAPI_CYBERSEC_SEV_LOW, "build.tool-missing",
                      l->tools[i], "not found: build of %s skipped", l->id);
            return false;
        }
        if (strstr(l->tools[i], "gcc") != NULL ||
            strstr(l->tools[i], "g++") != NULL)
        {
            char want[300];

            snprintf(want, sizeof(want), "%s --version 2>&1 | head -n 1",
                     l->tools[i]);
            p = run_sh(r, "tool-id", want, 60);
            if (p != NULL && count_lines_with(p, "tcc") > 0)
            {
                res_set(r, R_FAIL, "H4 FAIL: %s on the agent is tcc, not "
                        "GNU %s", l->tools[i], l->tools[i]);
                return false;
            }
        }
    }
    return true;
}

/** The command that starts a built service and asks it once. */
static void
t10_service_cmd(char *buf, size_t size, const char *bin, unsigned port)
{
    snprintf(buf, size,
             "LD_LIBRARY_PATH=$PWD/dist/lib %s & P=$!; OUT=; RC=1; "
             "for i in $(seq 1 60); do "
             "OUT=$(curl -sS -m 20 'http://127.0.0.1:%u/ring?value=1&hops=0' "
             "2>&1); RC=$?; [ $RC = 0 ] && break; sleep 0.25; done; "
             "echo \"$OUT\"; kill $P 2>/dev/null; wait $P 2>/dev/null; "
             "exit $RC", bin, port);
}

/**
 * Build one language, run its demo, report warnings and endpoints. Fills
 * @p r with the outcome; a message starts with "H4".
 */
static void
t10_run(res_t *r, const t10_lang *l)
{
    char     all_err[N_ERR * 400 + 64];
    char     cmd[2300];
    char     code[48];
    unsigned warnings = 0;
    size_t   i;
    proc_t  *p;

    t_report_begin();
    wd_init(r);
    if (r->kind == R_SETUP)
        return;
    mkdir(H3_OUT, 0755);
    setenv("C_DRIVER_SRC", C_DRIVER, 1);

    if (!t10_tools(r, l))
        return;

    for (i = 0; i < l->n_steps; i++)
    {
        const t10_step *s = &l->steps[i];

        TEST_STEP("Build %s (%s)", s->name, l->id);
        p = run_sh(r, "build", s->cmd, BUILD_TO);
        if (p == NULL)
        {
            res_set(r, R_FAIL, "H4 FAIL: %s: build of %s did not finish: %s",
                    l->id, s->name, r->msg);
            return;
        }
        log_command("build", s->cmd, p);
        warnings += count_lines_with(p, "warning");
        exit_code_str(p, code, sizeof(code));
        if (!WIFEXITED(p->status) || WEXITSTATUS(p->status) != 0)
        {
            first_error_lines(p->err, p->out, N_ERR, all_err,
                              sizeof(all_err));
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "example.build", s->name,
                      "build failed, exit code %s: %s", code, all_err);
            res_set(r, R_FAIL, "H4 FAIL: %s: build of %s (%s) failed, exit "
                    "code %s; compiler text: [%.900s]", l->id, s->name,
                    s->src, code, all_err);
            T_FINDING(TAPI_CYBERSEC_SEV_LOW, "build.warnings", l->id,
                      "%u warning line(s) in the build logs before the "
                      "failure", warnings);
            return;
        }
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "example.build", s->name,
                  "built, exit code 0");
    }
    T_FINDING(warnings > 0 ? TAPI_CYBERSEC_SEV_LOW : TAPI_CYBERSEC_SEV_INFO,
              "build.warnings", l->id, "%u warning line(s) in the build "
              "logs of %s", warnings, l->id);
    RING("webdeps H4 %s: %u warning line(s) in the build logs", l->id,
         warnings);

    if (l->ep != NULL)
    {
        unsigned out;

        TEST_STEP("Hardcoded endpoints of %s against the allowed list",
                  l->ep->file);
        out = endpoint_scan(l->ep->file, l->ep->lines, 3);
        RING("webdeps H4 %s: %u source line(s) with a destination outside "
             "the allowed list", l->id, out);
    }

    TEST_STEP("Run the built %s demo (%s)", l->id, l->demo);
    if (l->demo_cmd != NULL)
        snprintf(cmd, sizeof(cmd), "%s", l->demo_cmd);
    else
        t10_service_cmd(cmd, sizeof(cmd), l->service, tab_port[l->port_idx]);
    p = run_sh(r, "demo", cmd, RUN_TO);
    if (p == NULL)
    {
        res_set(r, R_FAIL, "H4 FAIL: %s: the demo %s did not finish within "
                "%d s: %s", l->id, l->demo, RUN_TO, r->msg);
        return;
    }
    log_command("demo", cmd, p);
    exit_code_str(p, code, sizeof(code));
    first_error_lines(p->err, p->out, 5, all_err, sizeof(all_err));
    if (!WIFEXITED(p->status) || WEXITSTATUS(p->status) != 0)
    {
        res_set(r, R_FAIL, "H4 FAIL: %s: built, but the demo %s ended with "
                "exit code %s; output [%.700s]", l->id, l->demo, code,
                all_err);
        return;
    }
    if (count_lines_with(p, l->expect) == 0)
    {
        res_set(r, R_FAIL, "H4 FAIL: %s: the demo %s exited 0 but its "
                "output has no line with \"%s\"; output [%.700s]", l->id,
                l->demo, l->expect, all_err);
        return;
    }
    res_set(r, R_PASS, "H4 PASS: %s: built with its own tool, the demo %s "
            "exited 0 and printed a line with \"%s\"; %u warning line(s) in "
            "the build logs", l->id, l->demo, l->expect, warnings);
}

/**
 * Check a source file alone with the compiler's syntax-only mode: is the
 * 'Parsing failed' report of an analyser a real syntax error or a gap of
 * the tool that made it. The answer goes to the log and the report.
 */
static void
t10_parse_alone(const char *label, const char *cmd)
{
    res_t    r = { .kind = R_PASS };
    proc_t  *p;
    char     lines[800];
    char     code[48];

    TEST_STEP("Parse %s alone", label);
    p = run_sh(&r, "parse", cmd, 300);
    if (p == NULL)
    {
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "build.parse-alone", label,
                  "the syntax check did not finish: %s", r.msg);
        return;
    }
    log_command("parse", cmd, p);
    exit_code_str(p, code, sizeof(code));
    first_error_lines(p->err, p->out, 5, lines, sizeof(lines));
    if (WIFEXITED(p->status) && WEXITSTATUS(p->status) == 0)
    {
        RING("webdeps H4: %s parses without error with the real compiler: "
             "the 'Parsing failed' report is a tool gap, not a syntax error",
             label);
        T_FINDING(TAPI_CYBERSEC_SEV_MEDIUM, "build.parse-alone", label,
                  "compiler accepts the file alone (exit code 0): the "
                  "'Parsing failed' report is a gap of the analyser, not a "
                  "syntax error");
    }
    else
    {
        RING("webdeps H4: %s does not parse: exit code %s, [%s]", label,
             code, lines);
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "build.parse-alone", label,
                  "compiler rejects the file alone (exit code %s): a real "
                  "error, [%s]", code, lines);
    }
}

#endif /* MDE_T10_BUILD_H */

/** @file
 * @brief devtool Group
 *
 * Rebuild the example's Python shim (python/src/pycore.c) on the agent
 * with tapi_cc, the way build.sh does it (python3-config flags), but with
 * -Wall -Wextra and a chosen compiler and optimization level. Count the
 * warnings by kind, and check the result against the shipped libpycore:
 * the same ring exports (py_step, py_weight) and the same NEEDED list.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "devtool/rebuild_pycore"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "tapi_file.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_cc.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"

/** Compilers. */
typedef enum rb_cc {
    RB_CC_CLANG,
    RB_CC_GCC,
    RB_CC_TCC,
} rb_cc;

#define RB_CC_LIST \
    { "clang", RB_CC_CLANG }, \
    { "gcc",   RB_CC_GCC }, \
    { "tcc",   RB_CC_TCC }

/** Optimization levels. */
typedef enum rb_opt {
    RB_OPT_O0,
    RB_OPT_O2,
} rb_opt;

#define RB_OPT_LIST \
    { "O0", RB_OPT_O0 }, \
    { "O2", RB_OPT_O2 }

/** Most flags taken from python3-config. */
#define RB_MAX_FLAGS    48
/** Most warning kinds told apart. */
#define RB_MAX_KINDS    32

/** Subjects of the findings. */
#define RB_SUBJECT      "pycore.c"
#define RB_CTL_EXPORT   "control-export"
#define RB_CTL_WARN     "control-warn"

/* Exported functions of the ring (py_*), sorted, one line. */
#define RB_EXPORTS_SCRIPT \
    "nm -D --defined-only '%s' 2>/dev/null | "                     \
    "awk '$2 == \"T\" || $2 == \"W\" { print $3 }' | "             \
    "grep '^py_' | sort | tr '\\n' ' '"

/* NEEDED entries, sorted, one line. */
#define RB_NEEDED_SCRIPT \
    "readelf -d '%s' 2>/dev/null | "                               \
    "sed -n 's/.*(NEEDED).*\\[\\(.*\\)\\]/\\1/p' | sort | tr '\\n' ' '"

/** Warnings of one compilation, by kind. */
typedef struct rb_warnings {
    char         *kind[RB_MAX_KINDS];
    double        count[RB_MAX_KINDS];
    unsigned int  n;
    unsigned int  total;
} rb_warnings;

/* Split a command line by blanks into allocated tokens. */
static size_t
rb_split(const char *text, char **tok, size_t max)
{
    char   *copy = strdup(text);
    char   *save = NULL;
    char   *t;
    size_t  n = 0;

    for (t = strtok_r(copy, " \t\r\n", &save); t != NULL && n < max;
         t = strtok_r(NULL, " \t\r\n", &save))
        tok[n++] = strdup(t);
    free(copy);

    return n;
}

/* Count the warnings in compiler diagnostics by their -W kind. */
static void
rb_count_warnings(const char *diag, rb_warnings *w)
{
    const char *p = diag;

    while (p != NULL && *p != '\0')
    {
        const char *eol = strchr(p, '\n');
        size_t      len = (eol != NULL) ? (size_t)(eol - p) : strlen(p);
        char        line[1024];
        char        kind[128] = "other";
        char       *open;
        char       *close;
        unsigned int i;

        if (len >= sizeof(line))
            len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        p = (eol != NULL) ? eol + 1 : NULL;

        if (strstr(line, "warning:") == NULL)
            continue;

        open = strstr(line, "[-W");
        while (open != NULL && strstr(open + 1, "[-W") != NULL)
            open = strstr(open + 1, "[-W");
        if (open != NULL && (close = strchr(open, ']')) != NULL &&
            (size_t)(close - open - 1) < sizeof(kind))
        {
            memcpy(kind, open + 1, close - open - 1);
            kind[close - open - 1] = '\0';
        }

        w->total++;
        for (i = 0; i < w->n; i++)
        {
            if (strcmp(w->kind[i], kind) == 0)
                break;
        }
        if (i == w->n && w->n < RB_MAX_KINDS)
        {
            w->kind[w->n] = strdup(kind);
            w->count[w->n] = 0;
            w->n++;
        }
        if (i < w->n)
            w->count[i]++;
    }
}

/* Report the warnings of a subject, one finding per kind. */
static void
rb_report_warnings(tsapi_mde_report *report, const char *subject,
                   const rb_warnings *w)
{
    unsigned int i;

    for (i = 0; i < w->n; i++)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_LOW,
                                 "build.warning", subject, "%.0f x %s",
                                 w->count[i], w->kind[i]);
    }
}

/* Free the kinds of a warning count. */
static void
rb_warnings_free(rb_warnings *w)
{
    unsigned int i;

    for (i = 0; i < w->n; i++)
        free(w->kind[i]);
    memset(w, 0, sizeof(*w));
}

/* Run one of the listing scripts on a file, keep its one-line output. */
static te_errno
rb_list(tsapi_mde_session *session, bool exports, const char *path,
        te_string *out)
{
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_errno            rc;

    if (exports)
        rc = tsapi_mde_sh(session, 30000, &sh, RB_EXPORTS_SCRIPT, path);
    else
        rc = tsapi_mde_sh(session, 30000, &sh, RB_NEEDED_SCRIPT, path);

    te_string_reset(out);
    /* A leading blank so that " name " finds whole words. */
    te_string_append(out, " %s", te_string_value(&sh.out));
    tsapi_mde_sh_result_free(&sh);

    return rc;
}

/* Whether a blank-separated list holds a word. */
static bool
rb_has_word(const char *list, const char *word)
{
    char needle[128];

    TE_SPRINTF(needle, " %s ", word);
    return strstr(list, needle) != NULL;
}

/*
 * Check what a built shim exports: py_step and py_weight must be there,
 * and the py_* set must be the shipped one when that is known.
 */
static void
rb_check_exports(tsapi_mde_report *report, const char *subject,
                 const char *built, const char *shipped)
{
    static const char *required[] = { "py_step", "py_weight" };
    unsigned int       i;

    for (i = 0; i < TE_ARRAY_LEN(required); i++)
    {
        if (!rb_has_word(built, required[i]))
        {
            tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "build.export-mismatch", subject,
                                     "the rebuilt shim does not export %s",
                                     required[i]);
        }
    }
    if (shipped != NULL && strcmp(built, shipped) != 0)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "build.export-mismatch", subject,
                                 "exports differ: rebuilt [%s], shipped [%s]",
                                 built, shipped);
    }
}

/*
 * Build the shim with the flags python3-config gave, plus @p extra.
 * @p ok tells whether it compiled; @p diag gets the diagnostics.
 */
static te_errno
rb_build(tapi_job_factory_t *factory, const char *cc, const char *olevel,
         const char *define, const char *src, const char *out,
         char **inc, size_t n_inc, char **ld, size_t n_ld,
         const char *extra, te_string *diag, double *secs, bool *ok)
{
    tapi_cc_opt         opt = tapi_cc_default_opt;
    tapi_cc_app        *app = NULL;
    tapi_devtool_output output;
    const char         *cflags[RB_MAX_FLAGS + 1];
    const char         *ldflags[RB_MAX_FLAGS];
    const char         *defines[1] = { define };
    const char         *sources[1] = { src };
    size_t              n_cflags = 0;
    size_t              i;
    double              started;
    te_errno            rc;

    for (i = 0; i < n_inc; i++)
        cflags[n_cflags++] = inc[i];
    if (extra != NULL)
        cflags[n_cflags++] = extra;
    for (i = 0; i < n_ld; i++)
        ldflags[i] = ld[i];

    opt.compiler = cc;
    opt.opt_level = olevel;
    opt.warn_all = true;
    opt.warn_extra = true;
    opt.pic = true;
    opt.shared = true;
    opt.output = out;
    opt.defines = defines;
    opt.n_defines = 1;
    opt.cflags = cflags;
    opt.n_cflags = n_cflags;
    opt.sources = sources;
    opt.n_sources = 1;
    opt.ldflags = ldflags;
    opt.n_ldflags = n_ld;

    started = tsapi_mde_now();
    rc = tapi_cc_do(factory, &opt, TAPI_DEVTOOL_TIMEOUT_MS, &app);
    *secs = tsapi_mde_now() - started;
    *ok = (rc == 0);
    if (rc != 0 && TE_RC_GET_ERROR(rc) == TE_ESHCMD)
        rc = 0;

    te_string_reset(diag);
    if (app != NULL)
    {
        tapi_cc_get_output(app, &output);
        te_string_append(diag, "%s", output.err);
        tapi_cc_destroy(app);
    }

    return rc;
}

int
main(int argc, char **argv)
{
    rb_cc                  cc;
    rb_opt                 opt;
    tapi_cybersec_severity min_sev;
    const char            *cc_name;
    const char            *olevel;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    bool                   report_up = false;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string              dir = TE_STRING_INIT;
    te_string              src = TE_STRING_INIT;
    te_string              out = TE_STRING_INIT;
    te_string              ctl_out = TE_STRING_INIT;
    te_string              ctl_src = TE_STRING_INIT;
    te_string              shipped = TE_STRING_INIT;
    te_string              define = TE_STRING_INIT;
    te_string              diag = TE_STRING_INIT;
    te_string              exp_built = TE_STRING_INIT;
    te_string              exp_shipped = TE_STRING_INIT;
    te_string              exp_ctl = TE_STRING_INIT;
    te_string              need_built = TE_STRING_INIT;
    te_string              need_shipped = TE_STRING_INIT;
    char                  *inc[RB_MAX_FLAGS];
    char                  *ld[RB_MAX_FLAGS];
    size_t                 n_inc = 0;
    size_t                 n_ld = 0;
    rb_warnings            warns;
    rb_warnings            ctl_warns;
    bool                   have_shipped;
    bool                   ok;
    double                 build_s = 0;
    double                 ctl_s = 0;
    double                 size_bytes = 0;
    char                   title[128];
    size_t                 i;

    TEST_START;

    memset(&dut, 0, sizeof(dut));
    memset(&warns, 0, sizeof(warns));
    memset(&ctl_warns, 0, sizeof(ctl_warns));

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(cc, RB_CC_LIST);
    TEST_GET_ENUM_PARAM(opt, RB_OPT_LIST);
    TEST_GET_MDE_SEVERITY(min_sev);
    cc_name = (cc == RB_CC_CLANG) ? "clang" :
              (cc == RB_CC_GCC) ? "gcc" : "tcc";
    olevel = (opt == RB_OPT_O0) ? "0" : "2";

    TEST_STEP("Locate the example under test");
    TSAPI_MDE_OPEN_OR_SKIP(session, "dev_pycore", dut, session_up);

    if (!tsapi_mde_have(&session, cc_name))
        TEST_VERDICT("%s is not installed on the agent", cc_name);
    if (!tsapi_mde_have(&session, "python3-config"))
        TEST_VERDICT("python3-config is missing (no python3-dev)");
    if (!tsapi_mde_have(&session, "nm") ||
        !tsapi_mde_have(&session, "readelf"))
        TEST_VERDICT("binutils are missing on the agent");

    te_string_append(&src, "%s/python/src/pycore.c", dut.root);
    if (!tsapi_mde_exists(&session, src.ptr))
        TEST_VERDICT("The source of the Python shim is missing");

    TEST_STEP("Ask python3-config for the flags build.sh uses");
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "python3-config --includes"));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("python3-config --includes failed");
    n_inc = rb_split(te_string_value(&sh.out), inc, RB_MAX_FLAGS);
    TEST_ARTIFACT("python3-config --includes: %s", te_string_value(&sh.out));

    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "python3-config --ldflags --embed"));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("python3-config --ldflags --embed failed");
    n_ld = rb_split(te_string_value(&sh.out), ld, RB_MAX_FLAGS);
    TEST_ARTIFACT("python3-config --ldflags --embed: %s",
                  te_string_value(&sh.out));

    te_string_append(&dir, "/tmp/mde-devtool-rebuild_pycore-%s-O%s",
                     cc_name, olevel);
    te_string_append(&out, "%s/libpycore.so", dir.ptr);
    te_string_append(&ctl_out, "%s/control-hidden.so", dir.ptr);
    te_string_append(&ctl_src, "%s/control-warn.c", dir.ptr);
    te_string_append(&define, "RING_PY_DIR=\"%s/python\"", dut.root);
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "rm -rf '%s' && mkdir -p '%s'",
                          dir.ptr, dir.ptr));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot create the build directory on the agent");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Rebuild the shim with -Wall -Wextra");
    CHECK_RC(rb_build(session.factory, cc_name, olevel, define.ptr, src.ptr,
                      out.ptr, inc, n_inc, ld, n_ld, NULL, &diag, &build_s,
                      &ok));
    RING("Diagnostics of %s -O%s:\n%s", cc_name, olevel,
         te_string_value(&diag));
    if (!ok)
        TEST_VERDICT("pycore.c does not build with %s -O%s", cc_name, olevel);

    rb_count_warnings(te_string_value(&diag), &warns);
    rb_report_warnings(&report, RB_SUBJECT, &warns);

    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "stat -c %%s '%s' && sha256sum '%s' | cut -d' ' -f1",
                          out.ptr, out.ptr));
    size_bytes = strtod(te_string_value(&sh.out), NULL);
    TEST_ARTIFACT("Rebuilt %s with %s -O%s in %.3f s: %s", out.ptr, cc_name,
                  olevel, build_s, te_string_value(&sh.out));

    TEST_STEP("Compare the exports and NEEDED with the shipped library");
    tsapi_mde_dut_lib_path(&dut, "libpycore", &shipped);
    have_shipped = tsapi_mde_exists(&session, shipped.ptr);
    CHECK_RC(rb_list(&session, true, out.ptr, &exp_built));
    CHECK_RC(rb_list(&session, false, out.ptr, &need_built));
    if (have_shipped)
    {
        CHECK_RC(rb_list(&session, true, shipped.ptr, &exp_shipped));
        CHECK_RC(rb_list(&session, false, shipped.ptr, &need_shipped));
    }
    TEST_ARTIFACT("Exports: rebuilt [%s], shipped [%s]", exp_built.ptr,
                  have_shipped ? exp_shipped.ptr : "(not built)");
    TEST_ARTIFACT("NEEDED: rebuilt [%s], shipped [%s]", need_built.ptr,
                  have_shipped ? need_shipped.ptr : "(not built)");

    rb_check_exports(&report, RB_SUBJECT, exp_built.ptr,
                     have_shipped ? exp_shipped.ptr : NULL);
    if (have_shipped && strcmp(need_built.ptr, need_shipped.ptr) != 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                 "build.needed-mismatch", RB_SUBJECT,
                                 "NEEDED differ: rebuilt [%s], shipped [%s]",
                                 need_built.ptr, need_shipped.ptr);
    }

    TEST_STEP("Known-bad control: hidden visibility exports nothing");
    CHECK_RC(rb_build(session.factory, cc_name, olevel, define.ptr, src.ptr,
                      ctl_out.ptr, inc, n_inc, ld, n_ld,
                      "-fvisibility=hidden", &diag, &ctl_s, &ok));
    if (!ok)
        TEST_FAIL("The hidden-visibility control does not build");
    CHECK_RC(rb_list(&session, true, ctl_out.ptr, &exp_ctl));
    rb_check_exports(&report, RB_CTL_EXPORT, exp_ctl.ptr,
                     have_shipped ? exp_shipped.ptr : exp_built.ptr);
    tsapi_mde_report_expect(&report, "build.export-mismatch", RB_CTL_EXPORT);

    TEST_STEP("Known-bad control: a source with planted warnings");
    CHECK_RC(tapi_file_create_ta(session.ta, ctl_src.ptr,
                                 "int control(int unused_arg)\n"
                                 "{\n"
                                 "    int unused_var;\n"
                                 "    return 0;\n"
                                 "}\n"));
    {
        tapi_cc_opt         wopt = tapi_cc_default_opt;
        tapi_cc_app        *app = NULL;
        tapi_devtool_output output;
        const char         *wsrc[1] = { ctl_src.ptr };
        te_string           wobj = TE_STRING_INIT;

        te_string_append(&wobj, "%s/control-warn.o", dir.ptr);
        wopt.compiler = cc_name;
        wopt.warn_all = true;
        wopt.warn_extra = true;
        wopt.compile_only = true;
        wopt.sources = wsrc;
        wopt.n_sources = 1;
        wopt.output = wobj.ptr;
        rc = tapi_cc_do(session.factory, &wopt, TAPI_DEVTOOL_TIMEOUT_MS, &app);
        if (app != NULL)
        {
            tapi_cc_get_output(app, &output);
            rb_count_warnings(output.err, &ctl_warns);
            tapi_cc_destroy(app);
        }
        te_string_free(&wobj);
        if (rc != 0)
            TEST_FAIL("The planted-warning control does not compile");
    }
    rb_report_warnings(&report, RB_CTL_WARN, &ctl_warns);
    tsapi_mde_report_expect(&report, "build.warning", RB_CTL_WARN);

    tsapi_mde_report_drop_subject(&report, RB_CTL_EXPORT);
    tsapi_mde_report_drop_subject(&report, RB_CTL_WARN);

    TEST_STEP("Chart the build");
    TE_SPRINTF(title, "Build time of pycore.c (%s -O%s)", cc_name, olevel);
    tsapi_mde_mi_point("devtool", title, TE_MI_MEAS_TIME, "build", build_s,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    TE_SPRINTF(title, "Size of the rebuilt libpycore (%s -O%s)", cc_name,
               olevel);
    tsapi_mde_mi_point("devtool", title, TE_MI_MEAS_MEMORY, "size",
                       size_bytes, TE_MI_MEAS_MULTIPLIER_PLAIN);
    TE_SPRINTF(title, "Warnings of pycore.c (%s -O%s)", cc_name, olevel);
    tsapi_mde_mi_point("devtool", title, TE_MI_MEAS_UNITLESS_VALUE,
                       "warnings", warns.total, TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (warns.n > 0)
    {
        TE_SPRINTF(title, "Warnings per kind (%s -O%s)", cc_name, olevel);
        tsapi_mde_mi_bars("devtool", title, TE_MI_MEAS_UNITLESS_VALUE,
                          "warnings", warns.n,
                          (const char * const *)warns.kind, warns.count,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    TEST_ARTIFACT("pycore.c with %s -O%s: %u warning(s) of %u kind(s); "
                  "planted-warning control: %u warning(s); hidden-visibility "
                  "control built in %.3f s", cc_name, olevel, warns.total,
                  warns.n, ctl_warns.total, ctl_s);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "devtool", min_sev);

    TEST_SUCCESS;

cleanup:

    if (session_up && dir.ptr != NULL)
    {
        tsapi_mde_sh_result rm = TSAPI_MDE_SH_RESULT_INIT;

        tsapi_mde_sh(&session, 30000, &rm, "rm -rf '%s'", dir.ptr);
        tsapi_mde_sh_result_free(&rm);
    }
    for (i = 0; i < n_inc; i++)
        free(inc[i]);
    for (i = 0; i < n_ld; i++)
        free(ld[i]);
    rb_warnings_free(&warns);
    rb_warnings_free(&ctl_warns);
    te_string_free(&dir);
    te_string_free(&src);
    te_string_free(&out);
    te_string_free(&ctl_out);
    te_string_free(&ctl_src);
    te_string_free(&shipped);
    te_string_free(&define);
    te_string_free(&diag);
    te_string_free(&exp_built);
    te_string_free(&exp_shipped);
    te_string_free(&exp_ctl);
    te_string_free(&need_built);
    te_string_free(&need_shipped);
    tsapi_mde_sh_result_free(&sh);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

/** @file
 * @brief devtool Group
 *
 * Is the example's Python shim reproducible? Build python/src/pycore.c
 * twice into two directories with identical flags (and -ffile-prefix-map
 * over the example root), then compare the two results byte for byte
 * (sha256) and section by section (readelf -S sizes). The known-bad
 * control proves the comparison sees a difference: a debug build of the
 * same file from two directories without a prefix map embeds the two
 * paths and must not come out identical.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "devtool/reproducible"

#include "te_config.h"

#include <stdio.h>
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
typedef enum rp_cc {
    RP_CC_CLANG,
    RP_CC_GCC,
    RP_CC_TCC,
} rp_cc;

#define RP_CC_LIST \
    { "clang", RP_CC_CLANG }, \
    { "gcc",   RP_CC_GCC }, \
    { "tcc",   RP_CC_TCC }

/** Most flags taken from python3-config. */
#define RP_MAX_FLAGS    48
/** Most sections compared. */
#define RP_MAX_SECTIONS 64

/** Subjects of the findings. */
#define RP_SUBJECT      "libpycore"
#define RP_CTL          "control"

/** Sections of one ELF file: name and size. */
typedef struct rp_sections {
    char         name[RP_MAX_SECTIONS][64];
    double       size[RP_MAX_SECTIONS];
    unsigned int n;
} rp_sections;

/** One build: its output, how long it took, what came out. */
typedef struct rp_build {
    char        hash[80];
    double      secs;
    rp_sections sections;
} rp_build;

/* Split a command line by blanks into allocated tokens. */
static size_t
rp_split(const char *text, char **tok, size_t max)
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

/* Parse "readelf -S -W": "  [ 1] .name TYPE addr off size ...". */
static void
rp_parse_sections(const char *text, rp_sections *s)
{
    char *copy = strdup(text);
    char *save = NULL;
    char *line;

    s->n = 0;
    for (line = strtok_r(copy, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        char               *br = strchr(line, '[');
        char               *close;
        char                name[64];
        char                type[32];
        unsigned long long  addr;
        unsigned long long  off;
        unsigned long long  size;
        long                idx;

        if (br == NULL || (close = strchr(br, ']')) == NULL)
            continue;
        idx = strtol(br + 1, NULL, 10);
        /* The header line "[Nr]" parses as 0, like the null section. */
        if (idx <= 0 || s->n >= RP_MAX_SECTIONS)
            continue;
        if (sscanf(close + 1, "%63s %31s %llx %llx %llx", name, type, &addr,
                   &off, &size) != 5)
            continue;
        TE_SPRINTF(s->name[s->n], "%s", name);
        s->size[s->n] = (double)size;
        s->n++;
    }
    free(copy);
}

/* Build one copy and describe it. */
static te_errno
rp_build_one(tsapi_mde_session *session, const tapi_cc_opt *base,
             const char *out, rp_build *b, bool *ok)
{
    tapi_cc_opt         opt = *base;
    tapi_cc_app        *app = NULL;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    double              started;
    te_errno            rc;

    memset(b, 0, sizeof(*b));
    opt.output = out;

    started = tsapi_mde_now();
    rc = tapi_cc_do(session->factory, &opt, TAPI_DEVTOOL_TIMEOUT_MS, &app);
    b->secs = tsapi_mde_now() - started;
    tapi_cc_destroy(app);
    *ok = (rc == 0);
    if (rc != 0)
        return (TE_RC_GET_ERROR(rc) == TE_ESHCMD) ? 0 : rc;

    rc = tsapi_mde_sh(session, 30000, &sh, "sha256sum '%s' | cut -d' ' -f1",
                      out);
    if (rc == 0)
    {
        TE_SPRINTF(b->hash, "%.64s", te_string_value(&sh.out));
        rc = tsapi_mde_sh(session, 30000, &sh, "readelf -S -W '%s'", out);
    }
    if (rc == 0)
        rp_parse_sections(te_string_value(&sh.out), &b->sections);
    tsapi_mde_sh_result_free(&sh);

    return rc;
}

/*
 * Compare two builds: hash, then section by section. Report what differs
 * about @p subject. @p same_sections counts the sections of equal size.
 */
static bool
rp_compare(tsapi_mde_report *report, const char *subject, const rp_build *a,
           const rp_build *b, unsigned int *same_sections)
{
    unsigned int i;
    unsigned int j;
    bool         identical = strcmp(a->hash, b->hash) == 0;

    *same_sections = 0;
    if (!identical)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "build.not-reproducible", subject,
                                 "two identical builds differ: %s vs %s",
                                 a->hash, b->hash);
    }

    if (a->sections.n != b->sections.n)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "build.not-reproducible", subject,
                                 "%u sections vs %u", a->sections.n,
                                 b->sections.n);
    }
    for (i = 0; i < a->sections.n; i++)
    {
        for (j = 0; j < b->sections.n; j++)
        {
            if (strcmp(a->sections.name[i], b->sections.name[j]) == 0)
                break;
        }
        if (j == b->sections.n)
        {
            tapi_cybersec_report_add(&report->cyber,
                                     TAPI_CYBERSEC_SEV_MEDIUM,
                                     "build.not-reproducible", subject,
                                     "section %s is in one build only",
                                     a->sections.name[i]);
        }
        else if (a->sections.size[i] != b->sections.size[j])
        {
            tapi_cybersec_report_add(&report->cyber,
                                     TAPI_CYBERSEC_SEV_MEDIUM,
                                     "build.not-reproducible", subject,
                                     "section %s: %.0f vs %.0f bytes",
                                     a->sections.name[i],
                                     a->sections.size[i],
                                     b->sections.size[j]);
        }
        else
        {
            (*same_sections)++;
        }
    }

    return identical;
}

int
main(int argc, char **argv)
{
    static const char *time_labels[] = {
        "build-a", "build-b", "control-a", "control-b",
    };
    rp_cc                  cc;
    tapi_cybersec_severity min_sev;
    const char            *cc_name;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    bool                   report_up = false;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string              dir = TE_STRING_INIT;
    te_string              src = TE_STRING_INIT;
    te_string              define = TE_STRING_INIT;
    te_string              prefix_map = TE_STRING_INIT;
    te_string              path = TE_STRING_INIT;
    te_string              ctl_a = TE_STRING_INIT;
    te_string              ctl_b = TE_STRING_INIT;
    char                  *inc[RP_MAX_FLAGS];
    char                  *ld[RP_MAX_FLAGS];
    size_t                 n_inc = 0;
    size_t                 n_ld = 0;
    const char            *cflags[RP_MAX_FLAGS + 1];
    const char            *ldflags[RP_MAX_FLAGS];
    const char            *defines[1];
    const char            *sources[1];
    tapi_cc_opt            opt;
    rp_build              *builds = NULL;
    double                 times[4] = { 0 };
    const char            *sec_labels[RP_MAX_SECTIONS];
    unsigned int           same_sections = 0;
    unsigned int           ctl_same = 0;
    bool                   identical;
    bool                   ok;
    char                   title[128];
    size_t                 i;

    TEST_START;

    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(cc, RP_CC_LIST);
    TEST_GET_MDE_SEVERITY(min_sev);
    cc_name = (cc == RP_CC_CLANG) ? "clang" :
              (cc == RP_CC_GCC) ? "gcc" : "tcc";

    TEST_STEP("Locate the example under test");
    TSAPI_MDE_OPEN_OR_SKIP(session, "dev_repro", dut, session_up);

    if (!tsapi_mde_have(&session, cc_name))
        TEST_SKIP("%s is not installed on the agent", cc_name);
    if (!tsapi_mde_have(&session, "python3-config"))
        TEST_SKIP("python3-config is missing (no python3-dev)");
    if (!tsapi_mde_have(&session, "readelf") ||
        !tsapi_mde_have(&session, "sha256sum"))
        TEST_SKIP("readelf or sha256sum is missing on the agent");

    te_string_append(&src, "%s/python/src/pycore.c", dut.root);
    if (!tsapi_mde_exists(&session, src.ptr))
        TEST_SKIP("The source of the Python shim is missing");

    TEST_STEP("Ask python3-config for the flags build.sh uses");
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "python3-config --includes"));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("python3-config --includes failed");
    n_inc = rp_split(te_string_value(&sh.out), inc, RP_MAX_FLAGS);
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "python3-config --ldflags --embed"));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("python3-config --ldflags --embed failed");
    n_ld = rp_split(te_string_value(&sh.out), ld, RP_MAX_FLAGS);

    TEST_STEP("Prepare two build directories and the control sources");
    te_string_append(&dir, "/tmp/mde-devtool-reproducible-%s", cc_name);
    te_string_append(&ctl_a, "%s/ca/ctl.c", dir.ptr);
    te_string_append(&ctl_b, "%s/cb/ctl.c", dir.ptr);
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "rm -rf '%s' && mkdir -p '%s/a' '%s/b' '%s/ca' "
                          "'%s/cb'", dir.ptr, dir.ptr, dir.ptr, dir.ptr,
                          dir.ptr));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot create the build directories on the agent");
    CHECK_RC(tapi_file_create_ta(session.ta, ctl_a.ptr,
                                 "int control(int x) { return x * 3; }\n"));
    CHECK_RC(tapi_file_create_ta(session.ta, ctl_b.ptr,
                                 "int control(int x) { return x * 3; }\n"));

    tsapi_mde_report_init(&report);
    report_up = true;
    builds = calloc(4, sizeof(*builds));

    TEST_STEP("Build the shim twice with identical flags");
    te_string_append(&define, "RING_PY_DIR=\"%s/python\"", dut.root);
    te_string_append(&prefix_map, "-ffile-prefix-map=%s=.", dut.root);
    for (i = 0; i < n_inc; i++)
        cflags[i] = inc[i];
    cflags[n_inc] = prefix_map.ptr;
    for (i = 0; i < n_ld; i++)
        ldflags[i] = ld[i];
    defines[0] = define.ptr;
    sources[0] = src.ptr;

    opt = tapi_cc_default_opt;
    opt.compiler = cc_name;
    opt.opt_level = "2";
    opt.pic = true;
    opt.shared = true;
    opt.defines = defines;
    opt.n_defines = 1;
    opt.cflags = cflags;
    opt.n_cflags = n_inc + 1;
    opt.sources = sources;
    opt.n_sources = 1;
    opt.ldflags = ldflags;
    opt.n_ldflags = n_ld;

    for (i = 0; i < 2; i++)
    {
        te_string_reset(&path);
        te_string_append(&path, "%s/%c/libpycore.so", dir.ptr,
                         i == 0 ? 'a' : 'b');
        CHECK_RC(rp_build_one(&session, &opt, path.ptr, &builds[i], &ok));
        if (!ok)
            TEST_VERDICT("pycore.c does not build with %s", cc_name);
        times[i] = builds[i].secs;
        TEST_ARTIFACT("Build %c: sha256 %s, %u sections, %.3f s",
                      i == 0 ? 'a' : 'b', builds[i].hash,
                      builds[i].sections.n, builds[i].secs);
    }

    TEST_STEP("Compare the two builds");
    identical = rp_compare(&report, RP_SUBJECT, &builds[0], &builds[1],
                           &same_sections);
    TEST_ARTIFACT("libpycore with %s: %s; %u of %u sections of equal size",
                  cc_name, identical ? "reproducible" : "NOT reproducible",
                  same_sections, builds[0].sections.n);

    TEST_STEP("Known-bad control: debug builds from two directories");
    opt = tapi_cc_default_opt;
    opt.compiler = cc_name;
    opt.debug = true;
    opt.pic = true;
    opt.shared = true;
    opt.n_sources = 1;
    opt.sources = sources;

    sources[0] = ctl_a.ptr;
    te_string_reset(&path);
    te_string_append(&path, "%s/ca/ctl.so", dir.ptr);
    CHECK_RC(rp_build_one(&session, &opt, path.ptr, &builds[2], &ok));
    if (!ok)
        TEST_FAIL("The control does not build");
    sources[0] = ctl_b.ptr;
    te_string_reset(&path);
    te_string_append(&path, "%s/cb/ctl.so", dir.ptr);
    CHECK_RC(rp_build_one(&session, &opt, path.ptr, &builds[3], &ok));
    if (!ok)
        TEST_FAIL("The control does not build");
    times[2] = builds[2].secs;
    times[3] = builds[3].secs;
    rp_compare(&report, RP_CTL, &builds[2], &builds[3], &ctl_same);
    TEST_ARTIFACT("Control: sha256 %s vs %s", builds[2].hash,
                  builds[3].hash);
    tsapi_mde_report_expect(&report, "build.not-reproducible", RP_CTL);
    tsapi_mde_report_drop_subject(&report, RP_CTL);

    TEST_STEP("Chart the builds");
    TE_SPRINTF(title, "Build times, reproducibility check (%s)", cc_name);
    tsapi_mde_mi_bars("devtool", title, TE_MI_MEAS_TIME, "build",
                      TE_ARRAY_LEN(time_labels), time_labels, times,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    for (i = 0; i < builds[0].sections.n; i++)
        sec_labels[i] = builds[0].sections.name[i];
    TE_SPRINTF(title, "Section sizes of libpycore (%s)", cc_name);
    tsapi_mde_mi_bars("devtool", title, TE_MI_MEAS_MEMORY, "size",
                      builds[0].sections.n, sec_labels,
                      builds[0].sections.size, TE_MI_MEAS_MULTIPLIER_PLAIN);
    TE_SPRINTF(title, "Identical rebuilds of libpycore (%s)", cc_name);
    tsapi_mde_mi_point("devtool", title, TE_MI_MEAS_UNITLESS_VALUE,
                       "identical", identical ? 1 : 0,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

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
    free(builds);
    te_string_free(&dir);
    te_string_free(&src);
    te_string_free(&define);
    te_string_free(&prefix_map);
    te_string_free(&path);
    te_string_free(&ctl_a);
    te_string_free(&ctl_b);
    tsapi_mde_sh_result_free(&sh);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

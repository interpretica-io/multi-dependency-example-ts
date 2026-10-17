/** @file
 * @brief devtool Group
 *
 * Compiler feature probes with tapi_cc_check_snippet(): does clang/gcc on
 * the agent support a hardening or sanitizer feature? Each probe stands
 * between controls that make its answer believable - plain C must build
 * (positive control), a syntax error must not (negative control), and
 * where the feature announces itself with a macro the probe must fail
 * with the feature turned off (proof the probe can tell on from off).
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "devtool/compile_probe"

#include "te_config.h"

#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_cc.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/** The features probed. */
typedef enum probe_feature_id {
    PROBE_ASAN,
    PROBE_UBSAN,
    PROBE_FUZZER,
    PROBE_STACK_PROTECTOR,
    PROBE_FORTIFY,
    PROBE_PIE,
    PROBE_CFI,
} probe_feature_id;

#define PROBE_FEATURE_LIST \
    { "asan",            PROBE_ASAN },            \
    { "ubsan",           PROBE_UBSAN },           \
    { "fuzzer",          PROBE_FUZZER },          \
    { "stack-protector", PROBE_STACK_PROTECTOR }, \
    { "fortify",         PROBE_FORTIFY },         \
    { "pie",             PROBE_PIE },             \
    { "cfi",             PROBE_CFI }

/** The compilers. */
typedef enum probe_cc {
    PROBE_CC_CLANG,
    PROBE_CC_GCC,
} probe_cc;

#define PROBE_CC_LIST \
    { "clang", PROBE_CC_CLANG }, \
    { "gcc",   PROBE_CC_GCC }

/** Most flags any probe passes. */
#define PROBE_MAX_FLAGS 4

/** How one feature is probed. */
typedef struct probe_feature {
    const char *name;
    /** Flags that turn the feature on. */
    const char *on[PROBE_MAX_FLAGS];
    /** Flags that turn it off, for features with a macro check. */
    const char *off[PROBE_MAX_FLAGS];
    /** Preprocessor test that fails unless the feature is on, or NULL. */
    const char *macro_check;
    /** Body exercising the feature. */
    const char *body;
    /** Whether clang / gcc are expected to support it. */
    bool        expect_clang;
    bool        expect_gcc;
} probe_feature;

/* __has_feature does not exist in older gcc. */
#define PROBE_PRELUDE \
    "#ifndef __has_feature\n#define __has_feature(x) 0\n#endif\n"

static const probe_feature probe_features[] = {
    [PROBE_ASAN] = {
        "asan", { "-fsanitize=address" }, { NULL },
        "#if !defined(__SANITIZE_ADDRESS__) && "
        "!__has_feature(address_sanitizer)\n#error asan is off\n#endif\n",
        "int probe(int *p) { return p[1]; }\n", true, true },
    [PROBE_UBSAN] = {
        "ubsan", { "-fsanitize=undefined" }, { NULL }, NULL,
        "int probe(int a, int b) { return a + b; }\n", true, true },
    [PROBE_FUZZER] = {
        "fuzzer", { "-fsanitize=fuzzer" }, { NULL }, NULL,
        "#include <stddef.h>\n#include <stdint.h>\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)\n"
        "{ return (n > 0 && d[0] == 'x') ? 0 : 0; }\n", true, false },
    [PROBE_STACK_PROTECTOR] = {
        "stack-protector", { "-fstack-protector-strong" },
        { "-fno-stack-protector" },
        "#if !defined(__SSP_STRONG__)\n#error ssp-strong is off\n#endif\n",
        "#include <string.h>\n"
        "void probe(char *d, const char *s) { char b[16]; "
        "strcpy(b, s); strcpy(d, b); }\n", true, true },
    [PROBE_FORTIFY] = {
        "fortify", { "-O2", "-D_FORTIFY_SOURCE=2" },
        { "-O2", "-U_FORTIFY_SOURCE" },
        "#include <string.h>\n"
        "#if !defined(__USE_FORTIFY_LEVEL) || __USE_FORTIFY_LEVEL < 1\n"
        "#error fortify is off\n#endif\n",
        "void probe(char *d, const char *s) { memcpy(d, s, 8); }\n",
        true, true },
    [PROBE_PIE] = {
        "pie", { "-fPIE" }, { "-fno-PIE" },
        "#if !defined(__PIE__)\n#error pie is off\n#endif\n",
        "int probe(void) { return 1; }\n", true, true },
    [PROBE_CFI] = {
        "cfi", { "-flto", "-fvisibility=hidden", "-fsanitize=cfi" },
        { NULL }, NULL,
        "struct A { int (*f)(void); };\n"
        "int probe(struct A *a) { return a->f(); }\n", true, false },
};

/** Labels of the probes, in the order they are charted. */
enum {
    PROBE_POS,      /**< Plain C. */
    PROBE_NEG,      /**< Syntax error. */
    PROBE_DEFAULT,  /**< Feature macro without any flag. */
    PROBE_OFF,      /**< Feature macro with the feature turned off. */
    PROBE_ON,       /**< The feature. */
    PROBE_N,
};

static const char *probe_labels[PROBE_N] = {
    "plain-c", "syntax-error", "default", "feature-off", "feature-on",
};

/* Copy a NULL-terminated flag list into a mutable argv-style array. */
static size_t
probe_flags(const char * const *src, const char **dst)
{
    size_t n = 0;

    while (n < PROBE_MAX_FLAGS && src[n] != NULL)
    {
        dst[n] = src[n];
        n++;
    }

    return n;
}

/*
 * Compile a snippet; @p builds says whether it compiled. Only a failure to
 * run the compiler at all is an error.
 */
static te_errno
probe_run(tapi_job_factory_t *factory, const char *cc, const char **flags,
          size_t n_flags, const char *snippet, bool *builds, double *secs)
{
    tapi_cc_opt opt = tapi_cc_default_opt;
    double      started = tsapi_mde_now();
    te_errno    rc;

    opt.compiler = cc;
    opt.cflags = flags;
    opt.n_cflags = n_flags;

    rc = tapi_cc_check_snippet(factory, &opt, TAPI_DEVTOOL_TIMEOUT_MS, "%s",
                               snippet);
    *secs = tsapi_mde_now() - started;
    *builds = (rc == 0);
    if (rc != 0 && TE_RC_GET_ERROR(rc) == TE_ESHCMD)
        rc = 0;

    return rc;
}

int
main(int argc, char **argv)
{
    probe_feature_id     feature;
    probe_cc             cc;
    const char          *cc_name;
    const probe_feature *feat;
    tsapi_mde_session    session;
    bool                 session_up = false;
    tsapi_mde_sh_result  sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string            snippet = TE_STRING_INIT;
    const char          *flags[PROBE_MAX_FLAGS];
    size_t               n_flags;
    bool                 builds[PROBE_N] = { false };
    double               built[PROBE_N] = { 0 };
    double               secs[PROBE_N] = { 0 };
    bool                 have_macro;
    bool                 expected;
    char                 title[128];
    unsigned int         i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(feature, PROBE_FEATURE_LIST);
    TEST_GET_ENUM_PARAM(cc, PROBE_CC_LIST);
    cc_name = (cc == PROBE_CC_CLANG) ? "clang" : "gcc";
    feat = &probe_features[feature];
    have_macro = (feat->macro_check != NULL);
    expected = (cc == PROBE_CC_CLANG) ? feat->expect_clang :
                                           feat->expect_gcc;

    TEST_STEP("Open a session on the agent");
    rc = tsapi_mde_session_init(&session, "dev_probe");
    session_up = true;
    if (rc != 0)
        TEST_FAIL("Cannot open a session on the agent: %r", rc);

    if (!tsapi_mde_have(&session, cc_name))
        TEST_SKIP("%s is not installed on the agent", cc_name);

    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "'%s' --version | head -n1",
                          cc_name));
    TEST_ARTIFACT("%s: %s", cc_name, te_string_value(&sh.out));

    TEST_STEP("Positive control: plain C must build");
    CHECK_RC(probe_run(session.factory, cc_name, flags, 0,
                       "int main(void) { return 0; }\n",
                       &builds[PROBE_POS], &secs[PROBE_POS]));
    if (!builds[PROBE_POS])
        TEST_VERDICT("Plain C does not compile with %s", cc_name);

    TEST_STEP("Negative control: a syntax error must not build");
    CHECK_RC(probe_run(session.factory, cc_name, flags, 0,
                       "int main(void) { return 0 }\n",
                       &builds[PROBE_NEG], &secs[PROBE_NEG]));
    if (builds[PROBE_NEG])
    {
        TEST_VERDICT("A snippet with a syntax error compiled with %s",
                     cc_name);
    }

    te_string_append(&snippet, "%s%s%s", PROBE_PRELUDE,
                     have_macro ? feat->macro_check : "", feat->body);

    if (have_macro)
    {
        TEST_STEP("Is the feature on without being asked for?");
        CHECK_RC(probe_run(session.factory, cc_name, flags, 0, snippet.ptr,
                           &builds[PROBE_DEFAULT], &secs[PROBE_DEFAULT]));
        TEST_ARTIFACT("%s: %s is %s by default", cc_name, feat->name,
                      builds[PROBE_DEFAULT] ? "on" : "off");

        TEST_STEP("Feature-off control: the macro check must fail");
        n_flags = probe_flags(feat->off, flags);
        CHECK_RC(probe_run(session.factory, cc_name, flags, n_flags,
                           snippet.ptr, &builds[PROBE_OFF],
                           &secs[PROBE_OFF]));
        if (builds[PROBE_OFF])
        {
            TEST_VERDICT("The %s probe passes with the feature turned off",
                         feat->name);
        }
    }

    TEST_STEP("Probe the feature");
    n_flags = probe_flags(feat->on, flags);
    CHECK_RC(probe_run(session.factory, cc_name, flags, n_flags,
                       snippet.ptr, &builds[PROBE_ON], &secs[PROBE_ON]));
    TEST_ARTIFACT("%s: %s %s (expected %s)", cc_name, feat->name,
                  builds[PROBE_ON] ? "supported" : "not supported",
                  expected ? "supported" : "not supported");

    TEST_STEP("Chart the probes");
    for (i = 0; i < PROBE_N; i++)
        built[i] = builds[i] ? 1 : 0;
    TE_SPRINTF(title, "Probe results: %s with %s", feat->name, cc_name);
    tsapi_mde_mi_bars("devtool", title, TE_MI_MEAS_UNITLESS_VALUE, "builds",
                      PROBE_N, probe_labels, built,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    TE_SPRINTF(title, "Probe compile time: %s with %s", feat->name, cc_name);
    tsapi_mde_mi_bars("devtool", title, TE_MI_MEAS_TIME, "compile", PROBE_N,
                      probe_labels, secs, TE_MI_MEAS_MULTIPLIER_PLAIN);
    TE_SPRINTF(title, "%s supported by %s", feat->name, cc_name);
    tsapi_mde_mi_point("devtool", title, TE_MI_MEAS_UNITLESS_VALUE,
                       "supported", built[PROBE_ON],
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Compare with what the compiler is known to support");
    if (!builds[PROBE_ON])
    {
        if (expected)
            TEST_VERDICT("%s does not support %s", cc_name, feat->name);
        TEST_SKIP("%s does not support %s", cc_name, feat->name);
    }
    if (!expected)
        RING("%s supports %s although it was not expected to", cc_name,
             feat->name);

    TEST_SUCCESS;

cleanup:

    te_string_free(&snippet);
    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

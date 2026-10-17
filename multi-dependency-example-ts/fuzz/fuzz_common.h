/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Fuzz group helpers
 *
 * What the fuzz tests share: the libFuzzer harness over the ring's C ABI
 * (double X_step(double value, int hops)), building it on the agent with
 * tapi_cc, reading libFuzzer's progress lines as a series, and the agent
 * directories the group works in.
 *
 * The harness dlopen()s the five ring libraries from dist/lib in build
 * order, looks the chosen stage up with dlsym() and calls it with a value
 * and a hop budget read from the input. A result that is not finite is a
 * defect and the harness raises SIGABRT on it from mde_result_not_finite();
 * the known-bad control variant additionally raises it from
 * mde_planted_defect() on any input starting with 'X'.
 *
 * SIGABRT must reach AddressSanitizer, not libFuzzer: libFuzzer's own
 * handler prints "libFuzzer: deadly signal" and exits with 77, which
 * tapi_sanitizer_parse() does not recognise and which is not a death by
 * signal either, so tapi_fuzz_crashes_collect() would call every abort
 * "not reproduced" (kind NONE) and fuzz/replay would call it "fixed".
 * With handle_abort=1 ASan installs its handler before libFuzzer looks,
 * libFuzzer leaves it alone, and an abort becomes
 * "AddressSanitizer: ABRT" with a symbolized stack; libFuzzer still
 * writes the crash artifact from its death callback.
 *
 * Everything here is static inline: each test is built from one C file
 * and an unused static function would break the -Werror build.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_FUZZ_COMMON_H__
#define __MDE_FUZZ_COMMON_H__

#include "te_config.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"
#include "logger_api.h"
#include "tapi_file.h"
#include "tapi_cc.h"
#include "tapi_fuzz.h"
#include "tapi_fuzz_crash.h"
#include "tapi_sanitizer.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_ring.h"

/** Scratch directory on the agent; the epilogue removes it. */
#define MDE_FUZZ_BUILD_DIR      "/tmp/mde-fuzz-build"
/** Regression corpus on the agent; it outlives the run on purpose. */
#define MDE_FUZZ_SEEDS_DIR      "/tmp/mde-fuzz-seeds"
/** Where crash reproducers land on the engine before they become seeds. */
#define MDE_FUZZ_SAVE_DIR       "/tmp/mde-fuzz-saved"
/** One shell command or one replay. */
#define MDE_FUZZ_TIMEOUT_MS     60000
/** Fewest inputs a campaign that did not crash must have executed. */
#define MDE_FUZZ_MIN_EXECS      1000
/** How long the known-bad control campaign may run, seconds. */
#define MDE_FUZZ_CONTROL_S      5
/** Number of ring libraries the harness loads. */
#define MDE_FUZZ_N_LIBS         5
/** Most points of a progress series charted. */
#define MDE_FUZZ_MAX_POINTS     256

/** Number of entries the group fuzzes. */
#define MDE_FUZZ_N_TARGETS      3

/**
 * An entry the group fuzzes.
 *
 * @param i     Index below #MDE_FUZZ_N_TARGETS.
 *
 * @return "cpp_step", "rust_step" or "go_step".
 */
static inline const char *
mde_fuzz_target(unsigned int i)
{
    static const char * const targets[MDE_FUZZ_N_TARGETS] = {
        "cpp_step", "rust_step", "go_step",
    };

    return i < MDE_FUZZ_N_TARGETS ? targets[i] : "?";
}

/**
 * Map a target name onto the ring model and the trace tag it prints.
 *
 * @param[in]  target   "cpp_step", "rust_step" or "go_step".
 * @param[out] stage    Stage of the model.
 * @param[out] tag      What the stage prints in its trace line.
 *
 * @return @c true if the target is known.
 */
static inline bool
mde_fuzz_target_stage(const char *target, tsapi_mde_stage *stage,
                      const char **tag)
{
    if (strcmp(target, "cpp_step") == 0)
    {
        *stage = TSAPI_MDE_STAGE_CPP;
        *tag = "[cpp ]";
    }
    else if (strcmp(target, "rust_step") == 0)
    {
        *stage = TSAPI_MDE_STAGE_RUST;
        *tag = "[rust]";
    }
    else if (strcmp(target, "go_step") == 0)
    {
        *stage = TSAPI_MDE_STAGE_GO;
        *tag = "[go  ]";
    }
    else
    {
        return false;
    }
    return true;
}

/**
 * The harness source. MDE_LIB_0..4 (string literals) and MDE_STAGE (a
 * bare symbol name) come in as -D defines; MDE_CONTROL plants the
 * known-bad abort.
 *
 * @return The C source.
 */
static inline const char *
mde_fuzz_harness_src(void)
{
    return
    "#define _GNU_SOURCE\n"
    "#include <dlfcn.h>\n"
    "#include <math.h>\n"
    "#include <signal.h>\n"
    "#include <stddef.h>\n"
    "#include <stdint.h>\n"
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "\n"
    "#define MDE_STR_(x) #x\n"
    "#define MDE_STR(x) MDE_STR_(x)\n"
    "\n"
    "typedef double (*mde_step_fn)(double value, int hops);\n"
    "\n"
    "static mde_step_fn mde_step;\n"
    "\n"
    "/* The Python, Go and .NET runtimes keep memory to the end by design,\n"
    " * and Go and .NET handle SIGSEGV themselves. handle_abort=1 makes an\n"
    " * abort an ASan report (\"ABRT\") instead of libFuzzer's unparsed\n"
    " * \"deadly signal\". Jobs on the agent do not inherit ASAN_OPTIONS, so\n"
    " * the defaults are compiled in. */\n"
    "const char *__asan_default_options(void);\n"
    "const char *\n"
    "__asan_default_options(void)\n"
    "{\n"
    "    return \"detect_leaks=0:allow_user_segv_handler=1:handle_abort=1\";\n"
    "}\n"
    "\n"
    "/* Named frames, so the crash signature says which oracle fired:\n"
    " * raise() keeps them in the top three frames, abort() would not. */\n"
    "__attribute__((noinline, noreturn)) static void\n"
    "mde_result_not_finite(void)\n"
    "{\n"
    "    raise(SIGABRT);\n"
    "    abort();\n"
    "}\n"
    "\n"
    "#ifdef MDE_CONTROL\n"
    "__attribute__((noinline, noreturn)) static void\n"
    "mde_planted_defect(void)\n"
    "{\n"
    "    raise(SIGABRT);\n"
    "    abort();\n"
    "}\n"
    "#endif\n"
    "\n"
    "static const char *const mde_libs[] = {\n"
    "    MDE_LIB_0, MDE_LIB_1, MDE_LIB_2, MDE_LIB_3, MDE_LIB_4,\n"
    "};\n"
    "\n"
    "int LLVMFuzzerInitialize(int *argc, char ***argv);\n"
    "int\n"
    "LLVMFuzzerInitialize(int *argc, char ***argv)\n"
    "{\n"
    "    const size_t n = sizeof(mde_libs) / sizeof(mde_libs[0]);\n"
    "    int deferred[sizeof(mde_libs) / sizeof(mde_libs[0])];\n"
    "    unsigned int second = 0;\n"
    "    size_t i;\n"
    "\n"
    "    (void)argc;\n"
    "    (void)argv;\n"
    "\n"
    "    /* Build order. libgocore leaves cpp_weight unresolved until\n"
    "     * libcppcore is in, so RTLD_NOW may refuse it (and what needs it)\n"
    "     * on the first pass; once libcppcore has brought the group in,\n"
    "     * the second pass must succeed. */\n"
    "    for (i = 0; i < n; i++) {\n"
    "        deferred[i] = dlopen(mde_libs[i], RTLD_NOW | RTLD_GLOBAL) == NULL;\n"
    "        if (deferred[i])\n"
    "            fprintf(stderr, \"mde-harness: deferred %s: %s\\n\",\n"
    "                    mde_libs[i], dlerror());\n"
    "    }\n"
    "    for (i = 0; i < n; i++) {\n"
    "        if (!deferred[i])\n"
    "            continue;\n"
    "        if (dlopen(mde_libs[i], RTLD_NOW | RTLD_GLOBAL) == NULL) {\n"
    "            fprintf(stderr, \"mde-harness: cannot load %s: %s\\n\",\n"
    "                    mde_libs[i], dlerror());\n"
    "            exit(2);\n"
    "        }\n"
    "        second++;\n"
    "    }\n"
    "\n"
    "    mde_step = (mde_step_fn)dlsym(RTLD_DEFAULT, MDE_STR(MDE_STAGE));\n"
    "    if (mde_step == NULL) {\n"
    "        fprintf(stderr, \"mde-harness: no symbol %s\\n\",\n"
    "                MDE_STR(MDE_STAGE));\n"
    "        exit(3);\n"
    "    }\n"
    "    fprintf(stderr, \"mde-harness: %s ready, %u librar%s on the \"\n"
    "            \"second pass\\n\", MDE_STR(MDE_STAGE), second,\n"
    "            second == 1 ? \"y\" : \"ies\");\n"
    "    return 0;\n"
    "}\n"
    "\n"
    "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);\n"
    "int\n"
    "LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)\n"
    "{\n"
    "    double value;\n"
    "    double result;\n"
    "    int32_t raw;\n"
    "    int hops;\n"
    "\n"
    "#ifdef MDE_CONTROL\n"
    "    if (size > 0 && data[0] == 'X')\n"
    "        mde_planted_defect();\n"
    "#endif\n"
    "    if (size < 12)\n"
    "        return 0;\n"
    "\n"
    "    memcpy(&value, data, sizeof(value));\n"
    "    memcpy(&raw, data + 8, sizeof(raw));\n"
    "    if (!isfinite(value))\n"
    "        return 0;\n"
    "    /* Finite and |v| < 1e6; hops folded into 0..3. */\n"
    "    value = fmod(value, 1e6);\n"
    "    hops = (int)(((raw % 4) + 4) % 4);\n"
    "\n"
    "    result = mde_step(value, hops);\n"
    "    printf(\"mde-harness: %s value=%.17g hops=%d result=%.17g\\n\",\n"
    "           MDE_STR(MDE_STAGE), value, hops, result);\n"
    "    fflush(stdout);\n"
    "\n"
    "    if (!isfinite(result))\n"
    "        mde_result_not_finite();\n"
    "    return 0;\n"
    "}\n";
}

/** Frame the control harness crashes in; see mde_fuzz_harness_src(). */
#define MDE_FUZZ_PLANTED_FRAME  "mde_planted_defect"

/**
 * Whether a replayed crash is the control's planted one, triaged in full:
 * ASan reported it (not a bare signal, not a fallback "unknown") and the
 * parsed stack goes through the planted function. Anything less means the
 * triage could not tell a real crash from a harness that merely exited.
 *
 * @param crash     Crash from tapi_fuzz_crashes_collect().
 *
 * @return @c true if it is.
 */
static inline bool
mde_fuzz_crash_is_planted(const tapi_fuzz_crash *crash)
{
    size_t i;

    if (crash->report.kind != TAPI_SANITIZER_ASAN)
        return false;

    for (i = 0; i < crash->report.n_frames; i++)
    {
        const char *fn = crash->report.frames[i].function;

        if (fn != NULL && strcmp(fn, MDE_FUZZ_PLANTED_FRAME) == 0)
            return true;
    }
    return false;
}

/**
 * The compiler options every harness of the group is built with.
 *
 * @param opt   Options to fill.
 */
static inline void
mde_fuzz_cc_opt_init(tapi_cc_opt *opt)
{
    static const char *cflags[] = {
        "-g", "-O1", "-fsanitize=fuzzer,address",
    };

    *opt = tapi_cc_default_opt;
    opt->compiler = "clang";
    opt->cflags = cflags;
    opt->n_cflags = TE_ARRAY_LEN(cflags);
}

/**
 * Whether the agent's clang can build a libFuzzer + ASan target.
 *
 * @param session   Session.
 *
 * @return @c true if it can.
 */
static inline bool
mde_fuzz_supported(tsapi_mde_session *session)
{
    tapi_cc_opt opt;

    if (!tsapi_mde_have(session, "clang"))
        return false;

    mde_fuzz_cc_opt_init(&opt);
    return tapi_cc_check_snippet(session->factory, &opt,
                                 TAPI_DEVTOOL_TIMEOUT_MS,
                                 "#include <stddef.h>\n"
                                 "#include <stdint.h>\n"
                                 "int LLVMFuzzerTestOneInput(const uint8_t *d, "
                                 "size_t n);\n"
                                 "int LLVMFuzzerTestOneInput(const uint8_t *d, "
                                 "size_t n)\n"
                                 "{ (void)d; (void)n; return 0; }\n") == 0;
}

/**
 * Write the harness into @p dir on the agent and build it.
 *
 * @param[in]  session  Session.
 * @param[in]  dut      Example.
 * @param[in]  target   Stage symbol, e.g. "cpp_step".
 * @param[in]  control  Plant the known-bad abort.
 * @param[in]  dir      Directory on the agent (must exist).
 * @param[out] harness  String to append the binary path to.
 * @param[out] build_s  Compile + link time, seconds.
 *
 * @return Status code; @c TE_ESHCMD when clang refuses it.
 */
static inline te_errno
mde_fuzz_build_harness(tsapi_mde_session *session, const tsapi_mde_dut *dut,
                       const char *target, bool control, const char *dir,
                       te_string *harness, double *build_s)
{
    static const char *libs[] = { "dl", "m" };
    tapi_cc_opt  opt;
    tapi_cc_app *app = NULL;
    te_string    src = TE_STRING_INIT;
    te_string    lib = TE_STRING_INIT;
    char        *defs[MDE_FUZZ_N_LIBS + 2];
    const char  *defines[MDE_FUZZ_N_LIBS + 2];
    char        *rpath = NULL;
    const char  *ldflags[1];
    const char  *sources[1];
    size_t       n_defs = 0;
    unsigned int i;
    double       t0;
    te_errno     rc;

    if (tsapi_mde_dut_n_libs != MDE_FUZZ_N_LIBS)
    {
        ERROR("The ring has %u libraries, the harness loads %u",
              tsapi_mde_dut_n_libs, MDE_FUZZ_N_LIBS);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    te_string_append(&src, "%s/harness-%s%s.c", dir, target,
                     control ? "-control" : "");
    te_string_append(harness, "%s/harness-%s%s", dir, target,
                     control ? "-control" : "");

    rc = tapi_file_create_ta(session->ta, src.ptr, "%s",
                             mde_fuzz_harness_src());
    if (rc != 0)
    {
        te_string_free(&src);
        return rc;
    }

    for (i = 0; i < MDE_FUZZ_N_LIBS; i++)
    {
        te_string_reset(&lib);
        tsapi_mde_dut_lib_path(dut, tsapi_mde_dut_libs[i], &lib);
        defs[n_defs++] = te_string_fmt("MDE_LIB_%u=\"%s\"", i, lib.ptr);
    }
    defs[n_defs++] = te_string_fmt("MDE_STAGE=%s", target);
    if (control)
        defs[n_defs++] = te_string_fmt("MDE_CONTROL=1");
    for (i = 0; i < n_defs; i++)
        defines[i] = defs[i];

    /* Belt and braces: the libraries' own DT_NEEDED resolve through it
     * even if their rpath is missing. */
    rpath = te_string_fmt("-Wl,-rpath,%s", dut->lib);
    ldflags[0] = rpath;
    sources[0] = src.ptr;

    mde_fuzz_cc_opt_init(&opt);
    opt.defines = defines;
    opt.n_defines = n_defs;
    opt.sources = sources;
    opt.n_sources = 1;
    opt.libs = libs;
    opt.n_libs = TE_ARRAY_LEN(libs);
    opt.ldflags = ldflags;
    opt.n_ldflags = 1;
    opt.output = harness->ptr;

    t0 = tsapi_mde_now();
    rc = tapi_cc_do(session->factory, &opt, TAPI_DEVTOOL_TIMEOUT_MS, &app);
    *build_s = tsapi_mde_now() - t0;
    (void)tapi_cc_destroy(app);

    for (i = 0; i < n_defs; i++)
        free(defs[i]);
    free(rpath);
    te_string_free(&lib);
    te_string_free(&src);

    return rc;
}

/** libFuzzer's progress, one point per "#N ... exec/s:" line. */
typedef struct mde_fuzz_series {
    size_t n;                               /**< Points kept. */
    double execs[MDE_FUZZ_MAX_POINTS];      /**< Inputs executed. */
    double cov[MDE_FUZZ_MAX_POINTS];        /**< Covered edges. */
    double ft[MDE_FUZZ_MAX_POINTS];         /**< Features. */
    double eps[MDE_FUZZ_MAX_POINTS];        /**< Inputs per second. */
} mde_fuzz_series;

/**
 * Read the unsigned number after @p key in @p line.
 *
 * @param line  Line.
 * @param key   Key, e.g. "cov:".
 *
 * @return The number, or @c 0 when the key is not there.
 */
static inline double
mde_fuzz_num_after(const char *line, const char *key)
{
    const char *p = strstr(line, key);

    if (p == NULL)
        return 0;
    return strtod(p + strlen(key), NULL);
}

/** Longest progress line kept whole; libFuzzer's are well under it. */
#define MDE_FUZZ_LINE_MAX       512

/**
 * Copy the line starting at @p line into @p buf (truncated) and say
 * whether it is one of libFuzzer's progress lines.
 *
 * @param[in]  line     Line start.
 * @param[out] end      Where the line ends (its newline or the NUL).
 * @param[out] buf      Buffer of #MDE_FUZZ_LINE_MAX bytes.
 *
 * @return @c true if it is a progress line.
 */
static inline bool
mde_fuzz_progress_line(const char *line, const char **end, char *buf)
{
    size_t len;

    *end = strchr(line, '\n');
    if (*end == NULL)
        *end = line + strlen(line);
    len = (size_t)(*end - line);
    if (len >= MDE_FUZZ_LINE_MAX)
        len = MDE_FUZZ_LINE_MAX - 1;
    memcpy(buf, line, len);
    buf[len] = '\0';

    return buf[0] == '#' && strstr(buf, "exec/s:") != NULL;
}

/**
 * Parse every progress line of what libFuzzer printed; when there are
 * more than #MDE_FUZZ_MAX_POINTS, every k-th is kept (the last always).
 *
 * @param[in]  text     libFuzzer's stderr.
 * @param[out] series   Series.
 *
 * @return Number of progress lines in @p text.
 */
static inline size_t
mde_fuzz_parse_series(const char *text, mde_fuzz_series *series)
{
    char        buf[MDE_FUZZ_LINE_MAX];
    const char *line;
    const char *end;
    size_t      total = 0;
    size_t      stride;
    size_t      idx = 0;

    memset(series, 0, sizeof(*series));

    for (line = text; *line != '\0'; line = (*end == '\0') ? end : end + 1)
    {
        if (mde_fuzz_progress_line(line, &end, buf))
            total++;
    }
    if (total == 0)
        return 0;

    stride = total / MDE_FUZZ_MAX_POINTS + 1;

    for (line = text; *line != '\0'; line = (*end == '\0') ? end : end + 1)
    {
        if (!mde_fuzz_progress_line(line, &end, buf))
            continue;

        idx++;
        if (idx % stride != 0 && idx != total)
            continue;
        if (series->n >= MDE_FUZZ_MAX_POINTS)
            series->n = MDE_FUZZ_MAX_POINTS - 1;

        series->execs[series->n] = strtod(buf + 1, NULL);
        series->cov[series->n] = mde_fuzz_num_after(buf, "cov:");
        series->ft[series->n] = mde_fuzz_num_after(buf, "ft:");
        series->eps[series->n] = mde_fuzz_num_after(buf, "exec/s:");
        series->n++;
    }

    return total;
}

/**
 * Number of regular files in a directory on the agent (crash inputs).
 *
 * @param[in]  session  Session.
 * @param[in]  dir      Directory.
 * @param[out] n        Count.
 *
 * @return Status code.
 */
static inline te_errno
mde_fuzz_count_files(tsapi_mde_session *session, const char *dir,
                     unsigned int *n)
{
    te_vec   files;
    te_errno rc;

    rc = tapi_fuzz_list_dir(session->factory, dir, MDE_FUZZ_TIMEOUT_MS,
                            &files);
    if (rc != 0)
        return rc;
    *n = (unsigned int)te_vec_size(&files);
    te_vec_deep_free(&files);
    return 0;
}

/**
 * Make a fresh scratch directory on the agent (removed first).
 *
 * @param session   Session.
 * @param dir       Directory.
 *
 * @return Status code; @c TE_EFAIL when the shell refused.
 */
static inline te_errno
mde_fuzz_fresh_dir(tsapi_mde_session *session, const char *dir)
{
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_errno            rc;

    rc = tsapi_mde_sh(session, MDE_FUZZ_TIMEOUT_MS, &sh,
                      "rm -rf '%s' && mkdir -p '%s'", dir, dir);
    if (rc == 0 && !tsapi_mde_sh_ok(&sh))
        rc = TE_RC(TE_TAPI, TE_EFAIL);
    tsapi_mde_sh_result_free(&sh);
    return rc;
}

#endif /* !__MDE_FUZZ_COMMON_H__ */

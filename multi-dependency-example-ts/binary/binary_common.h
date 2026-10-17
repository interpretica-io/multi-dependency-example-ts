/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Binary Group: helpers shared by the tests of the group
 *
 * Every test of the group compiles from a single .c file, so everything
 * here is static inline: a test that does not use a helper does not get
 * an unused-function warning for it.
 *
 * - where each of the ten artifacts of the example lives;
 * - a second, independent view of how a binary was built: @c readelf on
 *   the agent, parsed here, compared with what tapi_binscan read from the
 *   ELF on the engine (@c binary.view-mismatch when they disagree);
 * - the known-bad control binary, built on the agent without any
 *   hardening;
 * - a chart of several lines over a labelled index.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_BINARY_COMMON_H__
#define __MDE_BINARY_COMMON_H__

#include "te_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_str.h"
#include "te_string.h"
#include "logger_api.h"
#include "te_mi_log.h"

#include "tapi_binscan.h"
#include "tapi_cybersec.h"

#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"

/** Number of artifacts the example builds: five programs, five libraries. */
#define BINARY_N_ARTIFACTS  10

/** Subject name of the known-bad control in findings of this group. */
#define BINARY_CONTROL_NAME "mde-control"

/**
 * Name of the i-th artifact: the programs first, then the libraries.
 *
 * @param i     Index below #BINARY_N_ARTIFACTS.
 *
 * @return Name, e.g. @c "cpp-demo" or @c "libcppcore".
 */
static inline const char *
binary_artifact_name(unsigned int i)
{
    if (i < tsapi_mde_dut_n_bins)
        return tsapi_mde_dut_bins[i];
    return tsapi_mde_dut_libs[i - tsapi_mde_dut_n_bins];
}

/** Number of artifacts known to the suite library. */
static inline unsigned int
binary_n_artifacts(void)
{
    return tsapi_mde_dut_n_bins + tsapi_mde_dut_n_libs;
}

/**
 * Whether an artifact name is one of the ring libraries.
 *
 * @param name  Artifact name.
 *
 * @return @c true for a library.
 */
static inline bool
binary_artifact_is_lib(const char *name)
{
    return strncmp(name, "lib", 3) == 0;
}

/**
 * Full path of an artifact on the agent.
 *
 * @param dut   Example.
 * @param name  Artifact name.
 * @param path  String to append the path to.
 */
static inline void
binary_artifact_path(const tsapi_mde_dut *dut, const char *name,
                     te_string *path)
{
    if (binary_artifact_is_lib(name))
        tsapi_mde_dut_lib_path(dut, name, path);
    else
        te_string_append(path, "%s/%s", dut->bin, name);
}

/** How a binary was built, as one view of it says. */
typedef struct binary_props {
    bool         elf;        /**< It is an ELF object at all. */
    bool         dyn;        /**< ET_DYN: position independent. */
    bool         interp;     /**< It has a program interpreter. */
    bool         nx;         /**< The stack is not executable. */
    bool         nx_unknown; /**< There is no PT_GNU_STACK. */
    unsigned int relro;      /**< 0 none, 1 partial, 2 full. */
    bool         bindnow;    /**< Relocations are bound at startup. */
    bool         canary;     /**< Stack protector symbols are present. */
    bool         fortify;    /**< _FORTIFY_SOURCE wrappers are present. */
    unsigned int n_needed;   /**< Number of DT_NEEDED entries. */
} binary_props;

/**
 * Take the properties out of what tapi_binscan read.
 *
 * @param info  tapi_binscan_inspect() result.
 * @param props Properties.
 */
static inline void
binary_props_from_info(const tapi_binscan_info *info, binary_props *props)
{
    memset(props, 0, sizeof(*props));
    props->elf = info->elf;
    props->dyn = info->kind == TAPI_BINSCAN_KIND_PIE ||
                 info->kind == TAPI_BINSCAN_KIND_SHARED;
    props->interp = info->interp != NULL;
    props->nx = info->nx;
    props->nx_unknown = info->nx_unknown;
    props->relro = (unsigned int)info->relro;
    /* binscan folds BIND_NOW into RELRO: full means both. */
    props->bindnow = info->relro == TAPI_BINSCAN_RELRO_FULL;
    props->canary = info->canary;
    props->fortify = info->fortify;
    props->n_needed = (unsigned int)info->n_needed;
}

/**
 * The readelf view, printed as key=value lines. Each line reads one
 * property the way a person checking by hand would: the program
 * headers for INTERP, GNU_RELRO and GNU_STACK, the dynamic section for
 * BIND_NOW and NEEDED, both symbol tables for the canary and fortify
 * marks.
 */
#define BINARY_READELF_SH \
    "f='%s'; "                                                              \
    "if ! readelf -hW \"$f\" >/dev/null 2>&1; then echo elf=0; exit 0; fi; " \
    "echo elf=1; "                                                          \
    "echo type=$(readelf -hW \"$f\" | awk '/^ *Type:/{print $2; exit}'); "  \
    "echo interp=$(readelf -lW \"$f\" | grep -c '^ *INTERP '); "            \
    "echo relro=$(readelf -lW \"$f\" | grep -c '^ *GNU_RELRO '); "          \
    "echo now=$(readelf -dW \"$f\" | "                                      \
    "grep -Ec '\\(BIND_NOW\\)|\\(FLAGS\\).*BIND_NOW|\\(FLAGS_1\\).*NOW'); "  \
    "echo stack=$(readelf -lW \"$f\" | awk '/^ *GNU_STACK /"                \
    "{s=($0 ~ / RWE /)?\"exec\":\"noexec\"} "                               \
    "END{if (s==\"\") s=\"none\"; print s}'); "                             \
    "echo canary=$(readelf -sW \"$f\" 2>/dev/null | awk '{n=$8; "           \
    "sub(/@.*/,\"\",n); if (n==\"__stack_chk_fail\" || "                    \
    "n==\"__stack_chk_fail_local\" || n==\"__stack_chk_guard\" || "        \
    "n==\"__intel_security_cookie\") c++} "                                   \
    "END{print c+0}'); "                                                    \
    "echo fortify=$(readelf -sW \"$f\" 2>/dev/null | awk '{n=$8; "          \
    "sub(/@.*/,\"\",n); if (length(n) > 6 && n ~ /^__.*_chk$/) c++} "       \
    "END{print c+0}'); "                                                    \
    "echo needed=$(readelf -dW \"$f\" | grep -c '(NEEDED)')"

/**
 * Value of a "key=value" line in a text.
 *
 * @param text  Text.
 * @param key   Key.
 * @param dest  String to append the value to.
 *
 * @return @c true if the key was found.
 */
static inline bool
binary_kv_get(const char *text, const char *key, te_string *dest)
{
    size_t      klen = strlen(key);
    const char *line = text;

    while (line != NULL && *line != '\0')
    {
        const char *eol = strchr(line, '\n');
        size_t      len = (eol != NULL) ? (size_t)(eol - line) : strlen(line);

        if (len > klen && strncmp(line, key, klen) == 0 && line[klen] == '=')
        {
            te_string_append(dest, "%.*s", (int)(len - klen - 1),
                             line + klen + 1);
            return true;
        }
        line = (eol != NULL) ? eol + 1 : NULL;
    }

    return false;
}

/**
 * Unsigned value of a "key=value" line.
 *
 * @param text  Text.
 * @param key   Key.
 *
 * @return The value, or @c 0 if it is not there.
 */
static inline unsigned int
binary_kv_uint(const char *text, const char *key)
{
    te_string    val = TE_STRING_INIT;
    unsigned int result = 0;

    if (binary_kv_get(text, key, &val))
        result = (unsigned int)strtoul(te_string_value(&val), NULL, 10);
    te_string_free(&val);

    return result;
}

/**
 * Read how a binary was built with readelf on the agent.
 *
 * @param[in]  session  Session.
 * @param[in]  path     Path on the agent.
 * @param[out] props    Properties.
 * @param[out] raw      String to append the raw readelf summary to
 *                      (evidence for the log), or @c NULL.
 *
 * @return Status code; a file readelf cannot read gives @c elf=false.
 */
static inline te_errno
binary_readelf(tsapi_mde_session *session, const char *path,
               binary_props *props, te_string *raw)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    te_string           val = TE_STRING_INIT;
    unsigned int        relro;
    unsigned int        now;
    te_errno            rc;

    memset(props, 0, sizeof(*props));

    rc = tsapi_mde_sh(session, 120000, &res, BINARY_READELF_SH, path);
    if (rc != 0)
        goto out;
    if (!tsapi_mde_sh_ok(&res))
    {
        ERROR("readelf summary of %s failed: %s", path,
              te_string_value(&res.err));
        rc = TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }

    if (raw != NULL)
        te_string_append(raw, "%s", te_string_value(&res.out));

    props->elf = binary_kv_uint(te_string_value(&res.out), "elf") != 0;
    if (!props->elf)
        goto out;

    if (binary_kv_get(te_string_value(&res.out), "type", &val))
        props->dyn = strcmp(te_string_value(&val), "DYN") == 0;
    te_string_reset(&val);

    props->interp = binary_kv_uint(te_string_value(&res.out), "interp") != 0;
    relro = binary_kv_uint(te_string_value(&res.out), "relro");
    now = binary_kv_uint(te_string_value(&res.out), "now");
    props->bindnow = now != 0;
    props->relro = relro == 0 ? 0 : (now != 0 ? 2 : 1);

    if (binary_kv_get(te_string_value(&res.out), "stack", &val))
    {
        props->nx_unknown = strcmp(te_string_value(&val), "none") == 0;
        props->nx = strcmp(te_string_value(&val), "noexec") == 0;
    }
    else
    {
        props->nx_unknown = true;
    }

    props->canary = binary_kv_uint(te_string_value(&res.out), "canary") != 0;
    props->fortify = binary_kv_uint(te_string_value(&res.out), "fortify") != 0;
    props->n_needed = binary_kv_uint(te_string_value(&res.out), "needed");

out:
    te_string_free(&val);
    tsapi_mde_sh_result_free(&res);
    return rc;
}

/** Spell out a RELRO level of #binary_props. */
static inline const char *
binary_relro_str(unsigned int relro)
{
    switch (relro)
    {
        case 0:  return "none";
        case 1:  return "partial";
        default: return "full";
    }
}

/** Add one view-mismatch finding when two views disagree. */
static inline void
binary_mismatch_add(tsapi_mde_report *report, const char *name,
                    const char *prop, const char *a, const char *b)
{
    te_string subject = TE_STRING_INIT;

    te_string_append(&subject, "%s:%s", name, prop);
    tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                             "binary.view-mismatch", subject.ptr,
                             "tapi_binscan says %s, readelf on the agent "
                             "says %s", a, b);
    te_string_free(&subject);
}

#define BINARY_YN(_b) ((_b) ? "yes" : "no")

/**
 * Compare the binscan view with the readelf view of one binary and add
 * a @c binary.view-mismatch finding per property they disagree on.
 *
 * @param report    Report.
 * @param name      Artifact name, the subject prefix.
 * @param scan      binscan view.
 * @param elf       readelf view.
 *
 * @return Number of properties they disagree on.
 */
static inline unsigned int
binary_compare_views(tsapi_mde_report *report, const char *name,
                     const binary_props *scan, const binary_props *elf)
{
    unsigned int n = 0;
    char         a[32];
    char         b[32];

#define BINARY_CMP_BOOL(_field, _prop) \
    do {                                                                \
        if (scan->_field != elf->_field)                                \
        {                                                               \
            binary_mismatch_add(report, name, _prop,                    \
                                BINARY_YN(scan->_field),                \
                                BINARY_YN(elf->_field));                \
            n++;                                                        \
        }                                                               \
    } while (0)

    if (scan->elf != elf->elf)
    {
        binary_mismatch_add(report, name, "elf", BINARY_YN(scan->elf),
                            BINARY_YN(elf->elf));
        return 1;
    }
    if (!scan->elf)
        return 0;

    BINARY_CMP_BOOL(dyn, "pie");
    BINARY_CMP_BOOL(interp, "interp");
    BINARY_CMP_BOOL(nx_unknown, "gnu-stack");
    if (!scan->nx_unknown && !elf->nx_unknown)
        BINARY_CMP_BOOL(nx, "nx");
    if (scan->relro != elf->relro)
    {
        binary_mismatch_add(report, name, "relro",
                            binary_relro_str(scan->relro),
                            binary_relro_str(elf->relro));
        n++;
    }
    BINARY_CMP_BOOL(canary, "canary");
    BINARY_CMP_BOOL(fortify, "fortify");
    if (scan->n_needed != elf->n_needed)
    {
        TE_SPRINTF(a, "%u NEEDED", scan->n_needed);
        TE_SPRINTF(b, "%u NEEDED", elf->n_needed);
        binary_mismatch_add(report, name, "needed", a, b);
        n++;
    }

#undef BINARY_CMP_BOOL

    return n;
}

/**
 * Size and SHA-256 of a file on the agent, as evidence.
 *
 * @param[in]  session  Session.
 * @param[in]  path     Path on the agent.
 * @param[out] size     Size in bytes (0 if unknown).
 * @param[out] sha256   String to append the hex digest to.
 */
static inline void
binary_file_digest(tsapi_mde_session *session, const char *path,
                   unsigned long *size, te_string *sha256)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    char                hex[65];
    unsigned long       sz = 0;

    *size = 0;
    if (tsapi_mde_sh(session, 60000, &res,
                     "stat -L -c %%s '%s' && sha256sum '%s' | cut -c1-64",
                     path, path) == 0 && tsapi_mde_sh_ok(&res) &&
        sscanf(te_string_value(&res.out), "%lu %64s", &sz, hex) == 2)
    {
        *size = sz;
        te_string_append(sha256, "%s", hex);
    }
    else
    {
        te_string_append(sha256, "unknown");
    }
    tsapi_mde_sh_result_free(&res);
}

/**
 * Pick the C compiler of the agent.
 *
 * @param session   Session.
 *
 * @return @c "gcc", @c "cc", or @c NULL if there is none.
 */
static inline const char *
binary_compiler(tsapi_mde_session *session)
{
    if (tsapi_mde_have(session, "gcc"))
        return "gcc";
    if (tsapi_mde_have(session, "cc"))
        return "cc";
    return NULL;
}

/**
 * Build a C source on the agent with the given flags.
 *
 * The source is written with a quoted here-document, so it must not
 * contain a line that is exactly @c MDE_EOF.
 *
 * @param session   Session.
 * @param cc        Compiler.
 * @param src_path  Where to put the source.
 * @param out_path  Output file.
 * @param flags     Compiler and linker flags.
 * @param source    Source text.
 * @param log       String to append the compiler's diagnostics to.
 *
 * @return @c true if the output was produced.
 */
static inline bool
binary_build_c(tsapi_mde_session *session, const char *cc,
               const char *src_path, const char *out_path,
               const char *flags, const char *source, te_string *log)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    ok = tsapi_mde_sh(session, 120000, &res,
                      "rm -f '%s' && cat > '%s' <<'MDE_EOF'\n%s\nMDE_EOF\n"
                      "%s %s -o '%s' '%s' && test -f '%s'",
                      out_path, src_path, source, cc, flags, out_path,
                      src_path, out_path) == 0 &&
         tsapi_mde_sh_ok(&res);

    te_string_append(log, "%s%s", te_string_value(&res.out),
                     te_string_value(&res.err));
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/** Where the hardening control binary is built. */
#define BINARY_CONTROL_SRC  "/tmp/mde-binary-control.c"
/** The hardening control binary: no defence at all. */
#define BINARY_CONTROL_BIN  "/tmp/mde-binary-control"

/** Flags that turn every defence the scanner looks for off. */
#define BINARY_CONTROL_FLAGS \
    "-O0 -fno-stack-protector -fno-pie -no-pie -z execstack " \
    "-Wl,-z,norelro -Wl,-z,lazy"

/** Source of the control: a copy into a stack buffer. */
#define BINARY_CONTROL_SOURCE \
    "#include <stdio.h>\n"                                          \
    "#include <string.h>\n"                                         \
    "int main(int argc, char **argv)\n"                             \
    "{\n"                                                           \
    "    char buf[64];\n"                                           \
    "    strcpy(buf, argc > 1 ? argv[1] : \"control\");\n"          \
    "    puts(buf);\n"                                              \
    "    return 0;\n"                                               \
    "}"

/**
 * Build the hardening control on the agent.
 *
 * @param session   Session.
 * @param log       String to append the compiler's diagnostics to.
 *
 * @return @c true if it was built.
 */
static inline bool
binary_build_control(tsapi_mde_session *session, te_string *log)
{
    const char *cc = binary_compiler(session);

    if (cc == NULL)
    {
        te_string_append(log, "no C compiler on the agent");
        return false;
    }

    return binary_build_c(session, cc, BINARY_CONTROL_SRC,
                          BINARY_CONTROL_BIN, BINARY_CONTROL_FLAGS,
                          BINARY_CONTROL_SOURCE, log);
}

/**
 * Remove files from the agent, ignoring errors.
 *
 * @param session   Session.
 * @param paths     Space-separated list of paths.
 */
static inline void
binary_rm(tsapi_mde_session *session, const char *paths)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;

    (void)tsapi_mde_sh(session, 30000, &res, "rm -f %s", paths);
    tsapi_mde_sh_result_free(&res);
}

/**
 * Chart several lines over a labelled index, in one MI artifact.
 *
 * @param tool      Source label.
 * @param view      View id.
 * @param title     Caption.
 * @param n_x       Number of points on X.
 * @param x_labels  Labels of the points; they become keys @c x<i>.
 * @param n_y       Number of lines.
 * @param y_names   Names of the lines.
 * @param vals      Values, @p n_y rows of @p n_x values each.
 */
static inline void
binary_mi_matrix(const char *tool, const char *view, const char *title,
                 size_t n_x, const char * const *x_labels,
                 size_t n_y, const char * const *y_names,
                 const double *vals)
{
    te_mi_logger *logger;
    char          key[16];
    size_t        i;
    size_t        j;

    if (n_x == 0 || n_y == 0 || tsapi_mde_mi_create(tool, &logger) != 0)
        return;

    for (i = 0; i < n_x; i++)
    {
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "index", TE_MI_MEAS_AGGR_SINGLE, (double)i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        for (j = 0; j < n_y; j++)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  y_names[j], TE_MI_MEAS_AGGR_SINGLE,
                                  vals[j * n_x + i],
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        TE_SPRINTF(key, "x%zu", i);
        te_mi_logger_add_meas_key(logger, NULL, key, "%s", x_labels[i]);
    }

    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               view, title);
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH, view,
                                          TE_MI_GRAPH_AXIS_X, "index");
    for (j = 0; j < n_y; j++)
    {
        te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                              TE_MI_MEAS_VIEW_LINE_GRAPH,
                                              view, TE_MI_GRAPH_AXIS_Y,
                                              y_names[j]);
    }

    te_mi_logger_destroy(logger);
}

#endif /* !__MDE_BINARY_COMMON_H__ */

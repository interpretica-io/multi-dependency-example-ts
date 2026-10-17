/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Graph group helpers
 *
 * Read the linkage metadata of the five ring libraries on the agent - the
 * libraries each one needs at load time, the symbols it leaves undefined
 * and the symbols it exports - with readelf/nm on ELF hosts and otool/nm on
 * Mach-O hosts, normalised to plain names so the checks do not care which.
 *
 * Lists are kept as "\nname1\nname2\n" strings: membership is one strstr.
 *
 * Static inline only: each test is built from a single .c file.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __GRAPH_COMMON_H__
#define __GRAPH_COMMON_H__

#include "te_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_ring.h"

/** Linkage facts of one ring library. */
typedef struct graph_lib {
    tsapi_mde_stage stage;      /**< Its stage. */
    char            name[32];   /**< "libcppcore", ... */
    bool            present;    /**< The file exists. */
    te_string       needed;     /**< Load-time dependencies (base names). */
    te_string       undef;      /**< Undefined dynamic symbols. */
    te_string       exports;    /**< Exported (defined dynamic) symbols. */
    unsigned int    n_needed;
    unsigned int    n_undef;
    unsigned int    n_exports;
} graph_lib;

/** All five, indexed by #tsapi_mde_stage. */
typedef struct graph_libs {
    graph_lib lib[TSAPI_MDE_STAGE_N];
    bool      macho;            /**< Mach-O (otool) rather than ELF. */
} graph_libs;

/** Text of a string that may never have been allocated. */
static inline const char *
graph_str(const te_string *str)
{
    return str->ptr != NULL ? str->ptr : "";
}

/** Library name of a stage: "lib<stage>core". */
static inline void
graph_lib_name(tsapi_mde_stage stage, char *buf, size_t size)
{
    TE_SNPRINTF(buf, size, "lib%score", tsapi_mde_stage2str(stage));
}

/** Whether @p list holds exactly @p name. */
static inline bool
graph_list_has(const te_string *list, const char *name)
{
    te_string   pat = TE_STRING_INIT;
    bool        has;

    te_string_append(&pat, "\n%s\n", name);
    has = strstr(graph_str(list), pat.ptr) != NULL;
    te_string_free(&pat);

    return has;
}

/** Whether a library's load-time dependencies name the library of @p dep. */
static inline bool
graph_needs(const graph_lib *lib, tsapi_mde_stage dep)
{
    char core[32];

    /* "libgocore.so", "@rpath/libgocore.dylib", even a soname "cscore.so". */
    TE_SPRINTF(core, "%score.", tsapi_mde_stage2str(dep));
    return strstr(graph_str(&lib->needed), core) != NULL;
}

/** Contract symbol of a stage: "<stage>_step" or "<stage>_weight". */
static inline void
graph_sym(tsapi_mde_stage stage, bool step, char *buf, size_t size)
{
    TE_SNPRINTF(buf, size, "%s_%s", tsapi_mde_stage2str(stage),
                step ? "step" : "weight");
}

/** Whether the ELF/Mach-O tools needed here are available. */
static inline const char *
graph_tools_unavailable(tsapi_mde_session *session, bool macho)
{
    if (macho)
    {
        if (!tsapi_mde_have(session, "otool") || !tsapi_mde_have(session, "nm"))
            return "otool/nm are not available on the agent";
    }
    else
    {
        if (!tsapi_mde_have(session, "readelf") ||
            !tsapi_mde_have(session, "nm"))
            return "readelf/nm are not available on the agent";
    }

    return NULL;
}

/**
 * Run a command that prints one name per line and keep the output as a
 * "\n"-framed list.
 */
static inline te_errno
graph_list(tsapi_mde_session *session, te_string *list, unsigned int *count,
           const char *cmd)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const char         *p;
    te_errno            rc;

    te_string_free(list);
    *count = 0;

    rc = tsapi_mde_sh(session, 30000, &res, "%s", cmd);
    if (rc != 0)
    {
        tsapi_mde_sh_result_free(&res);
        return rc;
    }

    te_string_append(list, "\n%s", graph_str(&res.out));
    if (list->ptr[list->len - 1] != '\n')
        te_string_append(list, "\n");

    for (p = list->ptr + 1; *p != '\0'; p++)
    {
        if (*p == '\n' && p[-1] != '\n')
            (*count)++;
    }

    tsapi_mde_sh_result_free(&res);
    return 0;
}

/** Read the linkage of one library. */
static inline te_errno
graph_lib_load(tsapi_mde_session *session, const tsapi_mde_dut *dut,
               bool macho, graph_lib *lib)
{
    te_string path = TE_STRING_INIT;
    te_string cmd = TE_STRING_INIT;
    te_errno  rc;

    graph_lib_name(lib->stage, lib->name, sizeof(lib->name));
    tsapi_mde_dut_lib_path(dut, lib->name, &path);
    lib->present = tsapi_mde_exists(session, path.ptr);
    if (!lib->present)
    {
        te_string_free(&path);
        return 0;
    }

    /* Load-time dependencies, as base names. */
    if (macho)
        te_string_append(&cmd, "otool -L '%s' | tail -n +2 | "
                         "awk '{print $1}' | sed 's|.*/||' | "
                         "grep -v -x '%s.dylib'", path.ptr, lib->name);
    else
        te_string_append(&cmd, "readelf -d '%s' | "
                         "sed -n 's/.*(NEEDED)[^[]*\\[\\(.*\\)\\].*/\\1/p'",
                         path.ptr);
    rc = graph_list(session, &lib->needed, &lib->n_needed, cmd.ptr);

    /* Undefined dynamic symbols, without version or underscore prefix. */
    te_string_reset(&cmd);
    if (macho)
        te_string_append(&cmd, "nm -u '%s' | sed 's/^_//'", path.ptr);
    else
        te_string_append(&cmd, "nm -D --undefined-only '%s' | "
                         "awk '{print $NF}' | sed 's/@.*//'", path.ptr);
    if (rc == 0)
        rc = graph_list(session, &lib->undef, &lib->n_undef, cmd.ptr);

    /* Exported (defined) dynamic symbols. */
    te_string_reset(&cmd);
    if (macho)
        te_string_append(&cmd, "nm -gU '%s' | awk 'NF >= 3 {print $3}' | "
                         "sed 's/^_//'", path.ptr);
    else
        te_string_append(&cmd, "nm -D --defined-only '%s' | "
                         "awk 'NF >= 3 {print $3}' | sed 's/@.*//'",
                         path.ptr);
    if (rc == 0)
        rc = graph_list(session, &lib->exports, &lib->n_exports, cmd.ptr);

    RING("%s: %u NEEDED, %u undefined, %u exported\nNEEDED:%s",
         lib->name, lib->n_needed, lib->n_undef, lib->n_exports,
         graph_str(&lib->needed));

    te_string_free(&cmd);
    te_string_free(&path);
    return rc;
}

/** Read all five libraries. */
static inline te_errno
graph_libs_load(tsapi_mde_session *session, const tsapi_mde_dut *dut,
                graph_libs *libs)
{
    unsigned int i;
    te_errno     rc;

    libs->macho = strcmp(dut->dylib_ext, "dylib") == 0;
    for (i = 0; i < TSAPI_MDE_STAGE_N; i++)
    {
        libs->lib[i].stage = i;
        rc = graph_lib_load(session, dut, libs->macho, &libs->lib[i]);
        if (rc != 0)
            return rc;
    }

    return 0;
}

/** Prepare the set for loading. */
static inline void
graph_libs_init(graph_libs *libs)
{
    unsigned int i;

    memset(libs, 0, sizeof(*libs));
    for (i = 0; i < TSAPI_MDE_STAGE_N; i++)
    {
        libs->lib[i].needed = (te_string)TE_STRING_INIT;
        libs->lib[i].undef = (te_string)TE_STRING_INIT;
        libs->lib[i].exports = (te_string)TE_STRING_INIT;
    }
}

/** Release the set. */
static inline void
graph_libs_free(graph_libs *libs)
{
    unsigned int i;

    for (i = 0; i < TSAPI_MDE_STAGE_N; i++)
    {
        te_string_free(&libs->lib[i].needed);
        te_string_free(&libs->lib[i].undef);
        te_string_free(&libs->lib[i].exports);
    }
}

/**
 * Chart per library: NEEDED, undefined and exported symbol counts.
 */
static inline void
graph_chart_counts(const graph_libs *libs)
{
    te_mi_logger *logger;
    char          key[16];
    unsigned int  i;

    if (tsapi_mde_mi_create("graph", &logger) != 0)
        return;

    te_mi_logger_add_meas_key(logger, NULL, "format", "%s",
                              libs->macho ? "Mach-O" : "ELF");
    for (i = 0; i < TSAPI_MDE_STAGE_N; i++)
    {
        const graph_lib *lib = &libs->lib[i];

        TE_SPRINTF(key, "x%u", i);
        te_mi_logger_add_meas_key(logger, NULL, key, "%s", lib->name);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "library", TE_MI_MEAS_AGGR_SINGLE, i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "needed", TE_MI_MEAS_AGGR_SINGLE, lib->n_needed,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "undefined", TE_MI_MEAS_AGGR_SINGLE,
                              lib->n_undef, TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "exported", TE_MI_MEAS_AGGR_SINGLE,
                              lib->n_exports, TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    tsapi_mde_mi_line(logger, "counts", "Linkage per ring library: NEEDED, "
                      "undefined, exported", "library", "needed",
                      "undefined", "exported", NULL);
    te_mi_logger_destroy(logger);
}

/**
 * Drop every finding whose subject starts with @p prefix: the controls'
 * own findings, once they have been looked at.
 */
static inline void
graph_report_drop_prefix(tsapi_mde_report *report, const char *prefix)
{
    size_t plen = strlen(prefix);

    while (1)
    {
        const tapi_cybersec_finding *f;
        char                        *subject = NULL;

        TE_VEC_FOREACH(&report->cyber.findings, f)
        {
            if (strncmp(f->subject, prefix, plen) == 0)
            {
                subject = strdup(f->subject);
                break;
            }
        }
        if (subject == NULL)
            break;

        tsapi_mde_report_drop_subject(report, subject);
        free(subject);
    }
}

#endif /* !__GRAPH_COMMON_H__ */

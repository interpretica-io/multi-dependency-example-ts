/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Filesystem group helpers
 *
 * tsf-fs reports what it finds as tapi_kernel_issues, and the suite's
 * report fails a test over any kernel issue. The checks of this group are
 * ranked instead: every fs.* check id has a severity here, and the issues
 * are moved into the severity-ranked list of the report so that the
 * min_severity parameter decides. Plus the things several tests do: run a
 * workload of the example, chart findings per directory of the tree.
 *
 * Everything here is static inline: each test is built from one C file
 * and an unused static function would break the -Werror build.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_FS_COMMON_H__
#define __MDE_FS_COMMON_H__

#include "te_config.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "logger_api.h"
#include "tapi_cybersec.h"
#include "tapi_kernel_issue.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"

/** What a filesystem test drives. */
typedef enum fs_workload {
    FS_WORKLOAD_RING,   /**< The three ring demos. */
    FS_WORKLOAD_WEB,    /**< The web tier and requests through it. */
} fs_workload;

/** Mapping of the @c workload parameter. */
#define FS_WORKLOAD_LIST \
    { "ring", FS_WORKLOAD_RING }, \
    { "web",  FS_WORKLOAD_WEB }

/** Hop budget of every walk the group drives. */
#define FS_HOPS 7

/**
 * Severity of a tsf-fs check, or of a check of this group.
 *
 * @param check     Check id.
 *
 * @return Severity; unknown checks are medium.
 */
static inline tapi_cybersec_severity
fs_check_severity(const char *check)
{
    static const struct {
        const char            *check;
        tapi_cybersec_severity sev;
    } map[] = {
        { "fs.setuid",               TAPI_CYBERSEC_SEV_HIGH },
        { "fs.setgid",               TAPI_CYBERSEC_SEV_HIGH },
        { "fs.world-writable",       TAPI_CYBERSEC_SEV_MEDIUM },
        { "fs.no-sticky",            TAPI_CYBERSEC_SEV_MEDIUM },
        { "fs.unowned",              TAPI_CYBERSEC_SEV_LOW },
        { "fs.device-node",          TAPI_CYBERSEC_SEV_HIGH },
        { "fs.perm",                 TAPI_CYBERSEC_SEV_MEDIUM },
        { "fs.owner",                TAPI_CYBERSEC_SEV_MEDIUM },
        { "fs.file-caps",            TAPI_CYBERSEC_SEV_MEDIUM },
        { "fs.private-key",          TAPI_CYBERSEC_SEV_HIGH },
        { "fs.key-readable",         TAPI_CYBERSEC_SEV_HIGH },
        { "fs.canary",               TAPI_CYBERSEC_SEV_HIGH },
        { "fs.empty-password",       TAPI_CYBERSEC_SEV_CRITICAL },
        { "fs.weak-hash",            TAPI_CYBERSEC_SEV_HIGH },
        { "fs.passwd-hash",          TAPI_CYBERSEC_SEV_HIGH },
        { "fs.uid0",                 TAPI_CYBERSEC_SEV_CRITICAL },
        { "fs.aws-key",              TAPI_CYBERSEC_SEV_HIGH },
        { "fs.weak-hash-file",       TAPI_CYBERSEC_SEV_HIGH },
        { "fs.added",                TAPI_CYBERSEC_SEV_HIGH },
        { "fs.removed",              TAPI_CYBERSEC_SEV_HIGH },
        { "fs.modified",             TAPI_CYBERSEC_SEV_CRITICAL },
        { "fs.type-changed",         TAPI_CYBERSEC_SEV_HIGH },
        { "fs.mode-changed",         TAPI_CYBERSEC_SEV_HIGH },
        { "fs.owner-changed",        TAPI_CYBERSEC_SEV_HIGH },
        { "fs.link-changed",         TAPI_CYBERSEC_SEV_HIGH },
        { "fs.mount-option",         TAPI_CYBERSEC_SEV_MEDIUM },
        { "fs.noexec-not-enforced",  TAPI_CYBERSEC_SEV_HIGH },
        { "fs.ro-not-enforced",      TAPI_CYBERSEC_SEV_HIGH },
        { "fs.posture",              TAPI_CYBERSEC_SEV_LOW },
        { "fs.space",                TAPI_CYBERSEC_SEV_MEDIUM },
        { "fs.inodes",               TAPI_CYBERSEC_SEV_MEDIUM },
        { "fs.deleted-open",         TAPI_CYBERSEC_SEV_LOW },
        { "fs.errors",               TAPI_CYBERSEC_SEV_HIGH },
    };
    unsigned int i;

    for (i = 0; i < TE_ARRAY_LEN(map); i++)
    {
        if (strcmp(map[i].check, check) == 0)
            return map[i].sev;
    }

    return TAPI_CYBERSEC_SEV_MEDIUM;
}

/**
 * Move tsf-fs issues into the ranked list of a report and empty the
 * issue list.
 *
 * @param issues    Issues (emptied).
 * @param report    Report.
 *
 * @return Number of issues moved.
 */
static inline unsigned int
fs_issues_to_report(tapi_kernel_issues *issues, tsapi_mde_report *report)
{
    const tapi_kernel_issue *k;
    unsigned int             n = 0;

    TE_VEC_FOREACH(&issues->items, k)
    {
        tapi_cybersec_report_add(&report->cyber, fs_check_severity(k->check),
                                 k->check, k->subject, "%s",
                                 k->detail != NULL ? k->detail : "");
        n++;
    }
    tapi_kernel_issues_free(issues);
    tapi_kernel_issues_init(issues);

    return n;
}

/**
 * Chart the findings of a report per directory of a tree: the first
 * component of the path below @p root, two for @c dist (dist/bin,
 * dist/lib). Findings outside the tree go under "(outside)".
 *
 * @param report    Report.
 * @param root      Root of the tree.
 * @param tool      Chart label.
 * @param title     Chart title.
 */
static inline void
fs_chart_by_dir(const tsapi_mde_report *report, const char *root,
                const char *tool, const char *title)
{
    const tapi_cybersec_finding *f;
    char                        *labels[32];
    double                       counts[32];
    unsigned int                 n = 0;
    unsigned int                 i;
    size_t                       rlen = strlen(root);

    TE_VEC_FOREACH(&report->cyber.findings, f)
    {
        te_string   dir = TE_STRING_INIT;
        const char *rel;
        const char *slash;

        if (strncmp(f->subject, root, rlen) == 0 && f->subject[rlen] == '/')
        {
            rel = f->subject + rlen + 1;
            slash = strchr(rel, '/');
            if (slash != NULL && strncmp(rel, "dist/", 5) == 0)
                slash = strchr(slash + 1, '/');
            if (slash != NULL)
                te_string_append_buf(&dir, rel, (size_t)(slash - rel));
            else
                te_string_append(&dir, ".");
        }
        else
        {
            te_string_append(&dir, "(outside)");
        }

        for (i = 0; i < n; i++)
        {
            if (strcmp(labels[i], dir.ptr) == 0)
                break;
        }
        if (i == n && n < TE_ARRAY_LEN(labels))
        {
            labels[n] = strdup(dir.ptr);
            counts[n++] = 0;
        }
        if (i < n)
            counts[i]++;
        te_string_free(&dir);
    }

    if (n == 0)
    {
        tsapi_mde_mi_point(tool, title, TE_MI_MEAS_UNITLESS_VALUE,
                           "findings", 0, TE_MI_MEAS_MULTIPLIER_PLAIN);
        return;
    }

    tsapi_mde_mi_bars(tool, title, TE_MI_MEAS_UNITLESS_VALUE, "findings", n,
                      (const char * const *)labels, counts,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    for (i = 0; i < n; i++)
        free(labels[i]);
}

/**
 * Run the three ring demos once each.
 *
 * @param session   Session.
 * @param dut       Example.
 *
 * @return How many exited with status 0.
 */
static inline unsigned int
fs_run_ring(tsapi_mde_session *session, const tsapi_mde_dut *dut)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    unsigned int        ok = 0;

    if (tsapi_mde_sh(session, 60000, &res, "'%s/cpp-demo' 1 %d",
                     dut->bin, FS_HOPS) == 0 && tsapi_mde_sh_ok(&res))
        ok++;
    if (tsapi_mde_sh(session, 60000, &res, "'%s/rust-demo' 1 %d",
                     dut->bin, FS_HOPS) == 0 && tsapi_mde_sh_ok(&res))
        ok++;
    if (tsapi_mde_sh(session, 60000, &res, "python3 '%s/demo.py' 1 %d",
                     dut->python, FS_HOPS) == 0 && tsapi_mde_sh_ok(&res))
        ok++;

    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * Send requests into the web tier with curl, one after another.
 *
 * @param session   Session.
 * @param n         Number of requests.
 *
 * @return How many were answered with HTTP 200.
 */
static inline unsigned int
fs_web_requests(tsapi_mde_session *session, unsigned int n)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    te_string           url = TE_STRING_INIT;
    unsigned int        ok = 0;
    const char         *p;

    tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1, FS_HOPS, &url);
    if (tsapi_mde_sh(session, 30000 + (int)n * 2000, &res,
                     "i=0; ok=0; while [ $i -lt %u ]; do "
                     "c=$(curl -s -o /dev/null -m 10 -w '%%{http_code}' "
                     "'%s'); [ \"$c\" = 200 ] && ok=$((ok+1)); "
                     "i=$((i+1)); done; echo \"answered=$ok\"",
                     n, url.ptr) == 0)
    {
        p = strstr(te_string_value(&res.out), "answered=");
        if (p != NULL)
            ok = (unsigned int)strtoul(p + strlen("answered="), NULL, 10);
    }

    te_string_free(&url);
    tsapi_mde_sh_result_free(&res);

    return ok;
}

#endif /* !__MDE_FS_COMMON_H__ */

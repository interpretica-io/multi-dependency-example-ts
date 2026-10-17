/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief One report per test, filled by every module the test uses
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_LGR_USER "TSAPI MDE REPORT"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "logger_api.h"
#include "te_str.h"
#include "tapi_test_log.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"

/* See description in tsapi_mde_report.h */
void
tsapi_mde_report_init(tsapi_mde_report *report)
{
    memset(report, 0, sizeof(*report));
    tapi_cybersec_report_init(&report->cyber);
    tapi_kernel_issues_init(&report->issues);
    report->broken_controls = (te_string)TE_STRING_INIT;
}

/* See description in tsapi_mde_report.h */
void
tsapi_mde_report_free(tsapi_mde_report *report)
{
    tapi_cybersec_report_free(&report->cyber);
    tapi_kernel_issues_free(&report->issues);
    te_string_free(&report->broken_controls);
}

/* See description in tsapi_mde_report.h */
te_errno
tsapi_mde_severity_parse(const char *name, tapi_cybersec_severity *sev)
{
    static const struct {
        const char            *name;
        tapi_cybersec_severity sev;
    } map[] = {
        { "info",     TAPI_CYBERSEC_SEV_INFO },
        { "low",      TAPI_CYBERSEC_SEV_LOW },
        { "medium",   TAPI_CYBERSEC_SEV_MEDIUM },
        { "high",     TAPI_CYBERSEC_SEV_HIGH },
        { "critical", TAPI_CYBERSEC_SEV_CRITICAL },
    };
    unsigned int i;

    for (i = 0; i < TE_ARRAY_LEN(map); i++)
    {
        if (strcasecmp(name, map[i].name) == 0)
        {
            *sev = map[i].sev;
            return 0;
        }
    }

    return TE_RC(TE_TAPI, TE_EINVAL);
}

/* A check matches an exact id, or a family prefix that ends with a dot. */
static bool
check_matches(const char *pattern, const char *check)
{
    size_t len = strlen(pattern);

    if (len > 0 && pattern[len - 1] == '.')
        return strncmp(pattern, check, len) == 0;

    return strcmp(pattern, check) == 0;
}

/* See description in tsapi_mde_report.h */
unsigned int
tsapi_mde_report_has(const tsapi_mde_report *report, const char *check,
                     const char *subject)
{
    const tapi_cybersec_finding *f;
    const tapi_kernel_issue     *k;
    unsigned int                 n = 0;

    TE_VEC_FOREACH(&report->cyber.findings, f)
    {
        if (check_matches(check, f->check) &&
            (subject == NULL || strcmp(subject, f->subject) == 0))
            n++;
    }

    TE_VEC_FOREACH(&report->issues.items, k)
    {
        if (check_matches(check, k->check) &&
            (subject == NULL || strcmp(subject, k->subject) == 0))
            n++;
    }

    return n;
}

/* See description in tsapi_mde_report.h */
bool
tsapi_mde_report_expect(tsapi_mde_report *report, const char *check,
                        const char *subject)
{
    bool found = tsapi_mde_report_has(report, check, subject) > 0;

    report->n_controls++;
    if (found)
    {
        RING("Control %s on %s: found, the audit works", check,
             subject != NULL ? subject : "(any)");
    }
    else
    {
        ERROR("Control %s on %s: NOT found - the audit is blind to what "
              "was planted", check, subject != NULL ? subject : "(any)");
        te_string_append(&report->broken_controls, "%s%s on %s",
                         report->broken_controls.len > 0 ? "; " : "",
                         check, subject != NULL ? subject : "(any)");
    }

    return found;
}

/* See description in tsapi_mde_report.h */
void
tsapi_mde_report_drop_subject(tsapi_mde_report *report, const char *subject)
{
    size_t i;

    for (i = te_vec_size(&report->cyber.findings); i-- > 0; )
    {
        tapi_cybersec_finding *f = te_vec_get(&report->cyber.findings, i);

        if (strcmp(f->subject, subject) == 0)
        {
            free(f->check);
            free(f->subject);
            free(f->detail);
            te_vec_remove_index(&report->cyber.findings, i);
        }
    }

    for (i = te_vec_size(&report->issues.items); i-- > 0; )
    {
        tapi_kernel_issue *k = te_vec_get(&report->issues.items, i);

        /* The issue list owns its strings: removal frees them. */
        if (strcmp(k->subject, subject) == 0)
            te_vec_remove_index(&report->issues.items, i);
    }
}

/*
 * Make a subject under the example relative to its root. A verdict names
 * the subject, and TRC matches verdicts as text: an absolute path would
 * tie the expected results to the directory the example was built in.
 */
static void
subject_relative(char **subject, const char *root, size_t root_len)
{
    char *rel;

    if (*subject == NULL || strncmp(*subject, root, root_len) != 0 ||
        (*subject)[root_len] != '/')
        return;

    rel = strdup(*subject + root_len + 1);
    if (rel == NULL)
        return;
    free(*subject);
    *subject = rel;
}

/* Every subject of the report that lies under the example, made relative. */
static void
report_relative(tsapi_mde_report *report)
{
    const char            *root = tsapi_mde_src();
    size_t                 root_len;
    tapi_cybersec_finding *f;
    tapi_kernel_issue     *k;

    if (root == NULL)
        return;
    root_len = strlen(root);
    while (root_len > 1 && root[root_len - 1] == '/')
        root_len--;

    TE_VEC_FOREACH(&report->cyber.findings, f)
        subject_relative(&f->subject, root, root_len);
    TE_VEC_FOREACH(&report->issues.items, k)
        subject_relative(&k->subject, root, root_len);
}

/* Chart: findings per severity, plus kernel issues as their own point. */
static void
chart_severity(const tsapi_mde_report *report, const char *tool)
{
    static const char *labels[] = {
        "info", "low", "medium", "high", "critical",
    };
    double                       counts[TE_ARRAY_LEN(labels)] = { 0 };
    const tapi_cybersec_finding *f;
    te_mi_logger                *logger;
    unsigned int                 i;

    TE_VEC_FOREACH(&report->cyber.findings, f)
        counts[f->severity]++;

    if (tsapi_mde_mi_create(tool, &logger) != 0)
        return;

    for (i = 0; i < TE_ARRAY_LEN(labels); i++)
    {
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "severity", TE_MI_MEAS_AGGR_SINGLE, i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "findings", TE_MI_MEAS_AGGR_SINGLE, counts[i],
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "at_or_above",
                              TE_MI_MEAS_AGGR_SINGLE,
                              tapi_cybersec_report_count(&report->cyber, i),
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    te_mi_logger_add_meas_key(logger, NULL, "severity_axis", "%s",
                              "0=info 1=low 2=medium 3=high 4=critical");
    te_mi_logger_add_meas_key(logger, NULL, "kernel_issues", "%zu",
                              tapi_kernel_issues_count(&report->issues));
    te_mi_logger_add_meas_key(logger, NULL, "controls", "%u",
                              report->n_controls);
    tsapi_mde_mi_line(logger, "severity", "Findings per severity",
                      "severity", "findings", "at_or_above", NULL);
    te_mi_logger_destroy(logger);
}

/* Chart: findings per check family (the part of the id before the dot). */
static void
chart_families(const tsapi_mde_report *report, const char *tool)
{
    const tapi_cybersec_finding *f;
    const tapi_kernel_issue     *k;
    char                        *labels[64];
    double                       counts[64];
    unsigned int                 n = 0;
    unsigned int                 i;

#define COUNT_FAMILY(_check) \
    do {                                                            \
        const char *dot_ = strchr((_check), '.');                   \
        size_t      len_ = dot_ != NULL ? (size_t)(dot_ - (_check)) \
                                        : strlen(_check);           \
                                                                    \
        for (i = 0; i < n; i++)                                     \
        {                                                           \
            if (strlen(labels[i]) == len_ &&                        \
                strncmp(labels[i], (_check), len_) == 0)            \
                break;                                              \
        }                                                           \
        if (i == n && n < TE_ARRAY_LEN(labels))                     \
        {                                                           \
            labels[n] = strndup((_check), len_);                    \
            counts[n++] = 0;                                        \
        }                                                           \
        if (i < n)                                                  \
            counts[i]++;                                            \
    } while (0)

    TE_VEC_FOREACH(&report->cyber.findings, f)
        COUNT_FAMILY(f->check);
    TE_VEC_FOREACH(&report->issues.items, k)
        COUNT_FAMILY(k->check);

#undef COUNT_FAMILY

    tsapi_mde_mi_bars(tool, "Findings per check family",
                      TE_MI_MEAS_UNITLESS_VALUE, "findings", n,
                      (const char * const *)labels, counts,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    for (i = 0; i < n; i++)
        free(labels[i]);
}

/* See description in tsapi_mde_report.h */
bool
tsapi_mde_report_finish(tsapi_mde_report *report, const char *tool,
                        tapi_cybersec_severity min_severity,
                        te_string *verdict)
{
    const tapi_cybersec_finding *f;
    const tapi_kernel_issue     *k;
    bool                         fail = false;

    report_relative(report);
    tapi_cybersec_report_log(&report->cyber);
    tapi_kernel_issues_log(&report->issues);

    /* One artifact line per finding: visible in the result, not matched. */
    TE_VEC_FOREACH(&report->cyber.findings, f)
    {
        TEST_ARTIFACT("[%s] %s: %s - %s",
                      tapi_cybersec_severity2str(f->severity), f->check,
                      f->subject, f->detail != NULL ? f->detail : "");
    }
    TE_VEC_FOREACH(&report->issues.items, k)
    {
        TEST_ARTIFACT("[issue] %s: %s - %s", k->check, k->subject,
                      k->detail != NULL ? k->detail : "");
    }
    TEST_ARTIFACT("%s: %u finding(s), %u at or above %s, %zu issue(s), "
                  "%u control(s)", tool,
                  tapi_cybersec_report_count(&report->cyber,
                                             TAPI_CYBERSEC_SEV_INFO),
                  tapi_cybersec_report_count(&report->cyber, min_severity),
                  tapi_cybersec_severity2str(min_severity),
                  tapi_kernel_issues_count(&report->issues),
                  report->n_controls);

    if (te_vec_size(&report->cyber.findings) +
        te_vec_size(&report->issues.items) > 0)
    {
        chart_severity(report, tool);
        chart_families(report, tool);
    }

    /* A blind audit outranks whatever it reported about the DUT. */
    if (report->broken_controls.len > 0)
    {
        te_string_append(verdict, "Known-bad control not detected: %s",
                         report->broken_controls.ptr);
        return true;
    }

    if (tapi_cybersec_report_verdict(&report->cyber, min_severity, verdict))
        fail = true;

    if (tapi_kernel_issues_count(&report->issues) > 0)
    {
        if (fail)
            te_string_append(verdict, "; ");
        tapi_kernel_issues_verdict(&report->issues, verdict);
        fail = true;
    }

    return fail;
}

/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief One report per test, filled by every module the test uses
 *
 * Audits from tsf-cybersec and everything built on it append findings to
 * a tapi_cybersec_report; tsf-fs, tsf-flash and tsf-kernel append to a
 * tapi_kernel_issues list. A test of this suite keeps both in one
 * #tsapi_mde_report and decides once, at the end, what fails it - by a
 * severity threshold that is a package.xml parameter, so the same test
 * runs as a smoke check and as a hardening gate.
 *
 * On top of the gate, each report is turned into artifacts: a chart of
 * findings per severity, a chart per check family, and one artifact line
 * per finding, so the HTML log and Bublik show what was found without
 * reading the log.
 *
 * And because an audit that always comes back clean proves nothing, the
 * report checks known-bad controls: tsapi_mde_report_expect() says "this
 * audit, run against something planted to be wrong, must have found it".
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __TSAPI_MDE_REPORT_H__
#define __TSAPI_MDE_REPORT_H__

#include "te_config.h"
#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "tapi_cybersec.h"
#include "tapi_kernel_issue.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Both finding lists of a test, plus its control results. */
typedef struct tsapi_mde_report {
    /** Findings of tsf-cybersec and the modules built on it. */
    tapi_cybersec_report cyber;
    /** Issues of tsf-fs, tsf-flash and tsf-kernel. */
    tapi_kernel_issues   issues;
    /** Controls that did not find what was planted. */
    te_string            broken_controls;
    /** Number of controls checked. */
    unsigned int         n_controls;
} tsapi_mde_report;

/**
 * Prepare a report.
 *
 * @param report    Report.
 */
extern void tsapi_mde_report_init(tsapi_mde_report *report);

/**
 * Release a report.
 *
 * @param report    Report.
 */
extern void tsapi_mde_report_free(tsapi_mde_report *report);

/**
 * Parse a severity name ("info", "low", "medium", "high", "critical").
 *
 * @param[in]  name     Name.
 * @param[out] sev      Severity.
 *
 * @return Status code.
 */
extern te_errno tsapi_mde_severity_parse(const char *name,
                                         tapi_cybersec_severity *sev);

/**
 * Get the @c min_severity test parameter, the failing threshold.
 *
 * @param _var  Variable of type #tapi_cybersec_severity.
 */
#define TEST_GET_MDE_SEVERITY(_var) \
    do {                                                                   \
        const char *str_ = test_get_param(argc, argv, "min_severity");     \
                                                                           \
        if (str_ == NULL ||                                                \
            tsapi_mde_severity_parse(str_, &(_var)) != 0)                  \
            TEST_FAIL("Bad or missing min_severity parameter");            \
    } while (0)

/**
 * Whether the report holds a finding of @p check (exact id, or a prefix
 * ending with a dot such as @c "binary.") about @p subject (exact, or
 * @c NULL for any).
 *
 * @param report    Report.
 * @param check     Check id or family prefix.
 * @param subject   Subject, or @c NULL.
 *
 * @return Number of matching findings in both lists.
 */
extern unsigned int tsapi_mde_report_has(const tsapi_mde_report *report,
                                         const char *check,
                                         const char *subject);

/**
 * Record a known-bad control: @p check must have been found about
 * @p subject. A control that found nothing means the audit is broken and
 * its results on the DUT do not count; that is reported by
 * tsapi_mde_report_finish() as a verdict of its own.
 *
 * Call it after the audit ran on the planted defect.
 *
 * @param report    Report.
 * @param check     Check id or family prefix expected.
 * @param subject   The control's subject, or @c NULL for any.
 *
 * @return @c true if the control found what was planted.
 */
extern bool tsapi_mde_report_expect(tsapi_mde_report *report,
                                    const char *check, const char *subject);

/**
 * Remove findings about a subject from both lists - for the controls'
 * own findings once tsapi_mde_report_expect() has looked at them, so they
 * do not fail the DUT's gate.
 *
 * @param report    Report.
 * @param subject   Exact subject.
 */
extern void tsapi_mde_report_drop_subject(tsapi_mde_report *report,
                                          const char *subject);

/**
 * Log both lists, emit the artifacts (charts per severity and per check
 * family, one artifact line per finding) and build the verdict.
 *
 * @param[in]  report       Report.
 * @param[in]  tool         Label of the charts (the group or module).
 * @param[in]  min_severity Lowest severity worth failing over.
 * @param[out] verdict      Verdict text; untouched when nothing fails.
 *
 * @return @c true if the test should fail: a broken control, a cyber
 *         finding at or above @p min_severity, or any kernel issue.
 */
extern bool tsapi_mde_report_finish(tsapi_mde_report *report,
                                    const char *tool,
                                    tapi_cybersec_severity min_severity,
                                    te_string *verdict);

/**
 * Finish a report and stop the test with its verdict if it fails.
 *
 * @param _report   Report (pointer).
 * @param _tool     Chart label.
 * @param _sev      Threshold.
 */
#define TSAPI_MDE_REPORT_GATE(_report, _tool, _sev) \
    do {                                                                 \
        te_string verdict_ = TE_STRING_INIT;                             \
                                                                         \
        if (tsapi_mde_report_finish((_report), (_tool), (_sev),          \
                                    &verdict_))                          \
        {                                                                \
            ERROR_VERDICT("%s", verdict_.ptr);                           \
            te_string_free(&verdict_);                                   \
            TEST_STOP;                                                   \
        }                                                                \
        te_string_free(&verdict_);                                       \
    } while (0)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__TSAPI_MDE_REPORT_H__ */

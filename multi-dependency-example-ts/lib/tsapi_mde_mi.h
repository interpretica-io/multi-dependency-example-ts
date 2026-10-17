/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Measurement charts in the shape this suite draws them
 *
 * Thin helpers over TE's MI measurement artifacts (te_mi_log.h), so that
 * a test spends one line, not ten, on each chart - and therefore draws
 * one for every number it has. Every artifact carries the same keys
 * (suite, group, DUT root), so Bublik can match the same curve across
 * runs and builds.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __TSAPI_MDE_MI_H__
#define __TSAPI_MDE_MI_H__

#include "te_config.h"
#include "te_defs.h"
#include "te_errno.h"
#include "te_mi_log.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create an MI measurement logger tagged with the suite-wide keys.
 *
 * @param[in]  tool     Source of the data (a tool, a module, "model").
 * @param[out] logger   Logger; flush it with te_mi_logger_destroy().
 *
 * @return Status code.
 */
extern te_errno tsapi_mde_mi_create(const char *tool, te_mi_logger **logger);

/**
 * Add a line-graph view: X by metric name (or @c TE_MI_GRAPH_AUTO_SEQNO),
 * Y by a @c NULL-terminated list of metric names.
 *
 * @param logger    Logger.
 * @param view      View id, unique within the artifact.
 * @param title     Caption.
 * @param x         X metric name.
 * @param ...       Y metric names, then @c NULL.
 */
extern void tsapi_mde_mi_line(te_mi_logger *logger, const char *view,
                              const char *title, const char *x, ...);

/**
 * Log a value series as one chart over its index, in one call.
 *
 * @param tool      Source label.
 * @param title     Caption.
 * @param type      Metric type (gives the unit).
 * @param name      Metric name.
 * @param n         Number of values.
 * @param vals      Values.
 * @param mult      Scale of the values.
 */
extern void tsapi_mde_mi_series(const char *tool, const char *title,
                                te_mi_meas_type type, const char *name,
                                size_t n, const double *vals,
                                te_mi_meas_multiplier mult);

/**
 * Log labelled values (a bar chart as a line over the label index), in
 * one call. Labels go in as keys @c "x<i>" so the chart can be read.
 *
 * @param tool      Source label.
 * @param title     Caption.
 * @param type      Metric type.
 * @param name      Metric name.
 * @param n         Number of values.
 * @param labels    Labels.
 * @param vals      Values.
 * @param mult      Scale of the values.
 */
extern void tsapi_mde_mi_bars(const char *tool, const char *title,
                              te_mi_meas_type type, const char *name,
                              size_t n, const char * const *labels,
                              const double *vals,
                              te_mi_meas_multiplier mult);

/**
 * Log one value as a point view (a single number with a caption).
 *
 * @param tool      Source label.
 * @param title     Caption.
 * @param type      Metric type.
 * @param name      Metric name.
 * @param val       Value.
 * @param mult      Scale of the value.
 */
extern void tsapi_mde_mi_point(const char *tool, const char *title,
                               te_mi_meas_type type, const char *name,
                               double val, te_mi_meas_multiplier mult);

/**
 * Monotonic time in seconds, for timing what a test drives.
 *
 * @return Seconds.
 */
extern double tsapi_mde_now(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__TSAPI_MDE_MI_H__ */

/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Measurement charts in the shape this suite draws them
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_LGR_USER "TSAPI MDE MI"

#include "te_config.h"

#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#include "logger_api.h"
#include "te_str.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/* See description in tsapi_mde_mi.h */
te_errno
tsapi_mde_mi_create(const char *tool, te_mi_logger **logger)
{
    const char *src = tsapi_mde_src();
    te_errno    rc;

    rc = te_mi_logger_meas_create(tool, logger);
    if (rc != 0)
    {
        ERROR("Cannot create an MI logger for '%s': %r", tool, rc);
        return rc;
    }

    te_mi_logger_add_meas_key(*logger, NULL, "suite", "%s",
                              "multi-dependency-example-ts");
    te_mi_logger_add_meas_key(*logger, NULL, "dut", "%s",
                              src != NULL ? src : "(unset)");

    return 0;
}

/* See description in tsapi_mde_mi.h */
void
tsapi_mde_mi_line(te_mi_logger *logger, const char *view, const char *title,
                  const char *x, ...)
{
    const char *y;
    va_list     ap;

    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               view, title);
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH, view,
                                          TE_MI_GRAPH_AXIS_X, x);

    va_start(ap, x);
    while ((y = va_arg(ap, const char *)) != NULL)
    {
        te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                              TE_MI_MEAS_VIEW_LINE_GRAPH,
                                              view, TE_MI_GRAPH_AXIS_Y, y);
    }
    va_end(ap);
}

/* See description in tsapi_mde_mi.h */
void
tsapi_mde_mi_series(const char *tool, const char *title,
                    te_mi_meas_type type, const char *name, size_t n,
                    const double *vals, te_mi_meas_multiplier mult)
{
    te_mi_logger *logger;
    size_t        i;

    if (n == 0 || tsapi_mde_mi_create(tool, &logger) != 0)
        return;

    for (i = 0; i < n; i++)
        te_mi_logger_add_meas(logger, NULL, type, name, TE_MI_MEAS_AGGR_SINGLE,
                              vals[i], mult);

    tsapi_mde_mi_line(logger, "series", title, TE_MI_GRAPH_AUTO_SEQNO, name,
                      NULL);
    te_mi_logger_destroy(logger);
}

/* See description in tsapi_mde_mi.h */
void
tsapi_mde_mi_bars(const char *tool, const char *title, te_mi_meas_type type,
                  const char *name, size_t n, const char * const *labels,
                  const double *vals, te_mi_meas_multiplier mult)
{
    te_mi_logger *logger;
    char          key[16];
    size_t        i;

    if (n == 0 || tsapi_mde_mi_create(tool, &logger) != 0)
        return;

    for (i = 0; i < n; i++)
    {
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE, "index",
                              TE_MI_MEAS_AGGR_SINGLE, i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, type, name, TE_MI_MEAS_AGGR_SINGLE,
                              vals[i], mult);
        TE_SPRINTF(key, "x%zu", i);
        te_mi_logger_add_meas_key(logger, NULL, key, "%s", labels[i]);
    }

    tsapi_mde_mi_line(logger, "bars", title, "index", name, NULL);
    te_mi_logger_destroy(logger);
}

/* See description in tsapi_mde_mi.h */
void
tsapi_mde_mi_point(const char *tool, const char *title, te_mi_meas_type type,
                   const char *name, double val, te_mi_meas_multiplier mult)
{
    te_mi_logger *logger;

    if (tsapi_mde_mi_create(tool, &logger) != 0)
        return;

    te_mi_logger_add_meas(logger, NULL, type, name, TE_MI_MEAS_AGGR_SINGLE, val,
                          mult);
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_POINT, "point",
                               title);
    /* A point view draws nothing until it is told which value it shows. */
    te_mi_logger_meas_point_add(logger, NULL, "point", type, name,
                                TE_MI_MEAS_AGGR_SINGLE);
    te_mi_logger_destroy(logger);
}

/* See description in tsapi_mde_mi.h */
double
tsapi_mde_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

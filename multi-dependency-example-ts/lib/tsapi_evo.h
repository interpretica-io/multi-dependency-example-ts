/** @file
 * @brief TS API - Evolution Helpers
 *
 * API for performance metrics collection and analysis hints.
 *
 * Copyright (C) 2025-2026 Interpretica Unipessoal Lda
 *
 * @author Maxim Menshikov <maxim.menshikov@interpretica.io>
 */

#ifndef __TSAPI_EVO_H__
#define __TSAPI_EVO_H__

#include "te_config.h"
#include "te_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup tsapi_evo Evolution Helpers API
 * @ingroup mde_ts
 * @{
 *
 * @brief Functions for performance metrics collection and analysis hints.
 *
 * This module provides functionality for:
 * - Creating and managing simple performance charts
 * - Adding metrics to charts for throughput visualization
 * - Generating analysis hints for test environment documentation
 *
 * The output is formatted as JSON for consumption by the Evolution
 * analysis system.
 */

/**
 * Single metric of a simple chart.
 *
 * Represents a single data point in a performance chart,
 * consisting of x-axis value, y-axis value, and an optional
 * explanation string.
 */
typedef struct tsapi_evo_schart_metric {
    char *x_axis;       /**< X-axis value (e.g., stream count, channel) */
    char *y_axis;       /**< Y-axis value (e.g., throughput in Mbps) */
    char *explanation;  /**< Optional explanation or error message */
} tsapi_evo_schart_metric;

/**
 * Simple chart structure.
 *
 * Represents a performance chart that can collect multiple metrics
 * and output them in JSON format for visualization.
 */
typedef struct tsapi_evo_schart {
    char *group;                      /**< Chart group name for aggregation */
    char *name;                       /**< Chart name (e.g., "Throughput") */
    char *baseline;                   /**< Baseline value for comparison */
    char *unit;                       /**< Unit of measurement (e.g., "mbps") */
    tsapi_evo_schart_metric *metrics; /**< Array of metrics */
    size_t metrics_count;             /**< Number of metrics in array */
} tsapi_evo_schart;

/**
 * Initialize a simple chart.
 *
 * This function initializes a simple chart structure with the specified
 * parameters. The chart can then be populated with metrics using
 * tsapi_evo_schart_add_metric().
 *
 * @param[out] schart         Chart structure to initialize
 * @param[in]  chart_group    Group name for chart aggregation
 *                            (e.g., "LAN->WAN", "WLAN->WAN")
 * @param[in]  chart_name     Name of the chart (e.g., "Throughput / Streams")
 * @param[in]  chart_baseline Baseline value for comparison (e.g., "0")
 * @param[in]  chart_unit     Unit of measurement (e.g., "mbps")
 *
 * @note All string parameters are copied internally.
 *
 * @sa tsapi_evo_schart_fini
 * @sa tsapi_evo_schart_add_metric
 */
void tsapi_evo_schart_init(tsapi_evo_schart *schart,
                           const char *chart_group,
                           const char *chart_name,
                           const char *chart_baseline,
                           const char *chart_unit);

/**
 * Finalize a simple chart.
 *
 * This function releases all resources allocated for the chart,
 * including all metrics. After calling this function, the chart
 * structure should not be used without re-initialization.
 *
 * @param[in,out] schart  Chart structure to finalize
 *
 * @sa tsapi_evo_schart_init
 */
void tsapi_evo_schart_fini(tsapi_evo_schart *schart);

/**
 * Add a metric to a simple chart.
 *
 * This function adds a new data point to the chart. Multiple metrics
 * can be added to create a series of measurements.
 *
 * @param[in,out] schart      Chart to add metric to
 * @param[in]     x_axis      X-axis value (e.g., "8" for 8 streams)
 * @param[in]     y_axis      Y-axis value (e.g., "950.5" for 950.5 Mbps)
 * @param[in]     explanation Optional explanation or error message
 *                            (can be NULL for successful measurements)
 *
 * @note All string parameters are copied internally.
 *
 * @code
 * tsapi_evo_schart chart;
 * tsapi_evo_schart_init(&chart, "LAN->WAN", "Throughput", "0", "mbps");
 * tsapi_evo_schart_add_metric(&chart, "8", "945.2", NULL);
 * tsapi_evo_schart_add_metric(&chart, "32", "920.1", NULL);
 * tsapi_evo_schart_add_metric(&chart, "64", "0", "Server failed to start");
 * tsapi_evo_schart_print(&chart);
 * tsapi_evo_schart_fini(&chart);
 * @endcode
 *
 * @sa tsapi_evo_schart_print
 */
void tsapi_evo_schart_add_metric(tsapi_evo_schart *schart,
                                 const char *x_axis,
                                 const char *y_axis,
                                 const char *explanation);

/**
 * Print a simple chart to the log.
 *
 * This function outputs the chart in JSON format to the test log
 * using the RING() macro. The output can be parsed by the Evolution
 * analysis system for visualization.
 *
 * @param[in] schart  Chart to print
 *
 * @note The output format is: EVO: {"type": "schart", ...}
 *
 * @sa tsapi_evo_schart_add_metric
 */
void tsapi_evo_schart_print(tsapi_evo_schart *schart);

/**
 * Output an analysis hint to the log.
 *
 * This function outputs a hint message in JSON format to the test log.
 * Analysis hints provide context about the test environment, configuration,
 * and test progress for documentation and debugging purposes.
 *
 * @param[in] hint  Hint message string
 *
 * @note The output format is: EVO: {"type": "hint", "hint": "..."}
 *
 * @code
 * tsapi_evo_analysis_hint("This is iperf3 test. We check throughput on different mediums.");
 * tsapi_evo_analysis_hint("Connection to access point established.");
 * @endcode
 */
void tsapi_evo_analysis_hint(const char *hint);

/** @} */ /* end of tsapi_evo */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__TSAPI_EVO_H__ */
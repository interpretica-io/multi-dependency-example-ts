/** @file
 * @brief TS API - Evolution Helpers
 *
 * Implementation of performance metrics collection and analysis hints.
 *
 * Copyright (C) 2025-2026 Interpretica Unipessoal Lda
 *
 * @author Maxim Menshikov <maxim.menshikov@interpretica.io>
 */

#define TE_LGR_USER      "TSAPI Evo"

#include "te_config.h"
#include "tapi_test.h"
#include "tsapi_evo.h"

/* See the description in tsapi_evo.h */
void
tsapi_evo_schart_init(tsapi_evo_schart *schart,
    const char *chart_group,
    const char *chart_name,
    const char *chart_baseline,
    const char *chart_unit)
{
    memset(schart, 0, sizeof(*schart));
    schart->group = strdup(chart_group);
    schart->name = strdup(chart_name);
    schart->baseline = strdup(chart_baseline);
    schart->unit = strdup(chart_unit);
}

/* See the description in tsapi_evo.h */
void
tsapi_evo_schart_fini(tsapi_evo_schart *schart)
{
    free(schart->group);
    free(schart->name);
    free(schart->baseline);
    free(schart->unit);
    for (size_t i = 0; i < schart->metrics_count; i++) {
        free(schart->metrics[i].x_axis);
        free(schart->metrics[i].y_axis);
        free(schart->metrics[i].explanation);
    }
    free(schart->metrics);
}

/* See the description in tsapi_evo.h */
void
tsapi_evo_schart_add_metric(tsapi_evo_schart *schart,
    const char *x_axis,
    const char *y_axis,
    const char *explanation)
{
    schart->metrics = realloc(schart->metrics, sizeof(*schart->metrics) * (schart->metrics_count + 1));
    schart->metrics[schart->metrics_count].x_axis = strdup(x_axis);
    schart->metrics[schart->metrics_count].y_axis = strdup(y_axis);
    if (explanation == NULL)
        schart->metrics[schart->metrics_count].explanation = strdup("");
    else
        schart->metrics[schart->metrics_count].explanation = strdup(explanation);
    schart->metrics_count++;
}

static char *
tsapi_evo_schart_to_json(tsapi_evo_schart *schart)
{
    /* json representation of schart, first saved to a string */
    char *json = NULL;

    json = malloc(1024);
    snprintf(json, 1024, "{\"type\": \"schart\",\"name\":\"%s\",\"group\":\"%s\",\"baseline\":\"%s\",\"unit\":\"%s\",\"metrics\":[", schart->name, schart->group, schart->baseline, schart->unit);
    for (size_t i = 0; i < schart->metrics_count; i++) {
        snprintf(json + strlen(json), 1024 - strlen(json), "{\"x\":\"%s\",\"y\":\"%s\",\"explanation\":\"%s\"}", schart->metrics[i].x_axis, schart->metrics[i].y_axis, schart->metrics[i].explanation);
        if (i < schart->metrics_count - 1) {
            snprintf(json + strlen(json), 1024 - strlen(json), ",");
        }
    }
    snprintf(json + strlen(json), 1024 - strlen(json), "]}");
    return json;
}

/* See the description in tsapi_evo.h */
void
tsapi_evo_schart_print(tsapi_evo_schart *schart)
{
    /* json representation of schart, first saved to a string, then printed by RING() macro */
    char *json = tsapi_evo_schart_to_json(schart);
    if (json == NULL)
        return;

    RING("EVO: %s", json);
    free(json);
}

void
tsapi_evo_analysis_hint(const char *hint)
{
    RING("EVO: {\"type\": \"hint\",\"hint\":\"%s\"}", hint);
}

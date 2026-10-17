/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief The ring: a reference model, a trace parser and a comparison
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_LGR_USER "TSAPI MDE RING"

#include "te_config.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_str.h"
#include "tsapi_mde_ring.h"

/* Trace names, as the stages print them inside the brackets. */
static const char *stage_names[TSAPI_MDE_STAGE_N] = {
    "cpp", "rust", "go", "cs", "py",
};

/*
 * What each stage exports to its chord neighbour (cppcore.cpp, lib.rs,
 * gocore.go, RingStage.cs, ring_stage.py).
 */
static const double stage_weights[TSAPI_MDE_STAGE_N] = {
    1.01, 1.02, 1.03, 1.04, 1.05,
};

/* See description in tsapi_mde_ring.h */
const char *
tsapi_mde_stage2str(tsapi_mde_stage stage)
{
    return stage < TSAPI_MDE_STAGE_N ? stage_names[stage] : "?";
}

/* See description in tsapi_mde_ring.h */
double
tsapi_mde_stage_weight(tsapi_mde_stage stage)
{
    return stage < TSAPI_MDE_STAGE_N ? stage_weights[stage] : NAN;
}

/* See description in tsapi_mde_ring.h */
double
tsapi_mde_stage_apply(tsapi_mde_stage stage, double v)
{
    switch (stage)
    {
        case TSAPI_MDE_STAGE_CPP:
            return hypot(v, 3.0) * stage_weights[TSAPI_MDE_STAGE_PY];
        case TSAPI_MDE_STAGE_RUST:
            return (v * 1.5 + 1.0) * stage_weights[TSAPI_MDE_STAGE_CS];
        case TSAPI_MDE_STAGE_GO:
            return (v / 2.0 + 7.0) * stage_weights[TSAPI_MDE_STAGE_CPP];
        case TSAPI_MDE_STAGE_CS:
            return (v + 2.0) * stage_weights[TSAPI_MDE_STAGE_RUST];
        case TSAPI_MDE_STAGE_PY:
            return (v * 0.8 + 3.0) * stage_weights[TSAPI_MDE_STAGE_GO];
        default:
            return NAN;
    }
}

/* See description in tsapi_mde_ring.h */
double
tsapi_mde_ring_predict(tsapi_mde_stage entry, double value, int hops,
                       te_vec *steps)
{
    tsapi_mde_stage stage = entry;

    while (1)
    {
        tsapi_mde_step step = {
            .stage = stage,
            .hops = hops,
            .in = value,
            .out = tsapi_mde_stage_apply(stage, value),
        };

        TE_VEC_APPEND(steps, step);
        if (hops <= 0)
            return step.out;

        value = step.out;
        hops--;
        stage = (stage + 1) % TSAPI_MDE_STAGE_N;
    }
}

static bool
stage_from_name(const char *name, size_t len, tsapi_mde_stage *stage)
{
    unsigned int i;

    /* The C stand-in of the C# stage prints "cs*". */
    while (len > 0 && (name[len - 1] == ' ' || name[len - 1] == '*'))
        len--;

    for (i = 0; i < TSAPI_MDE_STAGE_N; i++)
    {
        if (strlen(stage_names[i]) == len &&
            strncmp(stage_names[i], name, len) == 0)
        {
            *stage = i;
            return true;
        }
    }

    return false;
}

/* See description in tsapi_mde_ring.h */
unsigned int
tsapi_mde_ring_parse(const char *text, te_vec *steps)
{
    const char  *line = text;
    unsigned int n = 0;

    while (line != NULL && *line != '\0')
    {
        const char *eol = strchr(line, '\n');
        const char *p = line;
        const char *close;
        tsapi_mde_step step;
        int consumed = 0;

        while (*p == ' ')
            p++;

        if (*p == '[' && (close = strchr(p, ']')) != NULL &&
            (eol == NULL || close < eol) &&
            stage_from_name(p + 1, close - p - 1, &step.stage) &&
            sscanf(close + 1, " hops=%d %lf -> %lf%n", &step.hops, &step.in,
                   &step.out, &consumed) == 3 && consumed > 0)
        {
            TE_VEC_APPEND(steps, step);
            n++;
        }

        line = (eol == NULL) ? NULL : eol + 1;
    }

    return n;
}

/* See description in tsapi_mde_ring.h */
bool
tsapi_mde_ring_parse_result(const char *text, double *result)
{
    const char *p = text;
    const char *last = NULL;

    while ((p = strstr(p, "result = ")) != NULL)
    {
        last = p;
        p++;
    }

    if (last == NULL)
        return false;

    *result = strtod(last + strlen("result = "), NULL);
    return true;
}

/* See description in tsapi_mde_ring.h */
unsigned int
tsapi_mde_ring_compare(tsapi_mde_stage entry, const te_vec *expected,
                       const te_vec *observed, bool have_result,
                       double exp_result, double obs_result, double tolerance,
                       tapi_cybersec_report *report)
{
    const char  *ename = tsapi_mde_stage2str(entry);
    size_t       n_exp = te_vec_size(expected);
    size_t       n_obs = te_vec_size(observed);
    size_t       n = MIN(n_exp, n_obs);
    unsigned int found = 0;
    char         subject[64];
    size_t       i;

#define FINDING(_sev, _check, _fmt...) \
    do {                                                               \
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_ ## _sev,   \
                                 _check, subject, _fmt);               \
        found++;                                                       \
    } while (0)

    TE_SPRINTF(subject, "%s/walk", ename);
    if (n_obs != n_exp)
    {
        FINDING(CRITICAL, "ring.depth",
                "%zu stage step(s) traced, the model predicts %zu", n_obs,
                n_exp);
    }

    for (i = 0; i < n_obs; i++)
    {
        const tsapi_mde_step *o = te_vec_get(observed, i);
        const tsapi_mde_step *e = i < n ? te_vec_get(expected, i) : NULL;
        double                f = tsapi_mde_stage_apply(o->stage, o->in);

        TE_SPRINTF(subject, "%s/step%zu:%s", ename, i,
                   tsapi_mde_stage2str(o->stage));

        /* Self-consistency: these hold whatever the model says. */
        if (fabs(f - o->out) > tolerance)
        {
            FINDING(HIGH, "ring.formula",
                    "computed %.4f from %.4f, its formula gives %.4f",
                    o->out, o->in, f);
        }

        if (i > 0)
        {
            const tsapi_mde_step *prev = te_vec_get(observed, i - 1);

            if (o->stage != (prev->stage + 1) % TSAPI_MDE_STAGE_N)
            {
                FINDING(HIGH, "ring.order", "called after %s, expected %s",
                        tsapi_mde_stage2str(prev->stage),
                        tsapi_mde_stage2str((prev->stage + 1) %
                                            TSAPI_MDE_STAGE_N));
            }
            if (o->hops != prev->hops - 1)
            {
                FINDING(HIGH, "ring.hop-counter",
                        "hops=%d after hops=%d", o->hops, prev->hops);
            }
            if (fabs(o->in - prev->out) > tolerance)
            {
                FINDING(HIGH, "ring.handoff",
                        "received %.4f, the previous stage computed %.4f",
                        o->in, prev->out);
            }
        }

        /* Against the model, position by position. */
        if (e != NULL)
        {
            if (o->stage != e->stage)
            {
                FINDING(HIGH, "ring.order", "stage %s where the model has %s",
                        tsapi_mde_stage2str(o->stage),
                        tsapi_mde_stage2str(e->stage));
            }
            if (fabs(o->in - e->in) > tolerance ||
                fabs(o->out - e->out) > tolerance)
            {
                FINDING(MEDIUM, "ring.value",
                        "%.4f -> %.4f, the model has %.4f -> %.4f",
                        o->in, o->out, e->in, e->out);
            }
        }
    }

    TE_SPRINTF(subject, "%s/result", ename);
    if (!have_result)
    {
        FINDING(CRITICAL, "ring.result", "no result line printed");
    }
    else if (fabs(obs_result - exp_result) > tolerance)
    {
        FINDING(CRITICAL, "ring.result", "returned %.4f, the model has %.4f",
                obs_result, exp_result);
    }

#undef FINDING

    return found;
}

/* See description in tsapi_mde_ring.h */
void
tsapi_mde_ring_chart(te_mi_logger *logger, const char *prefix,
                     const te_vec *expected, const te_vec *observed)
{
    size_t n_exp = te_vec_size(expected);
    size_t n_obs = te_vec_size(observed);
    size_t n = MAX(n_exp, n_obs);
    char   view[64];
    size_t i;

    /*
     * Every series gets one point per step index, so the X and Y metrics
     * have the same number of samples; a step one side did not take is
     * drawn as 0.
     */
    for (i = 0; i < n; i++)
    {
        const tsapi_mde_step *e = i < n_exp ? te_vec_get(expected, i) : NULL;
        const tsapi_mde_step *o = i < n_obs ? te_vec_get(observed, i) : NULL;

        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "step", TE_MI_MEAS_AGGR_SINGLE, i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "model_out", TE_MI_MEAS_AGGR_SINGLE,
                              e != NULL ? e->out : 0,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "observed_out", TE_MI_MEAS_AGGR_SINGLE,
                              o != NULL ? o->out : 0,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "model_hops", TE_MI_MEAS_AGGR_SINGLE,
                              e != NULL ? e->hops : -1,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "observed_hops", TE_MI_MEAS_AGGR_SINGLE,
                              o != NULL ? o->hops : -1,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TE_SPRINTF(view, "%s_values", prefix);
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               view, "Value per step: model vs. observed");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH, view,
                                          TE_MI_GRAPH_AXIS_X, "step");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH, view,
                                          TE_MI_GRAPH_AXIS_Y, "model_out");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH, view,
                                          TE_MI_GRAPH_AXIS_Y, "observed_out");

    TE_SPRINTF(view, "%s_hops", prefix);
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               view, "Hop counter per step: model vs. "
                               "observed");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH, view,
                                          TE_MI_GRAPH_AXIS_X, "step");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH, view,
                                          TE_MI_GRAPH_AXIS_Y, "model_hops");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH, view,
                                          TE_MI_GRAPH_AXIS_Y, "observed_hops");
}

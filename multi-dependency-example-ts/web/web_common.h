/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Web group helpers
 *
 * A model of the HTTP cycle gateway-rs -> service-go -> service-cs ->
 * gateway-rs (one formula per node, read from web/gateway-rs/src/main.rs,
 * web/service-go/main.go and web/service-cs/Program.cs), a parser of the
 * response body each node returns, a step-by-step comparison into a
 * report, and an HTTP GET through curl on the agent that keeps the status,
 * the time and the body.
 *
 * Static inline only: each test is built from a single .c file.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __WEB_COMMON_H__
#define __WEB_COMMON_H__

#include "te_config.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"

/** Absolute tolerance: the trace prints four decimals. */
#define WEB_TOLERANCE   1.0e-3

/** A node of the HTTP cycle, in cycle order (each calls the next). */
typedef enum web_node {
    WEB_NODE_GW = 0,    /**< gateway-rs */
    WEB_NODE_GO,        /**< service-go */
    WEB_NODE_CS,        /**< service-cs */
    WEB_NODE_N,
} web_node;

/** Name of a node as its body lines print it. */
static inline const char *
web_node2str(web_node node)
{
    switch (node)
    {
        case WEB_NODE_GW: return "gateway-rs";
        case WEB_NODE_GO: return "service-go";
        case WEB_NODE_CS: return "service-cs";
        default:          return "?";
    }
}

/** Node by name; @c WEB_NODE_N if unknown. */
static inline web_node
web_str2node(const char *name, size_t len)
{
    unsigned int i;

    for (i = 0; i < WEB_NODE_N; i++)
    {
        const char *n = web_node2str(i);

        if (strlen(n) == len && strncmp(n, name, len) == 0)
            return i;
    }

    return WEB_NODE_N;
}

/**
 * One node step:
 * - gateway-rs: rust_step(v, 0) = (v * 1.5 + 1) * cs_weight (1.04);
 * - service-go: (v + 5) * cs_weight (1.04);
 * - service-cs: (v * 0.5 + 4) * cpp_weight (1.01).
 */
static inline double
web_node_apply(web_node node, double v)
{
    switch (node)
    {
        case WEB_NODE_GW: return (v * 1.5 + 1.0) * 1.04;
        case WEB_NODE_GO: return (v + 5.0) * 1.04;
        case WEB_NODE_CS: return (v * 0.5 + 4.0) * 1.01;
        default:          return NAN;
    }
}

/** One step, as a body line prints it or as the model predicts it. */
typedef struct web_step {
    web_node node;
    int      hops;
    double   in;
    double   out;
} web_step;

/** "[node] upstream X unreachable" - a node that did not hand on. */
typedef struct web_unreach {
    web_node node;
    char     upstream[32];
} web_unreach;

/** A parsed response body. */
typedef struct web_trace {
    te_vec steps;       /**< #web_step */
    te_vec unreach;     /**< #web_unreach */
    bool   have_value;  /**< The final "value=" line was there. */
    double value;       /**< Its value. */
} web_trace;

/** Static initializer of #web_trace. */
#define WEB_TRACE_INIT { \
        .steps = TE_VEC_INIT(web_step),      \
        .unreach = TE_VEC_INIT(web_unreach), \
    }

/** Empty a trace for another parse. */
static inline void
web_trace_reset(web_trace *trace)
{
    te_vec_reset(&trace->steps);
    te_vec_reset(&trace->unreach);
    trace->have_value = false;
    trace->value = 0;
}

/** Release a trace. */
static inline void
web_trace_free(web_trace *trace)
{
    te_vec_free(&trace->steps);
    te_vec_free(&trace->unreach);
}

/**
 * Parse a response body:
 * @code
 * [gateway-rs] hops=5      1.0000 ->     2.6000   (rust_step, ...)
 * [gateway-rs] upstream service-go unreachable
 * value=2.6
 * @endcode
 */
static inline void
web_trace_parse(const char *text, web_trace *trace)
{
    const char *line = text;

    web_trace_reset(trace);

    while (line != NULL && *line != '\0')
    {
        const char *eol = strchr(line, '\n');
        size_t      len = eol != NULL ? (size_t)(eol - line) : strlen(line);
        char        buf[512];
        const char *close;

        if (len >= sizeof(buf))
            len = sizeof(buf) - 1;
        memcpy(buf, line, len);
        buf[len] = '\0';
        if (len > 0 && buf[len - 1] == '\r')
            buf[len - 1] = '\0';

        if (strncmp(buf, "value=", strlen("value=")) == 0)
        {
            trace->value = strtod(buf + strlen("value="), NULL);
            trace->have_value = true;
        }
        else if (buf[0] == '[' && (close = strchr(buf, ']')) != NULL)
        {
            web_node    node = web_str2node(buf + 1, close - buf - 1);
            web_step    step;
            web_unreach un;

            if (node != WEB_NODE_N)
            {
                memset(&un, 0, sizeof(un));
                if (sscanf(close + 1, " hops=%d %lf -> %lf", &step.hops,
                           &step.in, &step.out) == 3)
                {
                    step.node = node;
                    TE_VEC_APPEND(&trace->steps, step);
                }
                else if (sscanf(close + 1, " upstream %31s unreachable",
                                un.upstream) == 1)
                {
                    un.node = node;
                    TE_VEC_APPEND(&trace->unreach, un);
                }
            }
        }

        line = eol != NULL ? eol + 1 : NULL;
    }
}

/**
 * Predict a walk entering at @p entry.
 *
 * @return The value the walk returns.
 */
static inline double
web_predict(web_node entry, double value, int hops, te_vec *steps)
{
    web_node node = entry;

    while (1)
    {
        web_step step = {
            .node = node,
            .hops = hops,
            .in = value,
            .out = web_node_apply(node, value),
        };

        TE_VEC_APPEND(steps, step);
        if (hops <= 0)
            return step.out;

        value = step.out;
        hops--;
        node = (node + 1) % WEB_NODE_N;
    }
}

/**
 * Compare an observed trace with the model, check by check; subjects are
 * "<prefix>/walk", "<prefix>/step<N>:<node>", "<prefix>/result",
 * "<prefix>/<node>-><upstream>":
 *
 * - web.depth (critical)       fewer or more steps than predicted;
 * - web.order (high)           a step taken by the wrong node;
 * - web.hop-counter (high)     the budget did not count down by one;
 * - web.handoff (high)         a node received something else than the
 *                              previous one computed;
 * - web.formula (high)         a node did not compute its own formula;
 * - web.value (medium)         a step differs from the model's;
 * - web.unreachable (high)     a node could not reach its upstream;
 * - web.result (critical)      the returned value differs from the model's.
 *
 * @return Number of findings added.
 */
static inline unsigned int
web_compare(const char *prefix, const te_vec *expected, double exp_result,
            const web_trace *obs, tapi_cybersec_report *cyber)
{
    size_t             n_exp = te_vec_size(expected);
    size_t             n_obs = te_vec_size(&obs->steps);
    unsigned int       found = 0;
    const web_unreach *un;
    char               subject[128];
    size_t             i;

#define WEB_FINDING(_sev, _check, _fmt...) \
    do {                                                               \
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_ ## _sev,    \
                                 _check, subject, _fmt);               \
        found++;                                                       \
    } while (0)

    TE_SPRINTF(subject, "%s/walk", prefix);
    if (n_obs != n_exp)
    {
        WEB_FINDING(CRITICAL, "web.depth",
                    "%zu node step(s) traced, the model predicts %zu",
                    n_obs, n_exp);
    }

    for (i = 0; i < n_obs; i++)
    {
        const web_step *o = te_vec_get(&obs->steps, i);
        const web_step *e = i < n_exp ? te_vec_get(expected, i) : NULL;
        double          f = web_node_apply(o->node, o->in);

        TE_SPRINTF(subject, "%s/step%zu:%s", prefix, i,
                   web_node2str(o->node));

        if (!(fabs(f - o->out) <= WEB_TOLERANCE))
        {
            WEB_FINDING(HIGH, "web.formula",
                        "computed %.4f from %.4f, its formula gives %.4f",
                        o->out, o->in, f);
        }

        if (i > 0)
        {
            const web_step *p = te_vec_get(&obs->steps, i - 1);

            if (o->node != (p->node + 1) % WEB_NODE_N)
            {
                WEB_FINDING(HIGH, "web.order", "called after %s, expected "
                            "%s", web_node2str(p->node),
                            web_node2str((p->node + 1) % WEB_NODE_N));
            }
            if (o->hops != p->hops - 1)
            {
                WEB_FINDING(HIGH, "web.hop-counter", "hops=%d after hops=%d",
                            o->hops, p->hops);
            }
            if (!(fabs(o->in - p->out) <= WEB_TOLERANCE))
            {
                WEB_FINDING(HIGH, "web.handoff", "received %.4f, the "
                            "previous node computed %.4f", o->in, p->out);
            }
        }

        if (e != NULL)
        {
            if (o->node != e->node)
            {
                WEB_FINDING(HIGH, "web.order", "node %s where the model has "
                            "%s", web_node2str(o->node),
                            web_node2str(e->node));
            }
            if (!(fabs(o->in - e->in) <= WEB_TOLERANCE) ||
                !(fabs(o->out - e->out) <= WEB_TOLERANCE))
            {
                WEB_FINDING(MEDIUM, "web.value", "%.4f -> %.4f, the model "
                            "has %.4f -> %.4f", o->in, o->out, e->in,
                            e->out);
            }
        }
    }

    TE_VEC_FOREACH(&obs->unreach, un)
    {
        TE_SPRINTF(subject, "%s/%s->%s", prefix, web_node2str(un->node),
                   un->upstream);
        WEB_FINDING(HIGH, "web.unreachable", "%s did not reach its upstream",
                    web_node2str(un->node));
    }

    TE_SPRINTF(subject, "%s/result", prefix);
    if (!obs->have_value)
    {
        WEB_FINDING(CRITICAL, "web.result", "no value= line returned");
    }
    else if (!(fabs(obs->value - exp_result) <= WEB_TOLERANCE))
    {
        WEB_FINDING(CRITICAL, "web.result", "returned %.4f, the model has "
                    "%.4f", obs->value, exp_result);
    }

#undef WEB_FINDING

    return found;
}

/** What one HTTP request through curl gave. */
typedef struct web_reply {
    bool      ran;      /**< curl ran and printed its status line. */
    int       code;     /**< HTTP status, 0 if none. */
    double    time_s;   /**< curl's time_total. */
    long      size;     /**< Bytes of body downloaded. */
    te_string body;     /**< The body. */
} web_reply;

/** Static initializer of #web_reply. */
#define WEB_REPLY_INIT { .body = TE_STRING_INIT }

/** Text of a string that may never have been allocated. */
static inline const char *
web_str(const te_string *str)
{
    return str->ptr != NULL ? str->ptr : "";
}

/**
 * GET (or whatever @p opts ask for) a URL through curl on the agent.
 *
 * @param session   Session.
 * @param opts      Extra curl options ("" for a plain GET).
 * @param url       URL (single-quoted on the command line).
 * @param timeout_s curl --max-time.
 * @param reply     Reply; its body is replaced.
 *
 * @return Status code of running curl (not the HTTP status).
 */
static inline te_errno
web_get(tsapi_mde_session *session, const char *opts, const char *url,
        int timeout_s, web_reply *reply)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const char         *text;
    const char         *mark;
    const char         *p;
    te_errno            rc;

    te_string_free(&reply->body);
    reply->ran = false;
    reply->code = 0;
    reply->time_s = 0;
    reply->size = 0;

    rc = tsapi_mde_sh(session, (timeout_s + 10) * 1000, &res,
                      "curl -sS --max-time %d %s "
                      "-w '\\nMDE_HTTP=%%{http_code} MDE_T=%%{time_total} "
                      "MDE_SIZE=%%{size_download}\\n' '%s'",
                      timeout_s, opts, url);
    if (rc != 0)
    {
        tsapi_mde_sh_result_free(&res);
        return rc;
    }

    text = web_str(&res.out);
    mark = NULL;
    for (p = text; (p = strstr(p, "MDE_HTTP=")) != NULL; p++)
        mark = p;

    if (mark != NULL)
    {
        size_t body_len = mark - text;

        reply->ran = true;
        if (sscanf(mark, "MDE_HTTP=%d MDE_T=%lf MDE_SIZE=%ld", &reply->code,
                   &reply->time_s, &reply->size) < 1)
            reply->code = 0;
        /* Drop the newline -w put in front of the marker. */
        if (body_len > 0 && text[body_len - 1] == '\n')
            body_len--;
        te_string_append_buf(&reply->body, text, body_len);
    }

    RING("curl %s '%s' -> HTTP %d in %.3f s, %ld byte(s)\n%s%s", opts, url,
         reply->code, reply->time_s, reply->size, web_str(&reply->body),
         res.err.len > 0 ? web_str(&res.err) : "");

    tsapi_mde_sh_result_free(&res);
    return 0;
}

/**
 * Drop every finding whose subject starts with @p prefix: the controls'
 * own findings, once they have been looked at.
 */
static inline void
web_report_drop_prefix(tsapi_mde_report *report, const char *prefix)
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

/** Why the tier cannot be driven here, or @c NULL. */
static inline const char *
web_unavailable(tsapi_mde_session *session, const tsapi_mde_dut *dut)
{
    if (!tsapi_mde_web_built(session, dut))
        return "The web tier is not built - build the example first";
    if (!tsapi_mde_have(session, "curl"))
        return "curl is not available on the agent";

    return NULL;
}

/** Chart how long each service took to start listening. */
static inline void
web_chart_start(const tsapi_mde_web *web)
{
    const char  *names[TSAPI_MDE_WEB_N];
    double       secs[TSAPI_MDE_WEB_N];
    unsigned int i;

    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        names[i] = web->svc[i].name;
        secs[i] = web->svc[i].start_s;
        TEST_ARTIFACT("%s listened on %u after %.3f s", web->svc[i].name,
                      web->svc[i].port, web->svc[i].start_s);
    }

    tsapi_mde_mi_bars("web", "Service startup time", TE_MI_MEAS_TIME,
                      "start", web->n_started, names, secs,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
}

#endif /* !__WEB_COMMON_H__ */

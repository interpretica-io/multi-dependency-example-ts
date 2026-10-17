/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Ring group helpers
 *
 * What every ring test does: pick a demo (cpp-demo, rust-demo, the Python
 * demo), know where it enters the ring, run it on the agent capturing the
 * whole trace, its exit code and its wall time, and judge the trace against
 * the reference model of tsapi_mde_ring.h. Plus the known-bad controls that
 * prove the comparison and the crash detector are not blind.
 *
 * Static inline only: each test is built from a single .c file.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __RING_COMMON_H__
#define __RING_COMMON_H__

#include "te_config.h"

#include <inttypes.h>
#include <math.h>
#include <stdint.h>
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
#include "tsapi_mde_ring.h"

/** Absolute tolerance: the trace prints four decimals. */
#define RING_TOLERANCE  1.0e-3

/** Which demo enters the ring. */
typedef enum ring_demo {
    RING_DEMO_CPP,      /**< dist/bin/cpp-demo: enters at the Rust stage. */
    RING_DEMO_RUST,     /**< dist/bin/rust-demo: enters at the C++ stage. */
    RING_DEMO_PY,       /**< python/demo.py: enters at the C++ stage. */
    RING_DEMO_N,
} ring_demo;

/** Mapping of the @c entry parameter. */
#define RING_DEMO_LIST \
    { "cpp",  RING_DEMO_CPP  }, \
    { "rust", RING_DEMO_RUST }, \
    { "py",   RING_DEMO_PY   }

/** Parameter name of a demo. */
static inline const char *
ring_demo2str(ring_demo demo)
{
    switch (demo)
    {
        case RING_DEMO_CPP:  return "cpp";
        case RING_DEMO_RUST: return "rust";
        case RING_DEMO_PY:   return "py";
        default:             return "?";
    }
}

/**
 * The stage a demo calls first (read from cpp/src/demo.cpp,
 * rust/demo/src/main.rs and python/demo.py).
 */
static inline tsapi_mde_stage
ring_demo_entry(ring_demo demo)
{
    return demo == RING_DEMO_CPP ? TSAPI_MDE_STAGE_RUST : TSAPI_MDE_STAGE_CPP;
}

/** Shell command line that runs a demo. */
static inline void
ring_demo_cmd(const tsapi_mde_dut *dut, ring_demo demo, double value,
              int hops, te_string *cmd)
{
    /* %.17g round-trips the double through every demo's parser. */
    switch (demo)
    {
        case RING_DEMO_CPP:
            te_string_append(cmd, "'%s/cpp-demo' %.17g %d", dut->bin, value,
                             hops);
            break;

        case RING_DEMO_RUST:
            te_string_append(cmd, "'%s/rust-demo' %.17g %d", dut->bin, value,
                             hops);
            break;

        default:
            te_string_append(cmd, "python3 '%s/demo.py' %.17g %d",
                             dut->python, value, hops);
            break;
    }
}

/**
 * Why a demo cannot be run here, or @c NULL if it can. The text is stable:
 * it becomes the skip reason.
 */
static inline const char *
ring_demo_unavailable(tsapi_mde_session *session, const tsapi_mde_dut *dut,
                      ring_demo demo)
{
    te_string path = TE_STRING_INIT;
    bool      ok;

    if (demo == RING_DEMO_PY)
    {
        tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;

        te_string_append(&path, "%s/demo.py", dut->python);
        ok = tsapi_mde_exists(session, path.ptr);
        te_string_free(&path);
        if (!ok)
            return "python/demo.py is missing";

        ok = tsapi_mde_sh(session, 20000, &res,
                          "python3 -c 'import ctypes'") == 0 &&
             tsapi_mde_sh_ok(&res);
        tsapi_mde_sh_result_free(&res);
        if (!ok)
            return "python3 with ctypes is not available on the agent";

        return NULL;
    }

    te_string_append(&path, "%s/%s", dut->bin,
                     demo == RING_DEMO_CPP ? "cpp-demo" : "rust-demo");
    ok = tsapi_mde_exists(session, path.ptr);
    te_string_free(&path);

    return ok ? NULL : "The demo binary is missing - build the example first";
}

/** One run of a demo: what it printed and how it ended. */
typedef struct ring_walk {
    te_string out;          /**< Whole stdout. */
    te_string err;          /**< Whole stderr (plus the exit markers). */
    bool      started;      /**< The shell was started. */
    int       rc;           /**< Exit code of the demo (128+N on signal N). */
    bool      crashed;      /**< rc != 0. */
    double    wall_s;       /**< Wall time of the demo itself. */
    bool      agent_timed;  /**< wall_s was measured on the agent. */
    te_vec    steps;        /**< Parsed #tsapi_mde_step. */
    bool      have_result;  /**< "result = X" was printed. */
    double    result;       /**< The printed result. */
} ring_walk;

/** Static initializer of #ring_walk. */
#define RING_WALK_INIT { \
        .out = TE_STRING_INIT,                \
        .err = TE_STRING_INIT,                \
        .steps = TE_VEC_INIT(tsapi_mde_step), \
    }

/** Release a walk, leaving it ready for another run. */
static inline void
ring_walk_reset(ring_walk *walk)
{
    te_string_free(&walk->out);
    te_string_free(&walk->err);
    te_vec_reset(&walk->steps);
    walk->started = false;
    walk->rc = 0;
    walk->crashed = false;
    walk->wall_s = 0;
    walk->agent_timed = false;
    walk->have_result = false;
    walk->result = 0;
}

/** Release a walk for good. */
static inline void
ring_walk_free(ring_walk *walk)
{
    ring_walk_reset(walk);
    te_vec_free(&walk->steps);
}

/** Text of a string that may never have been allocated. */
static inline const char *
ring_str(const te_string *str)
{
    return str->ptr != NULL ? str->ptr : "";
}

/** Find the last occurrence of @p marker in @p text. */
static inline const char *
ring_last(const char *text, const char *marker)
{
    const char *p = text;
    const char *last = NULL;

    while ((p = strstr(p, marker)) != NULL)
    {
        last = p;
        p++;
    }

    return last;
}

/**
 * Run a shell command line on the agent, timing it there and recording its
 * exit code on stderr, so stdout stays exactly what the program printed.
 */
static inline te_errno
ring_walk_run_cmd(tsapi_mde_session *session, const char *cmd,
                  ring_walk *walk)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const char         *p;
    double              t0;
    te_errno            rc;

    ring_walk_reset(walk);

    t0 = tsapi_mde_now();
    rc = tsapi_mde_sh(session, 60000, &res,
                      "t0=$(date +%%s%%N); %s; rc=$?; t1=$(date +%%s%%N); "
                      "echo \"MDE_RC=$rc\" >&2; "
                      "echo \"MDE_NS=$((t1 - t0))\" >&2", cmd);
    walk->wall_s = tsapi_mde_now() - t0;
    if (rc != 0)
    {
        tsapi_mde_sh_result_free(&res);
        return rc;
    }

    walk->started = res.started;
    te_string_append(&walk->out, "%s", ring_str(&res.out));
    te_string_append(&walk->err, "%s", ring_str(&res.err));

    p = ring_last(ring_str(&walk->err), "MDE_RC=");
    if (p != NULL)
    {
        walk->rc = atoi(p + strlen("MDE_RC="));
    }
    else if (res.status.type == TAPI_JOB_STATUS_SIGNALED)
    {
        walk->rc = 128 + res.status.value;
    }
    else
    {
        walk->rc = res.status.type == TAPI_JOB_STATUS_EXITED ?
                   res.status.value : -1;
    }
    walk->crashed = walk->started && walk->rc != 0;

    p = ring_last(ring_str(&walk->err), "MDE_NS=");
    if (p != NULL)
    {
        long long ns = strtoll(p + strlen("MDE_NS="), NULL, 10);

        /* No %N in date (not GNU) gives garbage: keep the engine's time. */
        if (ns > 0 && ns < 600LL * 1000000000LL)
        {
            walk->wall_s = ns / 1e9;
            walk->agent_timed = true;
        }
    }

    tsapi_mde_ring_parse(ring_str(&walk->out), &walk->steps);
    walk->have_result = tsapi_mde_ring_parse_result(ring_str(&walk->out),
                                                    &walk->result);

    tsapi_mde_sh_result_free(&res);
    return 0;
}

/** Run a demo once. */
static inline te_errno
ring_walk_run(tsapi_mde_session *session, const tsapi_mde_dut *dut,
              ring_demo demo, double value, int hops, ring_walk *walk)
{
    te_string cmd = TE_STRING_INIT;
    te_errno  rc;

    ring_demo_cmd(dut, demo, value, hops, &cmd);
    rc = ring_walk_run_cmd(session, cmd.ptr, walk);
    if (rc == 0)
    {
        RING("%s -> exit %d, %zu stage line(s), %.3f s%s\n"
             "--- stdout ---\n%s\n--- stderr ---\n%s", cmd.ptr, walk->rc,
             te_vec_size(&walk->steps), walk->wall_s,
             walk->agent_timed ? " (agent)" : " (engine)",
             ring_str(&walk->out), ring_str(&walk->err));
    }
    te_string_free(&cmd);

    return rc;
}

/**
 * Report a demo that did not exit cleanly as a finding @c ring.crash about
 * the stage that was running: the one after the last traced step (it was
 * called and never printed), or the last one when the walk was ending.
 * The C# stage on Linux is the usual suspect: RingStage.cs binds dlsym
 * through [DllImport("libSystem.dylib")], which only exists on macOS.
 *
 * @param walk      The run.
 * @param entry     Entry stage.
 * @param prefix    Subject prefix (the entry stage name, or "control").
 * @param cyber     Report.
 *
 * @return @c true if a finding was added.
 */
static inline bool
ring_check_crash(const ring_walk *walk, tsapi_mde_stage entry,
                 const char *prefix, tapi_cybersec_report *cyber)
{
    size_t          n = te_vec_size(&walk->steps);
    tsapi_mde_stage culprit = entry;
    char            subject[96];

    if (!walk->crashed)
        return false;

    if (n > 0)
    {
        const tsapi_mde_step *last = te_vec_get(&walk->steps, n - 1);

        culprit = last->hops <= 0 ? last->stage :
                  (tsapi_mde_stage)((last->stage + 1) % TSAPI_MDE_STAGE_N);
    }

    TE_SPRINTF(subject, "%s/stage:%s", prefix, tsapi_mde_stage2str(culprit));
    tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_CRITICAL, "ring.crash",
                             subject,
                             "exit status %d%s after %zu traced step(s)",
                             walk->rc,
                             walk->rc > 128 ? " (killed by a signal)" : "",
                             n);
    return true;
}

/**
 * Drop every finding whose subject starts with @p prefix ("" drops all):
 * the controls' own findings, once they have been looked at.
 */
static inline void
ring_report_drop_prefix(tsapi_mde_report *report, const char *prefix)
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

/**
 * Known-bad control of the trace comparison: a model walk with a wrong
 * value planted at step 1 and its last step cut off must give
 * @c ring.formula and @c ring.depth. Call it on an empty report: it drops
 * everything the control found afterwards.
 */
static inline void
ring_control_compare(tsapi_mde_report *report, tsapi_mde_stage entry)
{
    te_vec                model = TE_VEC_INIT(tsapi_mde_step);
    te_vec                planted = TE_VEC_INIT(tsapi_mde_step);
    const tsapi_mde_step *s;
    char                  subject[96];
    double                result;
    size_t                i = 0;

    result = tsapi_mde_ring_predict(entry, 1.0, 3, &model);
    TE_VEC_FOREACH(&model, s)
    {
        tsapi_mde_step copy = *s;

        if (i == 1)
            copy.out += 1.0;
        if (i < 3)
            TE_VEC_APPEND(&planted, copy);
        i++;
    }

    tsapi_mde_ring_compare(entry, &model, &planted, true, result, result,
                           RING_TOLERANCE, &report->cyber);

    TE_SPRINTF(subject, "%s/step1:%s", tsapi_mde_stage2str(entry),
               tsapi_mde_stage2str((entry + 1) % TSAPI_MDE_STAGE_N));
    tsapi_mde_report_expect(report, "ring.formula", subject);
    TE_SPRINTF(subject, "%s/walk", tsapi_mde_stage2str(entry));
    tsapi_mde_report_expect(report, "ring.depth", subject);

    ring_report_drop_prefix(report, "");

    te_vec_free(&model);
    te_vec_free(&planted);
}

/**
 * Known-bad control of the crash detector: a shell that kills itself with
 * SIGSEGV must come out as @c ring.crash.
 */
static inline te_errno
ring_control_crash(tsapi_mde_session *session, tsapi_mde_report *report)
{
    ring_walk walk = RING_WALK_INIT;
    te_errno  rc;

    rc = ring_walk_run_cmd(session, "sh -c 'kill -SEGV $$'", &walk);
    if (rc == 0)
    {
        ring_check_crash(&walk, TSAPI_MDE_STAGE_CPP, "control",
                         &report->cyber);
        tsapi_mde_report_expect(report, "ring.crash", "control/stage:cpp");
        ring_report_drop_prefix(report, "control/");
    }
    ring_walk_free(&walk);

    return rc;
}

/** FNV-1a 64: a stable fingerprint of a trace. */
static inline uint64_t
ring_fnv1a(const char *text)
{
    uint64_t h = UINT64_C(14695981039346656037);

    for (; text != NULL && *text != '\0'; text++)
    {
        h ^= (unsigned char)*text;
        h *= UINT64_C(1099511628211);
    }

    return h;
}

/**
 * Chart the per-step residuals of an observed trace: how far each step's
 * output is from its own formula, and each hand-off from the previous
 * output. Both are zero for a healthy ring whatever its depth.
 */
static inline void
ring_chart_residuals(const char *title, const te_vec *observed)
{
    te_mi_logger *logger;
    size_t        n = te_vec_size(observed);
    size_t        i;

    if (n == 0 || tsapi_mde_mi_create("ring", &logger) != 0)
        return;

    for (i = 0; i < n; i++)
    {
        const tsapi_mde_step *o = te_vec_get(observed, i);
        const tsapi_mde_step *p = i > 0 ? te_vec_get(observed, i - 1) : NULL;

        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "step", TE_MI_MEAS_AGGR_SINGLE, i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "formula_residual", TE_MI_MEAS_AGGR_SINGLE,
                              fabs(tsapi_mde_stage_apply(o->stage, o->in) -
                                   o->out),
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "handoff_residual", TE_MI_MEAS_AGGR_SINGLE,
                              p != NULL ? fabs(o->in - p->out) : 0,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "stage", TE_MI_MEAS_AGGR_SINGLE, o->stage,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    te_mi_logger_add_meas_key(logger, NULL, "stage_axis", "%s",
                              "0=cpp 1=rust 2=go 3=cs 4=py");
    tsapi_mde_mi_line(logger, "residuals", title, "step",
                      "formula_residual", "handoff_residual", NULL);
    tsapi_mde_mi_line(logger, "stages", "Stage per step", "step", "stage",
                      NULL);
    te_mi_logger_destroy(logger);
}

#endif /* !__RING_COMMON_H__ */

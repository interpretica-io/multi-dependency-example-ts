/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief The ring: a reference model, a trace parser and a comparison
 *
 * Counting trace lines says how far a value went; it does not say whether
 * every stage computed what it should, handed the right value on, counted
 * the hops down or called the right neighbour. This holds a model of the
 * ring - the five stage formulas and their weights, taken from the
 * example's sources - so a test can predict the whole trace, parse the
 * trace the demo printed, and compare the two line by line.
 *
 * The model reproduces the one documented oracle (cpp-demo 1 7 ->
 * 20.0735), which is what makes it trustworthy as a reference.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __TSAPI_MDE_RING_H__
#define __TSAPI_MDE_RING_H__

#include "te_config.h"
#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "te_mi_log.h"
#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A stage of the ring, in ring order: each calls the next. */
typedef enum tsapi_mde_stage {
    TSAPI_MDE_STAGE_CPP = 0,
    TSAPI_MDE_STAGE_RUST,
    TSAPI_MDE_STAGE_GO,
    TSAPI_MDE_STAGE_CS,
    TSAPI_MDE_STAGE_PY,
    TSAPI_MDE_STAGE_N,
} tsapi_mde_stage;

/** One stage step, as printed by the stage or predicted by the model. */
typedef struct tsapi_mde_step {
    tsapi_mde_stage stage;  /**< Which stage. */
    int             hops;   /**< Hop budget it was called with. */
    double          in;     /**< Value it received. */
    double          out;    /**< Value it computed. */
} tsapi_mde_step;

/**
 * Name of a stage as the trace prints it (without padding).
 *
 * @param stage     Stage.
 *
 * @return A static string.
 */
extern const char *tsapi_mde_stage2str(tsapi_mde_stage stage);

/**
 * Weight a stage exports to its chord neighbour (cpp_weight, ...).
 *
 * @param stage     Stage.
 *
 * @return The weight.
 */
extern double tsapi_mde_stage_weight(tsapi_mde_stage stage);

/**
 * Apply one stage's formula.
 *
 * @param stage     Stage.
 * @param value     Value it receives.
 *
 * @return Value it hands on.
 */
extern double tsapi_mde_stage_apply(tsapi_mde_stage stage, double value);

/**
 * Predict the whole trace of a walk entering at @p entry.
 *
 * @param[in]  entry    First stage called.
 * @param[in]  value    Value passed in.
 * @param[in]  hops     Hop budget.
 * @param[out] steps    Vector of #tsapi_mde_step to append to.
 *
 * @return The value the walk returns.
 */
extern double tsapi_mde_ring_predict(tsapi_mde_stage entry, double value,
                                     int hops, te_vec *steps);

/**
 * Parse every stage line of a demo's output.
 *
 * Lines look like @c "  [rust] hops=7      1.0000 ->     2.6000   (...)";
 * anything else is ignored.
 *
 * @param[in]  text     Output of the demo.
 * @param[out] steps    Vector of #tsapi_mde_step to append to.
 *
 * @return Number of stage lines parsed.
 */
extern unsigned int tsapi_mde_ring_parse(const char *text, te_vec *steps);

/**
 * Parse the demo's final @c "result = X" line.
 *
 * @param[in]  text     Output of the demo.
 * @param[out] result   The value.
 *
 * @return @c true if the line was there.
 */
extern bool tsapi_mde_ring_parse_result(const char *text, double *result);

/**
 * Compare an observed trace with the predicted one, check by check.
 *
 * Every deviation is a finding in @p report, under a stable check id:
 *
 * - @c ring.depth          fewer or more steps than predicted;
 * - @c ring.order          a step was taken by the wrong stage;
 * - @c ring.hop-counter    the hop budget did not count down by one;
 * - @c ring.handoff        a stage received something other than what
 *                          the previous stage computed;
 * - @c ring.formula        a stage computed something other than its
 *                          formula gives for what it received;
 * - @c ring.value          the step's input or output differs from the
 *                          model's at the same position;
 * - @c ring.result         the returned value differs from the model's.
 *
 * Subjects are @c "<entry>/step<N>:<stage>", stable across runs.
 *
 * @param[in]  entry        Entry stage, for subjects.
 * @param[in]  expected     Predicted steps.
 * @param[in]  observed     Parsed steps.
 * @param[in]  have_result  Whether a result line was printed.
 * @param[in]  exp_result   Predicted result.
 * @param[in]  obs_result   Printed result.
 * @param[in]  tolerance    Absolute tolerance for values (the trace prints
 *                          four decimals, so 1e-3 is right).
 * @param      report       Report to add findings to.
 *
 * @return Number of findings added.
 */
extern unsigned int tsapi_mde_ring_compare(tsapi_mde_stage entry,
                                           const te_vec *expected,
                                           const te_vec *observed,
                                           bool have_result,
                                           double exp_result,
                                           double obs_result,
                                           double tolerance,
                                           tapi_cybersec_report *report);

/**
 * Add the expected-vs-observed walk to an MI logger as line graphs.
 *
 * Two views: values (model and observed output per step, over the step
 * index) and the hop counter (model and observed per step).
 *
 * @param logger    MI logger.
 * @param prefix    Prefix of the view names, unique within the artifact.
 * @param expected  Predicted steps.
 * @param observed  Parsed steps.
 */
extern void tsapi_mde_ring_chart(te_mi_logger *logger, const char *prefix,
                                 const te_vec *expected,
                                 const te_vec *observed);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__TSAPI_MDE_RING_H__ */

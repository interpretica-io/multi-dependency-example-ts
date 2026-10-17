/** @file
 * @brief AI Group
 *
 * An AI model as a second reader of the ring's evidence. cpp-demo walks
 * the ring; its trace and the README's stage formulas and weights go to
 * the model, which answers in JSON how many stages the walk visited, how
 * many it should have, whether it suspects a defect and where. The
 * model's count must equal the suite's own parse of the same trace - two
 * independent readings of one fact. What the model suspects is kept as an
 * artifact, not as a verdict. As a known-bad control the model is shown
 * a full-length trace with one stage's result planted wrong, and it must
 * flag a defect there.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ai/grade_trace"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_ai.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_ring.h"
#include "ai_common.h"

/* The step of the control trace whose result is planted wrong. */
#define CONTROL_BAD_STEP    1
/* How wrong: its result is multiplied by this. */
#define CONTROL_FACTOR      3.0

static const char grade_system[] =
    "You are a strict test oracle. You read program traces and answer "
    "with one JSON object and nothing else.";

/* The formula a stage's trace line shows, as in the README. */
static const char *
grade_formula(tsapi_mde_stage stage)
{
    switch (stage)
    {
        case TSAPI_MDE_STAGE_CPP:
            return "hypot(v, 3) * py_weight";
        case TSAPI_MDE_STAGE_RUST:
            return "(v * 1.5 + 1) * cs_weight";
        case TSAPI_MDE_STAGE_GO:
            return "(v / 2 + 7) * cpp_weight";
        case TSAPI_MDE_STAGE_CS:
            return "(v + 2) * rust_weight";
        case TSAPI_MDE_STAGE_PY:
            return "(v * 0.8 + 3) * go_weight";
        default:
            return "?";
    }
}

/* The prompt: the ring's rules from the README, the trace, the question. */
static void
grade_prompt(int hops, const char *trace, te_string *prompt)
{
    unsigned int s;

    te_string_append(prompt,
        "A value walks a ring of five stages in this fixed order: "
        "cpp -> rust -> go -> cs -> py -> cpp -> ... Each stage computes "
        "its result from the value v it receives, prints one trace line "
        "\"[stage] hops=H   input -> result   (formula)\", and, while its "
        "hop counter H is above 0, passes the result to the next stage "
        "with H-1. The stage called with hops=0 is the last one. So a "
        "walk started with a hop budget of N visits exactly N+1 stages.\n"
        "\nStage formulas (from the project README):\n");
    for (s = 0; s < TSAPI_MDE_STAGE_N; s++)
    {
        te_string_append(prompt, "- %s: %s\n",
                         tsapi_mde_stage2str((tsapi_mde_stage)s),
                         grade_formula((tsapi_mde_stage)s));
    }
    te_string_append(prompt, "\nWeights:\n");
    for (s = 0; s < TSAPI_MDE_STAGE_N; s++)
    {
        te_string_append(prompt, "- %s_weight = %.6f\n",
                         tsapi_mde_stage2str((tsapi_mde_stage)s),
                         tsapi_mde_stage_weight((tsapi_mde_stage)s));
    }
    te_string_append(prompt,
        "\nThe program below entered the ring at the rust stage with the "
        "value 1 and a hop budget of %d. Its output:\n\n%s\n"
        "Answer with this JSON object only:\n"
        "{\"stages_visited\": <number of stage trace lines in the output>, "
        "\"expected\": <number of stages a correct walk visits>, "
        "\"defect_suspected\": <true or false>, "
        "\"first_bad_stage\": \"<stage name where the walk first goes "
        "wrong, or none>\"}\n", hops, trace);
}

/* Write a trace in cpp-demo's format from a list of steps. */
static void
grade_trace_text(const te_vec *steps, int hops, te_string *text)
{
    const tsapi_mde_step *st;
    double                result = 0;

    te_string_append(text, "cpp-demo: entering the ring at the Rust stage\n"
                     "          value=1.0000 hops=%d\n\n", hops);
    TE_VEC_FOREACH(steps, st)
    {
        te_string_append(text, "  [%-4s] hops=%-2d %10.4f -> %10.4f   (%s)\n",
                         tsapi_mde_stage2str(st->stage), st->hops, st->in,
                         st->out, grade_formula(st->stage));
        result = st->out;
    }
    te_string_append(text, "\ncpp-demo: result = %.4f\n", result);
}

/* What a model answered. */
typedef struct grade_answer {
    bool      parsed;
    long      visited;
    long      expected;
    bool      defect;
    te_string bad_stage;
    double    secs;
    tapi_ai_usage usage;
} grade_answer;

/* Ask the model about one trace and parse its answer. */
static void
grade_ask(tapi_ai_conn *conn, const tapi_ai_opts *opts, int hops,
          const char *trace, const char *what, grade_answer *ans)
{
    te_string     prompt = TE_STRING_INIT;
    te_string     obj = TE_STRING_INIT;
    tapi_ai_reply reply;
    double        t0;

    memset(&reply, 0, sizeof(reply));
    grade_prompt(hops, trace, &prompt);

    t0 = tsapi_mde_now();
    ai_check_rc(tapi_ai_ask(conn, grade_system, prompt.ptr, opts,
                            AI_TIMEOUT_MS, &reply), "Asking about the trace");
    ans->secs = tsapi_mde_now() - t0;
    ans->usage = reply.usage;
    tapi_ai_reply_log(&reply);

    ans->parsed = ai_json_object(reply.text, &obj) &&
                  ai_json_int(obj.ptr, "stages_visited", &ans->visited) &&
                  ai_json_int(obj.ptr, "expected", &ans->expected) &&
                  ai_json_bool(obj.ptr, "defect_suspected", &ans->defect);
    if (ans->parsed)
        ai_json_str(obj.ptr, "first_bad_stage", &ans->bad_stage);

    TEST_ARTIFACT("Model on the %s trace (%s): %s", what,
                  reply.model != NULL ? reply.model : "?",
                  obj.ptr != NULL ? obj.ptr : "(no JSON object)");
    ai_chart_cost(what, ans->secs, &ans->usage);

    tapi_ai_reply_free(&reply);
    te_string_free(&prompt);
    te_string_free(&obj);
}

int
main(int argc, char **argv)
{
    tapi_ai_provider       provider = TAPI_AI_ANTHROPIC;
    int                    hops;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tapi_ai_conn           conn;
    bool                   conn_up = false;
    tapi_ai_opts           opts = TAPI_AI_OPTS_INIT;
    te_string              model = TE_STRING_INIT;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    tsapi_mde_report       report;
    te_vec                 observed = TE_VEC_INIT(tsapi_mde_step);
    te_vec                 expected = TE_VEC_INIT(tsapi_mde_step);
    te_vec                 planted = TE_VEC_INIT(tsapi_mde_step);
    te_string              control_trace = TE_STRING_INIT;
    grade_answer           real;
    grade_answer           control;
    unsigned int           n_obs;
    unsigned int           n_exp;
    unsigned int           i;

    TEST_START;
    memset(&dut, 0, sizeof(dut));
    memset(&conn, 0, sizeof(conn));
    memset(&real, 0, sizeof(real));
    memset(&control, 0, sizeof(control));
    real.bad_stage = (te_string)TE_STRING_INIT;
    control.bad_stage = (te_string)TE_STRING_INIT;
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(provider, AI_PROVIDER_MAPPING_LIST);
    TEST_GET_INT_PARAM(hops);
    TEST_GET_MDE_SEVERITY(min_severity);

    TEST_STEP("Open a session, locate the example, connect to the model");
    TSAPI_MDE_OPEN_OR_SKIP(session, "ai_trace", dut, session_up);
    ai_open(&session, provider, &conn, &conn_up, &model);
    opts.model = model.len > 0 ? model.ptr : NULL;
    opts.json_mode = true;
    opts.temperature_pct = 0;
    opts.max_tokens = 400;

    TEST_STEP("Walk the ring with cpp-demo 1 %d and parse it ourselves",
              hops);
    CHECK_RC(tsapi_mde_sh(&session, 60000, &sh, "'%s/cpp-demo' 1 %d",
                          dut.bin, hops));
    if (!tsapi_mde_sh_ok(&sh) || sh.out.ptr == NULL)
        TEST_VERDICT("cpp-demo did not run to completion");
    RING("cpp-demo 1 %d:\n%s", hops, sh.out.ptr);
    n_obs = tsapi_mde_ring_parse(sh.out.ptr, &observed);
    tsapi_mde_ring_predict(TSAPI_MDE_STAGE_RUST, 1.0, hops, &expected);
    n_exp = te_vec_size(&expected);
    TEST_ARTIFACT("Suite's own reading: %u stage(s) visited, %u expected - "
                  "%s", n_obs, n_exp,
                  n_obs == n_exp ? "no defect" : "the walk stops early");

    TEST_STEP("Ask the model to read the same trace");
    grade_ask(&conn, &opts, hops, sh.out.ptr, "real", &real);
    if (!real.parsed)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "ai.bad-json", "trace",
                                 "the model did not answer with the JSON "
                                 "object asked for");
    }
    else
    {
        TEST_ARTIFACT("Model's opinion (not a verdict): defect suspected %s, "
                      "first bad stage '%s'", real.defect ? "yes" : "no",
                      real.bad_stage.ptr != NULL ? real.bad_stage.ptr : "");
        if (real.visited != (long)n_obs)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                     "ai.disagrees", "trace/stages_visited",
                                     "the model counts %ld stage(s), the "
                                     "suite's parse %u", real.visited, n_obs);
        }
        if (real.expected != (long)n_exp)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                     "ai.disagrees", "trace/expected",
                                     "the model expects %ld stage(s), the "
                                     "model of the ring %u", real.expected,
                                     n_exp);
        }
        if (real.defect != (n_obs != n_exp))
        {
            RING("The model's defect opinion differs from the suite's depth "
                 "check: model %s, suite %s", real.defect ? "yes" : "no",
                 n_obs != n_exp ? "yes" : "no");
        }
    }

    TEST_STEP("Known-bad control: a full trace with step %d planted wrong",
              CONTROL_BAD_STEP);
    for (i = 0; i < te_vec_size(&expected); i++)
    {
        tsapi_mde_step st = TE_VEC_GET(tsapi_mde_step, &expected, i);

        if (i > 0)
        {
            const tsapi_mde_step *prev =
                &TE_VEC_GET(tsapi_mde_step, &planted, i - 1);

            st.in = prev->out;
            st.out = tsapi_mde_stage_apply(st.stage, st.in);
        }
        if (i == CONTROL_BAD_STEP)
            st.out *= CONTROL_FACTOR;
        TE_VEC_APPEND(&planted, st);
    }
    grade_trace_text(&planted, hops, &control_trace);
    RING("Control trace:\n%s", control_trace.ptr);
    grade_ask(&conn, &opts, hops, control_trace.ptr, "control", &control);
    if (control.parsed && control.defect)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                 "ai.defect-flagged", "control",
                                 "the model flags the planted defect, first "
                                 "bad stage '%s'",
                                 control.bad_stage.ptr != NULL ?
                                     control.bad_stage.ptr : "");
    }
    tsapi_mde_report_expect(&report, "ai.defect-flagged", "control");
    tsapi_mde_report_drop_subject(&report, "control");

    TEST_STEP("Chart the readings");
    {
        const char *labels[] = { "suite parse", "model (real)", "expected",
                                 "model (control)" };
        double      vals[4];

        vals[0] = n_obs;
        vals[1] = real.parsed ? real.visited : -1;
        vals[2] = n_exp;
        vals[3] = control.parsed ? control.visited : -1;
        tsapi_mde_mi_bars("ai", "Stages visited: suite vs model",
                          TE_MI_MEAS_UNITLESS_VALUE, "stages",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "ai", min_severity);

    TEST_SUCCESS;

cleanup:

    if (conn_up)
        tapi_ai_conn_fini(&conn);
    te_vec_free(&observed);
    te_vec_free(&expected);
    te_vec_free(&planted);
    te_string_free(&control_trace);
    te_string_free(&real.bad_stage);
    te_string_free(&control.bad_stage);
    te_string_free(&model);
    tsapi_mde_sh_result_free(&sh);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

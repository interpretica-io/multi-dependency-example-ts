/** @file
 * @brief cwmp Group
 *
 * The TR-069 SOAP codec, engine-side and pure. The ring's results (from
 * the reference model) are carried as ParameterValueStruct entries -
 * Device.X_MDE.Ring.Result, .Depth and .Stage.<i>.Out - encoded into a
 * SOAP envelope with tapi_cwmp_build_spv, then decoded back with
 * tapi_cwmp_parse_response and every field compared (a deep round-trip).
 * Malformed SOAP (truncated, garbage, oversized) is fed to the parser as
 * a control: it must be rejected cleanly, never parsed into values.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "cwmp/inform_codec"

#include "te_config.h"
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"

#include "tsapi_mde_ring.h"
#include "tsapi_mde_mi.h"

#include "tapi_cwmp.h"
#include "tapi_cwmp_msg.h"

/* cpp-demo enters the ring at the Rust stage. */
#define MDE_ENTRY   TSAPI_MDE_STAGE_RUST
#define MAXP    40

/* The type a decoded parameter came back as, by name, or -1 if absent. */
static int
decoded_type(const tapi_cwmp_result *result, const char *name)
{
    const tapi_cwmp_param *p;

    TE_VEC_FOREACH(&result->params, p)
    {
        if (strcmp(p->name, name) == 0)
            return (int)p->type;
    }

    return -1;
}

int
main(int argc, char **argv)
{
    int                 hops;
    te_vec              steps = TE_VEC_INIT(tsapi_mde_step);
    te_string           name_s[MAXP];
    te_string           val_s[MAXP];
    tapi_cwmp_param     params[MAXP];
    tapi_cwmp_result    decoded;
    bool                decoded_up = false;
    te_string           env = TE_STRING_INIT;
    te_string           id = TE_STRING_INIT;
    const char         *the_id = "mde-ring-1";
    double              result_value;
    size_t              n = 0;
    size_t              i;
    unsigned int        matched = 0;
    unsigned int        controls = 0;
    double              parse_s;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(hops);

    for (i = 0; i < MAXP; i++)
    {
        name_s[i] = (te_string)TE_STRING_INIT;
        val_s[i] = (te_string)TE_STRING_INIT;
    }

    TEST_STEP("Build the ring results from the reference model");
    result_value = tsapi_mde_ring_predict(MDE_ENTRY, 1.0, hops, &steps);

    te_string_append(&name_s[n], "Device.X_MDE.Ring.Result");
    te_string_append(&val_s[n], "%.4f", result_value);
    params[n].name = name_s[n].ptr;
    params[n].value = val_s[n].ptr;
    params[n].type = TAPI_CWMP_STRING;
    n++;

    te_string_append(&name_s[n], "Device.X_MDE.Ring.Depth");
    te_string_append(&val_s[n], "%zu", te_vec_size(&steps));
    params[n].name = name_s[n].ptr;
    params[n].value = val_s[n].ptr;
    params[n].type = TAPI_CWMP_UINT;
    n++;

    for (i = 0; i < te_vec_size(&steps) && n < MAXP; i++)
    {
        const tsapi_mde_step *step = te_vec_get(&steps, i);

        te_string_append(&name_s[n], "Device.X_MDE.Ring.Stage.%zu.Out", i);
        te_string_append(&val_s[n], "%.4f", step->out);
        params[n].name = name_s[n].ptr;
        params[n].value = val_s[n].ptr;
        params[n].type = TAPI_CWMP_STRING;
        n++;
    }

    TEST_STEP("Encode the parameters into a SOAP envelope");
    tapi_cwmp_build_spv(the_id, params, n, "mde-ring-key", &env);
    RING("Encoded %zu parameter(s) into %zu bytes:\n%s", n, env.len,
         te_string_value(&env));

    TEST_STEP("The envelope identifies as SetParameterValues, ID round-trips");
    if (tapi_cwmp_msg_rpc(env.ptr) != TAPI_CWMP_RPC_SET_PARAMETER_VALUES)
        TEST_VERDICT("The encoded envelope is not a SetParameterValues");
    if (!tapi_cwmp_msg_id(env.ptr, &id) || strcmp(id.ptr, the_id) != 0)
        TEST_VERDICT("The cwmp:ID did not round-trip");

    TEST_STEP("Decode the envelope back and compare every field");
    tapi_cwmp_result_init(&decoded);
    decoded_up = true;
    parse_s = tsapi_mde_now();
    CHECK_RC(tapi_cwmp_parse_response(env.ptr,
                                      TAPI_CWMP_RPC_GET_PARAMETER_VALUES,
                                      &decoded));
    parse_s = tsapi_mde_now() - parse_s;

    if (te_vec_size(&decoded.params) != n)
    {
        TEST_VERDICT("Decoded %zu parameter(s), encoded %zu",
                     te_vec_size(&decoded.params), n);
    }
    for (i = 0; i < n; i++)
    {
        const char *v = tapi_cwmp_result_value(&decoded, params[i].name);
        int         t = decoded_type(&decoded, params[i].name);

        if (v != NULL && strcmp(v, params[i].value) == 0 &&
            t == (int)params[i].type)
        {
            matched++;
        }
        else
        {
            RING("field %s did not round-trip: sent '%s'/%d, got '%s'/%d",
                 params[i].name, params[i].value, params[i].type,
                 v != NULL ? v : "(absent)", t);
        }
    }
    if (matched != n)
        TEST_VERDICT("CWMP field round-trip matched %u of %zu", matched, n);

    TEST_STEP("Malformed SOAP must be rejected cleanly (controls)");
    {
        te_string truncated = TE_STRING_INIT;
        te_string huge = TE_STRING_INIT;
        const char *garbage = "this is not SOAP at all, no tags here";
        const char *bad[3];
        size_t k;

        te_string_append_buf(&truncated, env.ptr, env.len / 2);
        for (k = 0; k < 20000; k++)
            te_string_append(&huge, "A");

        bad[0] = truncated.ptr;
        bad[1] = garbage;
        bad[2] = huge.ptr;

        for (k = 0; k < TE_ARRAY_LEN(bad); k++)
        {
            tapi_cwmp_result r2;

            tapi_cwmp_result_init(&r2);
            (void)tapi_cwmp_parse_response(
                bad[k], TAPI_CWMP_RPC_GET_PARAMETER_VALUES, &r2);
            if (te_vec_size(&r2.params) == 0)
                controls++;
            else
                RING("control %zu: a malformed envelope yielded %zu params",
                     k, te_vec_size(&r2.params));
            tapi_cwmp_result_free(&r2);
        }

        te_string_free(&truncated);
        te_string_free(&huge);
    }
    if (controls != 3)
        TEST_VERDICT("A malformed SOAP control was mis-parsed: %u of 3 clean",
                     controls);

    TEST_ARTIFACT("cwmp inform_codec hops=%d: %zu params, %zu bytes, "
                  "%u/%zu fields round-tripped, %u/3 controls clean, "
                  "parse %.6f s", hops, n, env.len, matched, n, controls,
                  parse_s);

    TEST_STEP("Chart the message size and the parse time");
    tsapi_mde_mi_point("cwmp", "SOAP message size", TE_MI_MEAS_MEMORY,
                       "message_bytes", (double)env.len,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("cwmp", "SOAP parse time", TE_MI_MEAS_TIME,
                       "parse_time", parse_s, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    if (decoded_up)
        tapi_cwmp_result_free(&decoded);
    for (i = 0; i < MAXP; i++)
    {
        te_string_free(&name_s[i]);
        te_string_free(&val_s[i]);
    }
    te_string_free(&env);
    te_string_free(&id);
    te_vec_free(&steps);

    TEST_END;
}

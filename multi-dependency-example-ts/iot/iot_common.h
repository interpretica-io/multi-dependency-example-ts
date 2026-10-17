/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief IoT group helpers
 *
 * What the radio and bus tests of this group share: the ring steps they
 * carry as payload (the model's prediction and the trace cpp-demo really
 * printed) and a fixed 24-byte binary encoding of one step, so every
 * codec round trip can be checked byte for byte.
 *
 * Everything here is static inline: each test is built from one .c file
 * and must not trip -Werror=unused-function on what it does not use.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_IOT_COMMON_H__
#define __MDE_IOT_COMMON_H__

#include "te_config.h"

#include <stdint.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "logger_api.h"
#include "tsapi_mde.h"
#include "tsapi_mde_ring.h"

/** Size of one encoded ring step. */
#define IOT_STEP_LEN 24

/** Where a step came from. */
typedef enum iot_source {
    IOT_SOURCE_MODEL = 0,   /**< tsapi_mde_ring_predict() */
    IOT_SOURCE_TRACE = 1,   /**< parsed from cpp-demo's output */
} iot_source;

/** One step to carry, with where it came from. */
typedef struct iot_step {
    iot_source     source;  /**< Model or trace. */
    unsigned int   index;   /**< Position within its walk. */
    tsapi_mde_step step;    /**< The step itself. */
} iot_step;

/** Little-endian 64-bit store. */
static inline void
iot_put_u64(uint8_t *out, uint64_t v)
{
    unsigned int i;

    for (i = 0; i < 8; i++)
        out[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}

/** Little-endian 64-bit load. */
static inline uint64_t
iot_get_u64(const uint8_t *in)
{
    uint64_t     v = 0;
    unsigned int i;

    for (i = 0; i < 8; i++)
        v |= (uint64_t)in[i] << (8 * i);

    return v;
}

/**
 * Encode a step into IOT_STEP_LEN bytes:
 * source, stage, index, hops (signed byte), four zero bytes, in and out as
 * IEEE-754 doubles, little endian. Exact: decoding gives back the very
 * same bits.
 */
static inline void
iot_step_encode(const iot_step *s, uint8_t *out)
{
    uint64_t bits;

    memset(out, 0, IOT_STEP_LEN);
    out[0] = (uint8_t)s->source;
    out[1] = (uint8_t)s->step.stage;
    out[2] = (uint8_t)s->index;
    out[3] = (uint8_t)(int8_t)s->step.hops;
    memcpy(&bits, &s->step.in, sizeof(bits));
    iot_put_u64(out + 8, bits);
    memcpy(&bits, &s->step.out, sizeof(bits));
    iot_put_u64(out + 16, bits);
}

/** Decode what iot_step_encode() wrote. */
static inline void
iot_step_decode(const uint8_t *in, iot_step *s)
{
    uint64_t bits;

    memset(s, 0, sizeof(*s));
    s->source = (iot_source)in[0];
    s->step.stage = (tsapi_mde_stage)in[1];
    s->index = in[2];
    s->step.hops = (int8_t)in[3];
    bits = iot_get_u64(in + 8);
    memcpy(&s->step.in, &bits, sizeof(bits));
    bits = iot_get_u64(in + 16);
    memcpy(&s->step.out, &bits, sizeof(bits));
}

/** Bit-exact comparison of two steps; names the first differing field. */
static inline const char *
iot_step_diff(const iot_step *a, const iot_step *b)
{
    if (a->source != b->source)
        return "source";
    if (a->index != b->index)
        return "index";
    if (a->step.stage != b->step.stage)
        return "stage";
    if (a->step.hops != b->step.hops)
        return "hops";
    if (memcmp(&a->step.in, &b->step.in, sizeof(double)) != 0)
        return "in";
    if (memcmp(&a->step.out, &b->step.out, sizeof(double)) != 0)
        return "out";

    return NULL;
}

/**
 * Collect the steps to carry: first the model's walk entering the ring
 * where cpp-demo does (the Rust stage) with value 1, then the trace
 * cpp-demo actually printed for the same value and hop budget.
 *
 * @param[in]  session  Session.
 * @param[in]  dut      Example.
 * @param[in]  hops     Hop budget.
 * @param[out] steps    Vector of #iot_step to append to.
 * @param[out] n_model  Number of model steps appended.
 * @param[out] n_trace  Number of trace steps appended.
 *
 * @return Status code; a demo that would not run is TE_ENOENT.
 */
static inline te_errno
iot_steps_collect(tsapi_mde_session *session, const tsapi_mde_dut *dut,
                  int hops, te_vec *steps, unsigned int *n_model,
                  unsigned int *n_trace)
{
    te_vec              model = TE_VEC_INIT(tsapi_mde_step);
    te_vec              trace = TE_VEC_INIT(tsapi_mde_step);
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const tsapi_mde_step *s;
    unsigned int        i = 0;
    te_errno            rc;

    *n_model = 0;
    *n_trace = 0;

    (void)tsapi_mde_ring_predict(TSAPI_MDE_STAGE_RUST, 1.0, hops, &model);
    TE_VEC_FOREACH(&model, s)
    {
        iot_step st = { .source = IOT_SOURCE_MODEL, .index = i++,
                        .step = *s };

        TE_VEC_APPEND(steps, st);
        (*n_model)++;
    }

    rc = tsapi_mde_sh(session, 30000, &res, "'%s/cpp-demo' 1 %d", dut->bin,
                      hops);
    if (rc == 0 && !tsapi_mde_sh_ok(&res))
    {
        ERROR("cpp-demo did not run cleanly: %s", te_string_value(&res.err));
        rc = TE_RC(TE_TAPI, TE_ENOENT);
    }
    if (rc == 0)
    {
        RING("cpp-demo 1 %d printed:\n%s", hops, te_string_value(&res.out));
        (void)tsapi_mde_ring_parse(te_string_value(&res.out), &trace);
        i = 0;
        TE_VEC_FOREACH(&trace, s)
        {
            iot_step st = { .source = IOT_SOURCE_TRACE, .index = i++,
                            .step = *s };

            TE_VEC_APPEND(steps, st);
            (*n_trace)++;
        }
    }

    tsapi_mde_sh_result_free(&res);
    te_vec_free(&model);
    te_vec_free(&trace);

    return rc;
}

/** Name of a source for logs and chart keys. */
static inline const char *
iot_source2str(iot_source source)
{
    return source == IOT_SOURCE_MODEL ? "model" : "trace";
}

#endif /* !__MDE_IOT_COMMON_H__ */

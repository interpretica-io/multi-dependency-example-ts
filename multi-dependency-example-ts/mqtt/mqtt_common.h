/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief mqtt group: shared helpers
 *
 * static inline helpers for the mqtt group - each test is a single .c
 * file, so there is no library to link, only this header.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_MQTT_COMMON_H__
#define __MDE_MQTT_COMMON_H__

#include "te_config.h"
#include "te_defs.h"
#include "te_string.h"
#include "tsapi_mde_ring.h"

/* cpp-demo enters the ring at the Rust stage (see the example's README). */
#define MDE_MQTT_ENTRY  TSAPI_MDE_STAGE_RUST

/* The topic one parsed ring step is published on. */
static inline void
mde_mqtt_step_topic(size_t i, tsapi_mde_stage stage, te_string *dest)
{
    te_string_append(dest, "mde/ring/%zu/%s", i, tsapi_mde_stage2str(stage));
}

/* The payload a step carries: "hops in out" with four decimals. */
static inline void
mde_mqtt_step_payload(const tsapi_mde_step *step, te_string *dest)
{
    te_string_append(dest, "%d %.4f %.4f", step->hops, step->in, step->out);
}

#endif /* !__MDE_MQTT_COMMON_H__ */

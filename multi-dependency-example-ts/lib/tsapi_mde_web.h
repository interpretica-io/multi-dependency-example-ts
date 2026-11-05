/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief The web tier as a running service set
 *
 * gateway-rs, service-go and service-cs call each other over HTTP in a
 * cycle (web/contract/services.tab). Many groups need them running -
 * the cycle test, the exposure scan, the HTTP and TLS audits, the
 * browser, the memory-map audit of a live process - so starting them,
 * waiting until each listens, and stopping them is here.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __TSAPI_MDE_WEB_H__
#define __TSAPI_MDE_WEB_H__

#include "te_config.h"
#include "te_defs.h"
#include "te_errno.h"
#include "tapi_job.h"
#include "tsapi_mde.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Number of services in the web tier. */
#define TSAPI_MDE_WEB_N 3

/** Port of the entry point, gateway-rs. */
#define TSAPI_MDE_WEB_GATEWAY_PORT 8081

/** One service of the tier. */
typedef struct tsapi_mde_web_service {
    const char         *name;   /**< Binary name under dist/bin. */
    unsigned int        port;   /**< Port from the contract. */
    tapi_job_t         *job;    /**< Its running process. */
    tapi_job_channel_t *out[2]; /**< stdout, stderr. */
    tapi_job_channel_t *ready;  /**< Readable filter for the ready line. */
    double              start_s; /**< Seconds it took to start listening. */
} tsapi_mde_web_service;

/** The tier. */
typedef struct tsapi_mde_web {
    tsapi_mde_web_service svc[TSAPI_MDE_WEB_N];  /**< In contract order. */
    unsigned int          n_started;             /**< How many are up. */
} tsapi_mde_web;

/**
 * Whether every service binary is built.
 *
 * @param session   Session.
 * @param dut       Example.
 *
 * @return @c true if all three are there.
 */
extern bool tsapi_mde_web_built(tsapi_mde_session *session,
                                const tsapi_mde_dut *dut);

/**
 * Start the tier and wait until each service announces its URL.
 *
 * @param session   Session.
 * @param dut       Example.
 * @param web       Tier; stop it with tsapi_mde_web_stop() whatever
 *                  this returns.
 *
 * @return Status code.
 */
extern te_errno tsapi_mde_web_start(tsapi_mde_session *session,
                                    const tsapi_mde_dut *dut,
                                    tsapi_mde_web *web);

/**
 * Reset a tier to "nothing started" with the contract filled in; call it
 * before tsapi_mde_web_start_one().
 *
 * @param web       Tier.
 */
extern void tsapi_mde_web_init(tsapi_mde_web *web);

/**
 * Start one service of the tier and wait until it announces its URL.
 * Services started one after another on the same tier run together.
 *
 * @param session   Session.
 * @param dut       Example.
 * @param web       Tier; stop it with tsapi_mde_web_stop().
 * @param idx       Index of the service (contract order).
 *
 * @return Status code.
 */
extern te_errno tsapi_mde_web_start_one(tsapi_mde_session *session,
                                        const tsapi_mde_dut *dut,
                                        tsapi_mde_web *web, unsigned int idx);

/**
 * Stop one service of the tier, leaving the others running.
 *
 * @param web       Tier.
 * @param idx       Index of the service.
 */
extern void tsapi_mde_web_stop_one(tsapi_mde_web *web, unsigned int idx);

/**
 * Stop whatever of the tier was started.
 *
 * @param web       Tier.
 */
extern void tsapi_mde_web_stop(tsapi_mde_web *web);

/**
 * Build the URL of one walk of the cycle.
 *
 * @param port      Port of the service to enter at.
 * @param value     Value to send.
 * @param hops      Hop budget.
 * @param url       String to append the URL to.
 */
extern void tsapi_mde_web_url(unsigned int port, double value, int hops,
                              te_string *url);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__TSAPI_MDE_WEB_H__ */

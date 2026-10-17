/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief The web tier as a running service set
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_LGR_USER "TSAPI MDE WEB"

#include "te_config.h"

#include <string.h>

#include "logger_api.h"
#include "te_string.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_web.h"

/* The tier, from web/contract/services.tab. gateway-rs is the entry. */
static const struct {
    const char  *name;
    unsigned int port;
} contract[TSAPI_MDE_WEB_N] = {
    { "gateway-rs", 8081 },
    { "service-go", 8082 },
    { "service-cs", 8083 },
};

/* See description in tsapi_mde_web.h */
bool
tsapi_mde_web_built(tsapi_mde_session *session, const tsapi_mde_dut *dut)
{
    unsigned int i;

    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        te_string path = TE_STRING_INIT;
        bool      ok;

        te_string_append(&path, "%s/%s", dut->bin, contract[i].name);
        ok = tsapi_mde_exists(session, path.ptr);
        te_string_free(&path);
        if (!ok)
            return false;
    }

    return true;
}

/*
 * Start one service and wait until it announces its listening URL. The Go
 * node logs that line to stderr, so the ready filter watches both channels.
 */
static te_errno
service_start(tsapi_mde_session *session, const tsapi_mde_dut *dut,
              tsapi_mde_web_service *svc)
{
    te_string         program = TE_STRING_INIT;
    te_string         ready_re = TE_STRING_INIT;
    tapi_job_buffer_t buf = TAPI_JOB_BUFFER_INIT;
    const char       *argv[2];
    double            t0;
    te_errno          rc;

    te_string_append(&program, "%s/%s", dut->bin, svc->name);
    argv[0] = program.ptr;
    argv[1] = NULL;

    rc = tapi_job_create(session->factory, NULL, program.ptr, argv, NULL,
                         &svc->job);
    if (rc != 0)
        goto out;

    rc = tapi_job_alloc_output_channels(svc->job, 2, svc->out);
    if (rc != 0)
        goto out;

    rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(svc->out[0], svc->out[1]),
                                svc->name, false, TE_LL_RING, NULL);
    if (rc != 0)
        goto out;

    rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(svc->out[0], svc->out[1]),
                                "ready", true, 0, &svc->ready);
    if (rc != 0)
        goto out;
    te_string_append(&ready_re, "\\[%s\\] http://", svc->name);
    rc = tapi_job_filter_add_regexp(svc->ready, ready_re.ptr, 0);
    if (rc != 0)
        goto out;

    t0 = tsapi_mde_now();
    rc = tapi_job_start(svc->job);
    if (rc != 0)
        goto out;

    rc = tapi_job_receive(TAPI_JOB_CHANNEL_SET(svc->ready), 15000, &buf);
    svc->start_s = tsapi_mde_now() - t0;
    if (rc != 0)
    {
        ERROR("Service '%s' did not become ready: %r", svc->name, rc);
        rc = TE_RC(TE_TAPI, TE_EFAIL);
    }

out:
    te_string_free(&program);
    te_string_free(&ready_re);
    te_string_free(&buf.data);
    return rc;
}

/* See description in tsapi_mde_web.h */
te_errno
tsapi_mde_web_start(tsapi_mde_session *session, const tsapi_mde_dut *dut,
                    tsapi_mde_web *web)
{
    te_errno     rc;
    unsigned int i;

    memset(web, 0, sizeof(*web));
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        web->svc[i].name = contract[i].name;
        web->svc[i].port = contract[i].port;
    }

    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        rc = service_start(session, dut, &web->svc[i]);
        web->n_started = i + 1;
        if (rc != 0)
            return rc;
        RING("%s listens on %u after %.3f s", web->svc[i].name,
             web->svc[i].port, web->svc[i].start_s);
    }

    return 0;
}

/* See description in tsapi_mde_web.h */
void
tsapi_mde_web_stop(tsapi_mde_web *web)
{
    unsigned int i;

    for (i = 0; i < web->n_started; i++)
    {
        if (web->svc[i].job != NULL)
        {
            tapi_job_destroy(web->svc[i].job, -1);
            web->svc[i].job = NULL;
        }
    }
    web->n_started = 0;
}

/* See description in tsapi_mde_web.h */
void
tsapi_mde_web_url(unsigned int port, double value, int hops, te_string *url)
{
    te_string_append(url, "http://127.0.0.1:%u/ring?value=%g&hops=%d", port,
                     value, hops);
}

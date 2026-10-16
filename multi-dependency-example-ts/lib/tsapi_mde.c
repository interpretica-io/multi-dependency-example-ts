/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Suite helpers
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_LGR_USER "TSAPI MDE"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_errno.h"
#include "te_string.h"
#include "tapi_job.h"
#include "tapi_job_factory_rpc.h"

#include "tsapi_mde.h"

/* See description in tsapi_mde.h */
te_errno
tsapi_mde_session_init(tsapi_mde_session *session, const char *name)
{
    te_errno rc;

    memset(session, 0, sizeof(*session));
    session->ta = TSAPI_MDE_TA;

    rc = rcf_rpc_server_create(session->ta, name, &session->pco);
    if (rc != 0)
    {
        ERROR("Cannot create the RPC server '%s' on %s: %r", name,
              session->ta, rc);
        return rc;
    }

    /*
     * Reading what a command printed needs output channels, and only the
     * RPC job factory has them.
     */
    rc = tapi_job_factory_rpc_create(session->pco, &session->factory);
    if (rc != 0)
    {
        ERROR("Cannot create a job factory over '%s': %r", name, rc);
        return rc;
    }

    /* Jobs do not inherit the agent's environment, so PATH is set here. */
    rc = tapi_job_factory_set_path(session->factory);
    if (rc != 0)
        WARN("Cannot set PATH in the job factory: %r", rc);

    return 0;
}

/* See description in tsapi_mde.h */
void
tsapi_mde_session_fini(tsapi_mde_session *session)
{
    if (session->factory != NULL)
    {
        tapi_job_factory_destroy(session->factory);
        session->factory = NULL;
    }

    if (session->pco != NULL)
    {
        rcf_rpc_server_destroy(session->pco);
        session->pco = NULL;
    }
}

/* See description in tsapi_mde.h */
const char *
tsapi_mde_src(void)
{
    const char *src = getenv("TE_TS_MDE_SRC");

    if (src == NULL || src[0] == '\0')
        return NULL;

    return src;
}

/* See description in tsapi_mde.h */
te_errno
tsapi_mde_run(tsapi_mde_session *session, const char *program,
              const char **argv, int timeout_ms, const char *count_re,
              const char *value_re, tsapi_mde_run_result *out)
{
    tapi_job_t         *job = NULL;
    tapi_job_channel_t *channels[2] = { NULL, NULL };
    tapi_job_channel_t *count_f = NULL;
    tapi_job_channel_t *value_f = NULL;
    tapi_job_buffer_t   buf = TAPI_JOB_BUFFER_INIT;
    te_errno            rc;

    memset(out, 0, sizeof(*out));

    rc = tapi_job_create(session->factory, NULL, program, argv, NULL, &job);
    if (rc != 0)
    {
        ERROR("Cannot create a job for '%s': %r", program, rc);
        return rc;
    }

    rc = tapi_job_alloc_output_channels(job, 2, channels);
    if (rc != 0)
        goto out;

    /* stderr is only logged, never read back. */
    rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(channels[1]),
                                "stderr", false, TE_LL_WARN, NULL);
    if (rc != 0)
        goto out;

    if (count_re != NULL)
    {
        rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(channels[0]),
                                    "count", true, TE_LL_RING, &count_f);
        if (rc == 0)
            rc = tapi_job_filter_add_regexp(count_f, count_re, 0);
        if (rc != 0)
            goto out;
    }

    if (value_re != NULL)
    {
        rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(channels[0]),
                                    "value", true, TE_LL_RING, &value_f);
        if (rc == 0)
            rc = tapi_job_filter_add_regexp(value_f, value_re, 1);
        if (rc != 0)
            goto out;
    }

    rc = tapi_job_start(job);
    if (rc != 0)
        goto out;
    out->started = true;

    /* Short-lived program: let it finish, then read what it queued. */
    rc = tapi_job_wait(job, timeout_ms, &out->status);
    if (rc != 0)
    {
        if (TE_RC_GET_ERROR(rc) == TE_EINPROGRESS)
            WARN("'%s' did not finish within %d ms", program, timeout_ms);
        else
            WARN("Waiting for '%s' failed: %r", program, rc);
        /* Not fatal: whatever it printed before is still worth reading. */
        rc = 0;
    }

    if (count_f != NULL)
    {
        while (1)
        {
            te_string_reset(&buf.data);
            rc = tapi_job_receive(TAPI_JOB_CHANNEL_SET(count_f), 1000, &buf);
            if (rc != 0)
            {
                rc = 0;
                break;
            }
            if (buf.eos)
                break;
            out->match_count++;
        }
    }

    if (value_f != NULL)
    {
        while (1)
        {
            te_string_reset(&buf.data);
            rc = tapi_job_receive(TAPI_JOB_CHANNEL_SET(value_f), 1000, &buf);
            if (rc != 0)
            {
                rc = 0;
                break;
            }
            if (buf.eos)
                break;
            out->value = strtod(buf.data.ptr, NULL);
            out->have_value = true;
        }
    }

out:
    te_string_free(&buf.data);
    if (job != NULL)
        tapi_job_destroy(job, -1);

    return rc;
}

/* See description in tsapi_mde.h */
bool
tsapi_mde_exists(tsapi_mde_session *session, const char *path)
{
    const char           *argv[] = { "ls", path, NULL };
    tsapi_mde_run_result  res;

    if (tsapi_mde_run(session, "ls", argv, 10000, NULL, NULL, &res) != 0)
        return false;

    return res.started &&
           res.status.type == TAPI_JOB_STATUS_EXITED &&
           res.status.value == 0;
}

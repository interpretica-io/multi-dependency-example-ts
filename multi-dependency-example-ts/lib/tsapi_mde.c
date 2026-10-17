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
#include <stdarg.h>
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

/* See description in tsapi_mde.h */
te_errno
tsapi_mde_sh(tsapi_mde_session *session, int timeout_ms,
             tsapi_mde_sh_result *res, const char *fmt, ...)
{
    tapi_job_t         *job = NULL;
    tapi_job_channel_t *channels[2] = { NULL, NULL };
    tapi_job_channel_t *filters[2] = { NULL, NULL };
    tapi_job_buffer_t   buf = TAPI_JOB_BUFFER_INIT;
    te_string           cmd = TE_STRING_INIT;
    const char         *argv[4];
    va_list             ap;
    te_errno            rc;
    unsigned int        i;

    te_string_reset(&res->out);
    te_string_reset(&res->err);
    res->started = false;
    memset(&res->status, 0, sizeof(res->status));

    va_start(ap, fmt);
    te_string_append_va(&cmd, fmt, ap);
    va_end(ap);

    argv[0] = "sh";
    argv[1] = "-c";
    argv[2] = cmd.ptr;
    argv[3] = NULL;

    rc = tapi_job_create(session->factory, NULL, "sh", argv, NULL, &job);
    if (rc != 0)
    {
        ERROR("Cannot create a job for '%s': %r", cmd.ptr, rc);
        goto out;
    }

    rc = tapi_job_alloc_output_channels(job, 2, channels);
    if (rc != 0)
        goto out;

    /* No regexp: a readable filter passes everything through. */
    rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(channels[0]), "out",
                                true, TE_LL_VERB, &filters[0]);
    if (rc == 0)
        rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(channels[1]), "err",
                                    true, TE_LL_VERB, &filters[1]);
    if (rc != 0)
        goto out;

    rc = tapi_job_start(job);
    if (rc != 0)
        goto out;
    res->started = true;

    rc = tapi_job_wait(job, timeout_ms, &res->status);
    if (rc != 0)
    {
        WARN("'%s' did not finish within %d ms: %r", cmd.ptr, timeout_ms, rc);
        rc = 0;
    }

    for (i = 0; i < 2; i++)
    {
        te_string *dst = (i == 0) ? &res->out : &res->err;

        while (1)
        {
            te_string_reset(&buf.data);
            if (tapi_job_receive(TAPI_JOB_CHANNEL_SET(filters[i]), 1000,
                                 &buf) != 0)
                break;
            if (buf.eos)
                break;
            te_string_append(dst, "%s", buf.data.ptr);
        }
    }

out:
    te_string_free(&buf.data);
    te_string_free(&cmd);
    if (job != NULL)
        tapi_job_destroy(job, -1);

    return rc;
}

/* See description in tsapi_mde.h */
void
tsapi_mde_sh_result_free(tsapi_mde_sh_result *res)
{
    te_string_free(&res->out);
    te_string_free(&res->err);
}

/* See description in tsapi_mde.h */
bool
tsapi_mde_have(tsapi_mde_session *session, const char *program)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    ok = tsapi_mde_sh(session, 10000, &res, "command -v '%s'", program) == 0 &&
         tsapi_mde_sh_ok(&res);
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/* See description in tsapi_mde.h */
const char * const tsapi_mde_dut_bins[] = {
    "cpp-demo", "rust-demo", "gateway-rs", "service-go", "service-cs",
};
/* See description in tsapi_mde.h */
const unsigned int tsapi_mde_dut_n_bins = TE_ARRAY_LEN(tsapi_mde_dut_bins);

/* See description in tsapi_mde.h */
const char * const tsapi_mde_dut_libs[] = {
    "libpycore", "libcscore", "libgocore", "librustcore", "libcppcore",
};
/* See description in tsapi_mde.h */
const unsigned int tsapi_mde_dut_n_libs = TE_ARRAY_LEN(tsapi_mde_dut_libs);

/* See description in tsapi_mde.h */
te_errno
tsapi_mde_dut_open(tsapi_mde_session *session, tsapi_mde_dut *dut)
{
    const char *src = tsapi_mde_src();
    te_string   path = TE_STRING_INIT;
    bool        built;

    memset(dut, 0, sizeof(*dut));
    if (src == NULL)
        return TE_RC(TE_TAPI, TE_ENOENT);

    dut->root = strdup(src);
    te_string_append(&path, "%s/dist/bin", src);
    dut->bin = path.ptr;
    path = (te_string)TE_STRING_INIT;
    te_string_append(&path, "%s/dist/lib", src);
    dut->lib = path.ptr;
    path = (te_string)TE_STRING_INIT;
    te_string_append(&path, "%s/python", src);
    dut->python = path.ptr;
    path = (te_string)TE_STRING_INIT;

    /*
     * cpp-demo is the sentinel for "built": it comes out of the same
     * ./build.sh run as every library.
     */
    te_string_append(&path, "%s/cpp-demo", dut->bin);
    built = tsapi_mde_exists(session, path.ptr);
    te_string_free(&path);
    if (!built)
        return TE_RC(TE_TAPI, TE_ENOENT);

    te_string_append(&path, "%s/libcppcore.dylib", dut->lib);
    dut->dylib_ext = tsapi_mde_exists(session, path.ptr) ? "dylib" : "so";
    te_string_free(&path);

    return 0;
}

/* See description in tsapi_mde.h */
void
tsapi_mde_dut_lib_path(const tsapi_mde_dut *dut, const char *name,
                       te_string *path)
{
    te_string_append(path, "%s/%s.%s", dut->lib, name, dut->dylib_ext);
}

/* See description in tsapi_mde.h */
void
tsapi_mde_dut_free(tsapi_mde_dut *dut)
{
    free(dut->root);
    free(dut->bin);
    free(dut->lib);
    free(dut->python);
    memset(dut, 0, sizeof(*dut));
}

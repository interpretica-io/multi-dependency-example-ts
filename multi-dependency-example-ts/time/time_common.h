/** @file
 * @brief Time Group
 *
 * Helpers shared by the tests of the time group: run a program on the
 * agent under a fake clock (or under the real one) and capture what it
 * printed, start a service of the web tier under a fake clock, and the
 * arithmetic of libfaketime offsets. Static inline only - every test is
 * one C file.
 *
 * Two ways of putting a process under the clock are used, both from
 * tapi_time:
 * - tapi_time_wrap() puts the faketime program in front of a job. faketime
 *   forks the program and waits for it, so it suits short-lived programs
 *   only: stopping the job stops faketime, not its child.
 * - tapi_time_env() builds LD_PRELOAD/FAKETIME for the job itself, which
 *   is what a long-running service needs.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_TIME_COMMON_H__
#define __MDE_TIME_COMMON_H__

#include "te_config.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"
#include "tapi_time.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/** Timeout of the tapi_time helpers, ms. */
#define MDE_TIME_TIMEOUT_MS     30000

/** Seconds the observed skew may differ from the requested one. */
#define MDE_TIME_TOLERANCE_S    10

/** PATH of the jobs that get an environment of their own. */
#define MDE_TIME_PATH \
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/** What running a program told us. */
typedef struct mde_time_run_result {
    bool              started;   /**< The program was started at all. */
    tapi_job_status_t status;    /**< Its exit status, if it finished. */
    te_string         out;       /**< Its stdout. */
    te_string         err;       /**< Its stderr. */
    double            elapsed_s; /**< Wall time of the run. */
} mde_time_run_result;

/** Static initializer of #mde_time_run_result. */
#define MDE_TIME_RUN_RESULT_INIT \
    { .out = TE_STRING_INIT, .err = TE_STRING_INIT }

/**
 * Release a run result.
 *
 * @param res   Result.
 */
static inline void
mde_time_run_result_free(mde_time_run_result *res)
{
    te_string_free(&res->out);
    te_string_free(&res->err);
}

/**
 * Whether a run finished with exit status 0.
 *
 * @param res   Result.
 *
 * @return @c true on a clean exit.
 */
static inline bool
mde_time_run_ok(const mde_time_run_result *res)
{
    return res->started && res->status.type == TAPI_JOB_STATUS_EXITED &&
           res->status.value == 0;
}

/**
 * Run a short-lived program to completion, optionally with the faketime
 * program in front of it (tapi_time_wrap()), and capture its output.
 *
 * @param session       Session.
 * @param clock         Fake clock, or @c NULL for the real one.
 * @param argv          @c NULL-terminated argv; argv[0] is the program.
 * @param timeout_ms    Time it is given to finish.
 * @param res           Result; release with mde_time_run_result_free().
 *
 * @return Status code. A non-zero exit is reported through @p res.
 */
static inline te_errno
mde_time_run(tsapi_mde_session *session, const tapi_time_opt *clock,
             const char **argv, int timeout_ms, mde_time_run_result *res)
{
    tapi_job_t         *job = NULL;
    tapi_job_channel_t *channels[2] = { NULL, NULL };
    tapi_job_channel_t *filters[2] = { NULL, NULL };
    tapi_job_buffer_t   buf = TAPI_JOB_BUFFER_INIT;
    double              t0;
    te_errno            rc;
    unsigned int        i;

    te_string_reset(&res->out);
    te_string_reset(&res->err);
    res->started = false;
    res->elapsed_s = 0.0;
    memset(&res->status, 0, sizeof(res->status));

    rc = tapi_job_create(session->factory, NULL, argv[0], argv, NULL, &job);
    if (rc != 0)
        return rc;

    if (clock != NULL)
        rc = tapi_time_wrap(job, clock);
    if (rc == 0)
        rc = tapi_job_alloc_output_channels(job, 2, channels);
    if (rc == 0)
    {
        rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(channels[0]), "out",
                                    true, TE_LL_VERB, &filters[0]);
    }
    if (rc == 0)
    {
        rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(channels[1]), "err",
                                    true, TE_LL_VERB, &filters[1]);
    }
    if (rc != 0)
        goto out;

    t0 = tsapi_mde_now();
    rc = tapi_job_start(job);
    if (rc != 0)
        goto out;
    res->started = true;

    rc = tapi_job_wait(job, timeout_ms, &res->status);
    res->elapsed_s = tsapi_mde_now() - t0;
    if (rc != 0)
    {
        WARN("'%s' did not finish within %d ms: %r", argv[0], timeout_ms,
             rc);
        res->status.type = TAPI_JOB_STATUS_UNKNOWN;
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
    if (job != NULL)
        tapi_job_destroy(job, -1);

    return rc;
}

/** A service of the web tier started by a test of the group. */
typedef struct mde_time_service {
    tapi_job_t         *job;     /**< The process. */
    tapi_job_channel_t *out[2];  /**< stdout, stderr. */
    tapi_job_channel_t *ready;   /**< Readable filter for the ready line. */
    double              start_s; /**< Seconds until it announced its URL. */
} mde_time_service;

/**
 * Start a service with an environment of its own and wait until it
 * announces @c "[name] http://".
 *
 * @param session       Session.
 * @param program       Absolute path of the service.
 * @param name          Its name, as it prints it.
 * @param env           @c NULL-terminated environment.
 * @param timeout_ms    Time it is given to become ready.
 * @param svc           Service; stop it with mde_time_service_stop()
 *                      whatever this returns.
 *
 * @return Status code; @c TE_ETIMEDOUT if it never became ready.
 */
static inline te_errno
mde_time_service_start(tsapi_mde_session *session, const char *program,
                       const char *name, const char **env, int timeout_ms,
                       mde_time_service *svc)
{
    tapi_job_buffer_t buf = TAPI_JOB_BUFFER_INIT;
    te_string         ready_re = TE_STRING_INIT;
    const char       *argv[2] = { program, NULL };
    double            t0;
    te_errno          rc;

    memset(svc, 0, sizeof(*svc));

    rc = tapi_job_create(session->factory, NULL, program, argv, env,
                         &svc->job);
    if (rc != 0)
        return rc;

    rc = tapi_job_alloc_output_channels(svc->job, 2, svc->out);
    if (rc == 0)
    {
        rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(svc->out[0],
                                                         svc->out[1]),
                                    name, false, TE_LL_RING, NULL);
    }
    if (rc == 0)
    {
        rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(svc->out[0],
                                                         svc->out[1]),
                                    "ready", true, 0, &svc->ready);
    }
    if (rc == 0)
    {
        te_string_append(&ready_re, "\\[%s\\] http://", name);
        rc = tapi_job_filter_add_regexp(svc->ready, ready_re.ptr, 0);
    }
    if (rc == 0)
    {
        t0 = tsapi_mde_now();
        rc = tapi_job_start(svc->job);
        if (rc == 0)
        {
            rc = tapi_job_receive(TAPI_JOB_CHANNEL_SET(svc->ready),
                                  timeout_ms, &buf);
            svc->start_s = tsapi_mde_now() - t0;
            if (rc != 0)
            {
                ERROR("'%s' did not become ready: %r", name, rc);
                rc = TE_RC(TE_TAPI, TE_ETIMEDOUT);
            }
        }
    }

    te_string_free(&ready_re);
    te_string_free(&buf.data);

    return rc;
}

/**
 * Stop a service started by mde_time_service_start().
 *
 * @param svc   Service.
 */
static inline void
mde_time_service_stop(mde_time_service *svc)
{
    if (svc->job != NULL)
    {
        tapi_job_destroy(svc->job, -1);
        svc->job = NULL;
    }
}

/**
 * Seconds a libfaketime offset stands for: @c "+10y", @c "-1d", @c "+0",
 * @c "+2h", @c "-30m", @c "+45s" (a year is 365 days, as libfaketime
 * counts it).
 *
 * @param[in]  offset   Offset.
 * @param[out] seconds  Seconds.
 *
 * @return @c true if it parses.
 */
static inline bool
mde_time_offset_seconds(const char *offset, int64_t *seconds)
{
    char   *end = NULL;
    double  value = strtod(offset, &end);
    double  mult;

    if (end == offset)
        return false;

    switch (*end)
    {
        case '\0':
        case 's':
            mult = 1;
            break;
        case 'm':
            mult = 60;
            break;
        case 'h':
            mult = 3600;
            break;
        case 'd':
            mult = 86400;
            break;
        case 'y':
            mult = 365.0 * 86400;
            break;
        default:
            return false;
    }

    *seconds = (int64_t)(value * mult);

    return true;
}

/**
 * FNV-1a 64-bit hash of a text: a short, stable fingerprint of an output
 * for artifacts and comparisons.
 *
 * @param text  Text.
 *
 * @return Hash.
 */
static inline uint64_t
mde_time_fnv1a(const char *text)
{
    uint64_t hash = UINT64_C(1469598103934665603);

    for (; *text != '\0'; text++)
    {
        hash ^= (unsigned char)*text;
        hash *= UINT64_C(1099511628211);
    }

    return hash;
}

/**
 * How many of the running processes of @p exe have libfaketime mapped:
 * the proof that the shim is inside a service, not only in @c date.
 *
 * A process is one of @p exe when /proc/PID/exe points at it or when the
 * file is mapped in /proc/PID/maps. The second view is needed where amd64
 * binaries run under a user-mode translator (Rosetta in Docker on Apple
 * silicon, qemu-user through binfmt_misc): there /proc/PID/exe is the
 * translator, e.g. /run/rosetta/rosetta, while the binary itself and the
 * LD_PRELOADed libfaketime are still mapped into the process.
 *
 * @param session   Session.
 * @param exe       Absolute path of the executable.
 * @param procs     Number of processes of @p exe found.
 *
 * @return Number of those with libfaketime in /proc/PID/maps.
 */
static inline unsigned int
mde_time_shim_mapped(tsapi_mde_session *session, const char *exe,
                     unsigned int *procs)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    unsigned int        mapped = 0;
    const char         *line;

    *procs = 0;
    if (tsapi_mde_sh(session, 30000, &res,
                     "p=$(readlink -f '%s'); "
                     "for d in /proc/[0-9]*; do "
                     "if [ \"$(readlink -f $d/exe 2>/dev/null)\" = \"$p\" ] "
                     "|| awk -v p=\"$p\" '$6 == p { f = 1; exit } "
                     "END { exit !f }' $d/maps 2>/dev/null; "
                     "then "
                     "echo P $(grep -c libfaketime $d/maps 2>/dev/null) "
                     "${d#/proc/} $(readlink $d/exe 2>/dev/null); "
                     "fi; done", exe) != 0)
    {
        tsapi_mde_sh_result_free(&res);
        return 0;
    }
    RING("Processes of %s (P <libfaketime maps> <pid> <exe>):\n%s", exe,
         te_string_value(&res.out));

    for (line = te_string_value(&res.out); line != NULL && *line != '\0'; )
    {
        const char *eol = strchr(line, '\n');

        if (strncmp(line, "P ", 2) == 0)
        {
            (*procs)++;
            if (strtoul(line + 2, NULL, 10) > 0)
                mapped++;
        }
        line = (eol != NULL) ? eol + 1 : NULL;
    }
    tsapi_mde_sh_result_free(&res);

    return mapped;
}

#endif /* !__MDE_TIME_COMMON_H__ */

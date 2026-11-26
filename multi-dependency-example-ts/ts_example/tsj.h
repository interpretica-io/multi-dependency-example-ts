/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: helpers of the three tapi_job tests
 *
 * Every program is run on the agent through tapi_job (directly or through
 * tsapi_mde_sh() and web_get(), which are built on it). Static inline only.
 *
 * @author midair <midair@localhost>
 */

#ifndef MDE_TSJ_H
#define MDE_TSJ_H

#include "../web/web_common.h"

#define TSJ_GO_PORT     8082

/** A long-running program started as a job. */
typedef struct tsj_svc {
    tapi_job_t         *job;
    tapi_job_channel_t *out[2];
    unsigned int        port;
} tsj_svc;

/** Project root on the agent, from TE_TS_MDE_SRC; NULL when not set. */
static inline const char *
tsj_root(void)
{
    const char *r = tsapi_mde_src();

    return (r != NULL && r[0] != '\0') ? r : NULL;
}

/** Whether a command succeeds on the agent. */
static inline bool
tsj_ok(tsapi_mde_session *s, int tmo_ms, const char *cmd)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    ok = tsapi_mde_sh(s, tmo_ms, &res, "%s", cmd) == 0 &&
         tsapi_mde_sh_ok(&res);
    tsapi_mde_sh_result_free(&res);
    return ok;
}

/** Log long text in pieces of at most 800 bytes. */
static inline void
tsj_log_text(const char *label, const char *text)
{
    size_t len = strlen(text);
    size_t off;
    char   piece[801];

    for (off = 0; off < len && off < 6400; off += 800)
    {
        snprintf(piece, sizeof(piece), "%s", text + off);
        RING("%s [%zu]: %s", label, off, piece);
    }
}

/** Copy at most @p size - 1 bytes of @p text into @p out, printable only. */
static inline const char *
tsj_cut(char *out, size_t size, const char *text)
{
    size_t i;

    for (i = 0; i + 1 < size && text[i] != '\0'; i++)
        out[i] = (text[i] >= 32 && text[i] < 127) || text[i] == '\n' ?
                 text[i] : '.';
    out[i] = '\0';
    return out;
}

/** The last @p n lines of @p text (the whole text when it has fewer). */
static inline const char *
tsj_last_lines(const char *text, int n)
{
    const char *p = text + strlen(text);

    if (p > text && p[-1] == '\n')
        p--;
    while (p > text && n > 0)
    {
        p--;
        if (*p == '\n')
            n--;
    }
    return (n == 0 && *p == '\n') ? p + 1 : p;
}

/** Record a request result as an artifact, with the body cut and cleaned. */
static inline void
tsj_art_reply(const char *id, const char *what, int code, const char *body)
{
    char cut[301];
    char one[301];
    size_t i;

    tsj_cut(cut, sizeof(cut), body);
    for (i = 0; cut[i] != '\0'; i++)
        one[i] = cut[i] == '\n' ? '|' : cut[i];
    one[i] = '\0';
    TEST_ARTIFACT("%s %s: HTTP %d body [%s]", id, what, code, one);
}

/** Start `sh -c cmd` as a job whose output goes to the TE log. */
static inline te_errno
tsj_start(tsapi_mde_session *s, const char *name, const char *cmd,
          unsigned int port, tsj_svc *svc)
{
    const char *argv[4] = { "sh", "-c", cmd, NULL };
    te_errno    rc;

    memset(svc, 0, sizeof(*svc));
    svc->port = port;
    rc = tapi_job_create(s->factory, NULL, "sh", argv, NULL, &svc->job);
    if (rc == 0)
        rc = tapi_job_alloc_output_channels(svc->job, 2, svc->out);
    if (rc == 0)
        rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(svc->out[0],
                                                         svc->out[1]),
                                    name, false, TE_LL_RING, NULL);
    if (rc == 0)
        rc = tapi_job_start(svc->job);
    return rc;
}

/** Whether the job is still running. */
static inline bool
tsj_running(tsj_svc *svc)
{
    tapi_job_status_t st;

    return svc->job != NULL &&
           TE_RC_GET_ERROR(tapi_job_wait(svc->job, 0, &st)) == TE_EINPROGRESS;
}

/** Wait until the port answers (any HTTP status) or the job dies. */
static inline bool
tsj_wait_port(tsapi_mde_session *s, tsj_svc *svc, int secs)
{
    web_reply reply = WEB_REPLY_INIT;
    char      url[100];
    int       i;
    bool      up = false;

    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring?value=1&hops=0",
             svc->port);
    for (i = 0; i < secs * 2 && !up; i++)
    {
        if (!tsj_running(svc))
            break;
        if (web_get(s, "", url, 2, &reply) == 0 && reply.code != 0)
            up = true;
        else
            usleep(500000);
    }
    te_string_free(&reply.body);
    return up;
}

/** Stop the job (SIGTERM, then kill) and forget it. */
static inline void
tsj_stop(tsj_svc *svc)
{
    if (svc->job != NULL)
    {
        tapi_job_destroy(svc->job, 3000);
        svc->job = NULL;
    }
}

/** A free TCP port on the agent loopback; 0 on failure. */
static inline unsigned int
tsj_free_port(tsapi_mde_session *s)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    unsigned int        port = 0;

    if (tsapi_mde_sh(s, 15000, &res,
                     "python3 -c \"import socket;k=socket.socket();"
                     "k.bind(('127.0.0.1',0));print(k.getsockname()[1])\"") == 0
        && tsapi_mde_sh_ok(&res))
        port = (unsigned int)strtoul(web_str(&res.out), NULL, 10);
    tsapi_mde_sh_result_free(&res);
    return port;
}

/** Command that runs the TypeScript service on @p port. */
static inline void
tsj_ts_cmd(const char *root, unsigned int port, char *buf, size_t size)
{
    snprintf(buf, size, "cd '%s/web/service-ts' && RING_HOST=127.0.0.1 "
             "RING_PORT=%u SERVICE_TS_CONTRACT='%s/web/contract/services.tab' "
             "exec node out/main.js", root, port, root);
}

#endif /* MDE_TSJ_H */

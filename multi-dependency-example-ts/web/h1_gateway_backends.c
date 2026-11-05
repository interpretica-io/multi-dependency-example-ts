/** @file
 * @brief Web Group
 *
 * Hypothesis H1: gateway-rs hard-depends on its loopback backends and
 * panics or fails when they are absent or answer bad data.
 *
 * gateway-rs is started alone, with nothing on 127.0.0.1:8082 (service-go)
 * and 127.0.0.1:8083 (service-cs). One HTTP request is sent to its
 * listener and the process is watched for up to five seconds: did it
 * exit, with which status or signal, and what did the request get. The
 * same is repeated with fake listeners on the backend addresses that
 * accept and answer garbage bytes, and with fake listeners that accept
 * and close at once.
 *
 * Verdict:
 * - the gateway aborts, dies on a signal or exits non-zero in any phase:
 *   H1 PROVEN (the test fails);
 * - it stays up in every phase and answers the requests: H1 DISPROVEN.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "web/h1_gateway_backends"

#include "hypo_common.h"

/** How long the gateway is watched after the request, ms. */
#define H1_WATCH_MS     5000
/** Request timeout, s. */
#define H1_REQUEST_S    5
/** Backends of the gateway: service-go and service-cs addresses. */
#define H1_PORT_GO      8082
#define H1_PORT_CS      8083
/** Connection logs of the fake backends. */
#define H1_LOG_GO       "/tmp/mde-h1-go.log"
#define H1_LOG_CS       "/tmp/mde-h1-cs.log"

/** One phase of the test. */
typedef struct h1_phase {
    const char *name;       /**< Label (chart, artifacts). */
    const char *peer_mode;  /**< Fake backend mode, @c NULL for none. */
} h1_phase;

static const h1_phase h1_phases[] = {
    { "no-backends", NULL },
    { "garbage",     HYPO_PEER_GARBAGE },
    { "close",       HYPO_PEER_CLOSE },
};

#define H1_N    TE_ARRAY_LEN(h1_phases)

/** What one phase saw. */
typedef struct h1_result {
    bool              started;  /**< The gateway announced its listener. */
    bool              alive;    /**< It was still running at the end. */
    tapi_job_status_t status;   /**< How it ended, if it did. */
    int               code;     /**< HTTP status of the request, 0 if none. */
    double            time_s;   /**< Time of the request. */
    unsigned int      hits;     /**< Connections the fake backends got. */
    bool              crashed;  /**< Signal, abort or non-zero exit. */
} h1_result;

/** Describe how a process ended. */
static void
h1_describe(const h1_result *r, te_string *out)
{
    if (!r->started)
        te_string_append(out, "did not start listening");
    else if (r->alive)
        te_string_append(out, "alive");
    else if (r->status.type == TAPI_JOB_STATUS_SIGNALED)
        te_string_append(out, "killed by signal %d", r->status.value);
    else
        te_string_append(out, "exited with status %d", r->status.value);
}

int
main(int argc, char **argv)
{
    tsapi_mde_session session = { .ta = NULL };
    tsapi_mde_dut     dut = { .root = NULL };
    bool              session_up = false;
    tsapi_mde_web     web;
    bool              web_up = false;
    unsigned int      pid_go = 0;
    unsigned int      pid_cs = 0;
    web_reply         reply = WEB_REPLY_INIT;
    te_string         url = TE_STRING_INIT;
    te_string         how = TE_STRING_INIT;
    h1_result         res[H1_N];
    double            codes[H1_N];
    double            alive[H1_N];
    const char       *labels[H1_N];
    unsigned int      n_crashed = 0;
    unsigned int      n_dead = 0;
    unsigned int      n_done = 0;
    const char       *why;
    size_t            i;

    TEST_START;

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "h1_gateway_backends", dut, session_up);

    TEST_STEP("Skip unless the gateway, curl and python3 can be run");
    why = web_unavailable(&session, &dut);
    if (why != NULL)
        TEST_SKIP("%s", why);
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("python3 is not available on the agent for the fake "
                  "backends");

    tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1, 3, &url);
    memset(res, 0, sizeof(res));

    for (i = 0; i < H1_N; i++)
    {
        const h1_phase *ph = &h1_phases[i];
        h1_result      *r = &res[i];
        te_errno        wrc;

        labels[i] = ph->name;

        TEST_STEP("Phase %s: backends %s", ph->name,
                  ph->peer_mode == NULL ? "absent" :
                  "answer with fake listeners");

        if (ph->peer_mode != NULL)
        {
            if (!hypo_peer_start(&session, ph->peer_mode, H1_PORT_GO,
                                 H1_LOG_GO, &pid_go) ||
                !hypo_peer_start(&session, ph->peer_mode, H1_PORT_CS,
                                 H1_LOG_CS, &pid_cs))
                TEST_FAIL("Cannot start the fake backends (is 8082/8083 "
                          "busy?)");
        }

        web_up = true;
        tsapi_mde_web_init(&web);
        r->started = tsapi_mde_web_start_one(&session, &dut, &web, 0) == 0;
        if (r->started)
        {
            CHECK_RC(web_get(&session, "", url.ptr, H1_REQUEST_S, &reply));
            r->code = reply.code;
            r->time_s = reply.time_s;
        }

        /* Wait up to 5 s for the process to go away. */
        if (web.svc[0].job != NULL)
            wrc = tapi_job_wait(web.svc[0].job, H1_WATCH_MS, &r->status);
        else
            wrc = TE_RC(TE_TAPI, TE_ECHILD);
        r->alive = TE_RC_GET_ERROR(wrc) == TE_EINPROGRESS;
        if (!r->alive)
        {
            n_dead++;
            r->crashed = r->status.type == TAPI_JOB_STATUS_SIGNALED ||
                         r->status.value != 0 || !r->started;
            if (r->crashed)
                n_crashed++;
        }

        if (ph->peer_mode != NULL)
            r->hits = hypo_peer_hits(&session, H1_LOG_GO) +
                      hypo_peer_hits(&session, H1_LOG_CS);

        te_string_reset(&how);
        h1_describe(r, &how);
        TEST_ARTIFACT("H1 %s: gateway %s; request HTTP %d in %.3f s; fake "
                      "backends accepted %u connection(s)", ph->name,
                      how.ptr, r->code, r->time_s, r->hits);

        codes[i] = r->code;
        alive[i] = r->alive ? 1 : 0;
        n_done++;

        tsapi_mde_web_stop(&web);
        web_up = false;
        hypo_kill(&session, pid_go);
        hypo_kill(&session, pid_cs);
        pid_go = pid_cs = 0;
    }

    TEST_STEP("Chart the outcome of each phase");
    tsapi_mde_mi_bars("web", "H1: HTTP status of the gateway per phase",
                      TE_MI_MEAS_UNITLESS_VALUE, "status", n_done, labels,
                      codes, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("web", "H1: gateway still alive after 5 s (1 = yes)",
                      TE_MI_MEAS_UNITLESS_VALUE, "alive", n_done, labels,
                      alive, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on H1");
    if (n_crashed > 0)
    {
        for (i = 0; i < H1_N; i++)
        {
            if (!res[i].crashed)
                continue;
            te_string_reset(&how);
            h1_describe(&res[i], &how);
            ERROR_VERDICT("H1 PROVEN: with backends %s the gateway %s",
                          h1_phases[i].name, how.ptr);
        }
        TEST_STOP;
    }
    if (n_dead > 0)
    {
        ERROR_VERDICT("H1 INCONCLUSIVE: the gateway exited cleanly (status "
                      "0) in %u phase(s) without being asked to", n_dead);
        TEST_STOP;
    }

    for (i = 0; i < H1_N; i++)
    {
        if (res[i].code == 0)
        {
            ERROR_VERDICT("H1 INCONCLUSIVE: the gateway is alive but "
                          "gave no HTTP answer with backends %s",
                          h1_phases[i].name);
            TEST_STOP;
        }
    }

    RING_VERDICT("H1 DISPROVEN: gateway-rs stayed up with its backends "
                 "absent, answering garbage and closing at once (HTTP "
                 "%d / %d / %d)", res[0].code, res[1].code, res[2].code);

    TEST_SUCCESS;

cleanup:

    hypo_kill(&session, pid_go);
    hypo_kill(&session, pid_cs);
    if (web_up)
        tsapi_mde_web_stop(&web);
    te_string_free(&url);
    te_string_free(&how);
    te_string_free(&reply.body);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

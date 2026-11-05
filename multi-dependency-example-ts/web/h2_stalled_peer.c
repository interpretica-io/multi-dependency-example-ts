/** @file
 * @brief Web Group
 *
 * Hypothesis H2: the service chain has no timeout, so a stalled peer hangs
 * the caller, or its failure is masked as success.
 *
 * All three services are started. Two cases follow:
 * - @c go-peer-silent: service-cs, the downstream peer of service-go
 *   (127.0.0.1:8083), is stopped and replaced with a listener that
 *   accepts connections and never replies; a request goes to the entry
 *   point of the chain, gateway-rs, and the time to the response is
 *   measured with a 30 s cap;
 * - @c cs-peer-closed: gateway-rs, the peer of service-cs
 *   (127.0.0.1:8081), is stopped and nothing listens there; a request goes
 *   to service-cs and the status is recorded.
 *
 * Verdict per case: no response within 30 s, a response slower than 10 s,
 * or a 2xx status with the peer dead proves H2; a bounded (within 10 s)
 * response that is not 2xx disproves it. One proven case proves H2.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "web/h2_stalled_peer"

#include "hypo_common.h"

/** Cap on the wait for a response, s. */
#define H2_CAP_S        30
/** A bounded error response must come within this, s. */
#define H2_BOUND_S      10
/** Hop budget that walks the whole cycle. */
#define H2_HOPS         6
/** Indexes of the services in the tier. */
#define H2_GW           0
#define H2_CS           2
/** Connection log of the fake peer. */
#define H2_LOG          "/tmp/mde-h2-peer.log"

/** What one case saw. */
typedef struct h2_case {
    const char *name;
    bool        proven;     /**< The case proves H2. */
    int         code;
    double      time_s;
    bool        masked;     /**< The body admits the failure. */
    unsigned int hits;      /**< Connections the fake peer accepted. */
} h2_case;

/** Judge one answer; @return reason text for a proven case, else NULL. */
static const char *
h2_judge(int code, double time_s)
{
    if (code == 0)
        return "no response within the 30 s cap";
    if (HYPO_IS_2XX(code))
        return "success status despite the dead peer";
    if (time_s > H2_BOUND_S)
        return "error response not bounded within 10 s";

    return NULL;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session session = { .ta = NULL };
    tsapi_mde_dut     dut = { .root = NULL };
    bool              session_up = false;
    tsapi_mde_web     web;
    bool              web_up = false;
    unsigned int      pid_peer = 0;
    web_reply         reply = WEB_REPLY_INIT;
    te_string         url = TE_STRING_INIT;
    h2_case           cases[2];
    double            times[2];
    double            codes[2];
    const char       *labels[2];
    const char       *why;
    unsigned int      n_proven = 0;
    size_t            i;

    TEST_START;

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "h2_stalled_peer", dut, session_up);

    TEST_STEP("Skip unless the services, curl and python3 can be run");
    why = web_unavailable(&session, &dut);
    if (why != NULL)
        TEST_SKIP("%s", why);
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("python3 is not available on the agent for the fake "
                  "peer");

    memset(cases, 0, sizeof(cases));
    cases[0].name = "go-peer-silent";
    cases[1].name = "cs-peer-closed";

    TEST_STEP("Case %s: start the tier, replace service-cs with a peer "
              "that never replies", cases[0].name);
    web_up = true;
    tsapi_mde_web_init(&web);
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    web_chart_start(&web);
    tsapi_mde_web_stop_one(&web, H2_CS);
    if (!hypo_peer_start(&session, HYPO_PEER_SILENT, web.svc[H2_CS].port,
                         H2_LOG, &pid_peer))
        TEST_FAIL("Cannot start the silent peer on port %u",
                  web.svc[H2_CS].port);

    te_string_reset(&url);
    tsapi_mde_web_url(web.svc[H2_GW].port, 1, H2_HOPS, &url);
    CHECK_RC(web_get(&session, "", url.ptr, H2_CAP_S, &reply));
    cases[0].code = reply.code;
    cases[0].time_s = reply.time_s;
    cases[0].masked = strstr(web_str(&reply.body), "unreachable") != NULL;
    cases[0].hits = hypo_peer_hits(&session, H2_LOG);

    TEST_STEP("Case %s: restart the tier, close the peer of service-cs",
              cases[1].name);
    hypo_kill(&session, pid_peer);
    pid_peer = 0;
    tsapi_mde_web_stop(&web);
    tsapi_mde_web_init(&web);
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    tsapi_mde_web_stop_one(&web, H2_GW);

    te_string_reset(&url);
    tsapi_mde_web_url(web.svc[H2_CS].port, 1, H2_HOPS, &url);
    CHECK_RC(web_get(&session, "", url.ptr, H2_CAP_S, &reply));
    cases[1].code = reply.code;
    cases[1].time_s = reply.time_s;
    cases[1].masked = strstr(web_str(&reply.body), "unreachable") != NULL;

    TEST_STEP("Judge both cases");
    for (i = 0; i < TE_ARRAY_LEN(cases); i++)
    {
        const char *reason = h2_judge(cases[i].code, cases[i].time_s);

        labels[i] = cases[i].name;
        times[i] = cases[i].time_s;
        codes[i] = cases[i].code;
        cases[i].proven = reason != NULL;
        TEST_ARTIFACT("H2 %s: HTTP %d in %.3f s; body %s the failure; fake "
                      "peer accepted %u connection(s); %s", cases[i].name,
                      cases[i].code, cases[i].time_s,
                      cases[i].masked ? "mentions" : "does not mention",
                      cases[i].hits, reason != NULL ? reason :
                      "bounded error response");
        if (reason != NULL)
        {
            n_proven++;
            ERROR_VERDICT("H2 PROVEN (%s): HTTP %d after %.3f s - %s",
                          cases[i].name, cases[i].code, cases[i].time_s,
                          reason);
        }
    }

    TEST_STEP("Chart time to response and status per case");
    tsapi_mde_mi_bars("web", "H2: time to response with a dead peer",
                      TE_MI_MEAS_TIME, "response", TE_ARRAY_LEN(cases),
                      labels, times, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("web", "H2: HTTP status with a dead peer",
                      TE_MI_MEAS_UNITLESS_VALUE, "status",
                      TE_ARRAY_LEN(cases), labels, codes,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on H2");
    if (n_proven > 0)
        TEST_STOP;

    RING_VERDICT("H2 DISPROVEN: a dead peer gave a bounded non-2xx "
                 "response within %d s in both cases (HTTP %d in %.3f s, "
                 "HTTP %d in %.3f s)", H2_BOUND_S, cases[0].code,
                 cases[0].time_s, cases[1].code, cases[1].time_s);

    TEST_SUCCESS;

cleanup:

    hypo_kill(&session, pid_peer);
    if (web_up)
        tsapi_mde_web_stop(&web);
    te_string_free(&url);
    te_string_free(&reply.body);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

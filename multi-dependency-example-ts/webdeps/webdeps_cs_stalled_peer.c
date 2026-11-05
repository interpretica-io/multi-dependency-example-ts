/** @file
 * @brief Webdeps Group
 *
 * Hypothesis H2: service-cs has no timeout toward its peer.
 *
 * service-cs is started with a stub peer in place of gateway-rs: the stub
 * accepts the connection and never answers. A request that makes
 * service-cs call its peer is sent to it and timed.
 *
 * - FAIL (H2 confirmed): no response or error within 10 s, or the stall
 *   is reported as plain success (2xx without an error indication).
 * - PASS: service-cs returns an error (non-2xx status, a transport error,
 *   or a body with an error field) within 10 s.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/webdeps_cs_stalled_peer"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "webdeps_common.h"

#define T       "webdeps_cs_stalled_peer"
#define H       "H2"
#define SVC     WD_CS
#define LIMIT_S 10
/** curl cap: well above the limit so that a late answer is measured. */
#define CAP_S   30

int
main(int argc, char **argv)
{
    wd_ctx    ctx = WD_CTX_INIT;
    web_reply reply = WEB_REPLY_INIT;
    char      snip[80];
    int       rc;
    bool      alive;
    bool      is_error;

    TEST_START;

    TEST_STEP("Open a session and learn the ports of the three binaries");
    WD_OPEN(ctx, T, H);
    WD_LEARN(ctx, T, H);

    TEST_STEP("Put a silent stub where %s's peer %s listens (port %u)",
              wd_names[SVC], wd_names[wd_peer[SVC]], ctx.port[wd_peer[SVC]]);
    if (!wd_stub_start(&ctx, wd_peer[SVC], "silent", WD_DIR "/stub.hits"))
        WD_FAIL(T, H, "cannot start the silent stub on port %u",
                ctx.port[wd_peer[SVC]]);

    TEST_STEP("Start %s", wd_names[SVC]);
    WD_START(ctx, SVC, T, H);

    TEST_STEP("Send a request that makes %s call its peer; time it",
              wd_names[SVC]);
    WD_GET(ctx, ctx.port[SVC], "/ring?value=1&hops=2", CAP_S, reply, T, H);
    wd_snippet(&reply.body, snip, sizeof(snip));
    alive = wd_alive(&ctx, wd_names[SVC], &rc);
    TEST_ARTIFACT("H2 %s: HTTP %d in %.3f s, body '%s'; stub saw %u "
                  "connection(s); service alive=%s", wd_names[SVC],
                  reply.code, reply.time_s, snip,
                  wd_stub_hits(&ctx, WD_DIR "/stub.hits"),
                  alive ? "yes" : "no");

    {
        const char *labels[] = { "response time" };
        double      vals[] = { reply.time_s };

        tsapi_mde_mi_bars("webdeps", "H2: time to answer with a stalled "
                          "peer", TE_MI_MEAS_TIME, "seconds",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide on H2");
    if (reply.code == 0 && WD_TIMED_OUT(&reply, CAP_S))
        WD_FAIL(T, H, "H2 confirmed: %s gave no response in %d s with a "
                "peer that never answers", wd_names[SVC], CAP_S);
    if (reply.time_s > LIMIT_S)
        WD_FAIL(T, H, "H2 confirmed: %s answered (HTTP %d) only after "
                "%.1f s, over the %d s limit", wd_names[SVC], reply.code,
                reply.time_s, LIMIT_S);

    is_error = !WD_IS_2XX(reply.code) ||
               wd_body_has_error_field(web_str(&reply.body));
    if (reply.code == 0)
        WD_PASS(T, H, "H2 disproved: %s returned a transport error in "
                "%.1f s with a stalled peer", wd_names[SVC], reply.time_s);
    if (!is_error)
        WD_FAIL(T, H, "H2 confirmed: %s reported the stalled peer as "
                "success: HTTP %d in %.1f s, body '%s'", wd_names[SVC],
                reply.code, reply.time_s, snip);

    WD_PASS(T, H, "H2 disproved: %s returned an error (HTTP %d) in %.1f s "
            "with a stalled peer", wd_names[SVC], reply.code, reply.time_s);

    TEST_SUCCESS;

cleanup:

    wd_close(&ctx);
    te_string_free(&reply.body);

    TEST_END;
}

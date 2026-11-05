/** @file
 * @brief Webdeps Group
 *
 * Hypothesis H1: the gateway's dependency on its backends is hard.
 *
 * As in webdeps_gw_no_backends gateway-rs is started alone and asked for
 * a walk that needs the backends. Then service-go and service-cs are
 * started, and the same request is repeated against the same gateway
 * process, without a restart.
 *
 * - PASS: the gateway (same pid) serves normally: HTTP 200, a body in
 *   which neither backend is reported unreachable.
 * - FAIL: the dependency is hard: the gateway died, or keeps failing the
 *   walk after the backends are back, so that only a restart helps.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/webdeps_gw_recovery"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "webdeps_common.h"

#define T   "webdeps_gw_recovery"
#define H   "H1"

#define WALK    "/ring?value=1&hops=3"

int
main(int argc, char **argv)
{
    wd_ctx       ctx = WD_CTX_INIT;
    web_reply    reply = WEB_REPLY_INIT;
    unsigned int pid_before;
    unsigned int try;
    bool         alive;
    int          rc;
    int          before;
    int          after = 0;
    bool         unreachable = true;
    char         snip[80] = "";

    TEST_START;

    TEST_STEP("Open a session and learn the ports of the three binaries");
    WD_OPEN(ctx, T, H);
    WD_LEARN(ctx, T, H);

    TEST_STEP("Start only gateway-rs and walk through it (as in "
              "webdeps_gw_no_backends)");
    WD_START(ctx, WD_GW, T, H);
    pid_before = ctx.pid[WD_GW];
    WD_GET(ctx, ctx.port[WD_GW], WALK, 10, reply, T, H);
    before = reply.code;
    wd_snippet(&reply.body, snip, sizeof(snip));
    TEST_ARTIFACT("H1 recovery: without backends HTTP %d, body '%s'", before,
                  snip);
    if (!wd_alive(&ctx, wd_names[WD_GW], &rc))
        WD_FAIL(T, H, "gateway-rs died (exit status %d) before the "
                "backends could come back: the dependency is hard", rc);

    TEST_STEP("Start service-go and service-cs; the gateway is not "
              "restarted");
    WD_START(ctx, WD_GO, T, H);
    WD_START(ctx, WD_CS, T, H);

    TEST_STEP("Walk through the same gateway process again");
    for (try = 0; try < 5; try++)
    {
        WD_GET(ctx, ctx.port[WD_GW], WALK, 10, reply, T, H);
        after = reply.code;
        unreachable = strstr(web_str(&reply.body), "unreachable") != NULL;
        wd_snippet(&reply.body, snip, sizeof(snip));
        TEST_ARTIFACT("H1 recovery: try %u with backends up -> HTTP %d in "
                      "%.3f s, unreachable=%s, body '%s'", try + 1, after,
                      reply.time_s, unreachable ? "yes" : "no", snip);
        if (after == 200 && !unreachable)
            break;
        usleep(500000);
    }

    alive = wd_alive(&ctx, wd_names[WD_GW], &rc);
    {
        const char *labels[] = { "before", "after" };
        double      vals[] = { before, after };

        tsapi_mde_mi_bars("webdeps", "H1: HTTP status before and after the "
                          "backends start", TE_MI_MEAS_UNITLESS_VALUE,
                          "status", TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide on H1");
    if (!alive)
        WD_FAIL(T, H, "H1: the dependency is hard: gateway-rs (pid %u) died "
                "(exit status %d) instead of recovering", pid_before, rc);
    if (after != 200 || unreachable)
        WD_FAIL(T, H, "H1: the dependency is hard: gateway-rs (pid %u, not "
                "restarted) still answers HTTP %d%s after the backends are "
                "up (without them: HTTP %d); body '%s'", pid_before, after,
                unreachable ? " reporting a backend unreachable" : "",
                before, snip);

    WD_PASS(T, H, "H1: the dependency is soft: gateway-rs (pid %u, not "
            "restarted) serves HTTP 200 once the backends are up (without "
            "them: HTTP %d)", pid_before, before);

    TEST_SUCCESS;

cleanup:

    wd_close(&ctx);
    te_string_free(&reply.body);

    TEST_END;
}

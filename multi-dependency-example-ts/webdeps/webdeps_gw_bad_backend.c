/** @file
 * @brief Webdeps Group
 *
 * Hypothesis H1: gateway-rs panics when a backend returns malformed data.
 *
 * The backend ports are taken from the process listing of service-go and
 * service-cs (the addresses gateway-rs calls). A stub listener on
 * 127.0.0.1 takes each of them in turn and answers (a) with an empty body,
 * (b) with non-JSON garbage, (c) with a connection reset. For each case a
 * fresh gateway is started, a request is sent through it, and then a
 * following request that needs no backend.
 *
 * - FAIL (H1 confirmed): the gateway dies, or prints 'panicked'.
 * - PASS: it stays up and keeps serving the following request.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/webdeps_gw_bad_backend"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "webdeps_common.h"

#define T   "webdeps_gw_bad_backend"
#define H   "H1"

/** Cases: how the stub backends misbehave. */
static const char * const cases[] = { "empty", "garbage", "reset" };
#define N_CASES TE_ARRAY_LEN(cases)

#define LOG_GO  WD_DIR "/stub-go.hits"
#define LOG_CS  WD_DIR "/stub-cs.hits"

int
main(int argc, char **argv)
{
    wd_ctx       ctx = WD_CTX_INIT;
    web_reply    reply = WEB_REPLY_INIT;
    te_string    summary = TE_STRING_INIT;
    te_string    err = TE_STRING_INIT;
    double       alive_v[N_CASES];
    double       served_v[N_CASES];
    const char  *labels[N_CASES];
    size_t       n_done = 0;
    size_t       i;

    TEST_START;

    TEST_STEP("Open a session; start the three binaries to learn the "
              "backend ports");
    WD_OPEN(ctx, T, H);
    WD_LEARN(ctx, T, H);

    for (i = 0; i < N_CASES; i++)
    {
        bool alive;
        int  rc;
        int  first;
        int  second;
        bool panicked;
        char snip[80];

        TEST_STEP("Case %s: stubs on ports %u and %u answer '%s'", cases[i],
                  ctx.port[WD_GO], ctx.port[WD_CS], cases[i]);
        if (!wd_stub_start(&ctx, WD_GO, cases[i], LOG_GO) ||
            !wd_stub_start(&ctx, WD_CS, cases[i], LOG_CS))
            WD_FAIL(T, H, "cannot start the %s stub on a backend port "
                    "(%u / %u busy?)", cases[i], ctx.port[WD_GO],
                    ctx.port[WD_CS]);

        WD_START(ctx, WD_GW, T, H);

        WD_GET(ctx, ctx.port[WD_GW], "/ring?value=1&hops=3", 10, reply, T,
               H);
        first = reply.code;
        wd_snippet(&reply.body, snip, sizeof(snip));
        TEST_ARTIFACT("H1 %s: request through the gateway -> HTTP %d in "
                      "%.3f s, body '%s'; stubs saw %u + %u connection(s)",
                      cases[i], first, reply.time_s, snip,
                      wd_stub_hits(&ctx, LOG_GO), wd_stub_hits(&ctx, LOG_CS));

        alive = wd_alive(&ctx, wd_names[WD_GW], &rc);
        panicked = wd_err_has(&ctx, wd_names[WD_GW], "panicked");
        if (!alive || panicked)
        {
            wd_output(&ctx, wd_names[WD_GW], "err", &err);
            WD_FAIL(T, H, "H1 confirmed: with the backends answering '%s' "
                    "gateway-rs %s (exit status %d); stderr: %s", cases[i],
                    alive ? "printed 'panicked'" : "died", rc, err.ptr);
        }

        WD_GET(ctx, ctx.port[WD_GW], "/ring?value=1&hops=0", 10, reply, T,
               H);
        second = reply.code;
        TEST_ARTIFACT("H1 %s: following request -> HTTP %d in %.3f s",
                      cases[i], second, reply.time_s);
        alive = wd_alive(&ctx, wd_names[WD_GW], &rc);
        if (!alive || second != 200)
            WD_FAIL(T, H, "H1 confirmed: after the '%s' backends gateway-rs "
                    "%s the following request (HTTP %d)", cases[i],
                    alive ? "no longer serves" : "died on", second);

        te_string_append(&summary, "%s%s: %d then %d", summary.len > 0 ?
                         "; " : "", cases[i], first, second);
        labels[n_done] = cases[i];
        alive_v[n_done] = 1;
        served_v[n_done] = second;
        n_done++;

        wd_stop_svc(&ctx, WD_GW);
        wd_stub_stop(&ctx, WD_GO);
        wd_stub_stop(&ctx, WD_CS);
    }

    tsapi_mde_mi_bars("webdeps", "H1: gateway alive with bad backends "
                      "(1 = yes)", TE_MI_MEAS_UNITLESS_VALUE, "alive",
                      n_done, labels, alive_v, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("webdeps", "H1: HTTP status of the following request",
                      TE_MI_MEAS_UNITLESS_VALUE, "status", n_done, labels,
                      served_v, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on H1");
    WD_PASS(T, H, "H1 disproved: gateway-rs stayed up and kept serving "
            "with backends answering empty, garbage and a reset (%s)",
            summary.ptr);

    TEST_SUCCESS;

cleanup:

    wd_close(&ctx);
    te_string_free(&summary);
    te_string_free(&err);
    te_string_free(&reply.body);

    TEST_END;
}

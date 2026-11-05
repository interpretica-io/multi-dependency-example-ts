/** @file
 * @brief Webdeps Group
 *
 * Hypothesis H1: gateway-rs panics when a backend is down.
 *
 * The three binaries are started once to learn their ports from the
 * process listing, then gateway-rs is started alone, service-go and
 * service-cs not running. Three requests are sent to each route the
 * gateway exposes (/ring with hops reaching the backends, /ring without
 * hops, and the fallback for any other path). The test records whether
 * the gateway pid is still alive and what status each request got.
 *
 * - PASS (H1 disproved): the process survives and every request is
 *   answered within 5 s (a 5xx, a transport error or whatever status it
 *   chose; the statuses are recorded in the verdict).
 * - FAIL (H1 confirmed): it exits, aborts or prints "panicked" on stderr;
 *   also when it survives but a request got no answer in 5 s.
 *
 * tapi_binscan is run on the three binaries and its result added to the
 * tapi_cybersec_report as information for H1 (no verdict).
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/webdeps_gw_no_backends"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "tapi_binscan.h"

#include "webdeps_common.h"

#define T   "webdeps_gw_no_backends"
#define H   "H1"

/** Routes of the gateway; each is requested three times. */
static const char * const routes[] = {
    "/ring?value=1&hops=3",
    "/ring?value=1&hops=1",
    "/",
};
#define REPEAT  3
#define LIMIT_S 5

int
main(int argc, char **argv)
{
    wd_ctx           ctx = WD_CTX_INIT;
    tsapi_mde_report report;
    bool             report_up = false;
    web_reply        reply = WEB_REPLY_INIT;
    te_string        path = TE_STRING_INIT;
    te_string        bad = TE_STRING_INIT;
    te_string        codes = TE_STRING_INIT;
    unsigned int     n_req = 0;
    unsigned int     n_ok = 0;
    bool             alive;
    int              rc;
    size_t           i;
    unsigned int     k;

    TEST_START;

    TEST_STEP("Open a session and start the three binaries");
    WD_OPEN(ctx, T, H);
    tsapi_mde_report_init(&report);
    report_up = true;
    WD_LEARN(ctx, T, H);

    TEST_STEP("tapi_binscan on the three binaries (information for H1)");
    for (i = 0; i < WD_N; i++)
    {
        tapi_binscan_info info;

        te_string_reset(&path);
        te_string_append(&path, "%s/%s", ctx.dut.bin, wd_names[i]);
        if (tapi_binscan_inspect(ctx.session.ta, path.ptr, &info) != 0)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                     "binscan.properties", wd_names[i],
                                     "H1 information: cannot be scanned");
            continue;
        }
        TEST_ARTIFACT("H1 binscan %s: NX=%s PIE=%s RELRO=%s canary=%s",
                      wd_names[i],
                      info.nx_unknown ? "unknown" : (info.nx ? "yes" : "no"),
                      info.kind == TAPI_BINSCAN_KIND_PIE ? "yes" : "no",
                      tapi_binscan_relro2str(info.relro),
                      info.canary ? "yes" : "no");
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                 "binscan.properties", wd_names[i],
                                 "H1 information: NX=%s PIE=%s RELRO=%s "
                                 "canary=%s",
                                 info.nx_unknown ? "unknown" :
                                 (info.nx ? "yes" : "no"),
                                 info.kind == TAPI_BINSCAN_KIND_PIE ? "yes" :
                                 "no", tapi_binscan_relro2str(info.relro),
                                 info.canary ? "yes" : "no");
        tapi_binscan_info_free(&info);
    }

    TEST_STEP("Start only gateway-rs; service-go and service-cs are not "
              "running");
    WD_START(ctx, WD_GW, T, H);

    TEST_STEP("Send %d requests to each route", REPEAT);
    for (i = 0; i < TE_ARRAY_LEN(routes); i++)
    {
        for (k = 0; k < REPEAT; k++)
        {
            char snip[80];
            bool good;

            WD_GET(ctx, ctx.port[WD_GW], routes[i], LIMIT_S, reply, T, H);
            n_req++;
            wd_snippet(&reply.body, snip, sizeof(snip));
            te_string_append(&codes, "%s%s=%d", codes.len > 0 ? " " : "",
                             routes[i], reply.code);
            TEST_ARTIFACT("H1 %s try %u: HTTP %d in %.3f s, body '%s'",
                          routes[i], k + 1, reply.code, reply.time_s, snip);

            /* Not a hang: curl gave up before the limit or got a status. */
            good = !WD_TIMED_OUT(&reply, LIMIT_S);
            if (good)
                n_ok++;
            else
                te_string_append(&bad, " %s timed out after %d s;",
                                 routes[i], LIMIT_S);
        }
    }

    TEST_STEP("Is the gateway still alive?");
    alive = wd_alive(&ctx, wd_names[WD_GW], &rc);
    TEST_ARTIFACT("H1 gateway-rs pid %u alive=%s exit status=%d",
                  ctx.pid[WD_GW], alive ? "yes" : "no", rc);

    {
        const char *labels[] = { "alive", "answered", "requests" };
        double      vals[] = { alive ? 1 : 0, n_ok, n_req };

        tsapi_mde_mi_bars("webdeps", "H1: gateway without backends",
                          TE_MI_MEAS_UNITLESS_VALUE, "count",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    {
        te_string text = TE_STRING_INIT;

        (void)tsapi_mde_report_finish(&report, "webdeps",
                                      TAPI_CYBERSEC_SEV_CRITICAL, &text);
        te_string_free(&text);
    }

    TEST_STEP("Decide on H1");
    if (wd_err_has(&ctx, wd_names[WD_GW], "panicked"))
    {
        te_string err = TE_STRING_INIT;

        wd_output(&ctx, wd_names[WD_GW], "err", &err);
        WD_FAIL(T, H, "H1 confirmed: gateway-rs printed 'panicked' on "
                "stderr with its backends down (alive=%s, exit status %d): "
                "%s", alive ? "yes" : "no", rc, err.ptr);
    }
    if (!alive)
        WD_FAIL(T, H, "H1 confirmed: gateway-rs exited with status %d "
                "(128+N is signal N) with its backends down; statuses: %s",
                rc, codes.ptr);
    if (n_ok != n_req)
        WD_FAIL(T, H, "H1 not disproved: gateway-rs survived but%s",
                bad.ptr);

    WD_PASS(T, H, "H1 disproved: gateway-rs (pid %u) survived %u request(s) "
            "with service-go and service-cs not running, each answered "
            "within %d s; statuses: %s", ctx.pid[WD_GW], n_req, LIMIT_S,
            codes.ptr);

    TEST_SUCCESS;

cleanup:

    wd_close(&ctx);
    if (report_up)
        tsapi_mde_report_free(&report);
    te_string_free(&path);
    te_string_free(&bad);
    te_string_free(&codes);
    te_string_free(&reply.body);

    TEST_END;
}

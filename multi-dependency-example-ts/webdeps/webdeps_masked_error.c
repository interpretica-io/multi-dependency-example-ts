/** @file
 * @brief Webdeps Group
 *
 * Hypothesis H2: peer errors are swallowed and reported as success.
 *
 * For each failure of the peer - HTTP 500, garbage, a closed connection -
 * and for each of service-go and service-cs, the service is started with
 * a stub in place of its peer and asked for a walk that calls the peer.
 *
 * - FAIL (H2 confirmed): a service answers 2xx without an error status or
 *   an error field (prose such as "upstream unreachable" inside a 200 is
 *   a swallowed error, not a report) when the peer failed.
 * - PASS: every service reports the failure with a non-2xx status, a
 *   transport error or an error field.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/webdeps_masked_error"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "webdeps_common.h"

#define T   "webdeps_masked_error"
#define H   "H2"

/** Failures of the peer. */
static const char * const cases[] = { "http500", "garbage", "close" };
#define N_CASES TE_ARRAY_LEN(cases)

/** Services that have a peer to mask. */
static const unsigned int svcs[] = { WD_GO, WD_CS };
#define N_SVCS  TE_ARRAY_LEN(svcs)

int
main(int argc, char **argv)
{
    wd_ctx       ctx = WD_CTX_INIT;
    web_reply    reply = WEB_REPLY_INIT;
    te_string    masked = TE_STRING_INIT;
    te_string    reported = TE_STRING_INIT;
    const char  *labels[N_CASES * N_SVCS];
    double       codes[N_CASES * N_SVCS];
    char         names[N_CASES * N_SVCS][48];
    unsigned int n = 0;
    unsigned int n_masked = 0;
    size_t       i;
    size_t       j;

    TEST_START;

    TEST_STEP("Open a session and learn the ports of the three binaries");
    WD_OPEN(ctx, T, H);
    WD_LEARN(ctx, T, H);

    for (i = 0; i < N_CASES; i++)
    {
        for (j = 0; j < N_SVCS; j++)
        {
            unsigned int svc = svcs[j];
            unsigned int peer = wd_peer[svc];
            bool         explicit_err;
            char         snip[80];

            TEST_STEP("%s with its peer %s failing as '%s'", wd_names[svc],
                      wd_names[peer], cases[i]);
            if (!wd_stub_start(&ctx, peer, cases[i], WD_DIR "/stub.hits"))
                WD_FAIL(T, H, "cannot start the '%s' stub for %s on port %u",
                        cases[i], wd_names[peer], ctx.port[peer]);
            WD_START(ctx, svc, T, H);

            WD_GET(ctx, ctx.port[svc], "/ring?value=1&hops=2", 15, reply, T,
                   H);
            wd_snippet(&reply.body, snip, sizeof(snip));
            explicit_err = !WD_IS_2XX(reply.code) ||
                           wd_body_has_error_field(web_str(&reply.body));
            TEST_ARTIFACT("H2 %s / peer '%s': HTTP %d in %.3f s, body '%s' "
                          "-> %s", wd_names[svc], cases[i], reply.code,
                          reply.time_s, snip,
                          explicit_err ? "failure reported" : "MASKED");

            snprintf(names[n], sizeof(names[n]), "%s/%s", wd_names[svc],
                     cases[i]);
            labels[n] = names[n];
            codes[n] = reply.code;
            n++;
            if (explicit_err)
            {
                te_string_append(&reported, "%s%s/%s=%d", reported.len > 0 ?
                                 " " : "", wd_names[svc], cases[i],
                                 reply.code);
            }
            else
            {
                n_masked++;
                te_string_append(&masked, "%s%s/%s answered HTTP %d '%s'",
                                 masked.len > 0 ? "; " : "", wd_names[svc],
                                 cases[i], reply.code, snip);
            }

            wd_stop_svc(&ctx, svc);
            wd_stub_stop(&ctx, peer);
        }
    }

    tsapi_mde_mi_bars("webdeps", "H2: HTTP status of a service whose peer "
                      "failed", TE_MI_MEAS_UNITLESS_VALUE, "status", n,
                      labels, codes, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on H2");
    if (n_masked > 0)
        WD_FAIL(T, H, "H2 confirmed: %u of %u peer failures were reported "
                "as success: %s", n_masked, n, masked.ptr);

    WD_PASS(T, H, "H2 disproved: all %u peer failures were reported with a "
            "non-2xx status or an error field (%s)", n, reported.ptr);

    TEST_SUCCESS;

cleanup:

    wd_close(&ctx);
    te_string_free(&masked);
    te_string_free(&reported);
    te_string_free(&reply.body);

    TEST_END;
}

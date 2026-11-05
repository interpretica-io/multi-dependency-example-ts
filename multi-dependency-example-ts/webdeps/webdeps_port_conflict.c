/** @file
 * @brief Webdeps Group
 *
 * Hypothesis H3: the fixed port coupling is strong.
 *
 * After the ports are learned from the running services, a listener is
 * started on service-go's hardcoded port before any service starts.
 * service-go is then started. The test checks whether it fails clearly
 * (exits non-zero with a message on stderr or stdout) or silently
 * continues. gateway-rs, which calls that port, is then started and asked
 * for a walk, and the listener's connection count is recorded: whether
 * the gateway talks to a listener that is not service-go.
 *
 * - PASS: service-go exits non-zero with a message.
 * - FAIL: it continues silently (alive, or exits 0 or without a message).
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/webdeps_port_conflict"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "webdeps_common.h"

#define T   "webdeps_port_conflict"
#define H   "H3"

#define LOG WD_DIR "/conflict.hits"

int
main(int argc, char **argv)
{
    wd_ctx       ctx = WD_CTX_INIT;
    web_reply    reply = WEB_REPLY_INIT;
    te_string    cmd = TE_STRING_INIT;
    te_string    why = TE_STRING_INIT;
    te_string    msg = TE_STRING_INIT;
    te_string    gw_why = TE_STRING_INIT;
    unsigned int port_stub;
    unsigned int port_found = 0;
    unsigned int hits = 0;
    unsigned int gw_hits = 0;
    unsigned int pid;
    int          rc = -1;
    bool         listening;
    bool         clear;

    TEST_START;

    TEST_STEP("Open a session and learn the ports of the three binaries");
    WD_OPEN(ctx, T, H);
    WD_LEARN(ctx, T, H);
    port_stub = ctx.port[WD_GO];

    TEST_STEP("Start another listener on service-go's port %u", port_stub);
    if (!wd_stub_start(&ctx, WD_GO, "http500", LOG))
        WD_FAIL(T, H, "cannot start the conflicting listener on port %u",
                port_stub);

    TEST_STEP("Start service-go on the occupied port");
    te_string_append(&cmd, "%s/%s", ctx.dut.bin, wd_names[WD_GO]);
    pid = wd_launch(&ctx, wd_names[WD_GO], cmd.ptr);
    if (pid == 0)
        WD_FAIL(T, H, "service-go could not be launched");
    ctx.pid[WD_GO] = pid;
    listening = wd_wait_port(&ctx, pid, 80, &port_found, &why);
    if (!listening && strncmp(why.ptr, "dead", 4) != 0)
    {
        /* Neither listening nor dead after 8 s. */
        wd_output(&ctx, wd_names[WD_GO], "err", &msg);
        WD_FAIL(T, H, "silent: service-go on the occupied port %u neither "
                "listens nor exits within 8 s (%s), stderr: '%s'", port_stub,
                why.ptr, msg.ptr);
    }

    if (listening)
    {
        te_string_append(&msg, "service-go is listening on port %u while "
                         "the other listener holds %u", port_found,
                         port_stub);
        WD_FAIL(T, H, "silent: service-go did not fail on the occupied port "
                "%u: %s", port_stub, msg.ptr);
    }

    (void)wd_alive(&ctx, wd_names[WD_GO], &rc);
    wd_output(&ctx, wd_names[WD_GO], "err", &msg);
    wd_output(&ctx, wd_names[WD_GO], "out", &msg);
    clear = rc > 0 && msg.len > 0 && strspn(msg.ptr, " ") < msg.len;
    TEST_ARTIFACT("H3 port conflict: service-go exit status %d, message '%s'",
                  rc, msg.ptr);

    TEST_STEP("Does gateway-rs, which calls that port, talk to the other "
              "listener?");
    if (wd_start_svc(&ctx, WD_GW, &gw_why))
    {
        if (wd_get(&ctx, ctx.port[WD_GW], "/ring?value=1&hops=2", 10,
                   &reply))
            TEST_ARTIFACT("H3 gateway-rs walk with the stub on %u: HTTP %d",
                          port_stub, reply.code);
        gw_hits = wd_stub_hits(&ctx, LOG);
    }
    hits = gw_hits;
    TEST_ARTIFACT("H3 the other listener on %u accepted %u connection(s) "
                  "from gateway-rs", port_stub, hits);

    {
        const char *labels[] = { "service-go exit status",
                                 "stub connections" };
        double      vals[] = { rc, hits };

        tsapi_mde_mi_bars("webdeps", "H3: port conflict",
                          TE_MI_MEAS_UNITLESS_VALUE, "value",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide on H3");
    if (!clear)
        WD_FAIL(T, H, "silent: service-go on the occupied port %u exited "
                "with status %d and %s", port_stub, rc,
                msg.len == 0 ? "no message" : "no usable message");

    WD_PASS(T, H, "service-go fails clearly on the occupied port %u: exit "
            "status %d, message '%s'. The coupling is fixed: gateway-rs "
            "sent %u connection(s) to the other listener on that port",
            port_stub, rc, msg.ptr, hits);

    TEST_SUCCESS;

cleanup:

    wd_close(&ctx);
    te_string_free(&cmd);
    te_string_free(&why);
    te_string_free(&msg);
    te_string_free(&gw_why);
    te_string_free(&reply.body);

    TEST_END;
}

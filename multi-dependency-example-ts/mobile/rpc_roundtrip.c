/** @file
 * @brief Mobile Group
 *
 * The stacks' RPCs are linked into the agent's RPC server and answer.
 * First a harmless call that needs no device: the RPC must come back
 * with the stack's own error, not RPC-ERPCNOTSUPP (the weak stub that
 * answers when an rpcs_* library was not linked in front of rpcxdrta).
 * Then, where the stack ships a stand-in server (tsf-android's fake adb
 * server, tsf-appium's fake Appium server), a full round trip: the
 * Configurator subtree (served by the agent) and the RPCs (served by the
 * RPC server, another process) must tell the same story, and a file
 * pushed to the device must come back bit for bit.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "mobile/rpc_roundtrip"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "te_rpc_errno.h"
#include "conf_api.h"
#include "tapi_android.h"
#include "tapi_android_rpc.h"
#include "tapi_apple_rpc.h"
#include "tapi_appium.h"
#include "tapi_appium_rpc.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "mobile_common.h"

/* Stand-ins installed with the tsf-* libraries. */
#define FAKE_ADB        "default/share/tsf-android/fake_adb_server.py"
#define FAKE_ADB_PORT   "15037"
#define FAKE_ADB_SERIAL "FAKE0001"
#define FAKE_APPIUM     "default/share/tsf-appium/fake_appium_server.py"
#define FAKE_APPIUM_PORT "14723"

/* Process names under /agent/process. */
#define PS_ADB          "mde_fake_adb"
#define PS_APPIUM       "mde_fake_appium"

/* Calls timed, for the latency chart. */
#define MAX_CALLS       16

typedef struct rt_calls {
    const char  *name[MAX_CALLS];
    double       secs[MAX_CALLS];
    unsigned int n;
} rt_calls;

static void
rt_time(rt_calls *calls, const char *name, double secs)
{
    if (calls->n < MAX_CALLS)
    {
        calls->name[calls->n] = name;
        calls->secs[calls->n] = secs;
        calls->n++;
    }
    RING("%s took %.3f s", name, secs);
}

/*
 * Judge the linkage probe: RPC-ERPCNOTSUPP means the RPC library is not
 * in the RPC server; otherwise the RPC answered with its own code.
 */
static void
rt_linkage(tsapi_mde_report *report, rcf_rpc_server *pco, const char *rpc,
           te_errno got, te_errno want)
{
    te_errno rpc_errno = RPC_ERRNO(pco);

    TEST_ARTIFACT("%s(): returned %r, RPC errno %r", rpc, got, rpc_errno);
    if (rpc_errno == (te_errno)RPC_ERPCNOTSUPP)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_CRITICAL,
                                 "mobile.rpc-not-linked", rpc,
                                 "%s() is answered by the weak stub: its "
                                 "rpcs_* library is not linked into the "
                                 "RPC server", rpc);
    }
    else if (got == 0)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "mobile.rpc-unexpected", rpc,
                                 "%s() succeeded where it had nothing to "
                                 "talk to", rpc);
    }
    else if (want != 0 && (te_errno)TE_RC_GET_ERROR(got) != want)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "mobile.rpc-unexpected", rpc,
                                 "%s() returned %s, expected %s", rpc,
                                 te_rc_err2str(got), te_rc_err2str(want));
    }
}

/* Android: the fake adb server, the subtree and the RPCs. */
static void
rt_android(tsapi_mde_session *session, tsapi_mde_report *report,
           rt_calls *calls, tapi_android **dev)
{
    static const char *props[][2] = {
        { "model",   "ro.product.model" },
        { "version", "ro.build.version.release" },
        { "sdk",     "ro.build.version.sdk" },
    };
    te_string    list = TE_STRING_INIT;
    te_string    out = TE_STRING_INIT;
    te_string    content = TE_STRING_INIT;
    te_string    sha_a = TE_STRING_INIT;
    te_string    sha_b = TE_STRING_INIT;
    char         src[64];
    char         dst[64];
    unsigned int i;
    double       t0;

    TEST_SUBSTEP("Wait for the fake device to be listed");
    for (i = 0; i < 20; i++)
    {
        te_string_reset(&list);
        if (tapi_android_devices(session->ta, &list) == 0 &&
            list.ptr != NULL && strstr(list.ptr, FAKE_ADB_SERIAL) != NULL)
            break;
        te_motivated_msleep(500, "the fake adb server is starting");
    }
    if (i == 20)
        TEST_VERDICT("The agent does not list the fake Android device");

    t0 = tsapi_mde_now();
    CHECK_RC(tapi_android_create(session->pco, FAKE_ADB_SERIAL, dev));
    CHECK_RC(tapi_android_wait_for_device(*dev, 10000));
    rt_time(calls, "android create+wait", tsapi_mde_now() - t0);

    TEST_SUBSTEP("Each property: Configurator vs RPC getprop");
    for (i = 0; i < TE_ARRAY_LEN(props); i++)
    {
        char *cfg = NULL;

        te_string_reset(&out);
        t0 = tsapi_mde_now();
        CHECK_RC(tapi_android_getprop(*dev, props[i][1], &out));
        rt_time(calls, props[i][1], tsapi_mde_now() - t0);
        CHECK_RC(cfg_get_string(&cfg, "/agent:%s/android:/device:%s/%s:",
                                session->ta, FAKE_ADB_SERIAL, props[i][0]));
        TEST_ARTIFACT("%s: Configurator '%s', RPC '%s'", props[i][1], cfg,
                      out.ptr);
        if (out.ptr == NULL || strcmp(cfg, out.ptr) != 0)
        {
            tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "mobile.cfg-rpc-mismatch",
                                     props[i][1],
                                     "Configurator '%s' vs RPC '%s'", cfg,
                                     out.ptr != NULL ? out.ptr : "");
        }
        free(cfg);
    }

    TEST_SUBSTEP("Known-bad control: a property the device does not have");
    te_string_reset(&out);
    CHECK_RC(tapi_android_getprop(*dev, "mde.no.such.prop", &out));
    if (out.ptr == NULL || strcmp(out.ptr, "Fake Phone") != 0)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "mobile.cfg-rpc-mismatch", "control",
                                 "a missing property reads '%s'",
                                 out.ptr != NULL ? out.ptr : "");
    }
    tsapi_mde_report_expect(report, "mobile.cfg-rpc-mismatch", "control");
    tsapi_mde_report_drop_subject(report, "control");

    TEST_SUBSTEP("Push a file, read it on the device, pull it back");
    TE_SPRINTF(src, "/tmp/mde-mobile-rt-%d.txt", (int)getpid());
    TE_SPRINTF(dst, "/tmp/mde-mobile-rt-%d.back", (int)getpid());
    te_string_append(&content, "mde roundtrip %d %.6f", (int)getpid(),
                     tsapi_mde_now());
    CHECK_RC(tapi_file_create_ta(session->ta, src, "%s", content.ptr));

    t0 = tsapi_mde_now();
    CHECK_RC(tapi_android_push(*dev, src, "/data/local/tmp/mde-rt.txt"));
    rt_time(calls, "android push", tsapi_mde_now() - t0);

    te_string_reset(&out);
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_android_shell(*dev, "cat /data/local/tmp/mde-rt.txt",
                                &out, NULL));
    rt_time(calls, "android shell cat", tsapi_mde_now() - t0);
    if (out.ptr == NULL || strcmp(out.ptr, content.ptr) != 0)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "mobile.push-mismatch", "android",
                                 "the device reads back '%s', pushed '%s'",
                                 out.ptr != NULL ? out.ptr : "",
                                 content.ptr);
    }

    t0 = tsapi_mde_now();
    CHECK_RC(tapi_android_pull(*dev, "/data/local/tmp/mde-rt.txt", dst));
    rt_time(calls, "android pull", tsapi_mde_now() - t0);
    {
        tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;

        CHECK_RC(tsapi_mde_sh(session, 30000, &sh,
                              "sha256sum '%s' '%s' | cut -d' ' -f1; "
                              "rm -f '%s' '%s'", src, dst, src, dst));
        if (sh.out.ptr != NULL)
        {
            char a[65] = "";
            char b[65] = "";

            if (sscanf(sh.out.ptr, "%64s %64s", a, b) == 2)
            {
                te_string_append(&sha_a, "%s", a);
                te_string_append(&sha_b, "%s", b);
            }
        }
        tsapi_mde_sh_result_free(&sh);
    }
    TEST_ARTIFACT("Pushed sha256 %s, pulled sha256 %s",
                  sha_a.ptr != NULL ? sha_a.ptr : "?",
                  sha_b.ptr != NULL ? sha_b.ptr : "?");
    if (sha_a.ptr == NULL || sha_b.ptr == NULL ||
        strcmp(sha_a.ptr, sha_b.ptr) != 0)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "mobile.push-pull-mismatch", "android",
                                 "the file pulled back differs from the "
                                 "file pushed");
    }

    te_string_free(&list);
    te_string_free(&out);
    te_string_free(&content);
    te_string_free(&sha_a);
    te_string_free(&sha_b);
}

/* Appium: the fake server, a session through the subtree, RPC actions. */
static void
rt_appium(tsapi_mde_session *session, tsapi_mde_report *report,
          rt_calls *calls, tapi_appium **ap)
{
    te_string id = TE_STRING_INIT;
    te_string element = TE_STRING_INIT;
    te_string text = TE_STRING_INIT;
    te_string source = TE_STRING_INIT;
    te_string events = TE_STRING_INIT;
    double    t0;
    te_errno  rc;

    t0 = tsapi_mde_now();
    CHECK_RC(tapi_appium_server_wait(session->ta, 10000));
    rt_time(calls, "appium server ready", tsapi_mde_now() - t0);

    t0 = tsapi_mde_now();
    CHECK_RC(tapi_appium_session_create(session->pco, "mde",
                                        "{\"platformName\": \"Android\"}",
                                        ap));
    rt_time(calls, "appium session", tsapi_mde_now() - t0);
    tapi_appium_session_id(*ap, &id);
    TEST_ARTIFACT("Appium session id: %s", id.ptr);
    if (id.len == 0)
        TEST_VERDICT("The Appium session has no WebDriver id");

    t0 = tsapi_mde_now();
    CHECK_RC(tapi_appium_wait_for(*ap, TAPI_APPIUM_ACCESSIBILITY_ID, "name",
                                  5000, &element));
    rt_time(calls, "appium find", tsapi_mde_now() - t0);
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_appium_type(*ap, TAPI_APPIUM_ACCESSIBILITY_ID, "name",
                              "te"));
    rt_time(calls, "appium type", tsapi_mde_now() - t0);
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_appium_tap(*ap, TAPI_APPIUM_ACCESSIBILITY_ID, "sign_in"));
    rt_time(calls, "appium tap", tsapi_mde_now() - t0);
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_appium_get_text(*ap, TAPI_APPIUM_ACCESSIBILITY_ID, "out",
                                  &text));
    rt_time(calls, "appium text", tsapi_mde_now() - t0);
    TEST_ARTIFACT("Text after sign-in: '%s'", text.ptr);
    if (text.ptr == NULL || strstr(text.ptr, "Hello, te") == NULL)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "mobile.ui-roundtrip", "appium",
                                 "typing 'te' and signing in shows '%s'",
                                 text.ptr != NULL ? text.ptr : "");
    }

    TEST_SUBSTEP("Known-bad control: expect a text the screen does not show");
    rc = tapi_appium_expect_text(*ap, TAPI_APPIUM_ACCESSIBILITY_ID, "out",
                                 "mde-not-on-the-screen");
    if (TE_RC_GET_ERROR(rc) == TE_EFAIL)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "mobile.ui-roundtrip", "control",
                                 "a text not on the screen is reported "
                                 "missing");
    }
    tsapi_mde_report_expect(report, "mobile.ui-roundtrip", "control");
    tsapi_mde_report_drop_subject(report, "control");

    t0 = tsapi_mde_now();
    CHECK_RC(tapi_appium_source(*ap, &source));
    rt_time(calls, "appium source", tsapi_mde_now() - t0);
    if (strstr(source.ptr != NULL ? source.ptr : "", "<hierarchy") == NULL)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "mobile.ui-roundtrip", "appium/source",
                                 "the page source has no hierarchy");
    }

    t0 = tsapi_mde_now();
    CHECK_RC(tapi_appium_execute(*ap, "mobile: events", NULL, &events));
    rt_time(calls, "appium execute", tsapi_mde_now() - t0);
    RING("Server-side events: %s", events.ptr);
    if (strstr(events.ptr != NULL ? events.ptr : "", "click sign_in") == NULL)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "mobile.ui-roundtrip", "appium/events",
                                 "the server did not record the tap the "
                                 "RPC made");
    }

    te_string_free(&id);
    te_string_free(&element);
    te_string_free(&text);
    te_string_free(&source);
    te_string_free(&events);
}

int
main(int argc, char **argv)
{
    mobile_stack           stack = MOBILE_STACK_ANDROID;
    tapi_cybersec_severity min_severity;
    const char            *name;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_report       report;
    rt_calls               calls;
    te_string              fixture = TE_STRING_INIT;
    te_string              remote = TE_STRING_INIT;
    const char            *ps_name = NULL;
    char                  *saved_server = NULL;
    tapi_android          *dev = NULL;
    tapi_appium           *ap = NULL;
    te_errno               got;
    double                 t0;
    bool                   have_fixture = false;

    TEST_START;
    tsapi_mde_report_init(&report);
    memset(&calls, 0, sizeof(calls));

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(stack, MOBILE_STACK_MAPPING_LIST);
    TEST_GET_MDE_SEVERITY(min_severity);
    name = mobile_stack2str(stack);

    TEST_STEP("Open a session: its RPC server serves the stack's RPCs");
    CHECK_RC(tsapi_mde_session_init(&session, "mobile_rpc"));
    session_up = true;

    TEST_STEP("Linkage probe: a harmless %s RPC with nothing to talk to",
              name);
    RPC_AWAIT_ERROR(session.pco);
    t0 = tsapi_mde_now();
    switch (stack)
    {
        case MOBILE_STACK_ANDROID:
        {
            int status = 0;

            /* Port 1 of the loopback: no adb server there. */
            got = rpc_android_shell(session.pco, "127.0.0.1:1",
                                    "MDE-NO-DEVICE", "true", NULL, NULL,
                                    &status);
            rt_time(&calls, "android_shell probe", tsapi_mde_now() - t0);
            rt_linkage(&report, session.pco, "android_shell", got, 0);
            break;
        }

        case MOBILE_STACK_APPLE:
            /* Terminating on a device is refused by rpcs_apple itself. */
            got = rpc_apple_terminate(session.pco, "MDE-NO-DEVICE", false,
                                      "com.example.none");
            rt_time(&calls, "apple_terminate probe", tsapi_mde_now() - t0);
            rt_linkage(&report, session.pco, "apple_terminate", got,
                       TE_EOPNOTSUPP);
            break;

        case MOBILE_STACK_APPIUM:
        {
            te_string src = TE_STRING_INIT;

            got = rpc_appium_source(session.pco, "http://127.0.0.1:1",
                                    "mde-no-session", &src);
            rt_time(&calls, "appium_source probe", tsapi_mde_now() - t0);
            rt_linkage(&report, session.pco, "appium_source", got, 0);
            te_string_free(&src);
            break;
        }
    }

    TEST_STEP("Full round trip through a stand-in server, where one ships");
    switch (stack)
    {
        case MOBILE_STACK_ANDROID:
            have_fixture = mobile_install_file(FAKE_ADB, &fixture);
            break;
        case MOBILE_STACK_APPIUM:
            have_fixture = mobile_install_file(FAKE_APPIUM, &fixture);
            break;
        default:
            RING("tsf-apple ships no stand-in for a device or a simulator");
            break;
    }
    if (have_fixture && !tsapi_mde_have(&session, "python3"))
    {
        RING("python3 is missing on the agent: the stand-in cannot run");
        have_fixture = false;
    }

    if (have_fixture && stack == MOBILE_STACK_ANDROID)
    {
        te_string state = TE_STRING_INIT;

        CHECK_RC(cfg_get_string(&saved_server, "/agent:%s/android:/server:",
                                session.ta));
        ps_name = PS_ADB;
        te_string_append(&state, "--state=/tmp/mde_fake_adb_state_%d",
                         (int)getpid());
        rc = mobile_fixture_start(session.ta, fixture.ptr, ps_name,
                                  "--port=" FAKE_ADB_PORT, state.ptr,
                                  &remote);
        te_string_free(&state);
        CHECK_RC(rc);
        CHECK_RC(tapi_android_set_server(session.ta,
                                         "127.0.0.1:" FAKE_ADB_PORT));
        rt_android(&session, &report, &calls, &dev);
    }
    else if (have_fixture && stack == MOBILE_STACK_APPIUM)
    {
        CHECK_RC(cfg_get_string(&saved_server, "/agent:%s/appium:/server:",
                                session.ta));
        ps_name = PS_APPIUM;
        CHECK_RC(mobile_fixture_start(session.ta, fixture.ptr, ps_name,
                                      "--port=" FAKE_APPIUM_PORT, NULL,
                                      &remote));
        CHECK_RC(tapi_appium_server_set(session.ta,
                                        "http://127.0.0.1:" FAKE_APPIUM_PORT));
        rt_appium(&session, &report, &calls, &ap);
    }
    else
    {
        TEST_ARTIFACT("%s: no stand-in server - the linkage probe is the "
                      "whole round trip", name);
    }

    TEST_STEP("Chart the RPC latencies");
    tsapi_mde_mi_bars("mobile", "RPC and subtree call latency",
                      TE_MI_MEAS_TIME, "latency", calls.n, calls.name,
                      calls.secs, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "mobile", min_severity);

    TEST_SUCCESS;

cleanup:

    tapi_appium_session_destroy(ap);
    tapi_android_destroy(dev);
    if (saved_server != NULL)
    {
        if (stack == MOBILE_STACK_ANDROID)
            CLEANUP_CHECK_RC(tapi_android_set_server(session.ta,
                                                     saved_server));
        else
            CLEANUP_CHECK_RC(tapi_appium_server_set(session.ta,
                                                    saved_server));
    }
    if (ps_name != NULL)
        mobile_fixture_stop(TSAPI_MDE_TA, ps_name, &remote);
    free(saved_server);
    te_string_free(&fixture);
    te_string_free(&remote);
    tsapi_mde_report_free(&report);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

/** @file
 * @brief Mobile Group
 *
 * List the devices a stack sees on the agent - Android devices of the
 * adb server, iOS devices and simulators, a ready Appium server - through
 * the stack's TAPI, and cross-check the count with the native tool when
 * it is there. The count is charted either way; with nothing attached
 * (the container has no devices) the test skips with the reason. When a
 * device is there, nothing is installed: its properties are read and
 * kept as artifacts, through the Configurator and through the RPCs, and
 * the two readings must agree.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "mobile/devices"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "conf_api.h"
#include "tapi_android.h"
#include "tapi_apple.h"
#include "tapi_appium.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "mobile_common.h"

/* Whether something listens on a TCP port of the agent. */
static bool
devices_port_open(tsapi_mde_session *session, unsigned int port)
{
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    if (!tsapi_mde_have(session, "python3"))
        return false;
    ok = tsapi_mde_sh(session, 10000, &sh,
                      "python3 -c 'import socket; "
                      "socket.create_connection((\"127.0.0.1\", %u), 2)"
                      ".close()'", port) == 0 && tsapi_mde_sh_ok(&sh);
    tsapi_mde_sh_result_free(&sh);

    return ok;
}

/* Read the properties of every Android device listed, two ways. */
static void
devices_android_props(tsapi_mde_session *session, const char *list)
{
    const char *p = list;

    while (p != NULL && *p != '\0')
    {
        const char   *nl = strchr(p, '\n');
        size_t        len = (nl == NULL) ? strlen(p) : (size_t)(nl - p);
        te_string     serial = TE_STRING_INIT;
        te_string     model = TE_STRING_INIT;
        te_string     version = TE_STRING_INIT;
        te_string     sdk = TE_STRING_INIT;
        te_string     state = TE_STRING_INIT;
        char         *cfg_model = NULL;
        tapi_android *dev = NULL;

        te_string_append(&serial, "%.*s", (int)len, p);
        p = (nl == NULL) ? NULL : nl + 1;
        if (serial.len == 0)
            continue;

        CHECK_RC(tapi_android_create(session->pco, serial.ptr, &dev));
        CHECK_RC(tapi_android_state(dev, &state));
        TEST_ARTIFACT("Android device %s: state %s", serial.ptr, state.ptr);
        if (state.ptr != NULL && strcmp(state.ptr, "device") == 0)
        {
            CHECK_RC(tapi_android_info(dev, &model, &version, &sdk));
            TEST_ARTIFACT("Android device %s: model '%s', Android %s, SDK %s",
                          serial.ptr, model.ptr, version.ptr, sdk.ptr);
            if (cfg_get_string(&cfg_model,
                               "/agent:%s/android:/device:%s/model:",
                               session->ta, serial.ptr) == 0)
            {
                TEST_ARTIFACT("Configurator model of %s: '%s'", serial.ptr,
                              cfg_model);
                if (model.ptr == NULL || strcmp(cfg_model, model.ptr) != 0)
                {
                    TEST_VERDICT("The Configurator and the RPC disagree on "
                                 "an Android device's model");
                }
            }
        }
        free(cfg_model);
        tapi_android_destroy(dev);
        te_string_free(&serial);
        te_string_free(&model);
        te_string_free(&version);
        te_string_free(&sdk);
        te_string_free(&state);
    }
}

/* Read the properties of every Apple device or simulator listed. */
static void
devices_apple_props(tsapi_mde_session *session, const char *list,
                    bool simulator)
{
    const char *p = list;

    while (p != NULL && *p != '\0')
    {
        const char *nl = strchr(p, '\n');
        size_t      len = (nl == NULL) ? strlen(p) : (size_t)(nl - p);
        te_string   udid = TE_STRING_INIT;
        te_string   dev_name = TE_STRING_INIT;
        te_string   product = TE_STRING_INIT;
        te_string   version = TE_STRING_INIT;
        tapi_apple *dev = NULL;

        te_string_append(&udid, "%.*s", (int)len, p);
        p = (nl == NULL) ? NULL : nl + 1;
        if (udid.len == 0)
            continue;

        CHECK_RC(tapi_apple_create(session->pco, udid.ptr, simulator, &dev));
        CHECK_RC(tapi_apple_name(dev, &dev_name));
        if (!simulator)
        {
            CHECK_RC(tapi_apple_info(dev, &product, &version));
            TEST_ARTIFACT("iOS device %s: '%s', %s, iOS %s", udid.ptr,
                          dev_name.ptr, product.ptr, version.ptr);
        }
        else
        {
            TEST_ARTIFACT("iOS simulator %s: '%s'", udid.ptr, dev_name.ptr);
        }
        tapi_apple_destroy(dev);
        te_string_free(&udid);
        te_string_free(&dev_name);
        te_string_free(&product);
        te_string_free(&version);
    }
}

int
main(int argc, char **argv)
{
    mobile_stack        stack = MOBILE_STACK_ANDROID;
    const char         *name;
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string           list = TE_STRING_INIT;
    te_string           sims = TE_STRING_INIT;
    char               *server = NULL;
    unsigned int        count = 0;
    unsigned int        n_sims = 0;
    int                 native = -1;
    double              t0;
    double              t_list;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(stack, MOBILE_STACK_MAPPING_LIST);
    name = mobile_stack2str(stack);

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "mobile_devices"));
    session_up = true;
    if (cfg_find_fmt(NULL, "/agent:%s/%s:", session.ta, name) != 0)
        TEST_SKIP("The agent serves no /agent/%s subtree", name);

    TEST_STEP("List what the %s stack sees", name);
    t0 = tsapi_mde_now();
    switch (stack)
    {
        case MOBILE_STACK_ANDROID:
            rc = tapi_android_devices(session.ta, &list);
            if (rc != 0)
                RING("The adb server lists nothing: %r", rc);
            count = mobile_count_lines(list.ptr);
            if (cfg_get_string(&server, "/agent:%s/android:/server:",
                               session.ta) == 0)
            {
                TEST_ARTIFACT("adb server: %s", server);
            }
            /* adb would start a server of its own: ask only a running one. */
            if (tsapi_mde_have(&session, "adb") &&
                devices_port_open(&session, 5037))
            {
                CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                                      "adb devices | tail -n +2 | "
                                      "grep -c 'device$'"));
                native = (int)strtol(sh.out.ptr != NULL ? sh.out.ptr : "0",
                                     NULL, 10);
            }
            break;

        case MOBILE_STACK_APPLE:
            CHECK_RC(tapi_apple_list(session.ta, false, &list));
            CHECK_RC(tapi_apple_list(session.ta, true, &sims));
            count = mobile_count_lines(list.ptr);
            n_sims = mobile_count_lines(sims.ptr);
            if (tsapi_mde_have(&session, "idevice_id"))
            {
                CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                                      "idevice_id -l | grep -c ."));
                native = (int)strtol(sh.out.ptr != NULL ? sh.out.ptr : "0",
                                     NULL, 10);
            }
            break;

        case MOBILE_STACK_APPIUM:
        {
            bool ready = false;

            rc = tapi_appium_server_ready(session.ta, &ready);
            if (rc != 0)
                RING("Cannot read the Appium server status: %r", rc);
            count = ready ? 1 : 0;
            if (cfg_get_string(&server, "/agent:%s/appium:/server:",
                               session.ta) == 0)
            {
                TEST_ARTIFACT("Appium server: %s", server);
            }
            if (server != NULL && tsapi_mde_have(&session, "curl"))
            {
                CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                                      "curl -s -m 5 '%s/status'", server));
                native = (tsapi_mde_sh_ok(&sh) && sh.out.ptr != NULL &&
                          strstr(sh.out.ptr, "\"ready\":true") != NULL) ?
                         1 : 0;
                if (sh.out.ptr != NULL && sh.out.len > 0)
                    TEST_ARTIFACT("Appium /status: %s", sh.out.ptr);
            }
            break;
        }
    }
    t_list = tsapi_mde_now() - t0;

    TEST_ARTIFACT("%s: %u device(s)%s, native tool: %d (-1 = not asked)",
                  name, count,
                  stack == MOBILE_STACK_APPLE ? " plus simulators" : "",
                  native);
    if (stack == MOBILE_STACK_APPLE)
        TEST_ARTIFACT("apple: %u simulator(s)", n_sims);

    tsapi_mde_mi_point("mobile", "Devices the stack lists",
                       TE_MI_MEAS_UNITLESS_VALUE, "devices", count + n_sims,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("mobile", "Time to list the devices", TE_MI_MEAS_TIME,
                       "list", t_list, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Cross-check the count with the native tool");
    if (native >= 0 && (unsigned int)native != count)
    {
        TEST_VERDICT("The %s stack and its native tool see a different "
                     "number of devices", name);
    }

    if (count + n_sims == 0)
    {
        switch (stack)
        {
            case MOBILE_STACK_ANDROID:
                TEST_SKIP("No Android device is attached to the agent");
                break;
            case MOBILE_STACK_APPLE:
                TEST_SKIP("No iOS device or simulator is visible to the "
                          "agent");
                break;
            default:
                TEST_SKIP("No Appium server is ready on the agent");
                break;
        }
    }

    TEST_STEP("Read the properties of what is attached, installing nothing");
    switch (stack)
    {
        case MOBILE_STACK_ANDROID:
            devices_android_props(&session, list.ptr);
            break;

        case MOBILE_STACK_APPLE:
            devices_apple_props(&session, list.ptr, false);
            devices_apple_props(&session, sims.ptr, true);
            break;

        default:
            /* The ready server and its /status are the artifacts. */
            break;
    }

    TEST_SUCCESS;

cleanup:

    free(server);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&list);
    te_string_free(&sims);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

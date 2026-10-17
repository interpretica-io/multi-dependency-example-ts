/** @file
 * @brief Mobile Group
 *
 * mobile group prologue: record which device control subtrees the agent
 * serves, which native tools are on it (adb, idevice_id, appium) and
 * which stand-in servers the tsf-* installation carries, and chart it.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "mobile/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "conf_api.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "mobile_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session session;
    bool              session_up = false;
    te_string         path = TE_STRING_INIT;
    const char       *labels[] = { "/agent/android", "/agent/apple",
                                   "/agent/appium", "adb", "idevice_id",
                                   "appium", "fake adb server",
                                   "fake appium server" };
    double            found[8];

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "mobile_prologue"));
    session_up = true;

    TEST_STEP("Inventory the device control stacks");
    found[0] = cfg_find_fmt(NULL, "/agent:%s/android:", session.ta) == 0;
    found[1] = cfg_find_fmt(NULL, "/agent:%s/apple:", session.ta) == 0;
    found[2] = cfg_find_fmt(NULL, "/agent:%s/appium:", session.ta) == 0;
    found[3] = tsapi_mde_have(&session, "adb");
    found[4] = tsapi_mde_have(&session, "idevice_id");
    found[5] = tsapi_mde_have(&session, "appium");
    found[6] = mobile_install_file(
                   "default/share/tsf-android/fake_adb_server.py", &path);
    te_string_reset(&path);
    found[7] = mobile_install_file(
                   "default/share/tsf-appium/fake_appium_server.py", &path);

    TEST_ARTIFACT("Subtrees: android %s, apple %s, appium %s; tools: adb %s, "
                  "idevice_id %s, appium %s; stand-ins: adb %s, appium %s",
                  found[0] > 0 ? "yes" : "no", found[1] > 0 ? "yes" : "no",
                  found[2] > 0 ? "yes" : "no", found[3] > 0 ? "yes" : "no",
                  found[4] > 0 ? "yes" : "no", found[5] > 0 ? "yes" : "no",
                  found[6] > 0 ? "yes" : "no", found[7] > 0 ? "yes" : "no");

    TEST_STEP("Chart the inventory");
    tsapi_mde_mi_bars("mobile", "Device control stack on the agent "
                      "(1 = present)", TE_MI_MEAS_UNITLESS_VALUE, "present",
                      TE_ARRAY_LEN(labels), labels, found,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    te_string_free(&path);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

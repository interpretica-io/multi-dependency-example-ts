/** @file
 * @brief Mobile Group
 *
 * The device control stacks are linked into the suite's agent, not just
 * built: every object of the stack's Configurator model must be
 * registered, the agent must serve the root of the subtree, its leaves
 * must be readable with their documented defaults. A planted object that
 * the model does not have is the known-bad control: the same lookup must
 * report it as missing.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "mobile/stack_presence"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "conf_api.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "mobile_common.h"

/* Depth of the subtree walked for instances. */
#define MAX_DEPTH   3

/* Check that an object is registered; a finding otherwise. */
static bool
presence_object(tsapi_mde_report *report, const char *oid)
{
    if (cfg_find_str(oid, NULL) == 0)
        return true;

    tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                             "mobile.object-unregistered", oid,
                             "the Configurator does not know %s", oid);
    return false;
}

int
main(int argc, char **argv)
{
    mobile_stack        stack = MOBILE_STACK_ANDROID;
    tapi_cybersec_severity min_severity;
    const char         *name;
    const char * const *objects;
    unsigned int        n_objects = 0;
    unsigned int        n_registered = 0;
    unsigned int        n_inst[MAX_DEPTH];
    unsigned int        n_inst_total = 0;
    tsapi_mde_report    report;
    te_string           pattern = TE_STRING_INIT;
    te_string           planted = TE_STRING_INIT;
    char               *value = NULL;
    double              t0;
    double              t_sync;
    unsigned int        i;
    unsigned int        d;

    TEST_START;
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(stack, MOBILE_STACK_MAPPING_LIST);
    TEST_GET_MDE_SEVERITY(min_severity);
    name = mobile_stack2str(stack);
    objects = mobile_stack_objects(stack, &n_objects);

    TEST_STEP("Every object of the %s model must be registered", name);
    for (i = 0; i < n_objects; i++)
    {
        if (presence_object(&report, objects[i]))
            n_registered++;
    }
    TEST_ARTIFACT("%s: %u of %u object(s) of cm_%s.yml registered", name,
                  n_registered, n_objects, name);

    TEST_STEP("Known-bad control: an object the model does not have");
    te_string_append(&planted, "/agent/%s/mde-no-such-node", name);
    presence_object(&report, planted.ptr);
    tsapi_mde_report_expect(&report, "mobile.object-unregistered",
                            planted.ptr);
    tsapi_mde_report_drop_subject(&report, planted.ptr);

    TEST_STEP("The agent must serve the root of /agent/%s", name);
    t0 = tsapi_mde_now();
    rc = cfg_synchronize_fmt(true, "/agent:%s/%s:", TSAPI_MDE_TA, name);
    t_sync = tsapi_mde_now() - t0;
    if (rc != 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "mobile.sync-failed", name,
                                 "synchronizing /agent:%s/%s: failed: %s",
                                 TSAPI_MDE_TA, name, te_rc_err2str(rc));
    }
    if (cfg_find_fmt(NULL, "/agent:%s/%s:", TSAPI_MDE_TA, name) != 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_CRITICAL,
                                 "mobile.subtree-missing", name,
                                 "the agent serves no /agent:%s/%s: - "
                                 "ta_%s_conf is not linked into it",
                                 TSAPI_MDE_TA, name, name);
    }

    TEST_STEP("Count the instances the agent serves, level by level");
    te_string_append(&pattern, "/agent:%s/%s:", TSAPI_MDE_TA, name);
    for (d = 0; d < MAX_DEPTH; d++)
    {
        cfg_handle  *handles = NULL;
        unsigned int n = 0;

        te_string_append(&pattern, "/*:*");
        if (cfg_find_pattern(pattern.ptr, &n, &handles) != 0)
            n = 0;
        free(handles);
        n_inst[d] = n;
        n_inst_total += n;
        RING("%s: %u instance(s)", pattern.ptr, n);
    }
    TEST_ARTIFACT("/agent:%s/%s: serves %u instance(s) below its root "
                  "(%u / %u / %u by level), synchronized in %.3f s",
                  TSAPI_MDE_TA, name, n_inst_total, n_inst[0], n_inst[1],
                  n_inst[2], t_sync);

    TEST_STEP("Read the leaves that have documented defaults");
    switch (stack)
    {
        case MOBILE_STACK_ANDROID:
            if (cfg_get_string(&value, "/agent:%s/android:/server:",
                               TSAPI_MDE_TA) != 0)
            {
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_HIGH,
                                         "mobile.leaf-unreadable",
                                         "android/server",
                                         "the adb server address cannot "
                                         "be read");
            }
            else
            {
                TEST_ARTIFACT("adb server address: %s", value);
                if (strcmp(value, "127.0.0.1:5037") != 0)
                {
                    tapi_cybersec_report_add(&report.cyber,
                                             TAPI_CYBERSEC_SEV_LOW,
                                             "mobile.default-changed",
                                             "android/server",
                                             "the adb server is %s, the "
                                             "default is 127.0.0.1:5037",
                                             value);
                }
            }
            break;

        case MOBILE_STACK_APPIUM:
        {
            int32_t status = 0;

            if (cfg_get_string(&value, "/agent:%s/appium:/server:",
                               TSAPI_MDE_TA) != 0)
            {
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_HIGH,
                                         "mobile.leaf-unreadable",
                                         "appium/server",
                                         "the Appium server URL cannot be "
                                         "read");
            }
            else
            {
                TEST_ARTIFACT("Appium server URL: %s", value);
                if (strcmp(value, "http://127.0.0.1:4723") != 0)
                {
                    tapi_cybersec_report_add(&report.cyber,
                                             TAPI_CYBERSEC_SEV_LOW,
                                             "mobile.default-changed",
                                             "appium/server",
                                             "the Appium server is %s, the "
                                             "default is "
                                             "http://127.0.0.1:4723", value);
                }
            }
            if (cfg_get_int32(&status, "/agent:%s/appium:/status:",
                              TSAPI_MDE_TA) != 0)
            {
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_HIGH,
                                         "mobile.leaf-unreadable",
                                         "appium/status",
                                         "the Appium server status cannot "
                                         "be read");
            }
            else
            {
                TEST_ARTIFACT("Appium server status: %d (1 = ready)",
                              (int)status);
            }
            break;
        }

        default:
            /* /agent/apple has no leaf of its own: the lists are enough. */
            RING("/agent/apple has no leaves outside its device lists");
            break;
    }

    TEST_STEP("Chart what was found");
    {
        const char *labels[] = { "objects in model", "objects registered",
                                 "instances level 1", "instances level 2",
                                 "instances level 3" };
        double      vals[5];

        vals[0] = n_objects;
        vals[1] = n_registered;
        vals[2] = n_inst[0];
        vals[3] = n_inst[1];
        vals[4] = n_inst[2];
        tsapi_mde_mi_bars("mobile", "Configurator nodes found for the stack",
                          TE_MI_MEAS_UNITLESS_VALUE, "nodes",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    tsapi_mde_mi_point("mobile", "Subtree synchronization time",
                       TE_MI_MEAS_TIME, "sync", t_sync,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "mobile", min_severity);

    TEST_SUCCESS;

cleanup:

    free(value);
    te_string_free(&pattern);
    te_string_free(&planted);
    tsapi_mde_report_free(&report);

    TEST_END;
}

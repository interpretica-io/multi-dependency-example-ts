/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Mobile group helpers
 *
 * The three device control stacks the suite links into its agent -
 * tsf-android, tsf-apple, tsf-appium - each with a Configurator subtree
 * served by the agent and RPCs served by its RPC server. What the tests
 * share: the stack parameter, the object model of each subtree (from
 * cm_android.yml, cm_apple.yml, cm_appium.yml), and the stand-in servers
 * tsf-android and tsf-appium install for an agent without hardware.
 *
 * Everything here is @c static @c inline: each test is one C file.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_MOBILE_COMMON_H__
#define __MDE_MOBILE_COMMON_H__

#include "te_config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_sleep.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_cfg_process.h"
#include "tsapi_mde.h"

/** A device control stack. */
typedef enum mobile_stack {
    MOBILE_STACK_ANDROID,   /**< tsf-android: adb server protocol */
    MOBILE_STACK_APPLE,     /**< tsf-apple: libimobiledevice, simctl */
    MOBILE_STACK_APPIUM,    /**< tsf-appium: a WebDriver client */
} mobile_stack;

/** Values of the @c stack parameter. */
#define MOBILE_STACK_MAPPING_LIST \
    { "android", MOBILE_STACK_ANDROID }, \
    { "apple",   MOBILE_STACK_APPLE },   \
    { "appium",  MOBILE_STACK_APPIUM }

/**
 * Name of a stack, which is also the name of its subtree under /agent.
 *
 * @param stack     Stack.
 *
 * @return A static string.
 */
static inline const char *
mobile_stack2str(mobile_stack stack)
{
    switch (stack)
    {
        case MOBILE_STACK_ANDROID:
            return "android";
        case MOBILE_STACK_APPLE:
            return "apple";
        case MOBILE_STACK_APPIUM:
            return "appium";
        default:
            return "?";
    }
}

/**
 * The object model of a stack's subtree, as its cm_*.yml registers it.
 *
 * @param[in]  stack    Stack.
 * @param[out] n        Number of objects.
 *
 * @return Object identifiers.
 */
static inline const char * const *
mobile_stack_objects(mobile_stack stack, unsigned int *n)
{
    static const char * const android[] = {
        "/agent/android",
        "/agent/android/server",
        "/agent/android/device",
        "/agent/android/device/state",
        "/agent/android/device/model",
        "/agent/android/device/version",
        "/agent/android/device/sdk",
        "/agent/android/device/app",
        "/agent/android/device/app/running",
    };
    static const char * const apple[] = {
        "/agent/apple",
        "/agent/apple/device",
        "/agent/apple/device/name",
        "/agent/apple/device/product",
        "/agent/apple/device/version",
        "/agent/apple/device/app",
        "/agent/apple/simulator",
        "/agent/apple/simulator/name",
        "/agent/apple/simulator/state",
        "/agent/apple/simulator/app",
    };
    static const char * const appium[] = {
        "/agent/appium",
        "/agent/appium/server",
        "/agent/appium/status",
        "/agent/appium/session",
        "/agent/appium/session/id",
    };

    switch (stack)
    {
        case MOBILE_STACK_ANDROID:
            *n = TE_ARRAY_LEN(android);
            return android;
        case MOBILE_STACK_APPLE:
            *n = TE_ARRAY_LEN(apple);
            return apple;
        default:
            *n = TE_ARRAY_LEN(appium);
            return appium;
    }
}

/**
 * Find a file the tsf-* installation put under TE_INSTALL.
 *
 * @param[in]  rel      Path relative to TE_INSTALL.
 * @param[out] path     String to append the full path to.
 *
 * @return @c true if the file is there.
 */
static inline bool
mobile_install_file(const char *rel, te_string *path)
{
    const char *install = getenv("TE_INSTALL");

    if (install == NULL)
        return false;
    te_string_append(path, "%s/%s", install, rel);

    return access(path->ptr, R_OK) == 0;
}

/**
 * Put a python stand-in server on the agent and start it as a
 * Configurator process (the rollback stops and removes it too).
 *
 * @param[in]  ta       Agent.
 * @param[in]  local    The script on the engine.
 * @param[in]  ps_name  Process name under /agent/process.
 * @param[in]  arg1     First argument (e.g. "--port=15037").
 * @param[in]  arg2     Second argument, or @c NULL.
 * @param[out] remote   String to append the script's path on the agent.
 *
 * @return Status code.
 */
static inline te_errno
mobile_fixture_start(const char *ta, const char *local, const char *ps_name,
                     const char *arg1, const char *arg2, te_string *remote)
{
    te_errno rc;

    tapi_file_make_custom_pathname(remote, "/tmp", "_mde_fixture.py");
    rc = rcf_ta_put_file(ta, 0, local, remote->ptr);
    if (rc == 0)
        rc = tapi_cfg_ps_add(ta, ps_name, "python3", false);
    if (rc == 0)
        rc = tapi_cfg_ps_add_arg(ta, ps_name, 1, remote->ptr);
    if (rc == 0)
        rc = tapi_cfg_ps_add_arg(ta, ps_name, 2, arg1);
    if (rc == 0 && arg2 != NULL)
        rc = tapi_cfg_ps_add_arg(ta, ps_name, 3, arg2);
    if (rc == 0)
        rc = tapi_cfg_ps_start(ta, ps_name);

    return rc;
}

/**
 * Stop and remove a stand-in started with mobile_fixture_start().
 *
 * @param ta        Agent.
 * @param ps_name   Process name.
 * @param remote    The script on the agent (may be empty).
 */
static inline void
mobile_fixture_stop(const char *ta, const char *ps_name,
                    const te_string *remote)
{
    if (cfg_find_fmt(NULL, "/agent:%s/process:%s", ta, ps_name) == 0)
    {
        tapi_cfg_ps_stop(ta, ps_name);
        tapi_cfg_ps_del(ta, ps_name);
    }
    if (remote->ptr != NULL)
        tapi_file_ta_unlink_fmt(ta, "%s", remote->ptr);
}

/**
 * Count the lines of a list ("a\nb\n").
 *
 * @param list  List (may be @c NULL).
 *
 * @return Number of lines.
 */
static inline unsigned int
mobile_count_lines(const char *list)
{
    unsigned int n = 0;

    if (list == NULL)
        return 0;
    for (; *list != '\0'; list++)
    {
        if (*list == '\n')
            n++;
    }

    return n;
}

#endif /* !__MDE_MOBILE_COMMON_H__ */

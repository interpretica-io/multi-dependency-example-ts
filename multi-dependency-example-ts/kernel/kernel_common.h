/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Kernel group helpers
 *
 * What several tests of the kernel group do the same way: run a workload
 * of the example (the ring demos or the web tier), find the PID of a
 * service, read the kernel log with or without sudo, and move the
 * issues tsf-kernel reports into the severity-ranked list of the
 * report, so that the min_severity parameter decides what fails.
 *
 * Everything here is static inline: each test is built from one C file
 * and an unused static function would break the -Werror build.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_KERNEL_COMMON_H__
#define __MDE_KERNEL_COMMON_H__

#include "te_config.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "logger_api.h"
#include "tapi_cybersec.h"
#include "tapi_kernel_issue.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"

/** What a kernel test drives while it watches. */
typedef enum kernel_workload {
    KERNEL_WORKLOAD_RING,   /**< The three ring demos. */
    KERNEL_WORKLOAD_WEB,    /**< The web tier and requests through it. */
} kernel_workload;

/** Mapping of the @c workload parameter. */
#define KERNEL_WORKLOAD_LIST \
    { "ring", KERNEL_WORKLOAD_RING }, \
    { "web",  KERNEL_WORKLOAD_WEB }

/** Hop budget of every walk the kernel group drives. */
#define KERNEL_HOPS 7

/**
 * Copy the issues of a tsf-kernel check into the severity-ranked list
 * of a report. tsapi_mde_report_finish() fails a test over any kernel
 * issue; the kernel of a shared container host is not the DUT, so its
 * state is ranked here and the min_severity parameter decides.
 *
 * @param issues    Issues to copy.
 * @param report    Report to add them to.
 * @param sev       Severity to give them.
 */
static inline void
kernel_issues_to_cyber(const tapi_kernel_issues *issues,
                       tsapi_mde_report *report,
                       tapi_cybersec_severity sev)
{
    const tapi_kernel_issue *k;

    TE_VEC_FOREACH(&issues->items, k)
    {
        tapi_cybersec_report_add(&report->cyber, sev, k->check, k->subject,
                                 "%s", k->detail != NULL ? k->detail : "");
    }
}

/**
 * Run the three ring demos once each (cpp-demo, rust-demo, demo.py).
 *
 * @param session   Session.
 * @param dut       Example.
 *
 * @return How many of them exited with status 0.
 */
static inline unsigned int
kernel_run_ring(tsapi_mde_session *session, const tsapi_mde_dut *dut)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    unsigned int        ok = 0;

    if (tsapi_mde_sh(session, 60000, &res, "'%s/cpp-demo' 1 %d",
                     dut->bin, KERNEL_HOPS) == 0 && tsapi_mde_sh_ok(&res))
        ok++;
    if (tsapi_mde_sh(session, 60000, &res, "'%s/rust-demo' 1 %d",
                     dut->bin, KERNEL_HOPS) == 0 && tsapi_mde_sh_ok(&res))
        ok++;
    if (tsapi_mde_sh(session, 60000, &res, "python3 '%s/demo.py' 1 %d",
                     dut->python, KERNEL_HOPS) == 0 && tsapi_mde_sh_ok(&res))
        ok++;

    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * Send @p n requests into the web tier, one after another, with curl.
 *
 * @param session   Session.
 * @param n         Number of requests.
 *
 * @return How many were answered with HTTP 200.
 */
static inline unsigned int
kernel_web_requests(tsapi_mde_session *session, unsigned int n)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    te_string           url = TE_STRING_INIT;
    unsigned int        ok = 0;
    const char         *p;

    if (n == 0)
        return 0;

    tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1, KERNEL_HOPS, &url);
    if (tsapi_mde_sh(session, 30000 + (int)n * 2000, &res,
                     "i=0; ok=0; while [ $i -lt %u ]; do "
                     "c=$(curl -s -o /dev/null -m 10 -w '%%{http_code}' "
                     "'%s'); [ \"$c\" = 200 ] && ok=$((ok+1)); "
                     "i=$((i+1)); done; echo \"answered=$ok\"",
                     n, url.ptr) == 0)
    {
        p = strstr(te_string_value(&res.out), "answered=");
        if (p != NULL)
            ok = (unsigned int)strtoul(p + strlen("answered="), NULL, 10);
    }

    te_string_free(&url);
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * Get the PID of the newest process with a given name (@c pgrep -n -x).
 *
 * @param[in]  session  Session.
 * @param[in]  name     Process name (comm).
 * @param[out] pid      PID.
 *
 * @return @c true if there is one.
 */
static inline bool
kernel_pid_of(tsapi_mde_session *session, const char *name,
              unsigned int *pid)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok = false;
    unsigned long       v;
    char               *end;

    if (tsapi_mde_sh(session, 10000, &res, "pgrep -n -x '%s'", name) == 0 &&
        tsapi_mde_sh_ok(&res))
    {
        v = strtoul(te_string_value(&res.out), &end, 10);
        if (end != te_string_value(&res.out) && v > 0)
        {
            *pid = (unsigned int)v;
            ok = true;
        }
    }

    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * Find how the kernel log can be read on the agent: plain @c dmesg when
 * @c dmesg_restrict allows it, @c "sudo -n dmesg" otherwise.
 *
 * @param session   Session.
 *
 * @return A static command prefix, or @c NULL when neither works (no
 *         CAP_SYSLOG in the container, no sudo).
 */
static inline const char *
kernel_dmesg_cmd(tsapi_mde_session *session)
{
    static const char  *cmds[] = { "dmesg", "sudo -n dmesg" };
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const char         *found = NULL;
    unsigned int        i;

    for (i = 0; i < TE_ARRAY_LEN(cmds) && found == NULL; i++)
    {
        if (tsapi_mde_sh(session, 20000, &res, "%s -r >/dev/null", cmds[i])
                == 0 && tsapi_mde_sh_ok(&res))
            found = cmds[i];
        else
            RING("'%s -r' cannot read the kernel log: %s", cmds[i],
                 te_string_value(&res.err));
    }

    tsapi_mde_sh_result_free(&res);

    return found;
}

#endif /* !__MDE_KERNEL_COMMON_H__ */

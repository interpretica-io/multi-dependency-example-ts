/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Exposure Group: helpers shared by the tests of the group
 *
 * Every test of the group compiles from a single .c file, so everything
 * here is static inline: a test that does not use a helper does not get
 * an unused-function warning for it.
 *
 * - waiting until the web tier answers on its contract ports (a service
 *   may announce its URL a moment before it binds);
 * - background processes on the agent: control listeners, load, held
 *   connections - started in their own session so that the job that
 *   started them can go away, and killed by pid;
 * - one walk through the web tier with the node steps counted;
 * - the non-loopback address of the agent, if it has one;
 * - a chart of several lines over a labelled index.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_EXPOSURE_COMMON_H__
#define __MDE_EXPOSURE_COMMON_H__

#include "te_config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_sockaddr.h"
#include "te_str.h"
#include "te_string.h"
#include "logger_api.h"
#include "te_mi_log.h"

#include "tapi_cybersec.h"
#include "tapi_netexpose.h"

#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"

/** First and last contract port of the web tier. */
#define EXPOSURE_WEB_FIRST  8081
#define EXPOSURE_WEB_LAST   8083

/** Whether a port belongs to the web tier. */
static inline bool
exposure_is_web_port(unsigned int port)
{
    return port >= EXPOSURE_WEB_FIRST && port <= EXPOSURE_WEB_LAST;
}

/**
 * Wait until every port of the web tier accepts a connection.
 *
 * @param session   Session.
 *
 * @return @c true if all three answered within about five seconds each.
 */
static inline bool
exposure_web_wait(tsapi_mde_session *session)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    ok = tsapi_mde_sh(session, 30000, &res,
                      "for p in 8081 8082 8083; do i=0; "
                      "until curl -s -o /dev/null -m 2 http://127.0.0.1:$p/; "
                      "do i=$((i+1)); [ $i -ge 50 ] && exit 1; sleep 0.1; "
                      "done; done; exit 0") == 0 && tsapi_mde_sh_ok(&res);
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * Start a command in the background on the agent, in a session of its
 * own, and return its pid.
 *
 * @param session   Session.
 * @param cmd       Command (a simple command: it is exec'ed by setsid).
 * @param pid       Its pid, @c 0 if it could not be started.
 *
 * @return @c true if it was started.
 */
static inline bool
exposure_spawn(tsapi_mde_session *session, const char *cmd,
               unsigned int *pid)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    *pid = 0;
    ok = tsapi_mde_sh(session, 20000, &res,
                      "setsid %s >/dev/null 2>&1 </dev/null & echo $!",
                      cmd) == 0 && tsapi_mde_sh_ok(&res);
    if (ok)
        *pid = (unsigned int)strtoul(te_string_value(&res.out), NULL, 10);
    tsapi_mde_sh_result_free(&res);

    return ok && *pid != 0;
}

/**
 * Kill a background process started by exposure_spawn().
 *
 * @param session   Session.
 * @param pid       Its pid; @c 0 does nothing.
 */
static inline void
exposure_kill(tsapi_mde_session *session, unsigned int pid)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;

    if (pid == 0)
        return;
    (void)tsapi_mde_sh(session, 10000, &res,
                       "kill %u 2>/dev/null; i=0; "
                       "while kill -0 %u 2>/dev/null && [ $i -lt 20 ]; "
                       "do i=$((i+1)); sleep 0.1; done; "
                       "kill -9 %u 2>/dev/null; true", pid, pid, pid);
    tsapi_mde_sh_result_free(&res);
}

/**
 * Start a throw-away HTTP listener on the agent and wait until it
 * accepts connections.
 *
 * @param session   Session.
 * @param port      Port.
 * @param bind      Address to bind, e.g. @c "0.0.0.0" or @c "127.0.0.1".
 * @param pid       Its pid, @c 0 if it is not up.
 *
 * @return @c true if it is listening.
 */
static inline bool
exposure_listener_start(tsapi_mde_session *session, unsigned int port,
                        const char *bind, unsigned int *pid)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    te_string           cmd = TE_STRING_INIT;
    bool                ok;

    te_string_append(&cmd, "python3 -m http.server %u --bind %s", port,
                     bind);
    if (!exposure_spawn(session, cmd.ptr, pid))
    {
        te_string_free(&cmd);
        return false;
    }
    te_string_free(&cmd);

    ok = tsapi_mde_sh(session, 20000, &res,
                      "i=0; until curl -s -o /dev/null -m 1 "
                      "http://127.0.0.1:%u/; do i=$((i+1)); "
                      "[ $i -ge 50 ] && exit 1; sleep 0.1; done",
                      port) == 0 && tsapi_mde_sh_ok(&res);
    tsapi_mde_sh_result_free(&res);

    if (!ok)
    {
        exposure_kill(session, *pid);
        *pid = 0;
    }

    return ok;
}

/** Count the node step lines of a web tier response body. */
static inline unsigned int
exposure_count_steps(const char *body)
{
    unsigned int n = 0;
    const char  *p = body;

    while (p != NULL && *p != '\0')
    {
        if (strncmp(p, "[gateway-rs] hops=", 18) == 0 ||
            strncmp(p, "[service-go] hops=", 18) == 0 ||
            strncmp(p, "[service-cs] hops=", 18) == 0)
            n++;
        p = strchr(p, '\n');
        if (p != NULL)
            p++;
    }

    return n;
}

/**
 * Send one walk into the web tier and count the node steps.
 *
 * @param[in]  session  Session.
 * @param[in]  port     Port to enter at.
 * @param[in]  hops     Hop budget.
 * @param[out] steps    Node steps the response reports.
 * @param[out] secs     How long the walk took.
 * @param[out] body     String to append the response body to, or @c NULL.
 *
 * @return @c true if the request was answered.
 */
static inline bool
exposure_walk(tsapi_mde_session *session, unsigned int port, int hops,
              unsigned int *steps, double *secs, te_string *body)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    te_string           url = TE_STRING_INIT;
    double              t0;
    bool                ok;

    tsapi_mde_web_url(port, 1, hops, &url);
    t0 = tsapi_mde_now();
    ok = tsapi_mde_sh(session, 60000, &res, "curl -s -m 30 '%s'",
                      url.ptr) == 0 && tsapi_mde_sh_ok(&res);
    *secs = tsapi_mde_now() - t0;
    *steps = exposure_count_steps(te_string_value(&res.out));
    if (body != NULL)
        te_string_append(body, "%s", te_string_value(&res.out));
    tsapi_mde_sh_result_free(&res);
    te_string_free(&url);

    return ok && *steps > 0;
}

/**
 * The first global IPv4 address of the agent.
 *
 * @param[in]  session  Session.
 * @param[out] addr     Address; untouched when there is none.
 * @param[out] text     String to append the address text to.
 *
 * @return @c true if the agent has one.
 */
static inline bool
exposure_host_addr(tsapi_mde_session *session, struct sockaddr_in *addr,
                   te_string *text)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    char                buf[INET_ADDRSTRLEN + 1] = "";
    bool                ok = false;

    if (tsapi_mde_sh(session, 10000, &res,
                     "a=$(ip -4 -o addr show scope global 2>/dev/null | "
                     "awk '{split($4, a, \"/\"); print a[1]; exit}'); "
                     "[ -n \"$a\" ] || a=$(hostname -I 2>/dev/null | "
                     "awk '{print $1}'); echo \"$a\"") == 0 &&
        tsapi_mde_sh_ok(&res) &&
        sscanf(te_string_value(&res.out), "%16s", buf) == 1)
    {
        memset(addr, 0, sizeof(*addr));
        addr->sin_family = AF_INET;
        if (inet_pton(AF_INET, buf, &addr->sin_addr) == 1 &&
            (ntohl(addr->sin_addr.s_addr) >> 24) != 127)
        {
            te_string_append(text, "%s", buf);
            ok = true;
        }
    }
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * Run a shell command on the agent and forget about its output.
 *
 * @param session   Session.
 * @param cmd       Command.
 *
 * @return @c true if it exited with 0.
 */
static inline bool
exposure_sh_quiet(tsapi_mde_session *session, const char *cmd)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    ok = tsapi_mde_sh(session, 60000, &res, "%s", cmd) == 0 &&
         tsapi_mde_sh_ok(&res);
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/** Port of a socket address, in host order. */
static inline unsigned int
exposure_port(const struct sockaddr_storage *ss)
{
    return ntohs(te_sockaddr_get_port(CONST_SA(ss)));
}

/** Whether a socket address is a loopback one. */
static inline bool
exposure_is_loopback(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;

        return (ntohl(sin->sin_addr.s_addr) >> 24) == 127;
    }
    if (ss->ss_family == AF_INET6)
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;

        return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
    }

    return false;
}

/** Whether a socket address is the wildcard one. */
static inline bool
exposure_is_wildcard(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;

        return sin->sin_addr.s_addr == htonl(INADDR_ANY);
    }
    if (ss->ss_family == AF_INET6)
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;

        return IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr);
    }

    return false;
}

/** Print the address (without the port) of a socket address. */
static inline void
exposure_addr_str(const struct sockaddr_storage *ss, te_string *dest)
{
    char buf[INET6_ADDRSTRLEN] = "?";

    if (ss->ss_family == AF_INET)
        inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr,
                  buf, sizeof(buf));
    else if (ss->ss_family == AF_INET6)
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)ss)->sin6_addr,
                  buf, sizeof(buf));
    te_string_append(dest, "%s", buf);
}

/** Options of the socket table reads of this group: TCP, both families. */
static inline tapi_netexpose_opt
exposure_tcp_opt(void)
{
    tapi_netexpose_opt opt = tapi_netexpose_default_opt;

    opt.udp = false;
    opt.tcp = true;

    return opt;
}

/**
 * Chart several lines over a labelled index, in one MI artifact.
 *
 * @param tool      Source label.
 * @param view      View id.
 * @param title     Caption.
 * @param n_x       Number of points on X.
 * @param x_labels  Labels of the points; they become keys @c x<i>.
 * @param n_y       Number of lines.
 * @param y_names   Names of the lines.
 * @param vals      Values, @p n_y rows of @p n_x values each.
 */
static inline void
exposure_mi_matrix(const char *tool, const char *view, const char *title,
                   size_t n_x, const char * const *x_labels,
                   size_t n_y, const char * const *y_names,
                   const double *vals)
{
    te_mi_logger *logger;
    char          key[16];
    size_t        i;
    size_t        j;

    if (n_x == 0 || n_y == 0 || tsapi_mde_mi_create(tool, &logger) != 0)
        return;

    for (i = 0; i < n_x; i++)
    {
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "index", TE_MI_MEAS_AGGR_SINGLE, (double)i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        for (j = 0; j < n_y; j++)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  y_names[j], TE_MI_MEAS_AGGR_SINGLE,
                                  vals[j * n_x + i],
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        TE_SPRINTF(key, "x%zu", i);
        te_mi_logger_add_meas_key(logger, NULL, key, "%s", x_labels[i]);
    }

    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               view, title);
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH, view,
                                          TE_MI_GRAPH_AXIS_X, "index");
    for (j = 0; j < n_y; j++)
    {
        te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                              TE_MI_MEAS_VIEW_LINE_GRAPH,
                                              view, TE_MI_GRAPH_AXIS_Y,
                                              y_names[j]);
    }

    te_mi_logger_destroy(logger);
}

/** Chart the time each service of the tier took to start. */
static inline void
exposure_chart_web_start(const tsapi_mde_web *web)
{
    const char  *labels[TSAPI_MDE_WEB_N];
    double       vals[TSAPI_MDE_WEB_N];
    unsigned int i;

    for (i = 0; i < web->n_started && i < TSAPI_MDE_WEB_N; i++)
    {
        labels[i] = web->svc[i].name;
        vals[i] = web->svc[i].start_s;
    }
    tsapi_mde_mi_bars("web", "Time each service took to announce its URL",
                      TE_MI_MEAS_TIME, "start", i, labels, vals,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
}

#endif /* !__MDE_EXPOSURE_COMMON_H__ */

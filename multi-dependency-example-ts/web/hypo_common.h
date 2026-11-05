/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Web group helpers of the hypothesis tests
 *
 * The tests that settle a hypothesis about the web tier (h1_*, h2_*)
 * stand in for a backend with a throw-away TCP listener on the agent,
 * bound to the loopback address the tier hardcodes. The listener is a
 * python3 one-liner that either accepts and answers garbage, accepts and
 * closes at once, or accepts and never answers. Every accepted connection
 * is counted in a file so the test can say whether the peer was reached at
 * all.
 *
 * Static inline only: each test is built from a single .c file.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __WEB_HYPO_COMMON_H__
#define __WEB_HYPO_COMMON_H__

#include "web_common.h"

/** What a fake peer does with an accepted connection. */
#define HYPO_PEER_GARBAGE   "garbage"
#define HYPO_PEER_CLOSE     "close"
#define HYPO_PEER_SILENT    "silent"

/** argv: mode port logfile. */
#define HYPO_PEER_PY \
    "import socketserver as S, sys, time; "                                 \
    "S.ThreadingTCPServer.allow_reuse_address = True; "                     \
    "S.ThreadingTCPServer.daemon_threads = True; "                          \
    "f = {\"garbage\": lambda s: s.request.sendall(b\"\\x00\\xffGARBAGE\\r\\n\"), " \
    "\"close\": lambda s: None, "                                           \
    "\"silent\": lambda s: time.sleep(3600)}[sys.argv[1]]; "                \
    "h = lambda s: (open(sys.argv[3], \"a\").write(\"c\\n\"), f(s)); "      \
    "S.ThreadingTCPServer((\"127.0.0.1\", int(sys.argv[2])), "              \
    "type(\"H\", (S.BaseRequestHandler,), {\"handle\": h})).serve_forever()"

/** Start a command in the background of the agent; its pid, 0 on failure. */
static inline bool
hypo_spawn(tsapi_mde_session *session, const char *cmd, unsigned int *pid)
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

/** Kill a process started by hypo_spawn(); 0 does nothing. */
static inline void
hypo_kill(tsapi_mde_session *session, unsigned int pid)
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
 * Start a fake peer on 127.0.0.1:@p port and wait until it accepts.
 *
 * @param session   Session.
 * @param mode      One of HYPO_PEER_*.
 * @param port      Port.
 * @param log       File on the agent that gets a line per connection.
 * @param pid       Its pid, 0 if it did not start.
 *
 * @return @c true if it is accepting connections.
 */
static inline bool
hypo_peer_start(tsapi_mde_session *session, const char *mode,
                unsigned int port, const char *log, unsigned int *pid)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    te_string           cmd = TE_STRING_INIT;
    bool                ok = false;

    if (!tsapi_mde_have(session, "python3"))
        return false;

    (void)tsapi_mde_sh(session, 10000, &res, "rm -f '%s'; : > '%s'", log, log);
    tsapi_mde_sh_result_free(&res);

    te_string_append(&cmd, "python3 -c '%s' %s %u '%s'", HYPO_PEER_PY, mode,
                     port, log);
    if (!hypo_spawn(session, cmd.ptr, pid))
        goto out;

    /* Probe without leaving a mark in the connection log. */
    ok = tsapi_mde_sh(session, 20000, &res,
                      "i=0; until python3 -c 'import socket, sys; "
                      "socket.create_connection((\"127.0.0.1\", "
                      "int(sys.argv[1])), 2)' %u 2>/dev/null; "
                      "do i=$((i+1)); [ $i -ge 50 ] && exit 1; sleep 0.1; "
                      "done; : > '%s'; exit 0", port, log) == 0 &&
         tsapi_mde_sh_ok(&res);
    tsapi_mde_sh_result_free(&res);

out:
    te_string_free(&cmd);
    return ok;
}

/** Number of connections a fake peer has accepted since it started. */
static inline unsigned int
hypo_peer_hits(tsapi_mde_session *session, const char *log)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    unsigned int        n = 0;

    if (tsapi_mde_sh(session, 10000, &res, "wc -l < '%s'", log) == 0 &&
        tsapi_mde_sh_ok(&res))
        n = (unsigned int)strtoul(te_string_value(&res.out), NULL, 10);
    tsapi_mde_sh_result_free(&res);

    return n;
}

/** Whether a status is 2xx. */
#define HYPO_IS_2XX(_code) ((_code) >= 200 && (_code) < 300)

#endif /* !__WEB_HYPO_COMMON_H__ */

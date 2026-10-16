/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Suite helpers
 *
 * Every test here needs the same things: an agent, an RPC server on it and a
 * job factory over that server, the location of the example under test, and a
 * way to run one of its programs and read back what it printed. This gathers
 * them in one place.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __TSAPI_MDE_H__
#define __TSAPI_MDE_H__

#include "te_config.h"
#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"
#include "tapi_job.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The agent this suite works on. */
#define TSAPI_MDE_TA   "Agt_A"

/** What a test needs to talk to the agent. */
typedef struct tsapi_mde_session {
    const char         *ta;      /**< Agent name. */
    rcf_rpc_server     *pco;     /**< RPC server on it. */
    tapi_job_factory_t *factory; /**< Job factory over that RPC server. */
} tsapi_mde_session;

/**
 * Open a session: an RPC server on the agent and a job factory over it.
 *
 * @param[out] session  Session.
 * @param[in]  name     Name for the RPC server, unique within the test.
 *
 * @return Status code.
 */
extern te_errno tsapi_mde_session_init(tsapi_mde_session *session,
                                       const char *name);

/**
 * Close a session.
 *
 * @param session       Session.
 */
extern void tsapi_mde_session_fini(tsapi_mde_session *session);

/**
 * Root of the example under test, from @c TE_TS_MDE_SRC.
 *
 * @return The path, or @c NULL if the variable is not set.
 */
extern const char *tsapi_mde_src(void);

/**
 * Whether a path exists on the agent (@c test -e).
 *
 * @param session       Session.
 * @param path          Absolute path on the agent.
 *
 * @return @c true if it exists.
 */
extern bool tsapi_mde_exists(tsapi_mde_session *session, const char *path);

/** What running a short-lived program told us. */
typedef struct tsapi_mde_run_result {
    bool              started;     /**< The process was started at all. */
    tapi_job_status_t status;      /**< Its exit status, if it ran. */
    unsigned int      match_count; /**< Lines that matched @p count_re. */
    bool              have_value;  /**< @p value_re matched at least once. */
    double            value;       /**< Last value extracted by @p value_re. */
} tsapi_mde_run_result;

/**
 * Run a short-lived program on the agent and read back what it printed.
 *
 * Two readable filters are attached to the program's stdout: one counts the
 * lines matching @p count_re, the other extracts group 1 of @p value_re as a
 * @c double (the last match wins). Either regexp may be @c NULL to skip it.
 * The program is expected to terminate on its own within @p timeout_ms.
 *
 * @param[in]  session    Session.
 * @param[in]  program    Absolute path or a name resolved through PATH.
 * @param[in]  argv       @c NULL-terminated argument vector (argv[0] included).
 * @param[in]  timeout_ms Grace period for the program to finish.
 * @param[in]  count_re   Line-counting regexp, or @c NULL.
 * @param[in]  value_re   Value-extraction regexp (group 1), or @c NULL.
 * @param[out] out        Result.
 *
 * @return Status code. A non-zero exit of the program is not an error here:
 *         it is reported through @p out so the caller decides what it means.
 */
extern te_errno tsapi_mde_run(tsapi_mde_session *session,
                              const char *program,
                              const char **argv,
                              int timeout_ms,
                              const char *count_re,
                              const char *value_re,
                              tsapi_mde_run_result *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__TSAPI_MDE_H__ */

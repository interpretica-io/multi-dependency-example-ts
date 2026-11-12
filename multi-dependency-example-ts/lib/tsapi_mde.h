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
#include <stdlib.h>
#include "te_compiler.h"
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

/** What running a command through the shell told us. */
typedef struct tsapi_mde_sh_result {
    bool              started;  /**< The shell was started at all. */
    tapi_job_status_t status;   /**< Its exit status, if it finished. */
    te_string         out;      /**< Everything it printed on stdout. */
    te_string         err;      /**< Everything it printed on stderr. */
} tsapi_mde_sh_result;

/** Static initializer for #tsapi_mde_sh_result. */
#define TSAPI_MDE_SH_RESULT_INIT \
    { .out = TE_STRING_INIT, .err = TE_STRING_INIT }

/**
 * Run a shell command on the agent and capture both output streams whole.
 *
 * For the checks that need the text rather than a count: a trace to parse
 * line by line, a listing to compare, a hash to keep as evidence.
 *
 * @param[in]  session    Session.
 * @param[in]  timeout_ms Grace period for the command to finish.
 * @param[out] res        Result; release with tsapi_mde_sh_result_free().
 * @param[in]  fmt        Command line format, run with @c "sh -c".
 * @param[in]  ...        Format arguments.
 *
 * @return Status code. A non-zero exit of the command is not an error here.
 */
extern te_errno tsapi_mde_sh(tsapi_mde_session *session, int timeout_ms,
                             tsapi_mde_sh_result *res, const char *fmt, ...)
    TE_LIKE_PRINTF(4, 5);

/**
 * Whether a shell command ran and exited with status 0.
 *
 * @param res   Result of tsapi_mde_sh().
 *
 * @return @c true on a clean exit.
 */
static inline bool
tsapi_mde_sh_ok(const tsapi_mde_sh_result *res)
{
    return res->started && res->status.type == TAPI_JOB_STATUS_EXITED &&
           res->status.value == 0;
}

/**
 * Release a shell result.
 *
 * @param res   Result.
 */
extern void tsapi_mde_sh_result_free(tsapi_mde_sh_result *res);

/**
 * Whether a program can be found through @c PATH on the agent.
 *
 * @param session   Session.
 * @param program   Program name.
 *
 * @return @c true if @c "command -v" finds it.
 */
extern bool tsapi_mde_have(tsapi_mde_session *session, const char *program);

/** Where the parts of the built example are. */
typedef struct tsapi_mde_dut {
    char *root;     /**< TE_TS_MDE_SRC. */
    char *bin;      /**< root/dist/bin. */
    char *lib;      /**< root/dist/lib. */
    char *python;   /**< root/python. */
    const char *dylib_ext; /**< "so" or "dylib", as the agent builds them. */
} tsapi_mde_dut;

/** The executables the example builds, under dist/bin. */
extern const char * const tsapi_mde_dut_bins[];
/** Number of entries in #tsapi_mde_dut_bins. */
extern const unsigned int tsapi_mde_dut_n_bins;
/** The ring libraries, without the extension, in build order. */
extern const char * const tsapi_mde_dut_libs[];
/** Number of entries in #tsapi_mde_dut_libs. */
extern const unsigned int tsapi_mde_dut_n_libs;

/**
 * Locate the built example on the agent.
 *
 * @param[in]  session  Session.
 * @param[out] dut      Paths; release with tsapi_mde_dut_free().
 *
 * @return Status code.
 * @retval TE_ENOENT    TE_TS_MDE_SRC is unset, or the example is not built
 *                      there (the caller skips).
 */
extern te_errno tsapi_mde_dut_open(tsapi_mde_session *session,
                                   tsapi_mde_dut *dut);

/**
 * Full path to a library of the ring.
 *
 * @param dut       Example.
 * @param name      Library name without the extension, e.g. @c "libcppcore".
 * @param path      String to append the path to.
 */
extern void tsapi_mde_dut_lib_path(const tsapi_mde_dut *dut, const char *name,
                                   te_string *path);

/**
 * Release what tsapi_mde_dut_open() allocated.
 *
 * @param dut       Example.
 */
extern void tsapi_mde_dut_free(tsapi_mde_dut *dut);

/**
 * Open a session and locate the example, or skip the test.
 *
 * The opening of almost every test of the suite.
 *
 * @param _session  Session variable.
 * @param _name     RPC server name.
 * @param _dut      Example variable.
 * @param _up       Boolean set once the session needs closing.
 */
#define TSAPI_MDE_OPEN_OR_SKIP(_session, _name, _dut, _up) \
    do {                                                                  \
        te_errno rc_ = tsapi_mde_session_init(&(_session), (_name));      \
                                                                          \
        if (rc_ != 0)                                                     \
            TEST_FAIL("Cannot open a session on the agent: %r", rc_);     \
        (_up) = true;                                                     \
        rc_ = tsapi_mde_dut_open(&(_session), &(_dut));                   \
        if (TE_RC_GET_ERROR(rc_) == TE_ENOENT)                            \
            TEST_VERDICT("The example is not built in TE_TS_MDE_SRC "     \
                         "although the suite prologue builds it");        \
        if (rc_ != 0)                                                     \
            TEST_FAIL("Cannot locate the example: %r", rc_);              \
    } while (0)

/**
 * Install what a group needs on the agent through
 * scripts/ensure-web-deps.sh and fail the prologue, with the script's own
 * message, when something is still missing afterwards.
 *
 * @param _session      Open session.
 * @param _components   Space separated components of the script: base,
 *                      build, exposure, fuzz, browser or all.
 */
#define TSAPI_MDE_ENSURE(_session, _components) \
    do {                                                                  \
        tsapi_mde_sh_result ens_ = TSAPI_MDE_SH_RESULT_INIT;              \
        const char *top_ = getenv("TS_TOPDIR");                           \
        const char *src_ = tsapi_mde_src();                               \
        te_errno    erc_;                                                 \
                                                                          \
        if (top_ == NULL || top_[0] == '\0' || src_ == NULL)              \
            TEST_FAIL("TS_TOPDIR or TE_TS_MDE_SRC is not set: cannot "    \
                      "run scripts/ensure-web-deps.sh");                  \
        erc_ = tsapi_mde_sh(&(_session), 3000000, &ens_,                  \
                            "'%s/scripts/ensure-web-deps.sh' '%s' %s",    \
                            top_, src_, (_components));                   \
        if (erc_ != 0 || !tsapi_mde_sh_ok(&ens_))                         \
        {                                                                 \
            ERROR("install of '%s' failed: %s", (_components),            \
                  ens_.err.ptr != NULL ? ens_.err.ptr : "(no output)");   \
            TEST_VERDICT("Cannot install what %s needs on the agent: %s", \
                         (_components), ens_.err.ptr != NULL &&           \
                         ens_.err.ptr[0] != '\0' ? ens_.err.ptr :         \
                         "the install script did not run");               \
        }                                                                 \
        RING("ensure-web-deps %s: %s", (_components),                     \
             ens_.out.ptr != NULL ? ens_.out.ptr : "ready");              \
        tsapi_mde_sh_result_free(&ens_);                                  \
    } while (0)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__TSAPI_MDE_H__ */

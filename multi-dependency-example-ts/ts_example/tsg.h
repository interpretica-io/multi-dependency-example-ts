/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: helpers of the guess, serve and upstream-error tests
 *
 * Every program is started on the agent through tapi_job, with RING_HOST and
 * RING_PORT in its environment. Static inline only.
 *
 * @author midair <midair@localhost>
 */

#ifndef MDE_TSG_H
#define MDE_TSG_H

#include "tsj.h"

#define TSG_ENV "RING_HOST=127.0.0.1 RING_PORT=9100"

/** Run `./scripts/run.sh guess <args>` in the project with @p env set. */
static inline te_errno
tsg_guess(tsapi_mde_session *s, const char *root, const char *env,
          const char *args, int tmo_s, tsapi_mde_sh_result *res)
{
    return tsapi_mde_sh(s, tmo_s * 1000, res,
                        "cd '%s' && env %s timeout %d ./scripts/run.sh guess "
                        "%s", root, env, tmo_s - 5, args);
}

/** Number of stage lines of a demo output. */
static inline int
tsg_stages(const char *out)
{
    int         n = 0;
    const char *p = out;

    while ((p = strstr(p, "] hops=")) != NULL)
    {
        n++;
        p += 7;
    }
    return n;
}

/** Whether the demo output ends with "result = <want>". */
static inline bool
tsg_last_value_is(const char *out, const char *want)
{
    const char *p = strstr(out, "result = ");
    size_t      n = strlen(want);

    return p != NULL && strncmp(p + 9, want, n) == 0 &&
           (p[9 + n] == '\n' || p[9 + n] == '\0');
}

/** Record one result as an artifact: exit code and the end of the output. */
static inline void
tsg_art(const char *id, const char *what, const tsapi_mde_sh_result *r)
{
    char cut[301];
    char one[301];
    size_t i;

    tsj_cut(cut, sizeof(cut), tsj_last_lines(web_str(&r->out), 2));
    for (i = 0; cut[i] != '\0'; i++)
        one[i] = cut[i] == '\n' ? '|' : cut[i];
    one[i] = '\0';
    TEST_ARTIFACT("%s %s: exit %d, stdout end [%s]", id, what,
                  r->status.type == TAPI_JOB_STATUS_EXITED ?
                  r->status.value : -1, one);
    tsj_cut(cut, sizeof(cut), tsj_last_lines(web_str(&r->err), 2));
    for (i = 0; cut[i] != '\0'; i++)
        one[i] = cut[i] == '\n' ? '|' : cut[i];
    one[i] = '\0';
    TEST_ARTIFACT("%s %s: stderr end [%s]", id, what, one);
}

/** Exit code of a finished command, -1 when it did not exit. */
static inline int
tsg_code(const tsapi_mde_sh_result *r)
{
    return r->started && r->status.type == TAPI_JOB_STATUS_EXITED ?
           (int)r->status.value : -1;
}

/** Skip the test when node is missing; the setup script installs it. */
#define TSG_NEED_NODE(_s) \
    do {                                                                \
        if (!tsapi_mde_have(&(_s), "node"))                             \
            TEST_SKIP("node is not on the agent: scripts/midair-setup.sh "\
                      "could not install it");                          \
    } while (0)

#endif /* MDE_TSG_H */

/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: smoke test for the C++ artifact (cpp-demo)
 *
 * Runs dist/bin/cpp-demo once with a valid input, as a defined example of
 * running the C++ build artifact. Settles no hypothesis.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/s_cpp"

#include "te_config.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "te_sockaddr.h"
#include "tsapi_mde.h"

#include "webdeps_lib.h"

#define RUN_TO  30  /**< s, grace period for the one-shot demo. */

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_SETUP };
    char     path[512];
    char     code[32];
    char     tail[400];
    char    *dargv[4];
    proc_t  *p;

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    snprintf(path, sizeof(path), "%s/dist/bin/cpp-demo", src_root);
    dargv[0] = path;
    dargv[1] = (char *)"1";
    dargv[2] = (char *)"1";
    dargv[3] = NULL;

    TEST_STEP("Run cpp-demo 1 1 once");
    p = run_once(&res, "cpp-demo", path, dargv, RUN_TO);
    if (p == NULL)
        goto verdict;

    exit_code_str(p, code, sizeof(code));
    file_tail(p->out, tail, sizeof(tail));
    if (!WIFEXITED(p->status) || WEXITSTATUS(p->status) != 0)
    {
        res_set(&res, R_FAIL, "s_cpp: cpp-demo exited with code %s instead "
                "of 0; stdout: [%s]", code, tail);
        goto verdict;
    }
    if (!file_has(p->out, "result ="))
    {
        res_set(&res, R_FAIL, "s_cpp: cpp-demo exited 0 but its output "
                "has no \"result =\": [%s]", tail);
        goto verdict;
    }
    res_set(&res, R_PASS, "s_cpp: cpp-demo 1 1 exited 0 and printed a "
            "result; tail: [%s]", tail);

verdict:
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}

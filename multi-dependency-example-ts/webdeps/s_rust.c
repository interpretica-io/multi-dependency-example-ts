/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: smoke test for the Rust artifact (gateway-rs)
 *
 * Starts gateway-rs and sends it one valid request, as a defined example
 * of running the Rust build artifact. Settles no hypothesis.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/s_rust"

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

int
main(int argc, char **argv)
{
    res_t res = { .kind = R_SETUP };

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Start gateway-rs and send one valid request");
    smoke_service(&res, "s_rust", GW);

verdict:
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}

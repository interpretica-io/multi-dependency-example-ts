/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H1, bad input to gateway-rs
 *
 * Start gateway-rs, send an empty body, a 64 KB header line, invalid UTF-8
 * in the path and a negative Content-Length, each on its own connection,
 * and after each one a valid request on a new connection. H1 is proven
 * (the test fails) if the process exits or a valid request gets no reply.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t_h1_gateway_bad_input"

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

#define BIG_LINE    (64u * 1024)

int
main(int argc, char **argv)
{
    static const char empty[] = "";
    static const char bad_utf8[] =
        "GET /\xff\xfe\xc0\x80\xed\xa0\x80 HTTP/1.1\r\nHost: x\r\n\r\n";
    static const char neg_len[] =
        "POST /ring HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n";
    static const char head[] = "GET /ring HTTP/1.1\r\nHost: x\r\nX-Big: ";
    static const char tail[] = "\r\n\r\n";
    struct {
        const char *name;
        const char *data;
        size_t      len;
        bool        half_close;
    } reqs[] = {
        { "empty body", empty, 0, true },
        { "64 KB header line", NULL, 0, false },
        { "invalid UTF-8 in the path", bad_utf8, sizeof(bad_utf8) - 1,
          false },
        { "negative Content-Length", neg_len, sizeof(neg_len) - 1, false },
    };
    res_t    res = { .kind = R_SETUP };
    proc_t  *gw;
    char    *big = NULL;
    char     seen[900] = "";
    unsigned i;

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Start gateway-rs and wait for its port");
    gw = svc_start(&res, GW);
    if (gw == NULL)
        goto verdict;

    big = malloc(sizeof(head) - 1 + BIG_LINE + sizeof(tail));
    if (big == NULL)
    {
        res_set(&res, R_SETUP, "no memory for the header line");
        goto verdict;
    }
    memcpy(big, head, sizeof(head) - 1);
    memset(big + sizeof(head) - 1, 'A', BIG_LINE);
    memcpy(big + sizeof(head) - 1 + BIG_LINE, tail, sizeof(tail));
    reqs[1].data = big;
    reqs[1].len = sizeof(head) - 1 + BIG_LINE + sizeof(tail) - 1;

    for (i = 0; i < sizeof(reqs) / sizeof(reqs[0]); i++)
    {
        hg_res h;

        TEST_STEP("Send: %s; then a valid request", reqs[i].name);
        send_once(gw->port, reqs[i].data, reqs[i].len, reqs[i].half_close,
                  500);
        http_get(gw->port, REQUEST, PROBE_TO, &h);
        if (proc_gone(gw))
        {
            char why[900];
            char last[300];

            proc_describe(gw, why, sizeof(why));
            last_line(gw->err, last, sizeof(last));
            gw->stopped = true;
            res_set(&res, R_FAIL, "t_h1_gateway_bad_input H1:proven: "
                    "gateway-rs exited after '%s'; %s; last stderr line: "
                    "[%s]; earlier: %s", reqs[i].name, why, last, seen);
            goto verdict;
        }
        if (h.how != HG_OK)
        {
            res_set(&res, R_FAIL, "t_h1_gateway_bad_input H1:proven: the "
                    "valid request after '%s' got no reply (%s); gateway-rs "
                    "is still running; earlier: %s", reqs[i].name,
                    hg_str(h.how), seen);
            goto verdict;
        }
        append(seen, sizeof(seen), "%s -> valid request HTTP %d; ",
               reqs[i].name, h.status);
    }
    res_set(&res, R_PASS, "t_h1_gateway_bad_input H1:disproved for these "
            "inputs: gateway-rs stayed up and answered every valid request: "
            "%s", seen);

verdict:
    free(big);
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}

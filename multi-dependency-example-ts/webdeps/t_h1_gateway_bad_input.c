/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H1, bad input to gateway-rs
 *
 * Start gateway-rs. On three separate connections send an empty body, a
 * 64 KiB header and a body carrying the invalid UTF-8 bytes 0xff 0xfe;
 * after each one, a valid request on a new connection. H1 is proven (the
 * test fails) if the process exits or a valid request gets no reply.
 * Disproving H1 additionally records whether the gateway answered every
 * bad request itself with 4xx, which the verdict names but does not
 * fail on: the hypothesis is about a reachable panic, not about status
 * codes.
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

/** Send bytes on a fresh connection and read back the HTTP status, if any. */
static int
send_bad(unsigned port, const char *data, size_t len, bool half_close,
        int wait_ms)
{
    struct timeval tv = { .tv_sec = 3 };
    char           buf[4096];
    char           got[512] = "";
    size_t         gotn = 0;
    double         end = now_s() + wait_ms / 1000.0;
    int            s = connect_loop(port);
    size_t         sent = 0;
    int            status = -1;

    if (s < 0)
        return -1;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    while (sent < len)
    {
        ssize_t w = write(s, data + sent, len - sent);

        if (w <= 0)
            break;
        sent += w;
    }
    if (half_close)
        shutdown(s, SHUT_WR);
    for (;;)
    {
        struct pollfd pfd = { .fd = s, .events = POLLIN };
        double        left = end - now_s();
        ssize_t       n;

        if (left <= 0 || poll(&pfd, 1, (int)(left * 1000) + 1) <= 0)
            break;
        n = read(s, buf, sizeof(buf));
        if (n <= 0)
            break;
        if (gotn < sizeof(got) - 1)
        {
            size_t c = sizeof(got) - 1 - gotn;

            memcpy(got + gotn, buf, (size_t)n < c ? (size_t)n : c);
            gotn += (size_t)n < c ? (size_t)n : c;
            got[gotn] = '\0';
        }
        if (sscanf(got, "HTTP/%*s %d", &status) == 1)
            break;
    }
    close(s);
    return status;
}

int
main(int argc, char **argv)
{
    static const char empty[] = "";
    static const char bad_utf8[] =
        "POST /ring HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n"
        "\xff\xfe";
    static const char head[] = "GET /ring HTTP/1.1\r\nHost: x\r\nX-Big: ";
    static const char tail[] = "\r\n\r\n";
    struct {
        const char *name;
        const char *data;
        size_t      len;
        bool        half_close;
    } reqs[] = {
        { "empty body", empty, 0, true },
        { "64 KiB header", NULL, 0, false },
        { "body with invalid UTF-8 (0xff 0xfe)", bad_utf8,
          sizeof(bad_utf8) - 1, false },
    };
    res_t    res = { .kind = R_SETUP };
    proc_t  *gw;
    char    *big = NULL;
    char     seen[900] = "";
    unsigned n_4xx = 0;
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
        int    bad_status;

        TEST_STEP("Send: %s; then a valid request", reqs[i].name);
        bad_status = send_bad(gw->port, reqs[i].data, reqs[i].len,
                              reqs[i].half_close, 500);
        http_get(gw->port, REQUEST, PROBE_TO, &h);
        if (proc_gone(gw))
        {
            char why[900];
            char last[300];
            char code[32];

            proc_describe(gw, why, sizeof(why));
            last_line(gw->err, last, sizeof(last));
            exit_code_str(gw, code, sizeof(code));
            gw->stopped = true;
            res_set(&res, R_FAIL, "t_h1_gateway_bad_input H1:proven: "
                    "gateway-rs exited (exit code %s) after '%s'; %s; last "
                    "stderr line: [%s]; earlier: %s", code, reqs[i].name,
                    why, last, seen);
            goto verdict;
        }
        if (h.how != HG_OK)
        {
            res_set(&res, R_FAIL, "t_h1_gateway_bad_input H1:proven: the "
                    "valid request after '%s' got no reply (%s); gateway-rs "
                    "is still running (no exit code); earlier: %s",
                    reqs[i].name, hg_str(h.how), seen);
            goto verdict;
        }
        if (bad_status >= 400 && bad_status < 500)
            n_4xx++;
        if (bad_status < 0)
            append(seen, sizeof(seen), "%s -> bad request got no reply, "
                   "valid request HTTP %d; ", reqs[i].name, h.status);
        else
            append(seen, sizeof(seen), "%s -> bad request HTTP %d, valid "
                   "request HTTP %d; ", reqs[i].name, bad_status, h.status);
    }
    res_set(&res, R_PASS, "t_h1_gateway_bad_input H1:disproved: gateway-rs "
            "stayed up (no exit code) and answered every valid request; "
            "%u/%zu bad requests got 4xx: %s", n_4xx,
            sizeof(reqs) / sizeof(reqs[0]), seen);

verdict:
    free(big);
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}

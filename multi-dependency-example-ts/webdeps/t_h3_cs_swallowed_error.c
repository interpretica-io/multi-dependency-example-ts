/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H3, service-cs and a failed backend call
 *
 * Start service-cs with its backend (gateway-rs, from the contract) not
 * running, so its port is closed, and send the request that reaches the
 * handler of the backend call. H3 is proven (the test fails) if the status
 * is 2xx. As a control the backend is started and the same request must
 * give a 2xx.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t_h3_cs_swallowed_error"

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

/** Body as one short line. */
static void
flat(const char *body, char *out, size_t size)
{
    const char *p = strstr(body, "\r\n\r\n");
    size_t      i;

    snprintf(out, size, "%s", p != NULL ? p + 4 : body);
    for (i = 0; out[i] != '\0'; i++)
    {
        if (out[i] == '\n' || out[i] == '\r')
            out[i] = '|';
    }
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_SETUP };
    proc_t  *cs;
    proc_t  *gw;
    hg_res   down;
    hg_res   control;
    char     down_body[400];
    char     ctl_body[400];

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Check that the backend port %u is closed", tab_port[GW]);
    if (port_accepts(tab_port[GW]))
    {
        setup_svc = names[GW];
        res_set(&res, R_SETUP, "127.0.0.1:%u is open before the start, the "
                "backend cannot be made unreachable", tab_port[GW]);
        goto verdict;
    }

    TEST_STEP("Start service-cs and wait for its port");
    cs = svc_start(&res, CS);
    if (cs == NULL)
        goto verdict;

    TEST_STEP("GET %s with the backend unreachable", REQUEST);
    http_get(cs->port, REQUEST, PROBE_TO + 2, &down);
    if (down.how != HG_OK)
    {
        res_set(&res, R_FAIL, "t_h3_cs_swallowed_error H3:not-settled: no "
                "HTTP reply from service-cs with the backend down (%s)",
                hg_str(down.how));
        goto verdict;
    }
    flat(down.body, down_body, sizeof(down_body));

    TEST_STEP("Control: start gateway-rs, same request, require 2xx");
    gw = svc_start(&res, GW);
    if (gw == NULL)
        goto verdict;
    http_get(cs->port, REQUEST, PROBE_TO + 2, &control);
    flat(control.body, ctl_body, sizeof(ctl_body));
    if (control.how != HG_OK || control.status < 200 || control.status > 299)
    {
        setup_svc = names[CS];
        res_set(&res, R_SETUP, "control request with the backend up gave "
                "%s, HTTP %d, not a 2xx; the failure case proves nothing",
                hg_str(control.how), control.status);
        goto verdict;
    }

    if (down.status >= 200 && down.status < 300)
        res_set(&res, R_FAIL, "t_h3_cs_swallowed_error H3:proven: service-cs "
                "answered HTTP %d with its backend unreachable, body [%s]; "
                "control with the backend up: HTTP %d", down.status,
                down_body, control.status);
    else
        res_set(&res, R_PASS, "t_h3_cs_swallowed_error H3:disproved: "
                "service-cs answered HTTP %d with its backend unreachable, "
                "body [%s]; control with the backend up: HTTP %d",
                down.status, down_body, control.status);

verdict:
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}

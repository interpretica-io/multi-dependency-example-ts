/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H3, service-cs and an invalid payload
 *
 * Start service-cs, read its port with tapi_netexpose and send a request
 * that must fail: a non-numeric value and hops. H3 is proven (the test
 * fails) if the status is 200 (any 2xx); the test passes only on 4xx or
 * 5xx. The status and the body are recorded.
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

#define BAD_REQUEST "/ring?value=not-a-number&hops=%7B%22x%22%3A"

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_SETUP };
    proc_t  *cs;
    tsapi_mde_session session = { .ta = NULL };
    hg_res   bad;
    char     body[400];

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Start service-cs and read its port with tapi_netexpose");
    if (tsapi_mde_session_init(&session, "t_h3") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for tapi_netexpose");
        goto verdict;
    }
    cs = svc_start_exposed(&res, &session, CS);
    if (cs == NULL)
        goto verdict;

    TEST_STEP("GET %s, an invalid payload", BAD_REQUEST);
    http_get(cs->port, BAD_REQUEST, PROBE_TO + 2, &bad);
    if (bad.how != HG_OK)
    {
        res_set(&res, R_FAIL, "t_h3_cs_swallowed_error H3:not-settled: no "
                "HTTP reply from service-cs to the invalid payload (%s)",
                hg_str(bad.how));
        goto verdict;
    }
    flat(bad.body, body, sizeof(body));
    RING("webdeps: service-cs answered HTTP %d to %s, body [%s]", bad.status,
         BAD_REQUEST, body);

    if (bad.status >= 400 && bad.status <= 599)
        res_set(&res, R_PASS, "t_h3_cs_swallowed_error H3:disproved: "
                "service-cs answered HTTP %d to the invalid payload, body "
                "[%s]", bad.status, body);
    else
        res_set(&res, R_FAIL, "t_h3_cs_swallowed_error H3:proven: "
                "service-cs answered HTTP %d, not 4xx/5xx, to the invalid "
                "payload, body [%s]", bad.status, body);

verdict:
    tsapi_mde_session_fini(&session);
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}

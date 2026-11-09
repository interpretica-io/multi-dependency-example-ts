/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H5, contract limits of service-go
 *
 * Start service-go, read its port with tapi_netexpose and send messages
 * at the limits of the /ring contract: an empty value, a value of the
 * maximum length (64 characters, a valid number), the maximum plus one
 * (65 characters) and values of the wrong type. H5 is proven (the test
 * fails) if any invalid message gets a success (2xx) reply. The status of
 * every message is recorded.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t_h5_go_contract_limits"

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

#define MAX_LEN     64      /**< Longest value the contract allows. */

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_SETUP };
    proc_t  *go;
    tsapi_mde_session session = { .ta = NULL };
    char     max_msg[MAX_LEN + 1];
    char     over_msg[MAX_LEN + 2];
    struct {
        const char *name;
        const char *query;
        bool        valid;
    } msgs[] = {
        { "empty", "value=&hops=1", false },
        { "maximum length", NULL, true },
        { "maximum plus one", NULL, false },
        { "wrong type value", "value=abc&hops=1", false },
        { "wrong type hops", "value=1&hops=x", false },
    };
    char     paths[sizeof(msgs) / sizeof(msgs[0])][160];
    char     seen[900] = "";
    char     bad[400] = "";
    unsigned i;

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    memset(max_msg, '1', MAX_LEN);
    max_msg[MAX_LEN] = '\0';
    memset(over_msg, '1', MAX_LEN + 1);
    over_msg[MAX_LEN + 1] = '\0';

    TEST_STEP("Start service-go and read its port with tapi_netexpose");
    if (tsapi_mde_session_init(&session, "t_h5") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for tapi_netexpose");
        goto verdict;
    }
    go = svc_start_exposed(&res, &session, GO);
    if (go == NULL)
        goto verdict;

    for (i = 0; i < sizeof(msgs) / sizeof(msgs[0]); i++)
    {
        hg_res h;

        if (i == 1)
            snprintf(paths[i], sizeof(paths[i]), "/ring?value=%s&hops=1",
                     max_msg);
        else if (i == 2)
            snprintf(paths[i], sizeof(paths[i]), "/ring?value=%s&hops=1",
                     over_msg);
        else
            snprintf(paths[i], sizeof(paths[i]), "/ring?%s", msgs[i].query);

        TEST_STEP("Send: %s", msgs[i].name);
        http_get(go->port, paths[i], PROBE_TO, &h);
        if (proc_gone(go))
        {
            char why[900];

            proc_describe(go, why, sizeof(why));
            go->stopped = true;
            res_set(&res, R_SETUP, "service-go died on '%s': %s",
                    msgs[i].name, why);
            goto verdict;
        }
        RING("webdeps: %s -> %s, HTTP %d", msgs[i].name,
             h.how == HG_OK ? "answered" : hg_str(h.how), h.status);
        append(seen, sizeof(seen), "%s -> HTTP %d; ", msgs[i].name,
               h.status);
        if (!msgs[i].valid && h.how == HG_OK && h.status >= 200 &&
            h.status < 300)
            append(bad, sizeof(bad), "%s%s", bad[0] != '\0' ? ", " : "",
                   msgs[i].name);
    }

    if (bad[0] != '\0')
        res_set(&res, R_FAIL, "t_h5_go_contract_limits H5:proven: "
                "service-go gave a success reply to invalid message(s): "
                "%s; statuses: %s", bad, seen);
    else
        res_set(&res, R_PASS, "t_h5_go_contract_limits H5:disproved: "
                "service-go rejected every invalid message; statuses: %s",
                seen);

verdict:
    tsapi_mde_session_fini(&session);
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}

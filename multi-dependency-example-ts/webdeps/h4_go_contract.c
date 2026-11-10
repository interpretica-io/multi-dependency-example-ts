/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H4, the contract of service-go
 *
 * The contract check in contract.go accepts a row only if it has five
 * columns and its port column parses as an integer (the checks at
 * contract.go:49 and :53, after the open at :33). Its message form for
 * /ring is: value is a number and hops is an integer. Start service-go
 * (its port is read with tapi_netexpose) and send one message that follows
 * that contract (value=1, hops=1) and one that breaks it by the same
 * condition (value=abc, hops=x, neither parses).
 *
 * H4 FAIL if the broken message gets a success (2xx) reply; H4 PASS if it
 * is rejected. Both replies are in the verdict.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/h4_go_contract"

#include "te_config.h"

#include "webdeps_lib.h"

#define VALID_MSG   "/ring?value=1&hops=1"
#define BROKEN_MSG  "/ring?value=abc&hops=x"

/** Reply as status and the first body lines on one short line. */
static void
reply_str(const hg_res *h, char *out, size_t size)
{
    const char *p = strstr(h->body, "\r\n\r\n");
    size_t      i;
    char        flat[300];

    snprintf(flat, sizeof(flat), "%.299s", p != NULL ? p + 4 : h->body);
    for (i = 0; flat[i] != '\0'; i++)
    {
        if (flat[i] == '\n' || flat[i] == '\r')
            flat[i] = '|';
    }
    snprintf(out, size, "HTTP %d [%s]", h->status, flat);
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_SETUP };
    proc_t  *go;
    tsapi_mde_session session = { .ta = NULL };
    hg_res   valid;
    hg_res   broken;
    char     vstr[400];
    char     bstr[400];

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Start service-go and read its port with tapi_netexpose");
    if (tsapi_mde_session_init(&session, "h4") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for tapi_netexpose");
        goto verdict;
    }
    go = svc_start_exposed(&res, &session, GO);
    if (go == NULL)
        goto verdict;

    TEST_STEP("Send the message that follows the contract: %s", VALID_MSG);
    http_get(go->port, VALID_MSG, PROBE_TO, &valid);
    TEST_STEP("Send the message that breaks it: %s", BROKEN_MSG);
    http_get(go->port, BROKEN_MSG, PROBE_TO, &broken);

    if (valid.how != HG_OK || broken.how != HG_OK)
    {
        setup_svc = "service-go";
        res_set(&res, R_SETUP, "no HTTP reply (valid message: %s, broken "
                "message: %s)", hg_str(valid.how), hg_str(broken.how));
        goto verdict;
    }
    reply_str(&valid, vstr, sizeof(vstr));
    reply_str(&broken, bstr, sizeof(bstr));
    RING("webdeps: service-go valid message -> %s; broken message -> %s",
         vstr, bstr);

    if (broken.status >= 200 && broken.status < 300)
        res_set(&res, R_FAIL, "H4 FAIL: service-go accepted the broken "
                "message with a success reply; valid message %s -> %s; "
                "broken message %s -> %s", VALID_MSG, vstr, BROKEN_MSG,
                bstr);
    else
        res_set(&res, R_PASS, "H4 PASS: service-go rejected the broken "
                "message; valid message %s -> %s; broken message %s -> %s",
                VALID_MSG, vstr, BROKEN_MSG, bstr);

verdict:
    tsapi_mde_session_fini(&session);
    HYP_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}

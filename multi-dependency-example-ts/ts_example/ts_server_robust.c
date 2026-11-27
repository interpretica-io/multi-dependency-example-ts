/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_server_robust, a malformed request and SIGTERM
 *        (settles H4)
 *
 * Starts the ts server (`guess serve`) as a job, sends a malformed HTTP
 * request line on a raw socket and expects 400 and a live server, checks
 * with tapi_netexpose that the listener is on loopback (a finding goes to a
 * tapi_cybersec_report that fails the test), then sends SIGTERM and expects
 * exit 0. Control: the status parser rejects planted replies.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_server_robust"

#include <arpa/inet.h>
#include <signal.h>
#include "tsg.h"
#include "tapi_cybersec.h"
#include "tapi_netexpose.h"
#include "te_sockaddr.h"

/** Status code of a raw HTTP reply; 0 when it is not one. */
static int
raw_status(const char *text)
{
    if (strncmp(text, "HTTP/1.", 7) != 0 || text[8] != ' ')
        return 0;
    return atoi(text + 9);
}

int
main(int argc, char **argv)
{
    tsapi_mde_session       session;
    bool                    up = false;
    tsj_svc                 svc = { .job = NULL };
    tsapi_mde_sh_result     res = TSAPI_MDE_SH_RESULT_INIT;
    web_reply               reply = WEB_REPLY_INIT;
    tapi_cybersec_report    cyber;
    bool                    cyber_up = false;
    tapi_netexpose_opt      opt = tapi_netexpose_default_opt;
    te_vec                  socks;
    bool                    socks_up = false;
    const tapi_netexpose_socket *sock;
    tapi_job_status_t       st;
    char                    cmd[500];
    char                    url[200];
    const char             *root;
    unsigned int            port;
    int                     code;
    int                     n_find = 0;
    bool                    seen = false;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_server_robust"));
    up = true;
    tapi_cybersec_report_init(&cyber);
    cyber_up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H4 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the status parser rejects planted replies");
    if (raw_status("HTTP/1.1 400 Bad Request\r\n") != 400 ||
        raw_status("HTTP/1.1 200 OK\r\n") == 400 ||
        raw_status("garbage") != 0 || raw_status("") != 0)
        TEST_VERDICT("H4 NOT SETTLED: the status parser is wrong");

    TSG_NEED_NODE(session);
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("python3 is not on the agent: scripts/midair-setup.sh "
                  "could not install it");

    TEST_STEP("Start the ts server");
    port = tsj_free_port(&session);
    if (port == 0)
        TEST_VERDICT("H4 NOT SETTLED: no free port on the agent");
    snprintf(cmd, sizeof(cmd), "cd '%s' && RING_HOST=127.0.0.1 RING_PORT=%u "
             "exec ./scripts/run.sh guess serve", root, port);
    CHECK_RC(tsj_start(&session, "guess-serve", cmd, port, &svc));
    if (!tsj_wait_port(&session, &svc, 600))
        TEST_VERDICT("H4 FAILED: the ts server did not open its port");

    TEST_STEP("Known-good control: a valid request answers 200");
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring?value=1&hops=0",
             port);
    CHECK_RC(web_get(&session, "", url, 5, &reply));
    if (reply.code != 200)
        TEST_VERDICT("H4 NOT SETTLED: a valid request did not answer 200, "
                     "so a 400 proves nothing");

    TEST_STEP("Send a malformed request line on a raw socket");
    CHECK_RC(tsapi_mde_sh(&session, 30000, &res,
                          "python3 -c \"import socket;"
                          "s=socket.create_connection(('127.0.0.1',%u),5);"
                          "s.sendall(b'BAD\\x01 REQ\\r\\n\\r\\n');"
                          "print(s.recv(4096).decode('latin1'))\"", port));
    tsj_log_text("raw reply", web_str(&res.out));
    code = raw_status(web_str(&res.out));
    TEST_ARTIFACT("H4 malformed request: HTTP %d", code);
    if (code != 400)
        TEST_VERDICT("H4 FAILED: a malformed request did not get 400");

    TEST_STEP("The server is still alive and answers a valid request");
    if (!tsj_running(&svc))
        TEST_VERDICT("H4 FAILED: the server exited after a malformed "
                     "request");
    CHECK_RC(web_get(&session, "", url, 5, &reply));
    if (reply.code != 200)
        TEST_VERDICT("H4 FAILED: the server did not answer 200 after a "
                     "malformed request");

    TEST_STEP("Check that the listener is on loopback only");
    opt.udp = false;
    opt.tcp = true;
    CHECK_RC(tapi_netexpose_sockets(session.factory, &opt, &socks));
    socks_up = true;
    TE_VEC_FOREACH(&socks, sock)
    {
        const struct sockaddr *sa = CONST_SA(&sock->local);

        if (!tapi_netexpose_socket_is_listening(sock) ||
            ntohs(te_sockaddr_get_port(sa)) != port)
            continue;
        seen = true;
        if (!(sa->sa_family == AF_INET &&
              (ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr) >>
               24) == 127))
            tapi_cybersec_report_add(&cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "net.exposed", "ts server",
                                     "the ts server listens beyond "
                                     "loopback");
    }
    if (!seen)
        TEST_VERDICT("H4 NOT SETTLED: the socket table has no listener on "
                     "the server port");
    {
        const tapi_cybersec_finding *f;

        TE_VEC_FOREACH(&cyber.findings, f)
            n_find++;
    }
    if (n_find > 0)
        TEST_VERDICT("H4 FAILED: the ts server listens beyond loopback");

    TEST_STEP("Send SIGTERM and expect exit 0");
    CHECK_RC(tapi_job_kill(svc.job, SIGTERM));
    rc = tapi_job_wait(svc.job, 10000, &st);
    if (TE_RC_GET_ERROR(rc) == TE_EINPROGRESS)
        TEST_VERDICT("H4 FAILED: the server did not exit within 10 s of "
                     "SIGTERM");
    CHECK_RC(rc);
    TEST_ARTIFACT("H4 SIGTERM: %s, value %d",
                  st.type == TAPI_JOB_STATUS_EXITED ? "exited" : "signaled",
                  st.value);
    if (st.type != TAPI_JOB_STATUS_EXITED || st.value != 0)
        TEST_VERDICT("H4 FAILED: SIGTERM did not give exit code 0");

    TEST_ARTIFACT("H4 the ts server answers a malformed request with 400, "
                  "stays alive, listens on loopback and exits 0 on SIGTERM");
    TEST_SUCCESS;

cleanup:
    tsj_stop(&svc);
    tsapi_mde_sh_result_free(&res);
    te_string_free(&reply.body);
    if (socks_up)
        tapi_netexpose_sockets_free(&socks);
    if (cyber_up)
        tapi_cybersec_report_free(&cyber);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}

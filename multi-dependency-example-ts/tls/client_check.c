/** @file
 * @brief TLS Group
 *
 * The web tier has no TLS client of its own, so the TLS clients of the
 * deployment are the agent's: curl and python3 urllib. Offer each of them
 * a server whose certificate is wrong in one chosen way (tapi_tls_server)
 * and read from the server's own statistics whether the client completed
 * the handshake anyway. A client that connects anyway is a critical
 * finding. curl -k, which checks nothing on purpose, is the known-bad
 * control and must be reported.
 *
 * The server's count alone is not the verdict: curl (with OpenSSL)
 * matches the host name only after the handshake, so on a wrong-name
 * certificate the server counts a finished handshake that curl then
 * drops with exit 60 before sending a request. A client accepted the
 * server only if it also got the page (HTTP 200); a finished handshake
 * the client abandoned is a refusal.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "tls/client_check"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_tls.h"
#include "tapi_tls_server.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tls_common.h"

/** First port; each client gets its own server. */
#define CLIENT_PORT_BASE    34530

/** Expired certificate made under faketime. */
#define CLIENT_EXP_CRT      "/tmp/mde-tls-client-expired.crt"
#define CLIENT_EXP_KEY      "/tmp/mde-tls-client-expired.key"

/** A client under test. */
typedef enum client_kind {
    CLIENT_CURL = 0,    /**< curl, verifying. */
    CLIENT_PYTHON,      /**< python3 urllib with a default context. */
    CLIENT_CURL_K,      /**< curl -k: the known-bad control. */
    CLIENT_N,
} client_kind;

/** Subjects of the findings, one per client. */
static const char *const client_names[CLIENT_N] = {
    "curl", "python3-urllib", "curl -k",
};

/** The certificate defect parameter. */
#define CLIENT_DEFECT_LIST \
    { "self_signed", TAPI_TLS_SERVER_SELF_SIGNED }, \
    { "expired",     TAPI_TLS_SERVER_EXPIRED },     \
    { "wrong_name",  TAPI_TLS_SERVER_WRONG_NAME }

/** Did the client get the page: the client's own view of the connection. */
static bool
client_got_page(client_kind kind, const tsapi_mde_sh_result *sh)
{
    const char *out = te_string_value(&sh->out);

    if (sh->status.type != TAPI_JOB_STATUS_EXITED || sh->status.value != 0)
        return false;

    if (kind == CLIENT_PYTHON)
        return strstr(out, "STATUS 200") != NULL;

    return strncmp(out, "200", 3) == 0;
}

/** Run one client against @p port, trusting @p ca (or the system store). */
static void
client_run(tsapi_mde_session *session, client_kind kind, unsigned int port,
           const char *ca, tsapi_mde_sh_result *sh)
{
    te_string cacert = TE_STRING_INIT;
    te_errno  rc = 0;

    if (ca != NULL && *ca != '\0')
        te_string_append(&cacert, "--cacert '%s'", ca);

    switch (kind)
    {
        case CLIENT_CURL:
            rc = tsapi_mde_sh(session, MDE_TLS_TIMEOUT_MS, sh,
                              "curl -sS -o /dev/null -w '%%{http_code}' "
                              "--max-time 10 %s 'https://localhost:%u/'",
                              te_string_value(&cacert), port);
            break;

        case CLIENT_PYTHON:
            rc = tsapi_mde_sh(session, MDE_TLS_TIMEOUT_MS, sh,
                              "python3 -c 'import ssl, sys, "
                              "urllib.request as u; "
                              "c = ssl.create_default_context("
                              "cafile=(sys.argv[2] or None)); "
                              "r = u.urlopen(sys.argv[1], context=c, "
                              "timeout=10); print(\"STATUS\", r.status)' "
                              "'https://localhost:%u/' '%s'",
                              port, ca != NULL ? ca : "");
            break;

        case CLIENT_CURL_K:
            rc = tsapi_mde_sh(session, MDE_TLS_TIMEOUT_MS, sh,
                              "curl -sSk -o /dev/null -w '%%{http_code}' "
                              "--max-time 10 'https://localhost:%u/'", port);
            break;

        default:
            break;
    }

    if (rc != 0)
        TEST_VERDICT("The %s client could not be run", client_names[kind]);

    te_string_free(&cacert);
}

int
main(int argc, char **argv)
{
    tapi_tls_server_defect     defect;
    tapi_cybersec_severity     min_severity;
    tsapi_mde_session          session;
    tsapi_mde_report           report;
    tapi_tls_server_opt        srv_opt;
    tapi_tls_server           *server = NULL;
    tapi_tls_client_behaviour  behaviour = TAPI_TLS_CLIENT_NONE;
    tsapi_mde_sh_result        sh = TSAPI_MDE_SH_RESULT_INIT;
    tsapi_mde_sh_result        rm = TSAPI_MDE_SH_RESULT_INIT;
    te_string                  ca = TE_STRING_INIT;
    te_string                  check = TE_STRING_INIT;
    double                     outcome[CLIENT_N];
    double                     exit_code[CLIENT_N];
    double                     time_ms[CLIENT_N];
    bool                       session_up = false;
    unsigned int               i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(defect, CLIENT_DEFECT_LIST);
    TEST_GET_MDE_SEVERITY(min_severity);
    tsapi_mde_report_init(&report);

    tsapi_evo_analysis_hint(
        "TLS clients of the agent offered a bad certificate. Outcome 1 = "
        "the client completed the handshake (a finding unless it is the "
        "curl -k control), 2 = it refused, 0 = it never arrived.");

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "tls_client"));
    session_up = true;

    if (!tsapi_mde_have(&session, "openssl"))
        TEST_SKIP("There is no openssl on the agent");
    if (!tsapi_mde_have(&session, "curl"))
        TEST_SKIP("There is no curl on the agent");
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("There is no python3 on the agent");

    if (defect == TAPI_TLS_SERVER_EXPIRED)
    {
        TEST_STEP("Date a certificate in the past with faketime");
        /* openssl 3.0 cannot backdate by itself; a faked clock can. */
        if (!tsapi_mde_have(&session, "faketime"))
            TEST_SKIP("faketime is needed to make an expired certificate");
        CHECK_RC(tsapi_mde_sh(&session, MDE_TLS_TIMEOUT_MS, &sh,
                              "faketime -f -400d openssl req -x509 "
                              "-newkey rsa:2048 -nodes -keyout '%s' "
                              "-out '%s' -days 30 -subj /CN=localhost "
                              "-addext subjectAltName=DNS:localhost",
                              CLIENT_EXP_KEY, CLIENT_EXP_CRT));
        if (!tsapi_mde_sh_ok(&sh))
            TEST_VERDICT("Cannot make an expired certificate");
    }

    for (i = 0; i < CLIENT_N; i++)
    {
        double t0;

        TEST_STEP("Offer the certificate to a client");
        srv_opt = tapi_tls_server_default_opt;
        srv_opt.port = CLIENT_PORT_BASE + i;
        srv_opt.defect = defect;
        srv_opt.common_name = "localhost";
        srv_opt.naccept = 1;
        srv_opt.www = true;
        if (defect == TAPI_TLS_SERVER_EXPIRED)
        {
            srv_opt.cert_file = CLIENT_EXP_CRT;
            srv_opt.key_file = CLIENT_EXP_KEY;
        }
        CHECK_RC(tapi_tls_server_start(session.factory, &srv_opt,
                                       MDE_TLS_TIMEOUT_MS, &server));

        /*
         * The client trusts what makes everything but the defect right:
         * the test authority, or the expired certificate itself. A
         * self-signed certificate has no authority: the system store.
         */
        te_string_reset(&ca);
        if (defect == TAPI_TLS_SERVER_EXPIRED)
            te_string_append(&ca, "%s", CLIENT_EXP_CRT);
        else if (tapi_tls_server_ca_file(server) != NULL)
            te_string_append(&ca, "%s", tapi_tls_server_ca_file(server));

        t0 = tsapi_mde_now();
        client_run(&session, (client_kind)i, srv_opt.port,
                   te_string_value(&ca), &sh);
        time_ms[i] = (tsapi_mde_now() - t0) * 1000.0;

        CHECK_RC(tapi_tls_server_stop(server, &behaviour));
        server = NULL;

        exit_code[i] = sh.status.type == TAPI_JOB_STATUS_EXITED ?
                           sh.status.value : -1;

        /*
         * A handshake the server saw finish but the client then dropped
         * without asking for the page is a refusal: curl checks the
         * name after the handshake.
         */
        if (behaviour == TAPI_TLS_CLIENT_COMPLETED &&
            !client_got_page((client_kind)i, &sh))
        {
            RING("%s: the handshake finished on the server, but the client "
                 "exited %.0f without the page - it refused after the "
                 "handshake", client_names[i], exit_code[i]);
            behaviour = TAPI_TLS_CLIENT_REJECTED;
        }
        outcome[i] = behaviour == TAPI_TLS_CLIENT_COMPLETED ? 1 :
                     behaviour == TAPI_TLS_CLIENT_REJECTED ? 2 : 0;
        TEST_ARTIFACT("%s vs %s certificate: %s, exit %.0f, stdout '%s'",
                      client_names[i], tapi_tls_defect2str(defect),
                      behaviour == TAPI_TLS_CLIENT_COMPLETED ? "completed" :
                      behaviour == TAPI_TLS_CLIENT_REJECTED ? "refused" :
                      "never arrived", exit_code[i],
                      te_string_value(&sh.out));
        if (sh.err.len > 0)
            RING("%s said: %s", client_names[i], te_string_value(&sh.err));

        if (behaviour == TAPI_TLS_CLIENT_NONE)
            TEST_VERDICT("The %s client never reached the server",
                         client_names[i]);

        /* Two views of one fact: the client's exit and the server's count. */
        if ((behaviour == TAPI_TLS_CLIENT_REJECTED) != (exit_code[i] != 0))
        {
            WARN("%s: the server says %s but the client exited %.0f",
                 client_names[i],
                 behaviour == TAPI_TLS_CLIENT_REJECTED ? "refused" :
                 "completed", exit_code[i]);
        }

        CHECK_RC(tapi_tls_check_client(defect, behaviour, client_names[i],
                                       &report.cyber));

        if (defect != TAPI_TLS_SERVER_EXPIRED && ca.len > 0)
            (void)tsapi_mde_sh(&session, 10000, &rm, "rm -f '%s'", ca.ptr);
    }

    TEST_STEP("Known-bad control: curl -k must be reported");
    te_string_append(&check, "tls.client-accepts-%s",
                     tapi_tls_defect2str(defect));
    tsapi_mde_report_expect(&report, check.ptr, client_names[CLIENT_CURL_K]);
    tsapi_mde_report_drop_subject(&report, client_names[CLIENT_CURL_K]);

    TEST_STEP("Chart the outcomes");
    tsapi_mde_mi_bars("tls-client", "Outcome per client "
                      "(0 none, 1 completed, 2 refused)",
                      TE_MI_MEAS_UNITLESS_VALUE, "outcome", CLIENT_N,
                      client_names, outcome, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("tls-client", "Client exit status",
                      TE_MI_MEAS_UNITLESS_VALUE, "exit_status", CLIENT_N,
                      client_names, exit_code, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("tls-client", "Client run time",
                      TE_MI_MEAS_LATENCY, "run_time", CLIENT_N,
                      client_names, time_ms, TE_MI_MEAS_MULTIPLIER_MILLI);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "tls", min_severity);

    TEST_SUCCESS;

cleanup:

    if (server != NULL)
        CLEANUP_CHECK_RC(tapi_tls_server_stop(server, &behaviour));
    if (session_up)
    {
        (void)tsapi_mde_sh(&session, 10000, &rm, "rm -f '%s' '%s'",
                           CLIENT_EXP_CRT, CLIENT_EXP_KEY);
    }
    tsapi_mde_sh_result_free(&sh);
    tsapi_mde_sh_result_free(&rm);
    te_string_free(&ca);
    te_string_free(&check);
    tsapi_mde_report_free(&report);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

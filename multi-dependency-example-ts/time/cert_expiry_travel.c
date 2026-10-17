/** @file
 * @brief Time Group
 *
 * tsf-time and tsf-tls together: a certificate valid for one day is served
 * by a tapi_tls_server on the real clock, and a TLS client trusting exactly
 * that certificate is run under libfaketime two days back, now, and two
 * days ahead. Now it must connect (the positive control); two days ahead
 * the certificate has expired and two days back it is not valid yet, so it
 * must refuse. curl -k two days ahead is the known-bad control: it accepts
 * anything and must be reported.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "time/cert_expiry_travel"

#include "te_config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_time.h"
#include "tapi_tls.h"
#include "tapi_tls_server.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "time_common.h"

/** First port; each run gets its own one-connection server. */
#define TRAVEL_PORT_BASE    34540

/** The one-day certificate on the agent. */
#define TRAVEL_CRT  "/tmp/mde-time-travel.crt"
#define TRAVEL_KEY  "/tmp/mde-time-travel.key"

/** The client parameter. */
typedef enum travel_client {
    TRAVEL_CURL,
    TRAVEL_PYTHON,
} travel_client;

#define TRAVEL_CLIENT_LIST \
    { "curl",    TRAVEL_CURL }, \
    { "python3", TRAVEL_PYTHON }

/** The offsets the client travels to. */
static const char *const travel_offsets[] = { "-2d", "+0", "+2d" };

#define TRAVEL_N_OFFSETS    TE_ARRAY_LEN(travel_offsets)

/** The client in python3. */
#define TRAVEL_PY \
    "import ssl, sys, urllib.request as u; "                              \
    "c = ssl.create_default_context(cafile=sys.argv[2]); "                \
    "r = u.urlopen(sys.argv[1], context=c, timeout=10); "                 \
    "print('STATUS', r.status)"

/**
 * Run one client under @p clock against a fresh one-connection server on
 * @p port, and return what the server saw.
 */
static tapi_tls_client_behaviour
travel_run(tsapi_mde_session *session, const tapi_time_opt *clock,
           travel_client client, bool insecure, unsigned int port,
           mde_time_run_result *res)
{
    tapi_tls_server_opt        opt = tapi_tls_server_default_opt;
    tapi_tls_server           *server = NULL;
    tapi_tls_client_behaviour  behaviour = TAPI_TLS_CLIENT_NONE;
    te_string                  url = TE_STRING_INIT;
    const char                *curl_argv[] = {
        "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", "10", "--cacert", TRAVEL_CRT, NULL, NULL,
    };
    const char                *curl_k_argv[] = {
        "curl", "-sSk", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", "10", NULL, NULL,
    };
    const char                *py_argv[] = {
        "python3", "-c", TRAVEL_PY, NULL, TRAVEL_CRT, NULL,
    };
    const char               **run_argv;

    opt.port = port;
    opt.defect = TAPI_TLS_SERVER_VALID;
    opt.cert_file = TRAVEL_CRT;
    opt.key_file = TRAVEL_KEY;
    opt.naccept = 1;
    opt.www = true;
    if (tapi_tls_server_start(session->factory, &opt, MDE_TIME_TIMEOUT_MS,
                              &server) != 0)
        TEST_VERDICT("The TLS server with the one-day certificate did not "
                     "start");

    te_string_append(&url, "https://localhost:%u/", port);
    if (insecure)
    {
        curl_k_argv[8] = url.ptr;
        run_argv = curl_k_argv;
    }
    else if (client == TRAVEL_CURL)
    {
        curl_argv[10] = url.ptr;
        run_argv = curl_argv;
    }
    else
    {
        py_argv[3] = url.ptr;
        run_argv = py_argv;
    }

    if (mde_time_run(session, clock, run_argv, MDE_TIME_TIMEOUT_MS,
                     res) != 0)
    {
        (void)tapi_tls_server_stop(server, &behaviour);
        te_string_free(&url);
        TEST_VERDICT("The client could not be run under the fake clock");
    }

    if (tapi_tls_server_stop(server, &behaviour) != 0)
        behaviour = TAPI_TLS_CLIENT_NONE;
    te_string_free(&url);

    return behaviour;
}

int
main(int argc, char **argv)
{
    travel_client              client;
    tsapi_mde_session          session;
    tsapi_mde_report           report;
    tsapi_mde_sh_result        sh = TSAPI_MDE_SH_RESULT_INIT;
    mde_time_run_result        res = MDE_TIME_RUN_RESULT_INIT;
    tapi_time_opt              clock;
    tapi_tls_client_behaviour  behaviour;
    te_string                  subject = TE_STRING_INIT;
    te_mi_logger              *logger = NULL;
    const char                *client_name;
    double                     outcome[TRAVEL_N_OFFSETS];
    double                     req_days[TRAVEL_N_OFFSETS];
    double                     obs_days[TRAVEL_N_OFFSETS];
    double                     exit_code[TRAVEL_N_OFFSETS];
    int64_t                    requested = 0;
    int64_t                    skew = 0;
    bool                       session_up = false;
    unsigned int               i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(client, TRAVEL_CLIENT_LIST);
    client_name = client == TRAVEL_CURL ? "curl" : "python3";
    tsapi_mde_report_init(&report);

    tsapi_evo_analysis_hint(
        "A one-day certificate and a client that trusts it, run under a "
        "fake clock at -2d, +0 and +2d. Outcome 1 = connected, 2 = "
        "refused: only +0 may connect. curl -k at +2d must be reported.");

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "time_travel"));
    session_up = true;

    if (!tapi_time_available(session.factory, MDE_TIME_TIMEOUT_MS))
        TEST_SKIP("libfaketime is not installed on the agent");
    if (!tsapi_mde_have(&session, "faketime"))
        TEST_SKIP("The faketime program is not installed on the agent");
    if (!tsapi_mde_have(&session, "openssl"))
        TEST_SKIP("There is no openssl on the agent");
    if (!tsapi_mde_have(&session, "curl"))
        TEST_SKIP("There is no curl on the agent");
    if (client == TRAVEL_PYTHON && !tsapi_mde_have(&session, "python3"))
        TEST_SKIP("There is no python3 on the agent");

    TEST_STEP("Make a certificate for localhost valid for one day");
    CHECK_RC(tsapi_mde_sh(&session, MDE_TIME_TIMEOUT_MS, &sh,
                          "openssl req -x509 -newkey rsa:2048 -nodes "
                          "-keyout '%s' -out '%s' -days 1 "
                          "-subj /CN=localhost "
                          "-addext subjectAltName=DNS:localhost && "
                          "openssl x509 -in '%s' -noout -startdate "
                          "-enddate",
                          TRAVEL_KEY, TRAVEL_CRT, TRAVEL_CRT));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_VERDICT("Cannot make the one-day certificate");
    TEST_ARTIFACT("One-day certificate %s: %s", TRAVEL_CRT,
                  te_string_value(&sh.out));

    for (i = 0; i < TRAVEL_N_OFFSETS; i++)
    {
        const char *offset = travel_offsets[i];

        TEST_STEP("Travel and connect");
        if (!mde_time_offset_seconds(offset, &requested))
            TEST_FAIL("Cannot parse offset %s", offset);

        clock = tapi_time_default_opt;
        clock.offset = offset;
        CHECK_RC(tapi_time_check(session.factory, &clock,
                                 MDE_TIME_TIMEOUT_MS, &skew));
        req_days[i] = requested / 86400.0;
        obs_days[i] = skew / 86400.0;
        if (skew - requested > MDE_TIME_TOLERANCE_S ||
            requested - skew > MDE_TIME_TOLERANCE_S)
            TEST_VERDICT("The fake clock did not move by %s", offset);

        behaviour = travel_run(&session, &clock, client, false,
                               TRAVEL_PORT_BASE + i, &res);
        outcome[i] = behaviour == TAPI_TLS_CLIENT_COMPLETED ? 1 :
                     behaviour == TAPI_TLS_CLIENT_REJECTED ? 2 : 0;
        exit_code[i] = res.status.type == TAPI_JOB_STATUS_EXITED ?
                           res.status.value : -1;
        TEST_ARTIFACT("%s at %s (skew %" PRId64 " s): %s, exit %.0f, "
                      "stdout '%s'", client_name, offset, skew,
                      behaviour == TAPI_TLS_CLIENT_COMPLETED ? "connected" :
                      behaviour == TAPI_TLS_CLIENT_REJECTED ? "refused" :
                      "never arrived", exit_code[i],
                      te_string_value(&res.out));
        if (res.err.len > 0)
            RING("%s at %s said: %s", client_name, offset,
                 te_string_value(&res.err));

        if (behaviour == TAPI_TLS_CLIENT_NONE)
            TEST_VERDICT("The client never reached the server at %s",
                         offset);

        te_string_reset(&subject);
        te_string_append(&subject, "%s@%s", client_name, offset);

        if (requested == 0)
        {
            /* The positive control: without it a refusal proves nothing. */
            if (behaviour != TAPI_TLS_CLIENT_COMPLETED)
                TEST_VERDICT("The client refused the certificate on the "
                             "real clock");
            CHECK_RC(tapi_tls_check_client(TAPI_TLS_SERVER_VALID, behaviour,
                                           subject.ptr, &report.cyber));
        }
        else if (requested > 0)
        {
            CHECK_RC(tapi_tls_check_client(TAPI_TLS_SERVER_EXPIRED,
                                           behaviour, subject.ptr,
                                           &report.cyber));
        }
        else if (behaviour == TAPI_TLS_CLIENT_COMPLETED)
        {
            tapi_cybersec_report_add(&report.cyber,
                TAPI_CYBERSEC_SEV_CRITICAL, "time.not-yet-valid-accepted",
                subject.ptr,
                "the client accepted a certificate whose validity starts "
                "%s from its clock", offset + 1);
        }
    }

    TEST_STEP("Known-bad control: curl -k two days ahead must be reported");
    clock = tapi_time_default_opt;
    clock.offset = "+2d";
    behaviour = travel_run(&session, &clock, client, true,
                           TRAVEL_PORT_BASE + TRAVEL_N_OFFSETS, &res);
    TEST_ARTIFACT("curl -k at +2d: %s",
                  behaviour == TAPI_TLS_CLIENT_COMPLETED ? "connected" :
                  behaviour == TAPI_TLS_CLIENT_REJECTED ? "refused" :
                  "never arrived");
    CHECK_RC(tapi_tls_check_client(TAPI_TLS_SERVER_EXPIRED, behaviour,
                                   "curl -k@+2d", &report.cyber));
    tsapi_mde_report_expect(&report, "tls.client-accepts-expired",
                            "curl -k@+2d");
    tsapi_mde_report_drop_subject(&report, "curl -k@+2d");

    TEST_STEP("Chart the outcome per offset");
    tsapi_mde_mi_bars("time-travel", "Outcome per clock offset "
                      "(1 connected, 2 refused)", TE_MI_MEAS_UNITLESS_VALUE,
                      "outcome", TRAVEL_N_OFFSETS, travel_offsets, outcome,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("time-travel", "Client exit status per clock offset",
                      TE_MI_MEAS_UNITLESS_VALUE, "exit_status",
                      TRAVEL_N_OFFSETS, travel_offsets, exit_code,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (tsapi_mde_mi_create("time-travel", &logger) == 0)
    {
        for (i = 0; i < TRAVEL_N_OFFSETS; i++)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "requested_days", TE_MI_MEAS_AGGR_SINGLE,
                                  req_days[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_days", TE_MI_MEAS_AGGR_SINGLE,
                                  obs_days[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        te_mi_logger_add_meas_key(logger, NULL, "client", "%s",
                                  client_name);
        tsapi_mde_mi_line(logger, "skew",
                          "Clock the client saw vs requested, days",
                          "requested_days", "observed_days", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "time", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    if (session_up)
    {
        (void)tsapi_mde_sh(&session, 10000, &sh, "rm -f '%s'", TRAVEL_KEY);
        tsapi_mde_session_fini(&session);
    }
    mde_time_run_result_free(&res);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&subject);
    tsapi_mde_report_free(&report);

    TEST_END;
}

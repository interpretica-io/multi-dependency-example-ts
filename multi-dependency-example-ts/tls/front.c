/** @file
 * @brief TLS Group
 *
 * Audit a TLS endpoint of the deployment with tapi_tls_check_server():
 * either a TLS terminator put in front of gateway-rs (python3 ssl,
 * forwarding to :8081) or a plain openssl s_server with default modern
 * settings. Both serve a certificate for localhost signed by a test
 * authority. The version scan, the certificate checks, what the handshake
 * really served and what a client gets through the front are cross-checked.
 * Two known-bad endpoints (a wrong name, an expired certificate) prove the
 * audit sees what it is meant to see.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "tls/front"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_file.h"
#include "tapi_tls.h"
#include "tapi_tls_cert.h"
#include "tapi_tls_server.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"
#include "tls_common.h"

/** Port of the TLS front of gateway-rs. */
#define FRONT_PORT_PROXY        34520
/** Port of the s_server endpoint. */
#define FRONT_PORT_S_SERVER     34521
/** Port of the wrong-name control. */
#define FRONT_PORT_CTRL_NAME    34522
/** Port of the expired control. */
#define FRONT_PORT_CTRL_EXPIRED 34523

/** Script of the front on the agent. */
#define FRONT_SCRIPT    "/tmp/mde-tls-front.py"
/** Expired control certificate and key on the agent. */
#define FRONT_EXP_CRT   "/tmp/mde-tls-front-expired.crt"
#define FRONT_EXP_KEY   "/tmp/mde-tls-front-expired.key"

/** What is audited. */
typedef enum front_endpoint {
    FRONT_GATEWAY,      /**< python3 TLS terminator before gateway-rs. */
    FRONT_S_SERVER,     /**< openssl s_server -www. */
} front_endpoint;

#define FRONT_ENDPOINT_LIST \
    { "gateway_front", FRONT_GATEWAY }, \
    { "s_server",      FRONT_S_SERVER }

/**
 * Audit a control endpoint and require one finding of it, then drop the
 * control's findings.
 */
static void
front_control(tsapi_mde_session *session, tsapi_mde_report *report,
              const tapi_tls_server_opt *opt, const char *ca_override,
              const char *expected_check)
{
    tapi_tls_server          *server = NULL;
    tapi_tls_probe_opt        probe = tapi_tls_probe_default_opt;
    tapi_tls_policy           policy = tapi_tls_default_policy;
    tapi_tls_client_behaviour behaviour;
    te_string                 subject = TE_STRING_INIT;
    te_string                 ca = TE_STRING_INIT;
    tsapi_mde_sh_result       sh = TSAPI_MDE_SH_RESULT_INIT;
    te_errno                  rc;

    rc = tapi_tls_server_start(session->factory, opt, MDE_TLS_TIMEOUT_MS,
                               &server);
    if (rc != 0)
        TEST_VERDICT("The %s control endpoint did not start",
                     tapi_tls_defect2str(opt->defect));

    if (ca_override != NULL)
        te_string_append(&ca, "%s", ca_override);
    else if (tapi_tls_server_ca_file(server) != NULL)
        te_string_append(&ca, "%s", tapi_tls_server_ca_file(server));

    probe.host = "127.0.0.1";
    probe.port = opt->port;
    probe.servername = "localhost";
    probe.ca_file = ca.len > 0 ? ca.ptr : NULL;
    policy.expected_name = "localhost";

    te_string_append(&subject, "127.0.0.1:%u", opt->port);
    rc = tapi_tls_check_server(session->factory, &probe, &policy,
                               MDE_TLS_PROBE_MS, &report->cyber);
    (void)tapi_tls_server_stop(server, &behaviour);
    if (rc != 0)
        TEST_VERDICT("The %s control endpoint could not be audited",
                     tapi_tls_defect2str(opt->defect));

    TEST_ARTIFACT("Control %s: %u tls.* finding(s)",
                  tapi_tls_defect2str(opt->defect),
                  tsapi_mde_report_has(report, "tls.", subject.ptr));
    tsapi_mde_report_expect(report, expected_check, subject.ptr);
    tsapi_mde_report_drop_subject(report, subject.ptr);

    /* The test authority of a generated control is not scratch: drop it. */
    if (ca_override == NULL && ca.len > 0)
        (void)tsapi_mde_sh(session, 10000, &sh, "rm -f '%s'", ca.ptr);

    tsapi_mde_sh_result_free(&sh);
    te_string_free(&subject);
    te_string_free(&ca);
}

int
main(int argc, char **argv)
{
    front_endpoint             endpoint;
    tapi_cybersec_severity     min_severity;
    tsapi_mde_session          session;
    tsapi_mde_dut              dut;
    tsapi_mde_web              web;
    tsapi_mde_report           report;
    tapi_tls_server_opt        srv_opt;
    tapi_tls_server           *server = NULL;
    tapi_tls_client_behaviour  behaviour;
    tapi_tls_probe_opt         probe;
    tapi_tls_policy            policy;
    tapi_tls_handshake         hs;
    tapi_tls_cert              cert;
    mde_tls_bg                 bg;
    tsapi_mde_sh_result        sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string                  crt = TE_STRING_INIT;
    te_string                  key = TE_STRING_INIT;
    te_string                  ca = TE_STRING_INIT;
    te_string                  subject = TE_STRING_INIT;
    te_string                  fp_served = TE_STRING_INIT;
    te_string                  fp_file = TE_STRING_INIT;
    const char                *labels[MDE_TLS_N_VERSIONS];
    double                     accepted_v[MDE_TLS_N_VERSIONS];
    unsigned int               accepted = 0;
    unsigned int               port;
    char                       port_str[16];
    tapi_tls_version           newest = TAPI_TLS_VERSION_ANY;
    bool                       obsolete = false;
    bool                       session_up = false;
    bool                       web_up = false;
    bool                       certs_made = false;
    bool                       hs_up = false;
    bool                       cert_up = false;
    double                     t0;
    double                     scan_s;
    double                     check_s;
    double                     seconds_left = 0.0;
    double                     days_left;
    unsigned int               i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(endpoint, FRONT_ENDPOINT_LIST);
    TEST_GET_MDE_SEVERITY(min_severity);
    port = endpoint == FRONT_GATEWAY ? FRONT_PORT_PROXY : FRONT_PORT_S_SERVER;
    TE_SPRINTF(port_str, "%u", port);

    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));
    memset(&bg, 0, sizeof(bg));
    memset(&hs, 0, sizeof(hs));
    memset(&cert, 0, sizeof(cert));
    tsapi_mde_report_init(&report);

    tsapi_evo_analysis_hint(
        "TLS endpoint of the deployment audited with tapi_tls_check_server: "
        "TLS 1.2+ only, a 2048-bit key, a chain that verifies against the "
        "test authority, a certificate for localhost valid for 365 days. "
        "The wrong-name and expired controls must be reported or the audit "
        "is blind.");

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "tls_front", dut, session_up);

    if (!tsapi_mde_have(&session, "openssl"))
        TEST_SKIP("There is no openssl on the agent");
    if (endpoint == FRONT_GATEWAY)
    {
        if (!tsapi_mde_have(&session, "python3"))
            TEST_SKIP("There is no python3 on the agent for the TLS front");
        if (!tsapi_mde_have(&session, "curl"))
            TEST_SKIP("There is no curl on the agent");
        if (!tsapi_mde_web_built(&session, &dut))
            TEST_SKIP("The web tier is not built");
    }

    TEST_STEP("Known-bad control: a certificate for the wrong name");
    srv_opt = tapi_tls_server_default_opt;
    srv_opt.port = FRONT_PORT_CTRL_NAME;
    srv_opt.defect = TAPI_TLS_SERVER_WRONG_NAME;
    srv_opt.common_name = "localhost";
    srv_opt.naccept = 0;
    front_control(&session, &report, &srv_opt, NULL, "tls.name-mismatch");

    TEST_STEP("Known-bad control: an expired certificate (dated with "
              "faketime)");
    if (tsapi_mde_have(&session, "faketime") &&
        tsapi_mde_sh(&session, MDE_TLS_TIMEOUT_MS, &sh,
                     "faketime -f -400d openssl req -x509 -newkey rsa:2048 "
                     "-nodes -keyout '%s' -out '%s' -days 30 "
                     "-subj /CN=localhost "
                     "-addext subjectAltName=DNS:localhost",
                     FRONT_EXP_KEY, FRONT_EXP_CRT) == 0 &&
        tsapi_mde_sh_ok(&sh))
    {
        srv_opt = tapi_tls_server_default_opt;
        srv_opt.port = FRONT_PORT_CTRL_EXPIRED;
        srv_opt.defect = TAPI_TLS_SERVER_EXPIRED;
        srv_opt.cert_file = FRONT_EXP_CRT;
        srv_opt.key_file = FRONT_EXP_KEY;
        srv_opt.naccept = 0;
        front_control(&session, &report, &srv_opt, FRONT_EXP_CRT,
                      "tls.certificate-expired");
    }
    else
    {
        RING("No faketime: the expired control is not run");
    }

    TEST_STEP("Generate a certificate for localhost signed by a test "
              "authority");
    srv_opt = tapi_tls_server_default_opt;
    srv_opt.defect = TAPI_TLS_SERVER_VALID;
    srv_opt.common_name = "localhost";
    certs_made = true;
    CHECK_RC(tapi_tls_server_make_cert(session.factory, &srv_opt,
                                       MDE_TLS_TIMEOUT_MS, &crt, &key, &ca));
    if (ca.len == 0)
        TEST_VERDICT("No test authority came with the generated certificate");

    TEST_STEP("Start the endpoint under audit");
    if (endpoint == FRONT_GATEWAY)
    {
        const char *front_argv[] = {
            "python3", FRONT_SCRIPT, port_str, crt.ptr, key.ptr, "8081", NULL,
        };

        web_up = true;
        if (tsapi_mde_web_start(&session, &dut, &web) != 0)
            TEST_VERDICT("The web tier did not start");

        CHECK_RC(tapi_file_create_ta(session.ta, FRONT_SCRIPT, "%s",
                                     mde_tls_front_script()));
        if (mde_tls_bg_start(&session, front_argv, "MDE_TLS_FRONT_READY",
                             15000, &bg) != 0)
            TEST_VERDICT("The TLS front of gateway-rs did not start");
    }
    else
    {
        srv_opt = tapi_tls_server_default_opt;
        srv_opt.port = FRONT_PORT_S_SERVER;
        srv_opt.defect = TAPI_TLS_SERVER_VALID;
        srv_opt.cert_file = crt.ptr;
        srv_opt.key_file = key.ptr;
        srv_opt.naccept = 0;
        CHECK_RC(tapi_tls_server_start(session.factory, &srv_opt,
                                       MDE_TLS_TIMEOUT_MS, &server));
    }

    probe = tapi_tls_probe_default_opt;
    probe.host = "127.0.0.1";
    probe.port = port;
    probe.servername = "localhost";
    probe.ca_file = ca.ptr;
    te_string_append(&subject, "127.0.0.1:%u", port);

    TEST_STEP("Scan the protocol versions");
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_tls_scan_versions(session.factory, &probe,
                                    MDE_TLS_PROBE_MS, &accepted));
    scan_s = tsapi_mde_now() - t0;
    for (i = 0; i < MDE_TLS_N_VERSIONS; i++)
    {
        tapi_tls_version v = mde_tls_version_at(i);

        labels[i] = tapi_tls_version2str(v);
        accepted_v[i] = (accepted & (1u << v)) != 0 ? 1 : 0;
        if (accepted_v[i] > 0)
        {
            newest = v;
            if (v < TAPI_TLS_VERSION_TLS1_2)
                obsolete = true;
        }
    }
    TEST_ARTIFACT("%s accepts version mask %#x (newest %s)", subject.ptr,
                  accepted, tapi_tls_version2str(newest));
    if (accepted == 0)
        TEST_VERDICT("No protocol version completed a handshake with the "
                     "endpoint");

    TEST_STEP("Check the endpoint against the default policy");
    policy = tapi_tls_default_policy;
    policy.expected_name = "localhost";
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_tls_check_server(session.factory, &probe, &policy,
                                   MDE_TLS_PROBE_MS, &report.cyber));
    check_s = tsapi_mde_now() - t0;

    if (obsolete !=
        (tsapi_mde_report_has(&report, "tls.obsolete-version",
                              subject.ptr) > 0))
    {
        TEST_VERDICT("The version scan and the policy check disagree about "
                     "obsolete versions");
    }

    TEST_STEP("Check what the handshake really served");
    CHECK_RC(tapi_tls_probe(session.factory, &probe, MDE_TLS_PROBE_MS, &hs));
    hs_up = true;
    tapi_tls_handshake_log(&hs);
    if (!hs.negotiated)
        TEST_VERDICT("The default handshake did not complete");
    if (hs.version != newest)
        TEST_VERDICT("The default handshake did not agree on the newest "
                     "accepted version");
    if (hs.verify_code != 0)
        TEST_VERDICT("The chain did not verify against the test authority");
    if (hs.chain_pem == NULL)
        TEST_VERDICT("The handshake carried no certificate");

    CHECK_RC(tapi_tls_cert_read(session.factory, hs.chain_pem,
                                MDE_TLS_TIMEOUT_MS, &cert));
    cert_up = true;
    tapi_tls_cert_log(&cert);

    mde_tls_fp_normalise(cert.fingerprint, &fp_served);
    if (!mde_tls_cert_der_sha256(&session, crt.ptr, &fp_file))
        TEST_VERDICT("Cannot hash the generated certificate");
    TEST_ARTIFACT("Served certificate sha256 %s, generated %s",
                  te_string_value(&fp_served), te_string_value(&fp_file));
    if (strcmp(te_string_value(&fp_served), te_string_value(&fp_file)) != 0)
        TEST_VERDICT("The endpoint does not serve the generated certificate");

    if (!tapi_tls_cert_matches_name(&cert, "localhost"))
        TEST_VERDICT("The certificate does not match the name it was made "
                     "for");
    if (tapi_tls_cert_matches_name(&cert, "evil.example.net"))
        TEST_VERDICT("The certificate matches a name it was not made for");
    if (cert.key_bits != 2048 ||
        (hs.server_key_bits != 0 && hs.server_key_bits != cert.key_bits))
    {
        TEST_VERDICT("The certificate and the handshake disagree on the key "
                     "size");
    }
    if (cert.expired || cert.self_signed)
        TEST_VERDICT("The generated certificate reads as expired or "
                     "self-signed");

    if (!mde_tls_cert_seconds_left(&session, crt.ptr, &seconds_left))
        TEST_VERDICT("Cannot read the expiry of the generated certificate");
    days_left = seconds_left / 86400.0;
    TEST_ARTIFACT("%s: %.2f day(s) to expiry, %u-bit key, signed with %s",
                  subject.ptr, days_left, cert.key_bits,
                  cert.signature_algorithm != NULL ?
                      cert.signature_algorithm : "?");
    if (days_left < 364.0 || days_left > 365.01)
        TEST_VERDICT("The generated certificate is not valid for 365 days");

    if (endpoint == FRONT_GATEWAY)
    {
        TEST_STEP("A client trusting the test authority reaches gateway-rs "
                  "through the front");
        CHECK_RC(tsapi_mde_sh(&session, MDE_TLS_TIMEOUT_MS, &sh,
                              "curl -sS --max-time 10 --cacert '%s' "
                              "'https://localhost:%u/ring?value=1&hops=0'",
                              ca.ptr, port));
        RING("Through the front:\n%s", te_string_value(&sh.out));
        if (!tsapi_mde_sh_ok(&sh) ||
            strstr(te_string_value(&sh.out), "[gateway-rs] hops=0") == NULL ||
            strstr(te_string_value(&sh.out), "value=") == NULL)
        {
            TEST_VERDICT("The TLS front does not carry GET /ring to "
                         "gateway-rs");
        }

        TEST_STEP("A client that does not trust the authority is refused");
        CHECK_RC(tsapi_mde_sh(&session, MDE_TLS_TIMEOUT_MS, &sh,
                              "curl -sS --max-time 10 -o /dev/null "
                              "'https://localhost:%u/ring?value=1&hops=0'",
                              port));
        TEST_ARTIFACT("curl without the test authority: exit %d",
                      sh.status.value);
        if (tsapi_mde_sh_ok(&sh))
            TEST_VERDICT("curl trusted a certificate of the test authority "
                         "without being told to");
    }

    TEST_STEP("Chart what was found");
    tsapi_mde_mi_bars("tls-front", "Protocol versions accepted (1/0)",
                      TE_MI_MEAS_UNITLESS_VALUE, "accepted",
                      MDE_TLS_N_VERSIONS, labels, accepted_v,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("tls-front", "Days to certificate expiry",
                       TE_MI_MEAS_UNITLESS_VALUE, "days_to_expiry",
                       days_left, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("tls-front", "Server key size, bits",
                       TE_MI_MEAS_UNITLESS_VALUE, "key_bits", cert.key_bits,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("tls-front", "Version scan duration",
                       TE_MI_MEAS_TIME, "scan_time", scan_s,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("tls-front", "Policy check duration",
                       TE_MI_MEAS_TIME, "check_time", check_s,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "tls", min_severity);

    TEST_SUCCESS;

cleanup:

    if (cert_up)
        tapi_tls_cert_free(&cert);
    if (hs_up)
        tapi_tls_handshake_free(&hs);
    if (server != NULL)
        CLEANUP_CHECK_RC(tapi_tls_server_stop(server, &behaviour));
    mde_tls_bg_stop(&bg);
    if (web_up)
        tsapi_mde_web_stop(&web);
    if (session_up)
    {
        (void)tsapi_mde_sh(&session, 10000, &sh,
                           "rm -f '%s' '%s' '%s' '%s' '%s'", FRONT_SCRIPT,
                           FRONT_EXP_CRT, FRONT_EXP_KEY,
                           certs_made ? te_string_value(&key) : "",
                           certs_made ? te_string_value(&ca) : "");
    }
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&crt);
    te_string_free(&key);
    te_string_free(&ca);
    te_string_free(&subject);
    te_string_free(&fp_served);
    te_string_free(&fp_file);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

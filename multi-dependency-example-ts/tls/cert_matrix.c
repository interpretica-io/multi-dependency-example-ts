/** @file
 * @brief TLS Group
 *
 * Make a certificate of a given key type and validity with openssl on the
 * agent, read it back with tapi_tls_cert_read() and check every fact
 * against what was asked for and against an independent view: key size,
 * names and the wildcard rule, self-signature, the fingerprint against a
 * hash of the DER, the public key against the private key, the validity
 * period against the dates, and tapi_tls_cert_checkend() around the
 * expiry moment.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "tls/cert_matrix"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_tls.h"
#include "tapi_tls_cert.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tls_common.h"

/** The key types of the matrix. */
typedef enum matrix_key {
    MATRIX_RSA2048,
    MATRIX_RSA4096,
    MATRIX_EC256,
} matrix_key;

#define MATRIX_KEY_LIST \
    { "rsa2048", MATRIX_RSA2048 }, \
    { "rsa4096", MATRIX_RSA4096 }, \
    { "ec256",   MATRIX_EC256 }

/** The name the certificate is made for. */
#define MATRIX_NAME     "mde-matrix.local"

/** Number of points of the checkend sweep. */
#define MATRIX_N_POINTS 6

int
main(int argc, char **argv)
{
    matrix_key           key;
    int                  days;
    tsapi_mde_session    session;
    tsapi_mde_sh_result  sh = TSAPI_MDE_SH_RESULT_INIT;
    tapi_tls_cert        cert;
    te_string            crt = TE_STRING_INIT;
    te_string            pem = TE_STRING_INIT;
    te_string            keyf = TE_STRING_INIT;
    te_string            fp_mod = TE_STRING_INIT;
    te_string            fp_der = TE_STRING_INIT;
    te_mi_logger        *logger = NULL;
    const char          *newkey = "rsa:2048";
    const char          *key_name = "rsa2048";
    unsigned int         expected_bits = 2048;
    double               keygen_s;
    double               t0;
    double               period_s = 0.0;
    double               left_s = 0.0;
    double               valid_for = 0.0;
    double               point_h[MATRIX_N_POINTS];
    double               point_valid[MATRIX_N_POINTS];
    double               point_expected[MATRIX_N_POINTS];
    bool                 session_up = false;
    bool                 cert_up = false;
    unsigned int         i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(key, MATRIX_KEY_LIST);
    TEST_GET_INT_PARAM(days);
    if (days <= 0)
        TEST_FAIL("days must be positive");

    switch (key)
    {
        case MATRIX_RSA2048:
            key_name = "rsa2048";
            newkey = "rsa:2048";
            expected_bits = 2048;
            break;

        case MATRIX_RSA4096:
            key_name = "rsa4096";
            newkey = "rsa:4096";
            expected_bits = 4096;
            break;

        case MATRIX_EC256:
            key_name = "ec256";
            newkey = "ec -pkeyopt ec_paramgen_curve:prime256v1";
            expected_bits = 256;
            break;

        default:
            TEST_FAIL("Unknown key type %d", key);
    }

    memset(&cert, 0, sizeof(cert));
    te_string_append(&crt, "/tmp/mde-tls-cert-matrix-%s-%d.crt", key_name,
                     days);
    te_string_append(&keyf, "/tmp/mde-tls-cert-matrix-%s-%d.key", key_name,
                     days);

    tsapi_evo_analysis_hint(
        "A generated certificate read back by tapi_tls_cert: every fact "
        "must match what was asked and an independent openssl view. The "
        "checkend sweep must flip from valid to expired exactly at the "
        "requested validity.");

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "tls_matrix"));
    session_up = true;

    if (!tsapi_mde_have(&session, "openssl"))
        TEST_SKIP("There is no openssl on the agent");

    TEST_STEP("Make the certificate");
    t0 = tsapi_mde_now();
    CHECK_RC(tsapi_mde_sh(&session, MDE_TLS_TIMEOUT_MS * 2, &sh,
                          "openssl req -x509 -newkey %s -nodes "
                          "-keyout '%s' -out '%s' -days %d "
                          "-subj '/CN=%s' -addext "
                          "'subjectAltName=DNS:%s,DNS:*.%s'",
                          newkey, keyf.ptr, crt.ptr, days, MATRIX_NAME,
                          MATRIX_NAME, MATRIX_NAME));
    keygen_s = tsapi_mde_now() - t0;
    if (!tsapi_mde_sh_ok(&sh))
        TEST_VERDICT("openssl could not make a %s certificate", key_name);

    TEST_STEP("Read it back with tapi_tls_cert_read()");
    CHECK_RC(tsapi_mde_sh(&session, MDE_TLS_TIMEOUT_MS, &sh, "cat '%s'",
                          crt.ptr));
    if (!tsapi_mde_sh_ok(&sh) ||
        strstr(te_string_value(&sh.out), "BEGIN CERTIFICATE") == NULL)
        TEST_VERDICT("The certificate cannot be read back");

    te_string_append(&pem, "%s", te_string_value(&sh.out));
    CHECK_RC(tapi_tls_cert_read(session.factory, te_string_value(&pem),
                                MDE_TLS_TIMEOUT_MS, &cert));
    cert_up = true;
    tapi_tls_cert_log(&cert);
    TEST_ARTIFACT("%s/%dd: %u-bit key, signed with %s, %s .. %s, "
                  "fingerprint %s", key_name, days, cert.key_bits,
                  cert.signature_algorithm != NULL ?
                      cert.signature_algorithm : "?",
                  cert.not_before != NULL ? cert.not_before : "?",
                  cert.not_after != NULL ? cert.not_after : "?",
                  cert.fingerprint != NULL ? cert.fingerprint : "?");

    TEST_STEP("Check the key size");
    if (cert.key_bits != expected_bits)
        TEST_VERDICT("A %s key reads as %u bits", key_name, cert.key_bits);

    TEST_STEP("Check the names and the wildcard rule");
    if (!tapi_tls_cert_matches_name(&cert, MATRIX_NAME))
        TEST_VERDICT("The certificate does not match its own name");
    if (!tapi_tls_cert_matches_name(&cert, "www." MATRIX_NAME))
        TEST_VERDICT("The wildcard does not cover one label");
    if (tapi_tls_cert_matches_name(&cert, "a.b." MATRIX_NAME))
        TEST_VERDICT("The wildcard covers more than one label");
    if (tapi_tls_cert_matches_name(&cert, "evil.example.net"))
        TEST_VERDICT("The certificate matches a name it was not made for");

    TEST_STEP("Check self-signature and expiry flags");
    if (!cert.self_signed)
        TEST_VERDICT("A self-signed certificate does not read as one");
    if (cert.expired)
        TEST_VERDICT("A fresh certificate reads as expired");

    TEST_STEP("Check the fingerprint against a hash of the DER");
    mde_tls_fp_normalise(cert.fingerprint, &fp_mod);
    if (!mde_tls_cert_der_sha256(&session, crt.ptr, &fp_der))
        TEST_VERDICT("Cannot hash the certificate");
    if (strcmp(te_string_value(&fp_mod), te_string_value(&fp_der)) != 0)
        TEST_VERDICT("The fingerprint is not the SHA-256 of the DER");

    TEST_STEP("Check the public key against the private key");
    CHECK_RC(tsapi_mde_sh(&session, MDE_TLS_TIMEOUT_MS, &sh,
                          "a=$(openssl x509 -in '%s' -noout -pubkey | "
                          "sha256sum | cut -d' ' -f1) && "
                          "b=$(openssl pkey -in '%s' -pubout | "
                          "sha256sum | cut -d' ' -f1) && "
                          "echo \"$a $b\" && [ \"$a\" = \"$b\" ]",
                          crt.ptr, keyf.ptr));
    TEST_ARTIFACT("Public key digests (certificate, key): %s",
                  te_string_value(&sh.out));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_VERDICT("The certificate does not carry the generated key");

    TEST_STEP("Check the validity period against the dates");
    CHECK_RC(tsapi_mde_sh(&session, MDE_TLS_TIMEOUT_MS, &sh,
                          "s=$(openssl x509 -in '%s' -noout -startdate | "
                          "cut -d= -f2) && "
                          "e=$(openssl x509 -in '%s' -noout -enddate | "
                          "cut -d= -f2) && "
                          "echo $(( $(date -u -d \"$e\" +%%s) - "
                          "$(date -u -d \"$s\" +%%s) ))",
                          crt.ptr, crt.ptr));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_VERDICT("Cannot read the validity dates");
    period_s = strtod(te_string_value(&sh.out), NULL);
    valid_for = period_s / 86400.0;
    TEST_ARTIFACT("Validity period: %.0f s (%.3f day(s), asked %d)",
                  period_s, valid_for, days);
    if (period_s < days * 86400.0 - 60 || period_s > days * 86400.0 + 60)
        TEST_VERDICT("The validity period is not the requested number of "
                     "days");

    if (!mde_tls_cert_seconds_left(&session, crt.ptr, &left_s))
        TEST_VERDICT("Cannot read the time left");

    TEST_STEP("Sweep checkend around the expiry moment");
    {
        /* Offsets in hours from now, and whether it is valid then. */
        const double hours[MATRIX_N_POINTS] = {
            0, days * 12.0, days * 24.0 - 1, days * 24.0 + 1,
            days * 24.0 + 24, days * 24.0 * 2 + 24,
        };

        for (i = 0; i < MATRIX_N_POINTS; i++)
        {
            bool valid = false;

            CHECK_RC(tapi_tls_cert_checkend(session.factory,
                                            te_string_value(&pem),
                                            (unsigned int)(hours[i] * 3600),
                                            MDE_TLS_TIMEOUT_MS, &valid));
            point_h[i] = hours[i];
            point_valid[i] = valid ? 1 : 0;
            point_expected[i] = hours[i] * 3600 < left_s ? 1 : 0;
            RING("checkend +%.0f h: %s (expected %s)", hours[i],
                 valid ? "valid" : "expired",
                 point_expected[i] > 0 ? "valid" : "expired");
            if (point_valid[i] != point_expected[i])
                TEST_VERDICT("checkend disagrees with the validity period "
                             "at sweep point %u", i);
        }
    }

    TEST_STEP("Chart the certificate");
    tsapi_mde_mi_point("tls-cert-matrix", "Key size, bits",
                       TE_MI_MEAS_UNITLESS_VALUE, "key_bits", cert.key_bits,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("tls-cert-matrix", "Validity, days",
                       TE_MI_MEAS_UNITLESS_VALUE, "validity_days", valid_for,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("tls-cert-matrix", "Key generation time",
                       TE_MI_MEAS_TIME, "keygen_time", keygen_s,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (tsapi_mde_mi_create("tls-cert-matrix", &logger) == 0)
    {
        for (i = 0; i < MATRIX_N_POINTS; i++)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "hours_ahead", TE_MI_MEAS_AGGR_SINGLE,
                                  point_h[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "valid", TE_MI_MEAS_AGGR_SINGLE,
                                  point_valid[i],
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "valid_expected", TE_MI_MEAS_AGGR_SINGLE,
                                  point_expected[i],
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        te_mi_logger_add_meas_key(logger, NULL, "key", "%s", key_name);
        te_mi_logger_add_meas_key(logger, NULL, "days", "%d", days);
        tsapi_mde_mi_line(logger, "checkend",
                          "Valid N hours from now: checkend vs dates",
                          "hours_ahead", "valid", "valid_expected", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    TEST_SUCCESS;

cleanup:

    if (cert_up)
        tapi_tls_cert_free(&cert);
    if (session_up)
    {
        /* The certificate stays as evidence; the private key does not. */
        (void)tsapi_mde_sh(&session, 10000, &sh, "rm -f '%s'", keyf.ptr);
        tsapi_mde_session_fini(&session);
    }
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&crt);
    te_string_free(&pem);
    te_string_free(&keyf);
    te_string_free(&fp_mod);
    te_string_free(&fp_der);

    TEST_END;
}

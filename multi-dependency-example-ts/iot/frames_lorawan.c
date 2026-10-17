/** @file
 * @brief IoT Group
 *
 * Carry the ring's steps as LoRaWAN frames: session keys derived from a
 * root key, payload encrypted, frame signed. Every frame is checked
 * against an independent AES/CMAC computation done here with OpenSSL,
 * taken apart and decrypted again; then the counter and key failures the
 * audit exists to find are planted.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "iot/frames_lorawan"

#include "te_config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_lorawan.h"
#include "tapi_lorawan_audit.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_ring.h"
#include "iot_common.h"

#define DIR_LIST \
    { "up",   0 }, \
    { "down", 1 }

/* A test root key, nothing more. */
static const char *app_key_hex = "2B7E151628AED2A6ABF7158809CF4F3C";
static const uint8_t net_id[3] = { 0x00, 0x00, 0x13 };
static const uint8_t app_nonce[3] = { 0xA1, 0xB2, 0xC3 };
static const uint8_t dev_nonce[2] = { 0x12, 0x34 };

#define DEV_ADDR        0x26011BDAu
#define FIRST_FCNT      10
#define CTL_REUSE       0xC0FFEE01u
#define CTL_RESET       0xC0FFEE02u
#define CTL_KNOWN       0xC0FFEE03u
#define CTL_SAME        0xC0FFEE04u

/* One AES-128 block, done here and not by the module. */
static bool
ref_aes_block(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int             len = 0;
    bool            ok;

    if (ctx == NULL)
        return false;
    ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 1 &&
         EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
         EVP_EncryptUpdate(ctx, out, &len, in, 16) == 1 && len == 16;
    EVP_CIPHER_CTX_free(ctx);

    return ok;
}

/* AES-CMAC through OpenSSL's own MAC interface. */
static bool
ref_cmac(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *mac)
{
    char         cipher[] = "AES-128-CBC";
    OSSL_PARAM   params[2];
    EVP_MAC     *m = EVP_MAC_fetch(NULL, "CMAC", NULL);
    EVP_MAC_CTX *ctx = NULL;
    size_t       out_len = 0;
    bool         ok = false;

    if (m == NULL)
        return false;
    ctx = EVP_MAC_CTX_new(m);
    if (ctx != NULL)
    {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                     cipher, 0);
        params[1] = OSSL_PARAM_construct_end();
        ok = EVP_MAC_init(ctx, key, 16, params) == 1 &&
             EVP_MAC_update(ctx, data, len) == 1 &&
             EVP_MAC_final(ctx, mac, &out_len, 16) == 1 && out_len == 16;
        EVP_MAC_CTX_free(ctx);
    }
    EVP_MAC_free(m);

    return ok;
}

/* The specification's key derivation, written out independently. */
static bool
ref_session_keys(const uint8_t *app_key, tapi_lorawan_keys *keys)
{
    uint8_t block[16] = { 0 };

    block[1] = app_nonce[2];
    block[2] = app_nonce[1];
    block[3] = app_nonce[0];
    block[4] = net_id[2];
    block[5] = net_id[1];
    block[6] = net_id[0];
    block[7] = dev_nonce[1];
    block[8] = dev_nonce[0];

    block[0] = 0x01;
    if (!ref_aes_block(app_key, block, keys->nwk_skey))
        return false;
    block[0] = 0x02;

    return ref_aes_block(app_key, block, keys->app_skey);
}

/* The MIC a frame should carry: CMAC over B0 and the frame, first 4 bytes. */
static bool
ref_mic(const uint8_t *wire, size_t len, uint32_t dev_addr, uint32_t fcnt,
        bool down, const tapi_lorawan_keys *keys, uint8_t *mic)
{
    uint8_t buf[16 + TAPI_LORAWAN_MAX_PAYLOAD + 32];
    uint8_t full[16];
    unsigned int k;

    if (len > sizeof(buf) - 16)
        return false;
    memset(buf, 0, 16);
    buf[0] = 0x49;
    buf[5] = down ? 1 : 0;
    for (k = 0; k < 4; k++)
    {
        buf[6 + k] = (uint8_t)((dev_addr >> (8 * k)) & 0xff);
        buf[10 + k] = (uint8_t)((fcnt >> (8 * k)) & 0xff);
    }
    buf[15] = (uint8_t)len;
    memcpy(buf + 16, wire, len);
    if (!ref_cmac(keys->nwk_skey, buf, 16 + len, full))
        return false;
    memcpy(mic, full, TAPI_LORAWAN_MIC_LEN);

    return true;
}

/* Build one frame and return its bytes. */
static te_errno
lorawan_seal(tapi_lorawan_frame *frame, const uint8_t *plain, size_t len,
             const tapi_lorawan_keys *keys, uint8_t *wire, size_t *wire_len)
{
    te_string hex = TE_STRING_INIT;
    te_errno  rc;

    rc = tapi_lorawan_build(frame, plain, len, keys, &hex);
    if (rc == 0)
        rc = tapi_lorawan_unhex(te_string_value(&hex), wire,
                                TAPI_LORAWAN_MAX_PAYLOAD + 16, wire_len);
    te_string_free(&hex);

    return rc;
}

/* A frame for the planted controls. */
static void
ctl_frame(tapi_lorawan_frame *frame, uint32_t dev_addr, uint32_t fcnt)
{
    *frame = tapi_lorawan_default_frame;
    frame->dev_addr = dev_addr;
    frame->fcnt = fcnt;
}

int
main(int argc, char **argv)
{
    int                    fport;
    int                    down;
    int                    hops = 5;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    te_vec                 steps = TE_VEC_INIT(iot_step);
    tapi_lorawan_frame    *frames = NULL;
    tapi_lorawan_keys      keys;
    tapi_lorawan_keys      ref_keys;
    uint8_t                app_key[TAPI_LORAWAN_KEY_LEN];
    unsigned int           n_model = 0;
    unsigned int           n_trace = 0;
    unsigned int           n_steps;
    unsigned int           i;
    te_mi_logger          *logger = NULL;
    uint64_t               total_bytes = 0;
    te_string              key_hex = TE_STRING_INIT;

    TEST_START;

    tsapi_mde_report_init(&report);
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(fport);
    {
        int dir;

        TEST_GET_ENUM_PARAM(dir, DIR_LIST);
        down = (dir == 1);
    }
    TEST_GET_INT_PARAM(hops);
    TEST_GET_MDE_SEVERITY(min_severity);
    if (fport < 1 || fport > 223)
        TEST_FAIL("fport must be an application port, 1..223");

    TEST_STEP("Derive the session keys and check them independently");
    CHECK_RC(tapi_lorawan_key_parse(app_key_hex, app_key));
    CHECK_RC(tapi_lorawan_session_keys(app_key, net_id, app_nonce, dev_nonce,
                                       &keys));
    if (!ref_session_keys(app_key, &ref_keys))
        TEST_FAIL("OpenSSL could not compute the reference keys");
    if (memcmp(keys.nwk_skey, ref_keys.nwk_skey, TAPI_LORAWAN_KEY_LEN) != 0 ||
        memcmp(keys.app_skey, ref_keys.app_skey, TAPI_LORAWAN_KEY_LEN) != 0)
    {
        TEST_VERDICT("The derived session keys differ from the "
                     "specification's derivation");
    }
    if (memcmp(keys.nwk_skey, keys.app_skey, TAPI_LORAWAN_KEY_LEN) == 0)
        TEST_VERDICT("The two derived session keys are equal");
    tapi_lorawan_hex(keys.nwk_skey, TAPI_LORAWAN_KEY_LEN, &key_hex);
    RING("NwkSKey %s (test key material)", key_hex.ptr);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "iot_lorawan", dut, session_up);

    TEST_STEP("Collect the ring steps: the model's walk and cpp-demo's trace");
    CHECK_RC(iot_steps_collect(&session, &dut, hops, &steps, &n_model,
                               &n_trace));
    n_steps = te_vec_size(&steps);
    TEST_ARTIFACT("LoRaWAN payload: %u model step(s) and %u traced step(s) "
                  "of cpp-demo 1 %d, port %d, %s", n_model, n_trace, hops,
                  fport, down ? "downlink" : "uplink");
    frames = calloc(n_steps, sizeof(*frames));
    CHECK_NOT_NULL(frames);

    CHECK_RC(tsapi_mde_mi_create("tapi_lorawan", &logger));
    te_mi_logger_add_meas_key(logger, NULL, "fport", "%d", fport);
    te_mi_logger_add_meas_key(logger, NULL, "dir", "%s",
                              down ? "down" : "up");

    TEST_STEP("Build, verify and decrypt a frame per ring step");
    for (i = 0; i < n_steps; i++)
    {
        const iot_step    *step = te_vec_get(&steps, i);
        tapi_lorawan_frame sent = tapi_lorawan_default_frame;
        tapi_lorawan_frame raw;
        iot_step           back;
        uint8_t            plain[IOT_STEP_LEN];
        uint8_t            wire[TAPI_LORAWAN_MAX_PAYLOAD + 16];
        uint8_t            again[IOT_STEP_LEN];
        uint8_t            mic[TAPI_LORAWAN_MIC_LEN];
        size_t             wire_len = 0;
        const char        *diff;
        double             t0;
        double             t1;
        double             t2;
        double             t3;
        bool               verified;

        iot_step_encode(step, plain);
        sent.mtype = down ? TAPI_LORAWAN_UNCONFIRMED_DOWN :
                            TAPI_LORAWAN_UNCONFIRMED_UP;
        sent.downlink = down != 0;
        sent.dev_addr = DEV_ADDR;
        sent.fcnt = FIRST_FCNT + i;
        sent.fport = (uint8_t)fport;

        t0 = tsapi_mde_now();
        CHECK_RC(lorawan_seal(&sent, plain, sizeof(plain), &keys, wire,
                              &wire_len));
        t1 = tsapi_mde_now();
        verified = tapi_lorawan_verify(wire, wire_len, &keys);
        t2 = tsapi_mde_now();
        CHECK_RC(tapi_lorawan_parse(wire, wire_len, &keys, &frames[i]));
        t3 = tsapi_mde_now();

        if (wire_len != 9 + IOT_STEP_LEN + TAPI_LORAWAN_MIC_LEN)
            TEST_VERDICT("A LoRaWAN frame is %zu bytes, not what its fields "
                         "add up to", wire_len);
        if (!verified)
            TEST_VERDICT("A frame the module built failed its own MIC check");
        if (!ref_mic(wire, wire_len - TAPI_LORAWAN_MIC_LEN, DEV_ADDR,
                     sent.fcnt, down != 0, &keys, mic))
            TEST_FAIL("OpenSSL could not compute the reference MIC");
        if (memcmp(mic, wire + wire_len - TAPI_LORAWAN_MIC_LEN,
                   TAPI_LORAWAN_MIC_LEN) != 0)
        {
            TEST_VERDICT("The MIC on the wire differs from an independent "
                         "AES-CMAC over B0 and the frame");
        }

        if (frames[i].mtype != sent.mtype)
            TEST_VERDICT("The message type did not survive the round trip");
        if (frames[i].downlink != sent.downlink)
            TEST_VERDICT("The direction did not survive the round trip");
        if (frames[i].dev_addr != DEV_ADDR)
            TEST_VERDICT("The DevAddr did not survive the round trip");
        if (frames[i].fcnt != (sent.fcnt & 0xffff))
            TEST_VERDICT("The frame counter did not survive the round trip");
        if (frames[i].fport != fport)
            TEST_VERDICT("The port did not survive the round trip");
        if (memcmp(frames[i].mic, sent.mic, TAPI_LORAWAN_MIC_LEN) != 0)
            TEST_VERDICT("The MIC did not survive the round trip");
        if (frames[i].payload_len != IOT_STEP_LEN ||
            memcmp(frames[i].payload, plain, IOT_STEP_LEN) != 0)
        {
            TEST_VERDICT("A decrypted payload differs from what was sent");
        }

        /* Without keys the payload stays as it is on the wire. */
        CHECK_RC(tapi_lorawan_parse(wire, wire_len, NULL, &raw));
        if (memcmp(raw.payload, wire + 9, IOT_STEP_LEN) != 0 ||
            memcmp(raw.payload, plain, IOT_STEP_LEN) == 0)
        {
            TEST_VERDICT("The payload on the wire is not the encrypted one");
        }
        /* The keystream is its own inverse. */
        memcpy(again, raw.payload, IOT_STEP_LEN);
        CHECK_RC(tapi_lorawan_crypt(again, IOT_STEP_LEN, &frames[i], &keys));
        if (memcmp(again, plain, IOT_STEP_LEN) != 0)
            TEST_VERDICT("Applying the keystream again did not decrypt");

        iot_step_decode(frames[i].payload, &back);
        diff = iot_step_diff(step, &back);
        if (diff != NULL)
        {
            TEST_VERDICT("The %s of a %s ring step did not survive the "
                         "round trip", diff, iot_source2str(step->source));
        }
        total_bytes += wire_len;

        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE, "step",
                              TE_MI_MEAS_AGGR_SINGLE, i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_MEMORY, "frame_len",
                              TE_MI_MEAS_AGGR_SINGLE, wire_len,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "build_us",
                              TE_MI_MEAS_AGGR_SINGLE, (t1 - t0) * 1e6,
                              TE_MI_MEAS_MULTIPLIER_MICRO);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "verify_us",
                              TE_MI_MEAS_AGGR_SINGLE, (t2 - t1) * 1e6,
                              TE_MI_MEAS_MULTIPLIER_MICRO);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "parse_us",
                              TE_MI_MEAS_AGGR_SINGLE, (t3 - t2) * 1e6,
                              TE_MI_MEAS_MULTIPLIER_MICRO);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "value_out", TE_MI_MEAS_AGGR_SINGLE,
                              back.step.out, TE_MI_MEAS_MULTIPLIER_PLAIN);

        if (i == 0 || i == n_model)
            tapi_lorawan_frame_log(iot_source2str(step->source), &frames[i]);
    }

    tsapi_mde_mi_line(logger, "frame_len", "LoRaWAN frame length per step "
                      "(model steps, then traced steps)", "step", "frame_len",
                      NULL);
    tsapi_mde_mi_line(logger, "timing", "Build, MIC check and parse time per "
                      "frame", "step", "build_us", "verify_us", "parse_us",
                      NULL);
    tsapi_mde_mi_line(logger, "values", "Ring value carried by each frame",
                      "step", "value_out", NULL);
    te_mi_logger_destroy(logger);
    logger = NULL;
    TEST_ARTIFACT("LoRaWAN: %u frame(s), %" PRIu64 " byte(s), every MIC "
                  "matched an independent AES-CMAC", n_steps, total_bytes);

    TEST_STEP("Control: one flipped bit must fail the MIC");
    {
        tapi_lorawan_frame sent = tapi_lorawan_default_frame;
        uint8_t            plain[IOT_STEP_LEN];
        uint8_t            wire[TAPI_LORAWAN_MAX_PAYLOAD + 16];
        size_t             wire_len = 0;

        iot_step_encode(te_vec_get(&steps, 0), plain);
        sent.dev_addr = DEV_ADDR;
        sent.fcnt = FIRST_FCNT;
        sent.fport = (uint8_t)fport;
        CHECK_RC(lorawan_seal(&sent, plain, sizeof(plain), &keys, wire,
                              &wire_len));
        wire[9] ^= 0x01;
        if (!tapi_lorawan_verify(wire, wire_len, &keys))
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "lorawan.mic-mismatch",
                                     "control/corrupted",
                                     "The MIC refused the flipped bit");
        }
        tsapi_mde_report_expect(&report, "lorawan.mic-mismatch",
                                "control/corrupted");
        tsapi_mde_report_drop_subject(&report, "control/corrupted");
    }

    TEST_STEP("Controls: planted counter reuse, counter reset, a known key "
              "and equal session keys");
    {
        tapi_lorawan_frame  ctl[2];
        tapi_lorawan_policy policy = tapi_lorawan_default_policy;
        tapi_lorawan_keys   same;
        const char         *forbidden[1];

        ctl_frame(&ctl[0], CTL_REUSE, 5);
        ctl_frame(&ctl[1], CTL_REUSE, 5);
        tapi_lorawan_audit(ctl, 2, NULL, NULL, &report.cyber);
        tsapi_mde_report_expect(&report, "lorawan.counter-reuse", "C0FFEE01");
        tsapi_mde_report_drop_subject(&report, "C0FFEE01");

        ctl_frame(&ctl[0], CTL_RESET, 9);
        ctl_frame(&ctl[1], CTL_RESET, 3);
        tapi_lorawan_audit(ctl, 2, NULL, NULL, &report.cyber);
        tsapi_mde_report_expect(&report, "lorawan.counter-reset", "C0FFEE02");
        tsapi_mde_report_drop_subject(&report, "C0FFEE02");

        forbidden[0] = key_hex.ptr;
        policy.forbidden_keys = forbidden;
        policy.n_forbidden_keys = 1;
        ctl_frame(&ctl[0], CTL_KNOWN, 20);
        ctl_frame(&ctl[1], CTL_KNOWN, 21);
        tapi_lorawan_audit(ctl, 2, &keys, &policy, &report.cyber);
        tsapi_mde_report_expect(&report, "lorawan.known-key", "C0FFEE03");
        tsapi_mde_report_drop_subject(&report, "C0FFEE03");

        memcpy(same.nwk_skey, keys.nwk_skey, TAPI_LORAWAN_KEY_LEN);
        memcpy(same.app_skey, keys.nwk_skey, TAPI_LORAWAN_KEY_LEN);
        ctl_frame(&ctl[0], CTL_SAME, 30);
        ctl_frame(&ctl[1], CTL_SAME, 31);
        tapi_lorawan_audit(ctl, 2, &same, NULL, &report.cyber);
        tsapi_mde_report_expect(&report, "lorawan.same-session-keys",
                                "C0FFEE04");
        tsapi_mde_report_drop_subject(&report, "C0FFEE04");
    }

    TEST_STEP("Audit the ring's own frames, looking for the all-zero key");
    {
        tapi_lorawan_policy policy = tapi_lorawan_default_policy;
        const char         *forbidden[] = {
            "00000000000000000000000000000000",
        };

        policy.forbidden_keys = forbidden;
        policy.n_forbidden_keys = TE_ARRAY_LEN(forbidden);
        tapi_lorawan_audit(frames, n_steps, &keys, &policy, &report.cyber);
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "iot", min_severity);

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    te_string_free(&key_hex);
    free(frames);
    te_vec_free(&steps);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

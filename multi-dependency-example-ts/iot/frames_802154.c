/** @file
 * @brief IoT Group
 *
 * Carry the ring's steps as IEEE 802.15.4 data frames protected with
 * AES-CCM*, take every frame apart again and prove nothing was lost; then
 * plant the failures the security audit exists to find.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "iot/frames_802154"

#include "te_config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_802154.h"
#include "tapi_802154_sec.h"
#include "tapi_802154_audit.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_ring.h"
#include "iot_common.h"

#define SECURITY_LIST \
    { "none",        TAPI_802154_SEC_NONE },        \
    { "mic32",       TAPI_802154_SEC_MIC32 },       \
    { "enc-mic64",   TAPI_802154_SEC_ENC_MIC64 },   \
    { "enc-mic128",  TAPI_802154_SEC_ENC_MIC128 }

/* A test key, nothing more: 00 01 02 ... 0F. */
static const uint8_t test_key[TAPI_802154_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const char *test_key_hex = "000102030405060708090A0B0C0D0E0F";

/* The device carrying the ring, and the two planted for the controls. */
#define DEV_ADDR        UINT64_C(0x0011223344556677)
#define CTL_REUSE_ADDR  UINT64_C(0x00000000C0FFEE01)
#define CTL_RESET_ADDR  UINT64_C(0x00000000C0FFEE02)
#define CTL_REUSE_SUBJ  "00000000C0FFEE01"
#define CTL_RESET_SUBJ  "00000000C0FFEE02"
#define PAN_ID          0xABCD
#define COORD_ADDR      0x0001
#define FIRST_COUNTER   100

/* Fill the header fields every frame of this test shares. */
static void
frame_setup(tapi_802154_frame *frame, uint64_t src, uint8_t seq,
            tapi_802154_sec_level level, uint32_t counter)
{
    *frame = tapi_802154_default_frame;
    frame->type = TAPI_802154_DATA;
    frame->seq = seq;
    frame->ack_request = true;
    frame->panid_compression = true;
    frame->dest_mode = TAPI_802154_ADDR_SHORT;
    frame->dest_panid = PAN_ID;
    frame->dest_addr = COORD_ADDR;
    frame->src_mode = TAPI_802154_ADDR_EXTENDED;
    frame->src_panid = PAN_ID;
    frame->src_addr = src;
    frame->secured = level != TAPI_802154_SEC_NONE;
    frame->sec_level = level;
    frame->frame_counter = counter;
    frame->key_index = 1;
}

/* Turn the hex a builder appended into bytes. */
static te_errno
frame_bytes(const te_string *hex, uint8_t *buf, size_t *len)
{
    return tapi_802154_unhex(te_string_value(hex), buf,
                             TAPI_802154_MAX_FRAME, len);
}

/*
 * Build one protected frame: the header alone first (it is what CCM*
 * signs), then the payload secured over it, then the whole frame.
 */
static te_errno
frame_seal(tapi_802154_frame *frame, const uint8_t *plain, size_t plain_len,
           uint8_t *wire, size_t *wire_len)
{
    tapi_802154_frame hdr_frame = *frame;
    te_string         hex = TE_STRING_INIT;
    uint8_t           hdr[TAPI_802154_MAX_FRAME];
    size_t            hdr_len = 0;
    uint8_t           body[TAPI_802154_MAX_FRAME];
    size_t            body_len = plain_len;
    uint8_t           nonce[TAPI_802154_NONCE_LEN];
    te_errno          rc;

    rc = tapi_802154_build(&hdr_frame, NULL, 0, &hex);
    if (rc == 0)
        rc = frame_bytes(&hex, hdr, &hdr_len);
    te_string_free(&hex);
    if (rc != 0)
        return rc;
    hdr_len -= TAPI_802154_FCS_LEN;

    memcpy(body, plain, plain_len);
    tapi_802154_nonce(frame->src_addr, frame->frame_counter,
                      frame->sec_level, nonce);
    rc = tapi_802154_secure(test_key, nonce, frame->sec_level, hdr, hdr_len,
                            body, &body_len, sizeof(body));
    if (rc != 0)
        return rc;

    rc = tapi_802154_build(frame, body, body_len, &hex);
    if (rc == 0)
        rc = frame_bytes(&hex, wire, wire_len);
    te_string_free(&hex);

    return rc;
}

/*
 * Take a frame apart and open its payload. The header CCM* signed is
 * whatever precedes the payload on the wire.
 */
static te_errno
frame_open(const uint8_t *wire, size_t wire_len, tapi_802154_frame *parsed,
           uint8_t *plain, size_t *plain_len)
{
    uint8_t  nonce[TAPI_802154_NONCE_LEN];
    size_t   hdr_len;
    te_errno rc;

    rc = tapi_802154_parse(wire, wire_len, parsed);
    if (rc != 0)
        return rc;

    hdr_len = wire_len - TAPI_802154_FCS_LEN - parsed->payload_len;
    memcpy(plain, parsed->payload, parsed->payload_len);
    *plain_len = parsed->payload_len;
    tapi_802154_nonce(parsed->src_addr, parsed->frame_counter,
                      parsed->sec_level, nonce);

    return tapi_802154_unsecure(test_key, nonce, parsed->sec_level, wire,
                                hdr_len, plain, plain_len);
}

/*
 * Log a frame. tapi_802154_frame_log() is not used: its format has a
 * "%0*" field width, which the TE logger cannot print (the message is
 * lost with "Cannot print message ... EINVAL").
 */
static void
frame_log(const char *what, const tapi_802154_frame *frame)
{
    RING("%s: seq %u, %04X/%016" PRIX64 " -> %04X/%04" PRIX64 ", %s, "
         "level %u, counter %u, key %u, %zu payload byte(s), checksum %s",
         what, (unsigned int)frame->seq, (unsigned int)frame->src_panid,
         frame->src_addr, (unsigned int)frame->dest_panid, frame->dest_addr,
         frame->secured ? "secured" : "no security",
         (unsigned int)frame->sec_level, (unsigned int)frame->frame_counter,
         (unsigned int)frame->key_index, frame->payload_len,
         frame->fcs_valid ? "good" : "BAD");
}

/* Put a fresh checksum on a frame whose bytes were changed on purpose. */
static void
frame_refcs(uint8_t *wire, size_t wire_len)
{
    uint16_t fcs = tapi_802154_fcs(wire, wire_len - TAPI_802154_FCS_LEN);

    wire[wire_len - 2] = (uint8_t)(fcs & 0xff);
    wire[wire_len - 1] = (uint8_t)(fcs >> 8);
}

/* Name the first header field a parsed frame got wrong, or NULL. */
static const char *
frame_diff(const tapi_802154_frame *sent, const tapi_802154_frame *got)
{
    if (got->type != sent->type)
        return "type";
    if (got->seq != sent->seq)
        return "seq";
    if (got->ack_request != sent->ack_request)
        return "ack_request";
    if (got->panid_compression != sent->panid_compression)
        return "panid_compression";
    if (got->dest_mode != sent->dest_mode || got->dest_addr != sent->dest_addr)
        return "dest_addr";
    if (got->dest_panid != sent->dest_panid)
        return "dest_panid";
    if (got->src_mode != sent->src_mode || got->src_addr != sent->src_addr)
        return "src_addr";
    if (got->src_panid != sent->src_panid)
        return "src_panid";
    if (got->secured != sent->secured)
        return "secured";
    if (got->secured && got->sec_level != sent->sec_level)
        return "sec_level";
    if (got->secured && got->frame_counter != sent->frame_counter)
        return "frame_counter";
    if (got->secured && got->key_index != sent->key_index)
        return "key_index";
    if (!got->fcs_valid || got->fcs != sent->fcs)
        return "fcs";

    return NULL;
}

int
main(int argc, char **argv)
{
    tapi_802154_sec_level  security;
    int                    hops;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    te_vec                 steps = TE_VEC_INIT(iot_step);
    tapi_802154_frame     *frames = NULL;
    unsigned int           n_model = 0;
    unsigned int           n_trace = 0;
    unsigned int           n_steps;
    unsigned int           i;
    te_mi_logger          *logger = NULL;
    uint64_t               total_bytes = 0;
    size_t                 mic_len;
    bool                   module_blind = false;

    TEST_START;

    tsapi_mde_report_init(&report);
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(security, SECURITY_LIST);
    TEST_GET_INT_PARAM(hops);
    TEST_GET_MDE_SEVERITY(min_severity);
    mic_len = tapi_802154_mic_len(security);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "iot_802154", dut, session_up);

    TEST_STEP("Collect the ring steps: the model's walk and cpp-demo's trace");
    CHECK_RC(iot_steps_collect(&session, &dut, hops, &steps, &n_model,
                               &n_trace));
    n_steps = te_vec_size(&steps);
    TEST_ARTIFACT("802.15.4 payload: %u model step(s) and %u traced step(s) "
                  "of cpp-demo 1 %d", n_model, n_trace, hops);
    frames = calloc(n_steps, sizeof(*frames));
    CHECK_NOT_NULL(frames);

    CHECK_RC(tsapi_mde_mi_create("tapi_802154", &logger));
    te_mi_logger_add_meas_key(logger, NULL, "security", "%s",
                              test_get_param(argc, argv, "security"));
    te_mi_logger_add_meas_key(logger, NULL, "hops", "%d", hops);

    TEST_STEP("Encode every step as a protected frame and parse it back");
    for (i = 0; i < n_steps; i++)
    {
        const iot_step   *step = te_vec_get(&steps, i);
        iot_step          back;
        tapi_802154_frame sent;
        uint8_t           plain[IOT_STEP_LEN];
        uint8_t           wire[TAPI_802154_MAX_FRAME];
        size_t            wire_len = 0;
        uint8_t           opened[TAPI_802154_MAX_FRAME];
        size_t            opened_len = 0;
        const char       *diff;
        double            t0;
        double            t1;
        double            t2;
        te_errno          rc;

        iot_step_encode(step, plain);
        frame_setup(&sent, DEV_ADDR, (uint8_t)i, security,
                    FIRST_COUNTER + i);

        t0 = tsapi_mde_now();
        CHECK_RC(frame_seal(&sent, plain, sizeof(plain), wire, &wire_len));
        t1 = tsapi_mde_now();
        rc = frame_open(wire, wire_len, &frames[i], opened, &opened_len);
        t2 = tsapi_mde_now();
        if (rc != 0)
        {
            TEST_VERDICT("A %s frame could not be opened again: %r",
                         iot_source2str(step->source), rc);
        }

        /*
         * FCF+seq 3, destination PAN and short address 4, extended
         * source 8 (its PAN compressed away), security header 6.
         */
        if (wire_len != (size_t)(3 + 4 + 8 + (sent.secured ? 6 : 0) +
                                 IOT_STEP_LEN + TAPI_802154_FCS_LEN) +
                        mic_len)
        {
            TEST_VERDICT("A frame is %zu bytes, not what its fields add up "
                         "to", wire_len);
        }

        diff = frame_diff(&sent, &frames[i]);
        if (diff != NULL)
        {
            TEST_VERDICT("The %s field of a %s frame did not survive the "
                         "round trip", diff, iot_source2str(step->source));
        }

        if (frames[i].payload_len != IOT_STEP_LEN + mic_len)
            TEST_VERDICT("A parsed frame carries a payload of the wrong "
                         "length");

        if (tapi_802154_encrypts(security) &&
            memcmp(frames[i].payload, plain, IOT_STEP_LEN) == 0)
        {
            TEST_VERDICT("An encrypting security level left the payload in "
                         "the clear");
        }

        if (opened_len != IOT_STEP_LEN ||
            memcmp(opened, plain, IOT_STEP_LEN) != 0)
        {
            TEST_VERDICT("A %s step came back different after the MIC "
                         "check and decryption",
                         iot_source2str(step->source));
        }

        iot_step_decode(opened, &back);
        diff = iot_step_diff(step, &back);
        if (diff != NULL)
        {
            TEST_VERDICT("The %s of a %s ring step did not survive the "
                         "round trip", diff, iot_source2str(step->source));
        }

        /* The audit wants frames as seen, payload decrypted. */
        memcpy(frames[i].payload, opened, opened_len);
        frames[i].payload_len = opened_len;
        total_bytes += wire_len;

        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE, "step",
                              TE_MI_MEAS_AGGR_SINGLE, i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_MEMORY, "frame_len",
                              TE_MI_MEAS_AGGR_SINGLE, wire_len,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "encode_us",
                              TE_MI_MEAS_AGGR_SINGLE, (t1 - t0) * 1e6,
                              TE_MI_MEAS_MULTIPLIER_MICRO);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "parse_us",
                              TE_MI_MEAS_AGGR_SINGLE, (t2 - t1) * 1e6,
                              TE_MI_MEAS_MULTIPLIER_MICRO);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "value_out", TE_MI_MEAS_AGGR_SINGLE,
                              back.step.out, TE_MI_MEAS_MULTIPLIER_PLAIN);

        if (i == 0 || i == n_model)
            frame_log(iot_source2str(step->source), &frames[i]);
    }

    tsapi_mde_mi_line(logger, "frame_len", "802.15.4 frame length per step "
                      "(model steps, then traced steps)", "step",
                      "frame_len", NULL);
    tsapi_mde_mi_line(logger, "timing", "Encode and parse time per frame",
                      "step", "encode_us", "parse_us", NULL);
    tsapi_mde_mi_line(logger, "values", "Ring value carried by each frame",
                      "step", "value_out", NULL);
    te_mi_logger_destroy(logger);
    logger = NULL;
    TEST_ARTIFACT("802.15.4: %u frame(s), %" PRIu64 " byte(s) on the wire, "
                  "every one parsed back field for field", n_steps,
                  total_bytes);

    TEST_STEP("Control: one corrupted payload byte must fail the FCS and, "
              "on a secured frame, the MIC");
    {
        tapi_802154_frame sent;
        tapi_802154_frame parsed;
        uint8_t           plain[IOT_STEP_LEN];
        uint8_t           wire[TAPI_802154_MAX_FRAME];
        size_t            wire_len = 0;
        uint8_t           opened[TAPI_802154_MAX_FRAME];
        size_t            opened_len = 0;
        te_errno          rc;

        iot_step_encode(te_vec_get(&steps, 0), plain);
        frame_setup(&sent, DEV_ADDR, 0, security, FIRST_COUNTER);
        CHECK_RC(frame_seal(&sent, plain, sizeof(plain), wire, &wire_len));
        /* The first byte of the payload, past every header field. */
        wire[wire_len - TAPI_802154_FCS_LEN - IOT_STEP_LEN - mic_len] ^= 0x01;

        rc = frame_open(wire, wire_len, &parsed, opened, &opened_len);
        if (!parsed.fcs_valid)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "ieee802154.fcs-mismatch",
                                     "control/corrupted",
                                     "The checksum caught the flipped bit");
        }
        tsapi_mde_report_expect(&report, "ieee802154.fcs-mismatch",
                                "control/corrupted");

        /*
         * security=none has no MIC at all: the checksum is the only
         * thing that can notice, and it is checked above.
         */
        if (security != TAPI_802154_SEC_NONE)
        {
            if (TE_RC_GET_ERROR(rc) == TE_EBADMSG)
            {
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_HIGH,
                                         "ieee802154.mic-mismatch",
                                         "control/corrupted",
                                         "The integrity code refused the "
                                         "flipped bit");
                tsapi_mde_report_expect(&report, "ieee802154.mic-mismatch",
                                        "control/corrupted");
            }
            else if (rc == 0)
            {
                /*
                 * Seen with the authentication-only levels (mic32):
                 * tapi_802154_unsecure() feeds the payload to CCM as
                 * additional data and never calls EVP_CipherFinal_ex(),
                 * which is where OpenSSL checks the tag when there is no
                 * ciphertext - so the MIC is never verified.
                 */
                ERROR_VERDICT("tapi_802154_unsecure() accepted a frame with "
                              "a flipped payload bit: the MIC was not "
                              "verified");
                module_blind = true;
            }
            else
            {
                TEST_VERDICT("A frame with a flipped payload bit failed with "
                             "%r instead of a MIC mismatch", rc);
            }
        }
        tsapi_mde_report_drop_subject(&report, "control/corrupted");
    }

    if (security != TAPI_802154_SEC_NONE)
    {
        tapi_802154_frame a;
        tapi_802154_frame b;
        tapi_802154_frame parsed;
        uint8_t           plain[IOT_STEP_LEN];
        uint8_t           wa[TAPI_802154_MAX_FRAME];
        uint8_t           wb[TAPI_802154_MAX_FRAME];
        size_t            la = 0;
        size_t            lb = 0;
        uint8_t           opened[TAPI_802154_MAX_FRAME];
        size_t            opened_len = 0;
        te_errno          rc;

        TEST_STEP("Control: the MIC must cover the header - a forged "
                  "sequence number must fail it");
        /*
         * Same key, address, counter and payload; only the sequence
         * number differs. CCM* authenticates the header, so the two MICs
         * must differ.
         */
        iot_step_encode(te_vec_get(&steps, 0), plain);
        frame_setup(&a, DEV_ADDR, 1, security, FIRST_COUNTER);
        frame_setup(&b, DEV_ADDR, 2, security, FIRST_COUNTER);
        CHECK_RC(frame_seal(&a, plain, sizeof(plain), wa, &la));
        CHECK_RC(frame_seal(&b, plain, sizeof(plain), wb, &lb));
        if (la != lb)
            TEST_VERDICT("Two frames differing only in the sequence number "
                         "have different lengths");
        if (memcmp(wa + la - TAPI_802154_FCS_LEN - mic_len,
                   wb + lb - TAPI_802154_FCS_LEN - mic_len, mic_len) == 0)
        {
            /*
             * Seen with mic32: tapi_802154_secure() passes the header and
             * the payload to CCM as two pieces of additional data, and
             * OpenSSL CCM starts the CBC-MAC afresh on each - only the
             * last piece (the payload) is authenticated.
             */
            ERROR_VERDICT("The MIC does not cover the frame header: two "
                          "frames differing only in the sequence number got "
                          "the same MIC");
            module_blind = true;
        }

        /* Forge the sequence number of a and give it a valid checksum. */
        wa[2] ^= 0x01;
        frame_refcs(wa, la);
        rc = frame_open(wa, la, &parsed, opened, &opened_len);
        if (!parsed.fcs_valid)
            TEST_VERDICT("A forged frame with a recomputed checksum failed "
                         "the checksum");
        if (TE_RC_GET_ERROR(rc) == TE_EBADMSG)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "ieee802154.mic-mismatch",
                                     "control/forged-header",
                                     "The integrity code refused a forged "
                                     "sequence number behind a valid "
                                     "checksum");
            tsapi_mde_report_expect(&report, "ieee802154.mic-mismatch",
                                    "control/forged-header");
        }
        else if (rc == 0)
        {
            /* Already a verdict when the MIC is not verified at all. */
            if (!module_blind)
            {
                ERROR_VERDICT("tapi_802154_unsecure() accepted a forged "
                              "header behind a valid checksum");
                module_blind = true;
            }
        }
        else
        {
            TEST_VERDICT("A frame with a forged header failed with %r "
                         "instead of a MIC mismatch", rc);
        }
        tsapi_mde_report_drop_subject(&report, "control/forged-header");
    }

    if (tapi_802154_encrypts(security))
    {
        tapi_802154_frame a;
        tapi_802154_frame b;
        uint8_t           pa[IOT_STEP_LEN];
        uint8_t           pb[IOT_STEP_LEN];
        uint8_t           wa[TAPI_802154_MAX_FRAME];
        uint8_t           wb[TAPI_802154_MAX_FRAME];
        size_t            la = 0;
        size_t            lb = 0;
        size_t            off;
        unsigned int      k;
        bool              leaks = true;

        TEST_STEP("Control: one counter used twice leaks the plaintexts");
        iot_step_encode(te_vec_get(&steps, 0), pa);
        iot_step_encode(te_vec_get(&steps, n_steps - 1), pb);
        pb[2] ^= 0x5a;  /* make sure the two plaintexts differ */
        frame_setup(&a, DEV_ADDR, 1, security, FIRST_COUNTER);
        frame_setup(&b, DEV_ADDR, 2, security, FIRST_COUNTER);
        CHECK_RC(frame_seal(&a, pa, sizeof(pa), wa, &la));
        CHECK_RC(frame_seal(&b, pb, sizeof(pb), wb, &lb));
        off = la - TAPI_802154_FCS_LEN - IOT_STEP_LEN - mic_len;
        for (k = 0; k < IOT_STEP_LEN; k++)
        {
            if ((wa[off + k] ^ wb[off + k]) != (pa[k] ^ pb[k]))
                leaks = false;
        }
        if (!leaks)
            TEST_VERDICT("Two frames under one counter did not share a "
                         "keystream - the nonce is not what the standard "
                         "says");
        TEST_ARTIFACT("802.15.4: two ciphertexts under one counter XOR to "
                      "the XOR of their plaintexts (%u bytes checked)",
                      IOT_STEP_LEN);
    }

    TEST_STEP("Control: planted counter reuse and counter reset");
    {
        tapi_802154_frame ctl[4];
        uint32_t          counters[4] = { 7, 7, 9, 3 };
        unsigned int      k;

        for (k = 0; k < TE_ARRAY_LEN(ctl); k++)
        {
            frame_setup(&ctl[k], k < 2 ? CTL_REUSE_ADDR : CTL_RESET_ADDR,
                        (uint8_t)k, TAPI_802154_SEC_ENC_MIC128, counters[k]);
        }
        tapi_802154_audit(ctl, TE_ARRAY_LEN(ctl), NULL, &report.cyber);
        tsapi_mde_report_expect(&report, "ieee802154.counter-reuse",
                                CTL_REUSE_SUBJ);
        tsapi_mde_report_expect(&report, "ieee802154.counter-reset",
                                CTL_RESET_SUBJ);
        tsapi_mde_report_drop_subject(&report, CTL_REUSE_SUBJ);
        tsapi_mde_report_drop_subject(&report, CTL_RESET_SUBJ);
    }

    TEST_STEP("Control: the test key is on the forbidden list");
    {
        tapi_802154_policy policy = tapi_802154_default_policy;
        const char        *forbidden[] = { test_key_hex };

        policy.forbidden_keys = forbidden;
        policy.n_forbidden_keys = TE_ARRAY_LEN(forbidden);
        policy.key_in_use = test_key_hex;
        tapi_802154_audit(frames, n_steps, &policy, &report.cyber);
        tsapi_mde_report_expect(&report, "ieee802154.known-key", "network");
        tsapi_mde_report_drop_subject(&report, "network");
    }

    TEST_STEP("Audit the ring's own frames with the default policy");
    tapi_802154_audit(frames, n_steps, NULL, &report.cyber);
    /*
     * The iterations without encryption are planted on purpose: they are
     * the controls of the unsecured and weak-level checks.
     */
    if (security == TAPI_802154_SEC_NONE)
    {
        tsapi_mde_report_expect(&report, "ieee802154.unsecured-frames",
                                "network");
        tsapi_mde_report_drop_subject(&report, "network");
    }
    else if (security == TAPI_802154_SEC_MIC32)
    {
        tsapi_mde_report_expect(&report, "ieee802154.weak-security-level",
                                "network");
        tsapi_mde_report_drop_subject(&report, "network");
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "iot", min_severity);

    /* The verdicts were given where the module's security went blind. */
    if (module_blind)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    free(frames);
    te_vec_free(&steps);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

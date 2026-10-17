/** @file
 * @brief IoT Group
 *
 * Put the ring's step values on a virtual CAN bus as frames, capture them
 * with candump, decode them back and prove the round trip; CAN FD where
 * the kernel allows it; and probe a UDS session on an id nothing answers,
 * expecting silence. The vcan interface is created with sudo and removed
 * in cleanup.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "iot/can_bus"

#include "te_config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_can.h"
#include "tapi_can_audit.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_ring.h"

#define VCAN_IF         "vcan0"
#define CAN_BASE_ID     0x100   /* id = base + stage */
#define CAPTURE_PATH    "/tmp/mde-iot-can.log"

/* Encode a ring step value as eight bytes: the IEEE-754 double, big endian. */
static void
value_to_bytes(double v, uint8_t *out)
{
    uint64_t     bits;
    unsigned int i;

    memcpy(&bits, &v, sizeof(bits));
    for (i = 0; i < 8; i++)
        out[i] = (uint8_t)((bits >> (8 * (7 - i))) & 0xff);
}

static double
bytes_to_value(const uint8_t *in)
{
    uint64_t     bits = 0;
    double       v;
    unsigned int i;

    for (i = 0; i < 8; i++)
        bits |= (uint64_t)in[i] << (8 * (7 - i));
    memcpy(&v, &bits, sizeof(v));

    return v;
}

/* Bring vcan0 up through sudo; return whether it is there now. */
static bool
vcan_up(tsapi_mde_session *session)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    (void)tsapi_mde_sh(session, 20000, &res,
                       "sudo -n modprobe vcan 2>&1; "
                       "sudo -n ip link add dev %s type vcan 2>&1; "
                       "sudo -n ip link set up %s 2>&1; "
                       "ip link show %s >/dev/null 2>&1 && echo UP",
                       VCAN_IF, VCAN_IF, VCAN_IF);
    ok = res.started && strstr(te_string_value(&res.out), "UP") != NULL;
    if (!ok)
        RING("vcan setup output: %s", te_string_value(&res.out));
    tsapi_mde_sh_result_free(&res);

    return ok;
}

static void
vcan_down(tsapi_mde_session *session)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;

    (void)tsapi_mde_sh(session, 20000, &res,
                       "sudo -n ip link set down %s 2>/dev/null; "
                       "sudo -n ip link delete %s 2>/dev/null; true",
                       VCAN_IF, VCAN_IF);
    tsapi_mde_sh_result_free(&res);
}

/* Does this kernel's vcan carry CAN FD frames? Try sending one. */
static bool
vcan_has_fd(tsapi_mde_session *session)
{
    tapi_can_frame frame = tapi_can_default_frame;

    frame.id = 0x7FF;
    frame.fd = true;
    frame.len = 16;
    memset(frame.data, 0xA5, frame.len);

    return tapi_can_send(session->factory, VCAN_IF, &frame,
                         TAPI_CAN_TIMEOUT_MS) == 0;
}

int
main(int argc, char **argv)
{
    int                    hops;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    bool                   vcan_created = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    te_vec                 model = TE_VEC_INIT(tsapi_mde_step);
    te_vec                 captured = TE_VEC_INIT(tapi_can_frame);
    bool                   captured_up = false;
    tsapi_mde_sh_result    res = TSAPI_MDE_SH_RESULT_INIT;
    te_mi_logger          *logger = NULL;
    const tsapi_mde_step  *s;
    unsigned int           n_steps;
    unsigned int           i;
    bool                   have_fd;
    uint64_t               total_bytes = 0;
    double                 t0;
    double                 send_s;

    TEST_START;

    tsapi_mde_report_init(&report);
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(hops);
    TEST_GET_MDE_SEVERITY(min_severity);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "iot_can", dut, session_up);

    TEST_STEP("Skip unless can-utils is on the agent");
    if (!tsapi_mde_have(&session, "cansend") ||
        !tsapi_mde_have(&session, "candump"))
    {
        TEST_SKIP("can-utils (cansend/candump) is not installed on the "
                  "agent");
    }

    TEST_STEP("Bring up a virtual CAN interface with sudo");
    if (!vcan_up(&session))
    {
        TEST_SKIP("Could not create %s: the vcan kernel module is absent or "
                  "passwordless sudo for 'ip link add type vcan' is not "
                  "permitted", VCAN_IF);
    }
    vcan_created = true;
    if (!tapi_can_available(session.factory, VCAN_IF, TAPI_CAN_TIMEOUT_MS))
        TEST_SKIP("%s came up but will not carry a frame", VCAN_IF);

    have_fd = vcan_has_fd(&session);
    TEST_ARTIFACT("CAN: %s is up; CAN FD is %s on this kernel", VCAN_IF,
                  have_fd ? "available" : "not available");

    TEST_STEP("Predict the ring walk whose values go on the bus");
    (void)tsapi_mde_ring_predict(TSAPI_MDE_STAGE_RUST, 1.0, hops, &model);
    n_steps = te_vec_size(&model);
    CHECK_RC(tsapi_mde_mi_create("tapi_can", &logger));
    te_mi_logger_add_meas_key(logger, NULL, "interface", "%s", VCAN_IF);

    TEST_STEP("Listen, then send one frame per step, then read the capture");
    /*
     * candump logs to a file and stops itself after the frame count. It is
     * started with setsid so it lands in its own session and survives the
     * teardown of this shell job's process group; a short settle lets it
     * bind its socket before the first frame goes out. One extra frame is
     * the CAN FD variant when the kernel has it.
     */
    CHECK_RC(tsapi_mde_sh(&session, 10000, &res,
                          "rm -f '%s' '%s.pid'; "
                          "setsid candump -L -n %u '%s' > '%s' 2>&1 & "
                          "echo $! > '%s.pid'; sleep 1",
                          CAPTURE_PATH, CAPTURE_PATH,
                          n_steps + (have_fd ? 1 : 0), VCAN_IF,
                          CAPTURE_PATH, CAPTURE_PATH));
    tsapi_mde_sh_result_free(&res);

    t0 = tsapi_mde_now();
    i = 0;
    TE_VEC_FOREACH(&model, s)
    {
        tapi_can_frame frame = tapi_can_default_frame;

        frame.id = CAN_BASE_ID + s->stage;
        value_to_bytes(s->out, frame.data);
        frame.len = 8;
        CHECK_RC(tapi_can_send(session.factory, VCAN_IF, &frame,
                               TAPI_CAN_TIMEOUT_MS));
        total_bytes += frame.len;
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE, "step",
                              TE_MI_MEAS_AGGR_SINGLE, i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "can_id", TE_MI_MEAS_AGGR_SINGLE, frame.id,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "value", TE_MI_MEAS_AGGR_SINGLE, s->out,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        i++;
    }
    if (have_fd)
    {
        tapi_can_frame frame = tapi_can_default_frame;

        frame.id = CAN_BASE_ID + 0x20;
        frame.fd = true;
        frame.bitrate_switch = true;
        value_to_bytes(1.0, frame.data);
        value_to_bytes(2.0, frame.data + 8);
        frame.len = 16;
        CHECK_RC(tapi_can_send(session.factory, VCAN_IF, &frame,
                               TAPI_CAN_TIMEOUT_MS));
        total_bytes += frame.len;
    }
    send_s = tsapi_mde_now() - t0;

    /* Let candump flush and exit on its count, then collect the log. */
    (void)tsapi_mde_sh(&session, 10000, &res,
                       "for i in 1 2 3 4 5; do "
                       "kill -0 $(cat '%s.pid' 2>/dev/null) 2>/dev/null || "
                       "break; sleep 1; done; "
                       "kill $(cat '%s.pid') 2>/dev/null; true",
                       CAPTURE_PATH, CAPTURE_PATH);
    tsapi_mde_sh_result_free(&res);

    CHECK_RC(tapi_can_read_log(session.factory, CAPTURE_PATH,
                               TAPI_CAN_TIMEOUT_MS, &captured));
    captured_up = true;

    TEST_STEP("Verify the round trip step by step");
    {
        unsigned int matched = 0;

        for (i = 0; i < te_vec_size(&model); i++)
        {
            const tsapi_mde_step *step = te_vec_get(&model, i);
            const tapi_can_frame *frame;
            uint32_t              want_id = CAN_BASE_ID + step->stage;
            bool                  found = false;

            TE_VEC_FOREACH(&captured, frame)
            {
                if (frame->id != want_id || frame->len != 8 || frame->fd)
                    continue;
                if (bytes_to_value(frame->data) == step->out)
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                TEST_VERDICT("A ring step did not come back off the bus "
                             "with its id and value intact");
            }
            matched++;
        }
        if (matched != n_steps)
            TEST_VERDICT("Fewer frames came back than were sent");
        TEST_ARTIFACT("CAN: %u classic frame(s) round-tripped through %s, "
                      "%" PRIu64 " data byte(s)", matched, VCAN_IF,
                      total_bytes);

        if (have_fd)
        {
            const tapi_can_frame *frame;
            bool                  fd_ok = false;

            TE_VEC_FOREACH(&captured, frame)
            {
                if (frame->fd && frame->len == 16 &&
                    bytes_to_value(frame->data) == 1.0 &&
                    bytes_to_value(frame->data + 8) == 2.0)
                {
                    fd_ok = true;
                    break;
                }
            }
            if (!fd_ok)
                TEST_VERDICT("The CAN FD frame did not round-trip");
            TEST_ARTIFACT("CAN FD: a 16-byte frame round-tripped with the "
                          "bit-rate-switch flag");
        }
    }

    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_FREQ, "frames_per_s",
                          TE_MI_MEAS_AGGR_SINGLE,
                          send_s > 0 ? n_steps / send_s : 0,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_line(logger, "values", "Ring value per CAN frame", "step",
                      "value", NULL);
    tsapi_mde_mi_line(logger, "ids", "CAN id per step (0x100 + stage)",
                      "step", "can_id", NULL);
    te_mi_logger_destroy(logger);
    logger = NULL;

    TEST_STEP("Control: a UDS session request on an id nothing answers");
    /*
     * There is no ECU on vcan0. The probe sends DiagnosticSessionControl
     * and listens; with nothing there it must come back silent and add no
     * uds-unauthenticated finding. A finding here would mean the probe
     * imagined an answer.
     */
    {
        tapi_can_uds_result result;

        CHECK_RC(tapi_can_uds_probe(session.factory, VCAN_IF, 0x7E0, 0x7E8,
                                    &report.cyber, &result, 3000));
        if (result.reachable ||
            tsapi_mde_report_has(&report, "can.uds-unauthenticated",
                                 NULL) > 0)
        {
            TEST_VERDICT("A UDS probe on an empty bus reported an answer");
        }
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                 "can.uds-no-response", "7E0@vcan0",
                                 "No ECU answered a diagnostic request on "
                                 "the empty bus, as expected");
        TEST_ARTIFACT("CAN: UDS probe on 0x7E0 got no response on the empty "
                      "bus (correct)");
    }

    TEST_STEP("Control: a diagnostic response in a capture is a finding");
    {
        tapi_can_frame diag[2];

        diag[0] = tapi_can_default_frame;
        diag[0].id = 0x7E0;
        diag[0].len = 8;
        diag[0].data[0] = 0x02;
        diag[0].data[1] = 0x10;
        diag[0].data[2] = 0x03;
        diag[1] = tapi_can_default_frame;
        diag[1].id = 0x7E8;
        diag[1].len = 8;
        diag[1].data[0] = 0x06;
        diag[1].data[1] = 0x50;
        diag[1].data[2] = 0x03;
        tapi_can_audit_capture(diag, 2, &report.cyber);
        tsapi_mde_report_expect(&report, "can.diagnostics-on-bus", "bus");
        tsapi_mde_report_drop_subject(&report, "bus");
    }

    TEST_STEP("Audit the ring's own capture: ordinary data, nothing "
              "diagnostic");
    {
        tapi_can_frame *arr = NULL;
        size_t          n = te_vec_size(&captured);

        if (n > 0)
        {
            arr = calloc(n, sizeof(*arr));
            CHECK_NOT_NULL(arr);
            for (i = 0; i < n; i++)
                arr[i] = *(tapi_can_frame *)te_vec_get(&captured, i);
            tapi_can_audit_capture(arr, n, &report.cyber);
            free(arr);
        }
        /* can.unauthenticated is INFO and always true of plain CAN. */
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "iot", min_severity);

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    if (captured_up)
        te_vec_free(&captured);
    if (session_up)
    {
        (void)tsapi_mde_sh(&session, 10000, &res, "rm -f '%s' '%s.pid'",
                           CAPTURE_PATH, CAPTURE_PATH);
    }
    if (vcan_created)
        vcan_down(&session);
    tsapi_mde_sh_result_free(&res);
    te_vec_free(&model);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

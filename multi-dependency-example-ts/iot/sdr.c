/** @file
 * @brief IoT Group
 *
 * Software defined radio without a radio: chart what each backend claims
 * to do and what the agent has, then drive the half of tsf-sdr that needs
 * no hardware - rtl_433 decoding a recording - over synthetic IQ
 * captures whose bursts are timed by the ring's values.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "iot/sdr"

#include "te_config.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_sdr.h"
#include "tapi_sdr_replay.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_ring.h"

/* 433.92 MHz: where the remotes and sensors rtl_433 knows live. */
#define SDR_FREQ_HZ     433920000ULL
#define SDR_RATE        250000
#define SDR_SUBJECT     "433920000 Hz"
#define SDR_TIMEOUT_MS  60000

static const tapi_sdr_backend backends[] = {
    TAPI_SDR_RTL, TAPI_SDR_HACKRF, TAPI_SDR_SOAPY,
};

/* What the README's table says each backend can do. */
static const unsigned int readme_features[] = {
    TAPI_SDR_FEAT_RECEIVE,
    TAPI_SDR_FEAT_RECEIVE | TAPI_SDR_FEAT_TRANSMIT,
    TAPI_SDR_FEAT_RECEIVE,
};

/* sha256 and size of a file on the agent, as one artifact line. */
static void
file_evidence(tsapi_mde_session *session, const char *path)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;

    if (tsapi_mde_sh(session, 30000, &res,
                     "stat -c %%s '%s' && sha256sum '%s' | cut -c1-64",
                     path, path) == 0 && tsapi_mde_sh_ok(&res))
    {
        TEST_ARTIFACT("%s: size and sha256 %s", path,
                      te_string_value(&res.out));
    }
    tsapi_mde_sh_result_free(&res);
}

int
main(int argc, char **argv)
{
    int                    seconds;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    tapi_sdr_replay_opt    opt = tapi_sdr_replay_default_opt;
    tapi_sdr_backend       found = TAPI_SDR_AUTO;
    te_vec                 model = TE_VEC_INIT(tsapi_mde_step);
    te_vec                 events = TE_VEC_INIT(tapi_sdr_event);
    bool                   events_up = false;
    te_string              path_a = TE_STRING_INIT;
    te_string              path_b = TE_STRING_INIT;
    te_string              path_missing = TE_STRING_INIT;
    te_string              bursts = TE_STRING_INIT;
    tsapi_mde_sh_result    res = TSAPI_MDE_SH_RESULT_INIT;
    bool                   files_made = false;
    bool                   decode_blind = false;
    const char            *labels[TE_ARRAY_LEN(backends)];
    double                 feats[TE_ARRAY_LEN(backends)];
    double                 probe_ms[TE_ARRAY_LEN(backends)];
    double                 avail[TE_ARRAY_LEN(backends)];
    const tsapi_mde_step  *s;
    double                 t0;
    double                 decode_s;
    unsigned int           i;
    unsigned int           n_bursts = 0;

    TEST_START;

    tsapi_mde_report_init(&report);
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(seconds);
    TEST_GET_MDE_SEVERITY(min_severity);

    TEST_STEP("Check the backends' declared features against the README");
    for (i = 0; i < TE_ARRAY_LEN(backends); i++)
    {
        unsigned int f = tapi_sdr_features(backends[i]);

        labels[i] = tapi_sdr_backend2str(backends[i]);
        feats[i] = (tapi_sdr_supports(backends[i], TAPI_SDR_FEAT_RECEIVE) ?
                    1 : 0) +
                   (tapi_sdr_supports(backends[i], TAPI_SDR_FEAT_TRANSMIT) ?
                    2 : 0);
        TEST_ARTIFACT("SDR backend %s: receive %s, transmit %s", labels[i],
                      (f & TAPI_SDR_FEAT_RECEIVE) ? "yes" : "no",
                      (f & TAPI_SDR_FEAT_TRANSMIT) ? "yes" : "no");
        if (f != readme_features[i])
            TEST_VERDICT("Backend %s claims features the README does not "
                         "list", labels[i]);
    }
    if (tapi_sdr_features(TAPI_SDR_AUTO) != 0)
        TEST_VERDICT("The unresolved AUTO backend claims features");
    tsapi_mde_mi_bars("tapi_sdr", "SDR feature mask per backend "
                      "(1 = receive, 2 = transmit)", TE_MI_MEAS_UNITLESS_VALUE,
                      "features", TE_ARRAY_LEN(backends), labels, feats,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "iot_sdr", dut, session_up);

    TEST_STEP("Ask the agent for each radio");
    for (i = 0; i < TE_ARRAY_LEN(backends); i++)
    {
        bool have;

        t0 = tsapi_mde_now();
        have = tapi_sdr_available(session.factory, backends[i],
                                  SDR_TIMEOUT_MS);
        probe_ms[i] = (tsapi_mde_now() - t0) * 1e3;
        avail[i] = have ? 1 : 0;
        TEST_ARTIFACT("SDR backend %s: %s on the agent", labels[i],
                      have ? "a radio answered" : "no radio");
    }
    tsapi_mde_mi_bars("tapi_sdr", "Radio present per backend",
                      TE_MI_MEAS_UNITLESS_VALUE, "present",
                      TE_ARRAY_LEN(backends), labels, avail,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("tapi_sdr", "Detection time per backend",
                      TE_MI_MEAS_TIME, "probe_ms", TE_ARRAY_LEN(backends),
                      labels, probe_ms, TE_MI_MEAS_MULTIPLIER_MILLI);

    opt.frequency_hz = SDR_FREQ_HZ;
    opt.sample_rate_hz = SDR_RATE;
    opt.record_seconds = (unsigned int)seconds;

    if (tapi_sdr_detect(session.factory, SDR_TIMEOUT_MS, &found) == 0)
    {
        te_string live = TE_STRING_INIT;

        TEST_STEP("A radio is attached: record and decode the air");
        te_string_append(&live, "/tmp/mde-iot-sdr-live-%ds.cu8", seconds);
        opt.backend = found;
        rc = tapi_sdr_replay_record(session.factory, &opt, live.ptr,
                                    SDR_TIMEOUT_MS + seconds * 1000);
        if (rc == 0)
        {
            file_evidence(&session, live.ptr);
            CHECK_RC(tapi_sdr_decode(session.factory, &opt, live.ptr,
                                     SDR_TIMEOUT_MS, &events));
            events_up = true;
            tapi_sdr_events_log("the live recording", &events);
            tsapi_mde_mi_point("tapi_sdr", "Things decoded on the air",
                               TE_MI_MEAS_UNITLESS_VALUE, "live_events",
                               te_vec_size(&events),
                               TE_MI_MEAS_MULTIPLIER_PLAIN);
            tapi_sdr_events_free(&events);
            events_up = false;
        }
        else
        {
            WARN("Recording from %s failed: %r", tapi_sdr_backend2str(found),
                 rc);
        }
        (void)tsapi_mde_sh(&session, 10000, &res, "rm -f '%s'", live.ptr);
        te_string_free(&live);
        opt.backend = TAPI_SDR_AUTO;
    }
    else
    {
        TEST_ARTIFACT("SDR: no radio on the agent (rtl_test, hackrf_info and "
                      "SoapySDRUtil --find found none); capture and transmit "
                      "are not exercised");
    }

    TEST_STEP("Skip the recording half unless rtl_433 and python3 are there");
    if (!tsapi_mde_have(&session, "rtl_433"))
        TEST_SKIP("rtl_433 is not installed on the agent and no SDR receiver "
                  "is attached");
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("python3 is not on the agent to synthesise an IQ capture");

    TEST_STEP("Synthesise two identical IQ captures timed by the ring");
    (void)tsapi_mde_ring_predict(TSAPI_MDE_STAGE_RUST, 1.0, 7, &model);
    TE_VEC_FOREACH(&model, s)
    {
        /* Burst length in microseconds, 200..999, from the value. */
        long us = 200 + (long)fmod(fabs(s->out) * 1000.0, 800.0);

        te_string_append(&bursts, "%s%ld", n_bursts > 0 ? "," : "", us);
        n_bursts++;
    }
    te_string_append(&path_a, "/tmp/mde-iot-sdr-%ds-a.cu8", seconds);
    te_string_append(&path_b, "/tmp/mde-iot-sdr-%ds-b.cu8", seconds);
    te_string_append(&path_missing, "/tmp/mde-iot-sdr-%ds-missing.cu8",
                     seconds);
    files_made = true;
    CHECK_RC(tsapi_mde_sh(&session, 120000, &res,
        "rm -f '%s' && python3 - '%s' %d %d '%s' <<'PYEOF'\n"
        "import math, sys\n"
        "path = sys.argv[1]\n"
        "rate = int(sys.argv[2])\n"
        "secs = int(sys.argv[3])\n"
        "bursts = [int(b) for b in sys.argv[4].split(',')]\n"
        "buf = bytearray()\n"
        "for us in bursts:\n"
        "    n = rate * us // 1000000\n"
        "    for k in range(n):\n"
        "        ph = 2 * math.pi * 50000 * k / rate\n"
        "        buf += bytes((int(127.5 + 100 * math.cos(ph)),\n"
        "                      int(127.5 + 100 * math.sin(ph))))\n"
        "    buf += bytes((127, 127)) * (rate // 500)\n"
        "total = rate * secs * 2\n"
        "buf = buf[:total]\n"
        "buf += bytes((127, 127)) * ((total - len(buf)) // 2)\n"
        "open(path, 'wb').write(bytes(buf))\n"
        "PYEOF\n"
        "cp '%s' '%s' && cmp '%s' '%s'",
        path_missing.ptr, path_a.ptr, SDR_RATE, seconds, bursts.ptr,
        path_a.ptr, path_b.ptr, path_a.ptr, path_b.ptr));
    if (!tsapi_mde_sh_ok(&res))
        TEST_FAIL("Could not write the synthetic captures: %s",
                  te_string_value(&res.err));
    TEST_ARTIFACT("SDR capture: %u burst(s) of ring-timed carrier, "
                  "durations %s us, %d s at %d S/s", n_bursts, bursts.ptr,
                  seconds, SDR_RATE);
    file_evidence(&session, path_a.ptr);

    TEST_STEP("Decode the capture; silence is an answer, not a failure");
    t0 = tsapi_mde_now();
    rc = tapi_sdr_decode(session.factory, &opt, path_a.ptr, SDR_TIMEOUT_MS,
                         &events);
    decode_s = tsapi_mde_now() - t0;
    if (rc != 0)
        TEST_VERDICT("rtl_433 could not read a well-formed capture: %r", rc);
    events_up = true;
    tapi_sdr_events_log("the synthetic capture", &events);
    TEST_ARTIFACT("SDR: rtl_433 recognised %zu thing(s) in %d s of "
                  "synthetic carrier", te_vec_size(&events), seconds);
    {
        te_mi_logger *logger;

        CHECK_RC(tsapi_mde_mi_create("tapi_sdr", &logger));
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "decode_s",
                              TE_MI_MEAS_AGGR_SINGLE, decode_s,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_MEMORY, "capture_bytes",
                              TE_MI_MEAS_AGGR_SINGLE,
                              (double)SDR_RATE * 2 * seconds,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "events", TE_MI_MEAS_AGGR_SINGLE,
                              te_vec_size(&events),
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "bursts", TE_MI_MEAS_AGGR_SINGLE, n_bursts,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        /*
         * Several single values: a line graph over the sequence
         * number draws each as a point (a point view takes one).
         */
        te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                                   "decode", "rtl_433 over a synthetic " "capture");
        te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                              TE_MI_MEAS_VIEW_LINE_GRAPH,
                                              "decode", TE_MI_GRAPH_AXIS_X,
                                              TE_MI_GRAPH_AUTO_SEQNO);
        te_mi_logger_destroy(logger);
    }
    tapi_sdr_events_free(&events);
    events_up = false;

    TEST_STEP("Control: a capture that does not exist must be an error");
    /*
     * tapi_sdr_decode() tells a missing file from a silent one only by
     * rtl_433's exit status. rtl_433 22.11 (Debian bookworm) prints
     * "Opening file: ... failed!" and still exits 0, so the module can
     * take a typo in a path for "nothing decoded". The file is made sure
     * to be absent, the module is asked, and when it answers "no error"
     * rtl_433 is run directly to show what the module missed.
     */
    CHECK_RC(tsapi_mde_sh(&session, 10000, &res, "rm -f '%s' && "
                          "test ! -e '%s'", path_missing.ptr,
                          path_missing.ptr));
    if (!tsapi_mde_sh_ok(&res))
        TEST_FAIL("Could not make sure the missing capture is absent");
    rc = tapi_sdr_decode(session.factory, &opt, path_missing.ptr,
                         SDR_TIMEOUT_MS, &events);
    events_up = true;
    if (rc != 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "sdr.unreadable-capture", "control/missing",
                                 "The decoder refused a missing file: %s",
                                 te_rc_err2str(rc));
        tsapi_mde_report_expect(&report, "sdr.unreadable-capture",
                                "control/missing");
    }
    else
    {
        bool said_failed;

        if (te_vec_size(&events) != 0)
            TEST_VERDICT("tapi_sdr_decode() reported events from a capture "
                         "that does not exist");

        CHECK_RC(tsapi_mde_sh(&session, SDR_TIMEOUT_MS, &res,
                              "rtl_433 -r '%s' -s %d -F json",
                              path_missing.ptr, SDR_RATE));
        RING("rtl_433 on a missing capture, exit %d:\n%s",
             res.status.type == TAPI_JOB_STATUS_EXITED ?
                 res.status.value : -1,
             te_string_value(&res.err));
        said_failed = strstr(te_string_value(&res.err), "failed") != NULL;
        TEST_ARTIFACT("SDR: rtl_433 on a missing capture exited %s and %s",
                      tsapi_mde_sh_ok(&res) ? "with 0" : "non-zero",
                      said_failed ? "said the open failed" :
                                    "said nothing about it");
        if (said_failed)
        {
            ERROR_VERDICT("tapi_sdr_decode() took a capture that does not "
                          "exist for an empty one: rtl_433 reported the "
                          "failed open but exited with status 0");
        }
        else
        {
            ERROR_VERDICT("Neither rtl_433 nor tapi_sdr_decode() reported "
                          "a capture that does not exist");
        }
        decode_blind = true;
    }
    tapi_sdr_events_free(&events);
    events_up = false;
    tsapi_mde_report_drop_subject(&report, "control/missing");

    TEST_STEP("Control: two identical recordings must not report silence");
    /*
     * The two files are byte-identical. Whatever the decoder makes of
     * them, the comparison has to say something: "nothing decoded" when
     * it recognised nothing, "repeats itself" if it did. An empty report
     * here would be the lie by silence the module promises not to tell.
     */
    CHECK_RC(tapi_sdr_replay_compare(session.factory, &opt, path_a.ptr,
                                     path_b.ptr, SDR_TIMEOUT_MS,
                                     &report.cyber));
    tsapi_mde_report_expect(&report, "sdr.", NULL);
    while (tsapi_mde_report_has(&report, "sdr.", NULL) > 0)
    {
        const tapi_cybersec_finding *f;
        char                        *subject = NULL;

        TE_VEC_FOREACH(&report.cyber.findings, f)
        {
            if (strncmp(f->check, "sdr.", 4) == 0)
            {
                subject = strdup(f->subject);
                break;
            }
        }
        if (subject == NULL)
            break;
        TEST_ARTIFACT("SDR compare of identical captures reported about %s",
                      subject);
        tsapi_mde_report_drop_subject(&report, subject);
        free(subject);
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "iot", min_severity);

    /* The verdict was given where the decoder went blind. */
    if (decode_blind)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (events_up)
        tapi_sdr_events_free(&events);
    if (files_made && session_up)
    {
        (void)tsapi_mde_sh(&session, 10000, &res, "rm -f '%s' '%s'",
                           path_a.ptr, path_b.ptr);
    }
    tsapi_mde_sh_result_free(&res);
    te_string_free(&path_a);
    te_string_free(&path_b);
    te_string_free(&path_missing);
    te_string_free(&bursts);
    te_vec_free(&model);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

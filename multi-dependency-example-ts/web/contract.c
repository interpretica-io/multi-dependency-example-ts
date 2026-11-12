/** @file
 * @brief Web Group
 *
 * The web tier's single source of truth is web/contract/services.tab: the
 * port, the upstream and the ring symbol of each service. Read it on the
 * agent, then check the running tier keeps it: each service listens on its
 * contracted port (seen by ss or lsof, and by an HTTP answer naming the
 * service), and calls the upstream the contract names (seen in the body:
 * the upstream's own trace line, or the node's "upstream X unreachable"
 * line when the hop is cut).
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "web/contract"

#include "web_common.h"

/** Rows the contract can hold here. */
#define CONTRACT_MAX    8

/** One row of services.tab. */
typedef struct contract_row {
    char         name[64];
    unsigned int port;
    char         upstream[64];
    char         ring_lib[64];
    char         ring_symbol[64];
} contract_row;

/** How the listening sockets can be seen on the agent. */
typedef enum contract_tool {
    CONTRACT_TOOL_SS,
    CONTRACT_TOOL_LSOF,
    CONTRACT_TOOL_NONE,
} contract_tool;

/** Parse services.tab: whitespace columns, '#' comments, blank lines. */
static unsigned int
contract_parse(const char *text, contract_row *rows, unsigned int max)
{
    const char  *line = text;
    unsigned int n = 0;

    while (line != NULL && *line != '\0' && n < max)
    {
        const char *eol = strchr(line, '\n');
        const char *p = line;

        while (*p == ' ' || *p == '\t')
            p++;

        if (*p != '#' && *p != '\n' && *p != '\0' &&
            sscanf(p, "%63s %u %63s %63s %63s", rows[n].name, &rows[n].port,
                   rows[n].upstream, rows[n].ring_lib,
                   rows[n].ring_symbol) == 5)
        {
            n++;
        }

        line = eol != NULL ? eol + 1 : NULL;
    }

    return n;
}

/**
 * Check one contracted service: something listens on its port (and, when
 * the tool tells, it is the right process), and an HTTP request there is
 * answered by that service. Findings @c web.contract-port about
 * "<prefix><name>".
 *
 * @return Answer time in seconds (0 when it did not answer).
 */
static double
contract_check_port(tsapi_mde_session *session, contract_tool tool,
                    const char *prefix, const contract_row *row,
                    web_trace *trace, tapi_cybersec_report *cyber)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    web_reply           reply = WEB_REPLY_INIT;
    te_string           url = TE_STRING_INIT;
    char                subject[128];
    double              answered = 0;

    TE_SPRINTF(subject, "%s%s", prefix, row->name);

    /* View 1: the socket table. */
    if (tool != CONTRACT_TOOL_NONE)
    {
        if (tool == CONTRACT_TOOL_SS)
            tsapi_mde_sh(session, 10000, &res, "ss -ltnpH 'sport = :%u'",
                         row->port);
        else
            tsapi_mde_sh(session, 10000, &res,
                         "lsof -nP -iTCP:%u -sTCP:LISTEN", row->port);

        RING("Listening on %u:\n%s", row->port, web_str(&res.out));
        if (res.out.len == 0)
        {
            tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "web.contract-port", subject,
                                     "nothing listens on contracted port %u",
                                     row->port);
        }
        else if (tool == CONTRACT_TOOL_SS &&
                 strstr(web_str(&res.out), "users:") != NULL)
        {
            char quoted[80];

            /* ss shows the comm, at most 15 characters, in quotes. */
            TE_SPRINTF(quoted, "\"%.15s\"", row->name);
            if (strstr(web_str(&res.out), quoted) == NULL)
            {
                tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                         "web.contract-port", subject,
                                         "port %u is held by another "
                                         "process", row->port);
            }
        }
    }

    /* View 2: who answers there. */
    tsapi_mde_web_url(row->port, 1.0, 0, &url);
    if (web_get(session, "", url.ptr, 15, &reply) == 0 && reply.ran)
    {
        web_trace_parse(web_str(&reply.body), trace);
        if (reply.code != 200)
        {
            tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "web.contract-port", subject,
                                     "no HTTP 200 on contracted port %u "
                                     "(HTTP %d)", row->port, reply.code);
        }
        else if (te_vec_size(&trace->steps) == 0 ||
                 strcmp(web_node2str(((const web_step *)
                                      te_vec_get(&trace->steps, 0))->node),
                        row->name) != 0)
        {
            tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "web.contract-port", subject,
                                     "port %u does not answer as %s",
                                     row->port, row->name);
        }
        else
        {
            answered = reply.time_s;
        }
    }
    else
    {
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "web.contract-port", subject,
                                 "could not query port %u", row->port);
    }

    te_string_free(&url);
    te_string_free(&reply.body);
    tsapi_mde_sh_result_free(&res);
    return answered;
}

/**
 * Check a service calls its contracted upstream: ask it for one hop and
 * look at who comes next in the body (the upstream's own line, or this
 * node's "upstream X unreachable"). Finding @c web.contract-upstream.
 */
static void
contract_check_upstream(tsapi_mde_session *session, const contract_row *row,
                        web_trace *trace, tapi_cybersec_report *cyber)
{
    web_reply   reply = WEB_REPLY_INIT;
    te_string   url = TE_STRING_INIT;
    const char *seen = NULL;

    tsapi_mde_web_url(row->port, 1.0, 1, &url);
    if (web_get(session, "", url.ptr, 30, &reply) == 0 && reply.ran)
    {
        const web_unreach *un;

        web_trace_parse(web_str(&reply.body), trace);
        if (te_vec_size(&trace->steps) > 1)
        {
            seen = web_node2str(((const web_step *)
                                 te_vec_get(&trace->steps, 1))->node);
        }
        TE_VEC_FOREACH(&trace->unreach, un)
        {
            if (seen == NULL &&
                strcmp(web_node2str(un->node), row->name) == 0)
                seen = un->upstream;
        }

        if (seen == NULL)
        {
            tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "web.contract-upstream", row->name,
                                     "the body does not show which upstream "
                                     "was called");
        }
        else if (strcmp(seen, row->upstream) != 0)
        {
            tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "web.contract-upstream", row->name,
                                     "calls %s, the contract says %s", seen,
                                     row->upstream);
        }
        else
        {
            RING("%s calls %s, as contracted", row->name, seen);
        }
    }
    else
    {
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "web.contract-upstream", row->name,
                                 "could not query port %u", row->port);
    }

    te_string_free(&url);
    te_string_free(&reply.body);
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut = { .root = NULL };
    tsapi_mde_report    report;
    bool                report_up = false;
    tsapi_mde_web       web;
    bool                web_up = false;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    web_trace           trace = WEB_TRACE_INIT;
    contract_row        rows[CONTRACT_MAX];
    contract_row        ghost;
    contract_tool       tool;
    unsigned int        n_rows;
    double              ports[CONTRACT_MAX];
    double              answer_ms[CONTRACT_MAX];
    const char         *labels[CONTRACT_MAX];
    const char         *why;
    unsigned int        i;
    unsigned int        j;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "contract", dut, session_up);

    TEST_STEP("Skip unless the services and curl can be run");
    why = web_unavailable(&session, &dut);
    if (why != NULL)
        TEST_VERDICT("%s", why);

    TEST_STEP("Read web/contract/services.tab on the agent");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &res,
                          "cat '%s/web/contract/services.tab'", dut.root));
    if (!tsapi_mde_sh_ok(&res))
        TEST_VERDICT("web/contract/services.tab is missing");
    n_rows = contract_parse(web_str(&res.out), rows, CONTRACT_MAX);
    RING("services.tab:\n%s", web_str(&res.out));
    TEST_ARTIFACT("Contract: %u service row(s), %zu byte(s)", n_rows,
                  res.out.len);
    if (n_rows == 0)
        TEST_VERDICT("The contract has no service rows");

    TEST_STEP("Check the contract is the one the suite drives, and closes "
              "into one cycle");
    if (n_rows != TSAPI_MDE_WEB_N)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "web.contract-rows", "services.tab",
                                 "%u row(s), the suite drives %u service(s)",
                                 n_rows, TSAPI_MDE_WEB_N);
    }
    for (i = 0; i < n_rows; i++)
    {
        bool found = false;

        for (j = 0; j < n_rows; j++)
        {
            if (strcmp(rows[j].name, rows[i].upstream) == 0)
                found = true;
            if (j != i && rows[j].port == rows[i].port)
            {
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_HIGH,
                                         "web.contract-port", rows[i].name,
                                         "port %u is contracted twice",
                                         rows[i].port);
            }
        }
        if (!found)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "web.contract-upstream", rows[i].name,
                                     "upstream %s is not in the contract",
                                     rows[i].upstream);
        }
        TEST_ARTIFACT("Contract row: %s :%u -> %s, ffi %s:%s", rows[i].name,
                      rows[i].port, rows[i].upstream, rows[i].ring_lib,
                      rows[i].ring_symbol);
    }
    {
        /* Following the upstreams from the first row visits all and returns. */
        unsigned int cur = 0;
        unsigned int steps;

        for (steps = 0; steps < n_rows; steps++)
        {
            for (j = 0; j < n_rows; j++)
            {
                if (strcmp(rows[j].name, rows[cur].upstream) == 0)
                    break;
            }
            if (j == n_rows)
                break;
            cur = j;
            if (cur == 0)
                break;
        }
        if (cur != 0 || steps + 1 != n_rows)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "web.contract-cycle", "services.tab",
                                     "the upstreams do not form one cycle "
                                     "through every service");
        }
    }

    TEST_STEP("Pick the tool that shows listening sockets");
    if (tsapi_mde_have(&session, "ss"))
        tool = CONTRACT_TOOL_SS;
    else if (tsapi_mde_have(&session, "lsof"))
        tool = CONTRACT_TOOL_LSOF;
    else
        tool = CONTRACT_TOOL_NONE;
    TEST_ARTIFACT("Socket view: %s", tool == CONTRACT_TOOL_SS ? "ss" :
                  tool == CONTRACT_TOOL_LSOF ? "lsof" : "none (HTTP only)");

    TEST_STEP("Start the three HTTP services");
    web_up = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    web_chart_start(&web);
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        for (j = 0; j < n_rows; j++)
        {
            if (strcmp(rows[j].name, web.svc[i].name) == 0)
                break;
        }
        if (j == n_rows || rows[j].port != web.svc[i].port)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "web.contract-rows", web.svc[i].name,
                                     "the suite starts it on %u, the "
                                     "contract says %s", web.svc[i].port,
                                     j == n_rows ? "nothing" : "otherwise");
        }
    }

    TEST_STEP("Known-bad control: a contracted port nothing listens on must "
              "give web.contract-port");
    memset(&ghost, 0, sizeof(ghost));
    TE_STRLCPY(ghost.name, "ghost", sizeof(ghost.name));
    TE_STRLCPY(ghost.upstream, "gateway-rs", sizeof(ghost.upstream));
    ghost.port = 1;
    contract_check_port(&session, tool, "control/", &ghost, &trace,
                        &report.cyber);
    tsapi_mde_report_expect(&report, "web.contract-port", "control/ghost");
    web_report_drop_prefix(&report, "control/");

    TEST_STEP("Check every contracted port and upstream on the running tier");
    for (i = 0; i < n_rows; i++)
    {
        double t;

        t = contract_check_port(&session, tool, "", &rows[i], &trace,
                                &report.cyber);
        contract_check_upstream(&session, &rows[i], &trace, &report.cyber);

        labels[i] = rows[i].name;
        ports[i] = rows[i].port;
        answer_ms[i] = t * 1000.0;
        TEST_ARTIFACT("%s: answered on %u in %.2f ms", rows[i].name,
                      rows[i].port, answer_ms[i]);
    }

    TEST_STEP("Chart ports and answer times");
    tsapi_mde_mi_bars("web", "Contracted port per service",
                      TE_MI_MEAS_UNITLESS_VALUE, "port", n_rows, labels,
                      ports, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("web", "Answer time on the contracted port",
                      TE_MI_MEAS_LATENCY, "answer", n_rows, labels, answer_ms,
                      TE_MI_MEAS_MULTIPLIER_MILLI);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "web", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    if (web_up)
        tsapi_mde_web_stop(&web);
    web_trace_free(&trace);
    tsapi_mde_sh_result_free(&res);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

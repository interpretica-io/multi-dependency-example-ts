/** @file
 * @brief web Group
 *
 * web group prologue: record what the group needs - the three service
 * binaries, the contract file, curl and a socket viewer - and whether the
 * contracted ports are free before any test starts the tier. Nothing here
 * fails the group: the tests skip on their own.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "web/prologue"

#include "web_common.h"

int
main(int argc, char **argv)
{
    static const char *tools[] = { "curl", "ss", "lsof" };
    static const char *services[] = {
        "gateway-rs", "service-go", "service-cs",
    };
    static const unsigned int ports[] = { 8081, 8082, 8083 };

    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut = { .root = NULL };
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const char         *labels[8];
    double              have[8];
    double              busy[3];
    unsigned int        n = 0;
    unsigned int        i;
    te_errno            err;

    TEST_START;

    TEST_STEP("Prepare the web group");
    CHECK_RC(tsapi_mde_session_init(&session, "web_prologue"));
    session_up = true;

    err = tsapi_mde_dut_open(&session, &dut);
    if (err != 0)
    {
        TEST_ARTIFACT("The example is not built here: the web tests will "
                      "skip");
        TEST_SUCCESS;
    }

    TEST_STEP("Record the service binaries and the contract");
    for (i = 0; i < TE_ARRAY_LEN(services); i++)
    {
        te_string path = TE_STRING_INIT;

        te_string_append(&path, "%s/%s", dut.bin, services[i]);
        labels[n] = services[i];
        have[n] = tsapi_mde_exists(&session, path.ptr) ? 1 : 0;
        TEST_ARTIFACT("%s: %s", services[i], have[n] > 0 ? "built" :
                      "missing");
        n++;
        te_string_free(&path);
    }
    {
        te_string path = TE_STRING_INIT;

        te_string_append(&path, "%s/web/contract/services.tab", dut.root);
        labels[n] = "services.tab";
        have[n] = tsapi_mde_exists(&session, path.ptr) ? 1 : 0;
        TEST_ARTIFACT("services.tab: %s", have[n] > 0 ? "present" :
                      "missing");
        n++;
        te_string_free(&path);
    }

    TEST_STEP("Record the tools the tests drive the tier with");
    for (i = 0; i < TE_ARRAY_LEN(tools); i++)
    {
        labels[n] = tools[i];
        have[n] = tsapi_mde_have(&session, tools[i]) ? 1 : 0;
        TEST_ARTIFACT("%s: %s", tools[i], have[n] > 0 ? "available" :
                      "missing");
        n++;
    }
    if (tsapi_mde_sh(&session, 10000, &res, "curl --version | head -n 1") ==
            0 && tsapi_mde_sh_ok(&res))
        TEST_ARTIFACT("%s", web_str(&res.out));
    tsapi_mde_mi_bars("web", "Availability (1 = present)",
                      TE_MI_MEAS_UNITLESS_VALUE, "available", n, labels, have,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Check the contracted ports are free before the tests");
    for (i = 0; i < TE_ARRAY_LEN(ports); i++)
    {
        busy[i] = 0;
        if (tsapi_mde_sh(&session, 10000, &res,
                         "(ss -ltnH 'sport = :%u' 2>/dev/null || "
                         "lsof -nP -iTCP:%u -sTCP:LISTEN 2>/dev/null) | "
                         "wc -l", ports[i], ports[i]) == 0 &&
            tsapi_mde_sh_ok(&res))
            busy[i] = atoi(web_str(&res.out)) > 0 ? 1 : 0;
        if (busy[i] > 0)
            WARN("Port %u is already in use: the web tests may fail to "
                 "start %s", ports[i], services[i]);
        TEST_ARTIFACT("Port %u: %s", ports[i], busy[i] > 0 ? "busy" : "free");
    }
    tsapi_mde_mi_bars("web", "Contracted port busy before the tests (1 = "
                      "busy)", TE_MI_MEAS_UNITLESS_VALUE, "busy",
                      TE_ARRAY_LEN(ports), services, busy,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&res);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

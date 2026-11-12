/** @file
 * @brief Container Group
 *
 * Container group prologue: is there a Docker that answers, and which
 * one. Installs it when it is missing and fails when none answers.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "container/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "container_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tapi_container_opt  opt;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    double              t0;
    double              t_avail;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "ct_prologue"));
    session_up = true;

    TEST_STEP("Install Docker if it is missing and check that its daemon answers");
    TSAPI_MDE_ENSURE(session, "docker");

    TEST_STEP("Check that Docker answers");
    t0 = tsapi_mde_now();
    if (!mde_ct_docker(&session, &opt))
        TEST_VERDICT("Docker is installed and its daemon answers, but the "
                     "TE container API cannot use it");
    t_avail = tsapi_mde_now() - t0;
    tsapi_mde_mi_point("container/prologue", "Docker answer time",
                       TE_MI_MEAS_TIME, "answer_s", t_avail,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Record client and server versions");
    CHECK_RC(tsapi_mde_sh(&session, MDE_CT_TIMEOUT_MS, &sh,
                          "docker version --format "
                          "'client {{.Client.Version}} server "
                          "{{.Server.Version}} {{.Server.Os}}/"
                          "{{.Server.Arch}}'"));
    mde_ct_chomp(&sh.out);
    TEST_ARTIFACT("docker: %s", te_string_value(&sh.out));

    CHECK_RC(tsapi_mde_sh(&session, MDE_CT_TIMEOUT_MS, &sh,
                          "docker info --format "
                          "'{{.SecurityOptions}} cgroup {{.CgroupVersion}}'"));
    mde_ct_chomp(&sh.out);
    TEST_ARTIFACT("docker security options: %s", te_string_value(&sh.out));

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

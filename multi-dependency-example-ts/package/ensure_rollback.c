/** @file
 * @brief package Group
 *
 * The ensure/rollback contract of tsf-package, checked end to end on a
 * real package: pick a tiny package the agent does not have, ensure it
 * (installed, recorded, runnable, its files listed and verified clean),
 * ensure it again (no second install, no second record), then roll back
 * and check the agent is as it was - not installed, binary gone, not
 * runnable. The rollback is the deep check: it is what a cleanup section
 * relies on.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "package/ensure_rollback"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_package.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/** A package small enough to install and remove in a test. */
typedef struct er_candidate {
    const char *pkg;    /**< Package name. */
    const char *bin;    /**< A file it installs, the one that runs. */
    const char *probe;  /**< Shell command that runs it. */
    const char *expect; /**< What the probe prints when it works. */
} er_candidate;

static const er_candidate er_candidates[] = {
    { "hello",   "/usr/bin/hello",     "/usr/bin/hello",
      "Hello, world!" },
    { "cowsay",  "/usr/games/cowsay",  "/usr/games/cowsay mde-probe",
      "< mde-probe >" },
    { "cmatrix", "/usr/bin/cmatrix",   "/usr/bin/cmatrix -V",
      "CMatrix" },
    { "sl",      "/usr/games/sl",      "test -x /usr/games/sl && echo sl-ok",
      "sl-ok" },
};

/* Whether the probe of a candidate prints what it should. */
static te_errno
er_runnable(tsapi_mde_session *session, const er_candidate *c, bool *ok,
            te_string *evidence)
{
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_errno            rc;

    *ok = false;
    rc = tsapi_mde_sh(session, 30000, &sh, "%s 2>&1", c->probe);
    if (rc == 0)
    {
        *ok = strstr(te_string_value(&sh.out), c->expect) != NULL;
        if (evidence != NULL)
        {
            te_string_reset(evidence);
            te_string_append(evidence, "%s", te_string_value(&sh.out));
        }
    }
    tsapi_mde_sh_result_free(&sh);

    return rc;
}

int
main(int argc, char **argv)
{
    static const char *phase_labels[] = {
        "update", "ensure", "ensure-again", "rollback",
    };
    tsapi_mde_session   session;
    bool                session_up = false;
    tapi_package_ctx    ctx;
    bool                ctx_up = false;
    bool                rolled_back = true;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    const er_candidate *cand = NULL;
    const char         *cand_labels[TE_ARRAY_LEN(er_candidates)];
    double              cand_present[TE_ARRAY_LEN(er_candidates)];
    double              phase_s[TE_ARRAY_LEN(phase_labels)] = { 0 };
    tapi_package_info   info;
    te_vec              files = TE_VEC_INIT_AUTOPTR(char *);
    te_vec              changed = TE_VEC_INIT_AUTOPTR(char *);
    te_string           evidence = TE_STRING_INIT;
    char * const       *file;
    bool                installed;
    bool                runnable;
    bool                bin_listed = false;
    double              started;
    size_t              i;

    TEST_START;

    memset(&info, 0, sizeof(info));

    TEST_STEP("Open a session on the agent");
    rc = tsapi_mde_session_init(&session, "pkg_ensure");
    session_up = true;
    if (rc != 0)
        TEST_FAIL("Cannot open a session on the agent: %r", rc);

    TEST_STEP("Detect the package manager");
    rc = tapi_package_ctx_init(session.factory, &ctx);
    if (rc != 0)
        TEST_SKIP("No package manager on the agent");
    ctx_up = true;

    TEST_STEP("Make sure the agent may install packages");
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "if [ \"$(id -u)\" = 0 ]; then echo root; "
                          "elif sudo -n true 2>/dev/null; then echo sudo; "
                          "else echo none; fi"));
    if (strstr(te_string_value(&sh.out), "root") != NULL)
        ctx.sudo = false;
    else if (strstr(te_string_value(&sh.out), "sudo") != NULL)
        ctx.sudo = true;
    else
        TEST_SKIP("The agent is neither root nor has passwordless sudo");
    TEST_ARTIFACT("Installing as %s via %s", ctx.sudo ? "sudo" : "root",
                  tapi_package_manager2str(ctx.manager));

    TEST_STEP("Pick the first candidate package that is not installed");
    for (i = 0; i < TE_ARRAY_LEN(er_candidates); i++)
    {
        CHECK_RC(tapi_package_installed(session.factory, &ctx,
                                        er_candidates[i].pkg, &installed));
        cand_labels[i] = er_candidates[i].pkg;
        cand_present[i] = installed ? 1 : 0;
        if (installed || cand != NULL)
            continue;

        /* Absent per the manager must also mean absent per the agent. */
        CHECK_RC(er_runnable(&session, &er_candidates[i], &runnable, NULL));
        if (runnable)
        {
            WARN("%s is not installed but its probe works: not using it",
                 er_candidates[i].pkg);
            continue;
        }
        cand = &er_candidates[i];
    }
    tsapi_mde_mi_bars("package",
                      "Candidate packages installed before the test",
                      TE_MI_MEAS_UNITLESS_VALUE, "installed",
                      TE_ARRAY_LEN(er_candidates), cand_labels, cand_present,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (cand == NULL)
        TEST_SKIP("Every candidate package is already installed");
    TEST_ARTIFACT("Candidate: %s", cand->pkg);

    TEST_STEP("Refresh the package index");
    started = tsapi_mde_now();
    rc = tapi_package_update(session.factory, &ctx);
    phase_s[0] = tsapi_mde_now() - started;
    if (rc != 0)
        TEST_SKIP("Cannot refresh the package index (no network?)");

    TEST_STEP("Ensure the candidate is installed");
    started = tsapi_mde_now();
    rc = tapi_package_ensure(session.factory, &ctx, cand->pkg);
    phase_s[1] = tsapi_mde_now() - started;
    /* Whatever was recorded is undone in cleanup, even on failure. */
    rolled_back = false;
    if (rc != 0)
        TEST_SKIP("The agent cannot install packages");

    if (te_vec_size(&ctx.installed_by_us) != 1)
        TEST_VERDICT("ensure() did not record the package it installed");

    TEST_STEP("Check it is installed, listed, clean and runnable");
    CHECK_RC(tapi_package_query(session.factory, &ctx, cand->pkg, &info));
    if (!info.installed || info.version == NULL)
        TEST_VERDICT("The package is not installed after ensure()");
    TEST_ARTIFACT("%s %s (%s) installed in %.3f s", cand->pkg, info.version,
                  info.arch != NULL ? info.arch : "-", phase_s[1]);

    rc = tapi_package_files(session.factory, &ctx, cand->pkg, &files);
    if (rc == 0)
    {
        TE_VEC_FOREACH(&files, file)
        {
            if (strcmp(*file, cand->bin) == 0)
                bin_listed = true;
        }
        TEST_ARTIFACT("%s owns %zu path(s)", cand->pkg, te_vec_size(&files));
        tsapi_mde_mi_point("package", "Paths owned by the ensured package",
                           TE_MI_MEAS_UNITLESS_VALUE, "paths",
                           (double)te_vec_size(&files),
                           TE_MI_MEAS_MULTIPLIER_PLAIN);
        if (te_vec_size(&files) == 0)
            TEST_VERDICT("The installed package owns no files");
        if (!bin_listed)
            TEST_VERDICT("The file list of the package lacks its binary");
    }
    else if (TE_RC_GET_ERROR(rc) != TE_EOPNOTSUPP)
    {
        TEST_FAIL("Cannot list the files of %s: %r", cand->pkg, rc);
    }

    rc = tapi_package_verify(session.factory, &ctx, cand->pkg, &changed);
    if (rc == 0)
    {
        TEST_ARTIFACT("%s verifies with %zu changed file(s)", cand->pkg,
                      te_vec_size(&changed));
        if (te_vec_size(&changed) != 0)
            TEST_VERDICT("A freshly installed package fails verification");
    }
    else if (TE_RC_GET_ERROR(rc) != TE_EOPNOTSUPP)
    {
        TEST_FAIL("Cannot verify %s: %r", cand->pkg, rc);
    }

    CHECK_RC(er_runnable(&session, cand, &runnable, &evidence));
    RING("Probe of %s after install:\n%s", cand->pkg,
         te_string_value(&evidence));
    if (!runnable)
        TEST_VERDICT("The installed package is not runnable");

    TEST_STEP("Ensure it again: nothing must be installed or recorded");
    started = tsapi_mde_now();
    rc = tapi_package_ensure(session.factory, &ctx, cand->pkg);
    phase_s[2] = tsapi_mde_now() - started;
    if (rc != 0)
        TEST_VERDICT("ensure() of an installed package failed");
    if (te_vec_size(&ctx.installed_by_us) != 1)
        TEST_VERDICT("ensure() recorded an already installed package again");

    TEST_STEP("Roll back and check the agent is as it was");
    started = tsapi_mde_now();
    rc = tapi_package_ctx_rollback(session.factory, &ctx);
    phase_s[3] = tsapi_mde_now() - started;
    rolled_back = true;
    if (rc != 0)
        TEST_VERDICT("Rollback failed");
    if (te_vec_size(&ctx.installed_by_us) != 0)
        TEST_VERDICT("Rollback left records behind");

    CHECK_RC(tapi_package_installed(session.factory, &ctx, cand->pkg,
                                    &installed));
    if (installed)
        TEST_VERDICT("The package is still installed after rollback");
    if (tsapi_mde_exists(&session, cand->bin))
        TEST_VERDICT("The binary of the package is left after rollback");
    CHECK_RC(er_runnable(&session, cand, &runnable, NULL));
    if (runnable)
        TEST_VERDICT("The package is still runnable after rollback");

    TEST_ARTIFACT("Timings: update %.3f s, ensure %.3f s, ensure-again "
                  "%.3f s, rollback %.3f s", phase_s[0], phase_s[1],
                  phase_s[2], phase_s[3]);

    TEST_SUCCESS;

cleanup:

    if (phase_s[1] > 0 || phase_s[0] > 0)
    {
        tsapi_mde_mi_bars("package", "Time per ensure/rollback phase",
                          TE_MI_MEAS_TIME, "duration",
                          TE_ARRAY_LEN(phase_labels), phase_labels, phase_s,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    if (ctx_up && !rolled_back)
    {
        te_errno rrc = tapi_package_ctx_rollback(session.factory, &ctx);

        if (rrc != 0)
            ERROR("Cleanup rollback failed: %r", rrc);
    }
    tapi_package_info_free(&info);
    te_vec_free(&files);
    te_vec_free(&changed);
    te_string_free(&evidence);
    tsapi_mde_sh_result_free(&sh);
    if (ctx_up)
        tapi_package_ctx_fini(&ctx);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

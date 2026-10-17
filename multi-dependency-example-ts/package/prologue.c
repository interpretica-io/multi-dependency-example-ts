/** @file
 * @brief package Group
 *
 * package group prologue: which package manager the agent has and how
 * many packages it knows about. Never skips - a missing manager is
 * something the tests of the group find out and skip on themselves.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "package/prologue"

#include "te_config.h"

#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_package.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/* Architectures charted separately; anything else is "other". */
static const char *prologue_archs[] = { "amd64", "arm64", "all", "other" };

int
main(int argc, char **argv)
{
    tsapi_mde_session  session;
    bool               session_up = false;
    tapi_package_ctx   ctx;
    bool               ctx_up = false;
    te_vec             packages = TE_VEC_INIT(tapi_package_info);
    tapi_package_info *pkg;
    double             per_arch[TE_ARRAY_LEN(prologue_archs)] = { 0 };
    double             started;
    double             list_s;
    size_t             n_packages;
    unsigned int       i;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    rc = tsapi_mde_session_init(&session, "pkg_prologue");
    session_up = true;
    if (rc != 0)
        TEST_FAIL("Cannot open a session on the agent: %r", rc);

    TEST_STEP("Detect the package manager");
    rc = tapi_package_ctx_init(session.factory, &ctx);
    if (rc != 0)
    {
        TEST_ARTIFACT("Package manager: none found (%r)", rc);
        RING("No package manager on the agent: the package tests skip");
        TEST_SUCCESS;
    }
    ctx_up = true;
    TEST_ARTIFACT("Package manager: %s",
                  tapi_package_manager2str(ctx.manager));

    TEST_STEP("Count the installed packages");
    started = tsapi_mde_now();
    rc = tapi_package_list(session.factory, &ctx, &packages);
    list_s = tsapi_mde_now() - started;
    if (rc != 0)
    {
        WARN("Cannot list the installed packages: %r", rc);
        TEST_SUCCESS;
    }

    n_packages = te_vec_size(&packages);
    TE_VEC_FOREACH(&packages, pkg)
    {
        for (i = 0; i + 1 < TE_ARRAY_LEN(prologue_archs); i++)
        {
            if (pkg->arch != NULL && strcmp(pkg->arch, prologue_archs[i]) == 0)
                break;
        }
        per_arch[i]++;
    }

    TEST_ARTIFACT("Installed packages: %zu (listed in %.3f s)", n_packages,
                  list_s);
    tsapi_mde_mi_point("package", "Installed packages on the agent",
                       TE_MI_MEAS_UNITLESS_VALUE, "packages",
                       (double)n_packages, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("package", "Time to list the installed packages",
                       TE_MI_MEAS_TIME, "list", list_s,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("package", "Installed packages per architecture",
                      TE_MI_MEAS_UNITLESS_VALUE, "packages",
                      TE_ARRAY_LEN(prologue_archs), prologue_archs, per_arch,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    tapi_package_list_free(&packages);
    if (ctx_up)
        tapi_package_ctx_fini(&ctx);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

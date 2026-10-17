/** @file
 * @brief devtool Group
 *
 * Build the example's C stand-in for the C# stage
 * (csharp/stub/cscore_stub.c) with a tiny Makefile through tapi_make, and
 * check make's incremental semantics deeply: the first build runs the
 * recipe; a second one does nothing and leaves the output untouched; a
 * dry run shows nothing to do; after the source is touched a dry run shows
 * the recipe without running it, and a real run rebuilds; -B rebuilds an
 * up-to-date target; the built library exports the stage's two symbols.
 *
 * The recipe adds -D_GNU_SOURCE, which build.sh does not: the stub uses
 * RTLD_DEFAULT, which glibc only declares for _GNU_SOURCE.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "devtool/make_stub"

#include "te_config.h"

#include <string.h>

#include "tapi_test.h"
#include "tapi_file.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_make.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/** Compilers handed to make as CC. */
typedef enum ms_cc {
    MS_CC_CLANG,
    MS_CC_GCC,
} ms_cc;

#define MS_CC_LIST \
    { "clang", MS_CC_CLANG }, \
    { "gcc",   MS_CC_GCC }

/** What the recipe prints when it runs: the output file name. */
#define MS_RECIPE_MARK  "-o libcscore_stub.so"

/** The steps, in order. */
enum {
    MS_BUILD,       /**< First build. */
    MS_NOOP,        /**< Second build, nothing changed. */
    MS_DRY_CLEAN,   /**< Dry run, nothing changed. */
    MS_DRY_STALE,   /**< Dry run after touching the source. */
    MS_REBUILD,     /**< Build after touching the source. */
    MS_ALWAYS,      /**< -B on an up-to-date target. */
    MS_N,
};

static const char *ms_labels[MS_N] = {
    "build", "noop", "dry-clean", "dry-stale", "rebuild", "always",
};

/* Run make once; @p log gets stdout and stderr, @p secs its duration. */
static te_errno
ms_make(tapi_job_factory_t *factory, const char *dir, const char *cc_var,
        bool dry_run, bool always, te_string *log, double *secs)
{
    tapi_make_opt       opt = tapi_make_default_opt;
    tapi_make_app      *app = NULL;
    tapi_devtool_output output;
    const char         *variables[1] = { cc_var };
    double              started;
    te_errno            rc;

    opt.directory = dir;
    opt.variables = variables;
    opt.n_variables = 1;
    opt.dry_run = dry_run;
    opt.always_make = always;

    started = tsapi_mde_now();
    rc = tapi_make_do(factory, &opt, TAPI_DEVTOOL_TIMEOUT_MS, &app);
    *secs = tsapi_mde_now() - started;

    te_string_reset(log);
    if (app != NULL)
    {
        tapi_make_get_output(app, &output);
        te_string_append(log, "%s%s", output.out, output.err);
        tapi_make_destroy(app);
    }
    RING("make%s%s in %s:\n%s", dry_run ? " -n" : "", always ? " -B" : "",
         dir, te_string_value(log));

    return rc;
}

/* Modification time (with nanoseconds) and hash of the output. */
static te_errno
ms_stamp(tsapi_mde_session *session, const char *path, te_string *stamp)
{
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_errno            rc;

    rc = tsapi_mde_sh(session, 30000, &sh,
                      "stat -c %%y '%s' && sha256sum '%s' | cut -d' ' -f1",
                      path, path);
    te_string_reset(stamp);
    if (rc == 0 && tsapi_mde_sh_ok(&sh))
        te_string_append(stamp, "%s", te_string_value(&sh.out));
    else if (rc == 0)
        te_string_append(stamp, "(missing)");
    tsapi_mde_sh_result_free(&sh);

    return rc;
}

/* Whether two stamps are the same. */
static bool
ms_same(const te_string *a, const te_string *b)
{
    return strcmp(te_string_value(a), te_string_value(b)) == 0;
}

/* Whether make ran (or, dry, showed) the recipe. */
static double
ms_recipe(const te_string *log)
{
    return strstr(te_string_value(log), MS_RECIPE_MARK) != NULL ? 1 : 0;
}

/* Whether make said it had nothing to do. */
static bool
ms_idle(const char *log)
{
    return strstr(log, "is up to date") != NULL ||
           strstr(log, "Nothing to be done") != NULL;
}

int
main(int argc, char **argv)
{
    ms_cc               cc;
    const char         *cc_name;
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string           dir = TE_STRING_INIT;
    te_string           src = TE_STRING_INIT;
    te_string           lib = TE_STRING_INIT;
    te_string           makefile = TE_STRING_INIT;
    te_string           cc_var = TE_STRING_INIT;
    te_string           log = TE_STRING_INIT;
    te_string           stamp_built = TE_STRING_INIT;
    te_string           stamp_now = TE_STRING_INIT;
    double              secs[MS_N] = { 0 };
    double              recipes[MS_N] = { 0 };
    char                title[128];

    TEST_START;

    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(cc, MS_CC_LIST);
    cc_name = (cc == MS_CC_CLANG) ? "clang" : "gcc";

    TEST_STEP("Locate the example under test");
    TSAPI_MDE_OPEN_OR_SKIP(session, "dev_make", dut, session_up);

    if (!tsapi_mde_have(&session, "make"))
        TEST_SKIP("make is not installed on the agent");
    if (!tsapi_mde_have(&session, cc_name))
        TEST_SKIP("%s is not installed on the agent", cc_name);

    te_string_append(&src, "%s/csharp/stub/cscore_stub.c", dut.root);
    if (!tsapi_mde_exists(&session, src.ptr))
        TEST_SKIP("The C stub of the C# stage is missing");

    TEST_STEP("Put a copy of the stub and a Makefile on the agent");
    te_string_append(&dir, "/tmp/mde-devtool-make_stub-%s", cc_name);
    te_string_append(&lib, "%s/libcscore_stub.so", dir.ptr);
    te_string_append(&makefile, "%s/Makefile", dir.ptr);
    te_string_append(&cc_var, "CC=%s", cc_name);
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "rm -rf '%s' && mkdir -p '%s' && "
                          "cp '%s' '%s/stub.c'",
                          dir.ptr, dir.ptr, src.ptr, dir.ptr));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot prepare the build directory on the agent");
    CHECK_RC(tapi_file_create_ta(session.ta, makefile.ptr,
                                 "OUT := libcscore_stub.so\n"
                                 "all: $(OUT)\n"
                                 "$(OUT): stub.c\n"
                                 "\t$(CC) -shared -fPIC -O2 -D_GNU_SOURCE "
                                 "-o $(OUT) stub.c\n"));

    TEST_STEP("First build: the recipe must run");
    rc = ms_make(session.factory, dir.ptr, cc_var.ptr, false, false, &log,
                 &secs[MS_BUILD]);
    if (rc != 0)
        TEST_VERDICT("make cannot build the C stub with %s", cc_name);
    recipes[MS_BUILD] = ms_recipe(&log);
    if (recipes[MS_BUILD] == 0)
        TEST_VERDICT("The first build did not run the recipe");
    CHECK_RC(ms_stamp(&session, lib.ptr, &stamp_built));
    TEST_ARTIFACT("Built %s: %s", lib.ptr, te_string_value(&stamp_built));
    if (strcmp(te_string_value(&stamp_built), "(missing)") == 0)
        TEST_VERDICT("make reported success but produced no library");

    TEST_STEP("Second build: nothing to do, output untouched");
    CHECK_RC(ms_make(session.factory, dir.ptr, cc_var.ptr, false, false, &log,
                     &secs[MS_NOOP]));
    recipes[MS_NOOP] = ms_recipe(&log);
    if (recipes[MS_NOOP] != 0 || !ms_idle(te_string_value(&log)))
        TEST_VERDICT("An up-to-date target was rebuilt");
    CHECK_RC(ms_stamp(&session, lib.ptr, &stamp_now));
    if (!ms_same(&stamp_now, &stamp_built))
        TEST_VERDICT("An up-to-date library was touched");

    TEST_STEP("Dry run on an up-to-date tree: nothing to show");
    CHECK_RC(ms_make(session.factory, dir.ptr, cc_var.ptr, true, false, &log,
                     &secs[MS_DRY_CLEAN]));
    recipes[MS_DRY_CLEAN] = ms_recipe(&log);
    if (recipes[MS_DRY_CLEAN] != 0)
        TEST_VERDICT("A dry run of an up-to-date tree shows a recipe");

    TEST_STEP("Touch the source");
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "sleep 1 && touch '%s/stub.c'",
                          dir.ptr));

    TEST_STEP("Dry run on a stale tree: the recipe is shown, not run");
    CHECK_RC(ms_make(session.factory, dir.ptr, cc_var.ptr, true, false, &log,
                     &secs[MS_DRY_STALE]));
    recipes[MS_DRY_STALE] = ms_recipe(&log);
    if (recipes[MS_DRY_STALE] == 0)
        TEST_VERDICT("A dry run of a stale tree does not show the recipe");
    CHECK_RC(ms_stamp(&session, lib.ptr, &stamp_now));
    if (!ms_same(&stamp_now, &stamp_built))
        TEST_VERDICT("A dry run changed the library");

    TEST_STEP("Build after the touch: the recipe must run again");
    CHECK_RC(ms_make(session.factory, dir.ptr, cc_var.ptr, false, false, &log,
                     &secs[MS_REBUILD]));
    recipes[MS_REBUILD] = ms_recipe(&log);
    if (recipes[MS_REBUILD] == 0)
        TEST_VERDICT("A touched source did not trigger a rebuild");
    CHECK_RC(ms_stamp(&session, lib.ptr, &stamp_now));
    if (ms_same(&stamp_now, &stamp_built))
        TEST_VERDICT("The rebuild left the library as it was");
    TEST_ARTIFACT("Rebuilt %s: %s", lib.ptr, te_string_value(&stamp_now));

    TEST_STEP("Unconditional build (-B) of an up-to-date target");
    CHECK_RC(ms_make(session.factory, dir.ptr, cc_var.ptr, false, true, &log,
                     &secs[MS_ALWAYS]));
    recipes[MS_ALWAYS] = ms_recipe(&log);
    if (recipes[MS_ALWAYS] == 0)
        TEST_VERDICT("make -B did not run the recipe");

    TEST_STEP("The library exports the C# stage's two symbols");
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "nm -D --defined-only '%s' | "
                          "awk '$2 == \"T\" { print $3 }' | sort | "
                          "tr '\\n' ' '", lib.ptr));
    TEST_ARTIFACT("Exports of %s: %s", lib.ptr, te_string_value(&sh.out));
    if (strstr(te_string_value(&sh.out), "cs_step") == NULL ||
        strstr(te_string_value(&sh.out), "cs_weight") == NULL)
        TEST_VERDICT("The stub built by make lacks cs_step or cs_weight");

    TEST_STEP("Chart the make runs");
    TE_SPRINTF(title, "make durations (CC=%s)", cc_name);
    tsapi_mde_mi_bars("devtool", title, TE_MI_MEAS_TIME, "duration", MS_N,
                      ms_labels, secs, TE_MI_MEAS_MULTIPLIER_PLAIN);
    TE_SPRINTF(title, "Recipe run or shown per make call (CC=%s)", cc_name);
    tsapi_mde_mi_bars("devtool", title, TE_MI_MEAS_UNITLESS_VALUE, "recipe",
                      MS_N, ms_labels, recipes, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    if (session_up && dir.ptr != NULL)
    {
        tsapi_mde_sh_result rm = TSAPI_MDE_SH_RESULT_INIT;

        tsapi_mde_sh(&session, 30000, &rm, "rm -rf '%s'", dir.ptr);
        tsapi_mde_sh_result_free(&rm);
    }
    te_string_free(&dir);
    te_string_free(&src);
    te_string_free(&lib);
    te_string_free(&makefile);
    te_string_free(&cc_var);
    te_string_free(&log);
    te_string_free(&stamp_built);
    te_string_free(&stamp_now);
    tsapi_mde_sh_result_free(&sh);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

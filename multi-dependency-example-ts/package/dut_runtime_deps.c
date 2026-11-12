/** @file
 * @brief package Group
 *
 * Runtime dependencies of every binary and library of the example: the
 * shared libraries each one names (readelf -d NEEDED) and what the dynamic
 * loader resolves them to (ldd), each resolved file mapped to the package
 * that owns it (dpkg -S), and each such package confirmed installed by the
 * package manager (tapi_package). An unresolved dependency is critical;
 * the two views (NEEDED vs ldd, dpkg -S vs the package manager) must agree.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "package/dut_runtime_deps"

#include "te_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_package.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"

/** Bins + libs + the control. */
#define DEPS_MAX_ARTIFACTS  16
/** Distinct packages remembered across all artifacts. */
#define DEPS_MAX_PKGS       128
/** NEEDED entries remembered per artifact. */
#define DEPS_MAX_NEEDED     64
/** ldd entries remembered per artifact. */
#define DEPS_MAX_LDD        128

/** Where the control is planted. */
#define DEPS_CTL_DIR    "/tmp/mde-package-dut_runtime_deps"
/** Subject of the control's findings. */
#define DEPS_CTL        "control"

/*
 * One artifact's dependencies, one tagged line each:
 *   N <NEEDED entry>                     (readelf -d)
 *   L <name> <resolved path> <owner|->   (ldd, resolved)
 *   X <name>                             (ldd, "not found")
 */
#define DEPS_SCRIPT \
    "f='%s'; own() { for x in \"$1\" \"$(readlink -f \"$1\")\"; do "          \
    "for y in \"$x\" \"${x#/usr}\" \"/usr$x\"; do "                           \
    "q=$(dpkg -S \"$y\" 2>/dev/null | grep -v '^diversion' | head -n1 | "     \
    "cut -d: -f1); if [ -n \"$q\" ]; then echo \"$q\"; return; fi; "          \
    "done; done; echo -; }; "                                                 \
    "readelf -d \"$f\" 2>/dev/null | "                                        \
    "sed -n 's/.*(NEEDED).*\\[\\(.*\\)\\]/N \\1/p'; "                         \
    "ldd \"$f\" 2>&1 | while read -r a b c rest; do "                         \
    "if [ \"$b\" = '=>' ]; then case \"$c\" in "                              \
    "not) echo \"X $a\";; /*) echo \"L $a $c $(own \"$c\")\";; esac; "        \
    "else case \"$a\" in /*) echo \"L $a $a $(own \"$a\")\";; esac; fi; done"

/** Distinct packages the artifacts depend on. */
typedef struct deps_pkgs {
    char         *names[DEPS_MAX_PKGS];
    unsigned int  users[DEPS_MAX_PKGS];
    unsigned int  n;
} deps_pkgs;

/** Counts of one artifact, for the charts. */
typedef struct deps_counts {
    unsigned int needed;
    unsigned int resolved;
    unsigned int unresolved;
    unsigned int packages;
} deps_counts;

/* Remember a package, once per artifact. Return true if new for it. */
static bool
deps_pkgs_add(deps_pkgs *set, const char *name, char **seen,
              unsigned int *n_seen)
{
    unsigned int i;

    for (i = 0; i < *n_seen; i++)
    {
        if (strcmp(seen[i], name) == 0)
            return false;
    }
    if (*n_seen < DEPS_MAX_LDD)
        seen[(*n_seen)++] = strdup(name);

    for (i = 0; i < set->n; i++)
    {
        if (strcmp(set->names[i], name) == 0)
        {
            set->users[i]++;
            return true;
        }
    }
    if (set->n < DEPS_MAX_PKGS)
    {
        set->names[set->n] = strdup(name);
        set->users[set->n] = 1;
        set->n++;
    }

    return true;
}

/* Last path component. */
static const char *
deps_base(const char *path)
{
    const char *slash = strrchr(path, '/');

    return (slash != NULL) ? slash + 1 : path;
}

/*
 * Analyse one artifact: run the script, parse it, report what is wrong.
 */
static te_errno
deps_analyse(tsapi_mde_session *session, tsapi_mde_report *report,
             const tsapi_mde_dut *dut, const char *subject, const char *path,
             deps_pkgs *pkgs, deps_counts *counts)
{
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    char               *text = NULL;
    char               *line;
    char               *save = NULL;
    char               *needed[DEPS_MAX_NEEDED];
    unsigned int        n_needed = 0;
    char               *ldd_names[DEPS_MAX_LDD];
    unsigned int        n_ldd = 0;
    char               *seen[DEPS_MAX_LDD];
    unsigned int        n_seen = 0;
    unsigned int        i;
    unsigned int        j;
    te_errno            rc;

    memset(counts, 0, sizeof(*counts));

    rc = tsapi_mde_sh(session, 60000, &sh, DEPS_SCRIPT, path);
    if (rc != 0)
        goto out;
    RING("Dependencies of %s (%s):\n%s", subject, path,
         te_string_value(&sh.out));

    text = strdup(te_string_value(&sh.out));
    for (line = strtok_r(text, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        char name[512];
        char where[512];
        char owner[256];

        if (strncmp(line, "N ", 2) == 0)
        {
            if (n_needed < DEPS_MAX_NEEDED)
                needed[n_needed++] = strdup(line + 2);
            counts->needed++;
        }
        else if (strncmp(line, "X ", 2) == 0)
        {
            if (n_ldd < DEPS_MAX_LDD)
                ldd_names[n_ldd++] = strdup(line + 2);
            counts->unresolved++;
            tapi_cybersec_report_add(&report->cyber,
                                     TAPI_CYBERSEC_SEV_CRITICAL,
                                     "package.unresolved-dep", subject,
                                     "needs %s: not found by the loader",
                                     line + 2);
        }
        else if (strncmp(line, "L ", 2) == 0 &&
                 sscanf(line + 2, "%511s %511s %255s", name, where,
                        owner) == 3)
        {
            if (n_ldd < DEPS_MAX_LDD)
            {
                ldd_names[n_ldd++] = strdup(name);
                if (n_ldd < DEPS_MAX_LDD)
                    ldd_names[n_ldd++] = strdup(where);
            }
            counts->resolved++;

            if (strncmp(where, dut->root, strlen(dut->root)) == 0)
            {
                /* The example's own library: owned by the DUT, not dpkg. */
                if (deps_pkgs_add(pkgs, "(dut)", seen, &n_seen))
                    counts->packages++;
            }
            else if (strcmp(owner, "-") == 0)
            {
                tapi_cybersec_report_add(&report->cyber,
                                         TAPI_CYBERSEC_SEV_INFO,
                                         "package.unowned-dep", subject,
                                         "%s resolves to %s, which no "
                                         "package owns", name, where);
            }
            else if (deps_pkgs_add(pkgs, owner, seen, &n_seen))
            {
                counts->packages++;
            }
        }
    }

    /* Every NEEDED entry must be in the loader's view, by name or file. */
    for (i = 0; i < n_needed; i++)
    {
        bool found = false;

        for (j = 0; j < n_ldd && !found; j++)
        {
            found = strcmp(needed[i], ldd_names[j]) == 0 ||
                    strcmp(deps_base(needed[i]),
                           deps_base(ldd_names[j])) == 0;
        }
        if (!found)
        {
            tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "package.view-mismatch", subject,
                                     "NEEDED %s is missing from the ldd view",
                                     needed[i]);
        }
    }

    TEST_ARTIFACT("%s: %u NEEDED, %u resolved, %u not found, %u package(s)",
                  subject, counts->needed, counts->resolved,
                  counts->unresolved, counts->packages);

out:
    for (i = 0; i < n_needed; i++)
        free(needed[i]);
    for (i = 0; i < n_ldd; i++)
        free(ldd_names[i]);
    for (i = 0; i < n_seen; i++)
        free(seen[i]);
    free(text);
    tsapi_mde_sh_result_free(&sh);

    return rc;
}

/* Chart: NEEDED, resolved and packages per artifact, one line each. */
static void
deps_chart(size_t n, const char * const *labels, const deps_counts *counts)
{
    te_mi_logger *logger;
    char          key[16];
    size_t        i;

    if (n == 0 || tsapi_mde_mi_create("package", &logger) != 0)
        return;

    for (i = 0; i < n; i++)
    {
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "index", TE_MI_MEAS_AGGR_SINGLE, (double)i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "needed", TE_MI_MEAS_AGGR_SINGLE,
                              counts[i].needed, TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "resolved", TE_MI_MEAS_AGGR_SINGLE,
                              counts[i].resolved,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "packages", TE_MI_MEAS_AGGR_SINGLE,
                              counts[i].packages,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        TE_SPRINTF(key, "x%zu", i);
        te_mi_logger_add_meas_key(logger, NULL, key, "%s", labels[i]);
    }

    tsapi_mde_mi_line(logger, "deps", "Runtime dependencies per artifact",
                      "index", "needed", "resolved", "packages", NULL);
    te_mi_logger_destroy(logger);
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity min_sev;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    bool                   dut_up = false;
    tapi_package_ctx       ctx;
    bool                   ctx_up = false;
    tsapi_mde_report       report;
    bool                   report_up = false;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    deps_pkgs              pkgs;
    deps_pkgs              ctl_pkgs;
    deps_counts            counts[DEPS_MAX_ARTIFACTS];
    deps_counts            ctl_counts;
    const char            *labels[DEPS_MAX_ARTIFACTS];
    double                 users[DEPS_MAX_PKGS];
    te_string              path = TE_STRING_INIT;
    size_t                 n = 0;
    unsigned int           i;

    TEST_START;

    memset(&pkgs, 0, sizeof(pkgs));
    memset(&ctl_pkgs, 0, sizeof(ctl_pkgs));
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Locate the example under test");
    dut_up = true;
    TSAPI_MDE_OPEN_OR_SKIP(session, "pkg_deps", dut, session_up);

    if (!tsapi_mde_have(&session, "readelf") ||
        !tsapi_mde_have(&session, "ldd"))
        TEST_VERDICT("readelf or ldd is missing on the agent");

    rc = tapi_package_ctx_init(session.factory, &ctx);
    if (rc != 0)
        TEST_SKIP("No package manager on the agent");
    ctx_up = true;

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Analyse every binary and library of the example");
    for (i = 0; i < tsapi_mde_dut_n_bins + tsapi_mde_dut_n_libs; i++)
    {
        const char *name;

        te_string_reset(&path);
        if (i < tsapi_mde_dut_n_bins)
        {
            name = tsapi_mde_dut_bins[i];
            te_string_append(&path, "%s/%s", dut.bin, name);
        }
        else
        {
            name = tsapi_mde_dut_libs[i - tsapi_mde_dut_n_bins];
            tsapi_mde_dut_lib_path(&dut, name, &path);
        }

        if (!tsapi_mde_exists(&session, path.ptr))
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                     "package.artifact-missing", name,
                                     "%s is not built", path.ptr);
            continue;
        }
        if (n >= DEPS_MAX_ARTIFACTS)
            break;

        CHECK_RC(deps_analyse(&session, &report, &dut, name, path.ptr, &pkgs,
                              &counts[n]));
        labels[n] = name;
        n++;
    }
    if (n == 0)
        TEST_VERDICT("None of the example's artifacts is built");

    TEST_STEP("Confirm every owning package with the package manager");
    for (i = 0; i < pkgs.n; i++)
    {
        tapi_package_info info;

        users[i] = pkgs.users[i];
        if (strcmp(pkgs.names[i], "(dut)") == 0)
        {
            TEST_ARTIFACT("Dependency package (dut): used by %u artifact(s)",
                          pkgs.users[i]);
            continue;
        }

        rc = tapi_package_query(session.factory, &ctx, pkgs.names[i], &info);
        if (rc != 0)
        {
            tapi_package_info_free(&info);
            TEST_FAIL("Cannot query package %s: %r", pkgs.names[i], rc);
        }
        if (!info.installed)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "package.view-mismatch", pkgs.names[i],
                                     "dpkg -S names it as an owner, the "
                                     "package manager says it is not "
                                     "installed");
        }
        TEST_ARTIFACT("Dependency package %s %s: used by %u artifact(s)",
                      pkgs.names[i],
                      info.version != NULL ? info.version : "(not installed)",
                      pkgs.users[i]);
        tapi_package_info_free(&info);
    }

    TEST_STEP("Known-bad control: a library whose dependency was deleted");
    CHECK_RC(tsapi_mde_sh(&session, 120000, &sh,
                          "set -e; rm -rf " DEPS_CTL_DIR "; "
                          "mkdir -p " DEPS_CTL_DIR "; cd " DEPS_CTL_DIR "; "
                          "printf 'int ghost(void) { return 1; }\\n' > g.c; "
                          "printf 'int ghost(void);\\n"
                          "int host(void) { return ghost(); }\\n' > c.c; "
                          "cc -shared -fPIC -Wl,-soname,libmde_ghost.so "
                          "-o libmde_ghost.so g.c; "
                          "cc -shared -fPIC -o control.so c.c -L. "
                          "-lmde_ghost; rm -f libmde_ghost.so"));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot plant the control: %s", te_string_value(&sh.err));

    CHECK_RC(deps_analyse(&session, &report, &dut, DEPS_CTL,
                          DEPS_CTL_DIR "/control.so", &ctl_pkgs,
                          &ctl_counts));
    if (ctl_counts.needed == 0)
        TEST_VERDICT("readelf found no NEEDED entry in the control");
    tsapi_mde_report_expect(&report, "package.unresolved-dep", DEPS_CTL);
    tsapi_mde_report_drop_subject(&report, DEPS_CTL);

    TEST_STEP("Chart the dependencies");
    deps_chart(n, labels, counts);
    tsapi_mde_mi_bars("package", "Artifacts using each dependency package",
                      TE_MI_MEAS_UNITLESS_VALUE, "artifacts", pkgs.n,
                      (const char * const *)pkgs.names, users,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("package", "Distinct dependency packages",
                       TE_MI_MEAS_UNITLESS_VALUE, "packages", pkgs.n,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("%zu artifact(s) analysed, %u distinct package(s)", n,
                  pkgs.n);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "package", min_sev);

    TEST_SUCCESS;

cleanup:

    if (session_up)
    {
        tsapi_mde_sh_result rm = TSAPI_MDE_SH_RESULT_INIT;

        tsapi_mde_sh(&session, 30000, &rm, "rm -rf " DEPS_CTL_DIR);
        tsapi_mde_sh_result_free(&rm);
    }
    for (i = 0; i < pkgs.n; i++)
        free(pkgs.names[i]);
    for (i = 0; i < ctl_pkgs.n; i++)
        free(ctl_pkgs.names[i]);
    te_string_free(&path);
    tsapi_mde_sh_result_free(&sh);
    if (report_up)
        tsapi_mde_report_free(&report);
    if (ctx_up)
        tapi_package_ctx_fini(&ctx);
    if (dut_up)
        tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

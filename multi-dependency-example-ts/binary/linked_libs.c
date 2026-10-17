/** @file
 * @brief Binary Group
 *
 * What each artifact of the example links, against what it is expected
 * to link.
 *
 * Two lists are checked. The allow-list is the C and C++ runtime, the
 * Python runtime the Python stage embeds, the dynamic loader and the ring
 * itself: anything else is a @c binary.unexpected-lib finding. The ring
 * edges are the build-time links the example documents (README, build
 * order table): an edge that is missing from DT_NEEDED is a
 * @c binary.missing-ring-link finding - with the injected defects some
 * linkers drop a library whose only use was compiled away.
 *
 * The NEEDED list comes from tapi_binscan; readelf on the agent gives a
 * second view of the same list, and the two must be equal
 * (@c binary.view-mismatch).
 *
 * Known-bad control: a binary built on the agent with two libraries
 * nobody allowed must come back with @c binary.unexpected-lib for both.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "binary/linked_libs"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "binary_common.h"

/** Sonames (prefixes) an artifact of the example may need. */
static const char * const allowed_prefixes[] = {
    "libc.so", "libm.so", "libstdc++.so", "libgcc_s.so", "libpython3",
    "libdl.so", "libpthread.so", "ld-linux",
    "libpycore.", "libcscore.", "libgocore.", "librustcore.", "libcppcore.",
};

/** A build-time link of the example (README: build order, web tier). */
typedef struct ring_link {
    const char *from;   /**< Artifact. */
    const char *to;     /**< Library it links, without the extension. */
} ring_link;

static const ring_link ring_links[] = {
    { "libgocore",   "libcscore" },
    { "librustcore", "libgocore" },
    { "librustcore", "libcscore" },
    { "libcppcore",  "librustcore" },
    { "libcppcore",  "libpycore" },
    { "cpp-demo",    "libcppcore" },
    { "cpp-demo",    "librustcore" },
    { "gateway-rs",  "librustcore" },
    { "service-go",  "libcscore" },
};

/** Whether a soname is on the allow-list. */
static bool
lib_allowed(const char *soname)
{
    size_t i;

    for (i = 0; i < TE_ARRAY_LEN(allowed_prefixes); i++)
    {
        if (strncmp(soname, allowed_prefixes[i],
                    strlen(allowed_prefixes[i])) == 0)
            return true;
    }

    return false;
}

/** Whether a NEEDED list holds a library (by name without extension). */
static bool
lib_needed(const tapi_binscan_info *info, const char *name)
{
    size_t len = strlen(name);
    size_t i;

    for (i = 0; i < info->n_needed; i++)
    {
        if (strncmp(info->needed[i], name, len) == 0 &&
            info->needed[i][len] == '.')
            return true;
    }

    return false;
}

/**
 * Read the NEEDED list with readelf, one soname per line.
 *
 * @param session   Session.
 * @param path      Binary on the agent.
 * @param list      String to append the list to.
 *
 * @return @c true if readelf ran.
 */
static bool
lib_readelf_needed(tsapi_mde_session *session, const char *path,
                   te_string *list)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    ok = tsapi_mde_sh(session, 60000, &res,
                      "readelf -dW '%s' | "
                      "sed -n 's/.*(NEEDED).*\\[\\(.*\\)\\].*/\\1/p'",
                      path) == 0 && tsapi_mde_sh_ok(&res);
    if (ok)
        te_string_append(list, "%s", te_string_value(&res.out));
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/** Whether a line-per-entry list holds an exact line. */
static bool
lib_list_has(const char *list, const char *entry)
{
    size_t      len = strlen(entry);
    const char *p = list;

    while (p != NULL && *p != '\0')
    {
        const char *eol = strchr(p, '\n');
        size_t      l = (eol != NULL) ? (size_t)(eol - p) : strlen(p);

        if (l == len && strncmp(p, entry, len) == 0)
            return true;
        p = (eol != NULL) ? eol + 1 : NULL;
    }

    return false;
}

/** Number of lines of a line-per-entry list. */
static unsigned int
lib_list_count(const char *list)
{
    unsigned int n = 0;
    const char  *p = list;

    while (p != NULL && *p != '\0')
    {
        const char *eol = strchr(p, '\n');

        if (eol != p)
            n++;
        p = (eol != NULL) ? eol + 1 : NULL;
    }

    return n;
}

/**
 * Check one binary's NEEDED list against the allow-list.
 *
 * @param report    Report.
 * @param name      Subject prefix.
 * @param info      binscan view.
 *
 * @return Number of unexpected libraries.
 */
static unsigned int
lib_check_allowed(tsapi_mde_report *report, const char *name,
                  const tapi_binscan_info *info)
{
    unsigned int n = 0;
    size_t       i;

    for (i = 0; i < info->n_needed; i++)
    {
        te_string subject = TE_STRING_INIT;

        if (lib_allowed(info->needed[i]))
            continue;

        te_string_append(&subject, "%s/%s", name, info->needed[i]);
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_LOW,
                                 "binary.unexpected-lib", subject.ptr,
                                 "%s needs %s, which is not on the "
                                 "allow-list of the example", name,
                                 info->needed[i]);
        te_string_free(&subject);
        n++;
    }

    return n;
}

/** Where the control is built. */
#define LIBS_CONTROL_SRC    "/tmp/mde-binary-libs-control.c"
#define LIBS_CONTROL_BIN    "/tmp/mde-binary-libs-control"

int
main(int argc, char **argv)
{
    tapi_cybersec_severity  min_sev;
    tsapi_mde_session       session = { .ta = NULL };
    tsapi_mde_dut           dut = { .root = NULL };
    bool                    session_up = false;
    tsapi_mde_report        report;
    bool                    report_up = false;
    bool                    have_readelf;
    bool                    control_built = false;
    const char             *cc;
    te_string               log = TE_STRING_INIT;
    const char             *names[BINARY_N_ARTIFACTS];
    double                  vals[3 * BINARY_N_ARTIFACTS];
    const char             *lines[] = { "needed", "unexpected",
                                        "ring_links" };
    unsigned int            n = 0;
    unsigned int            n_unexpected = 0;
    unsigned int            n_missing_links = 0;
    unsigned int            i;
    size_t                  k;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "binary_libs", dut, session_up);
    have_readelf = tsapi_mde_have(&session, "readelf");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Known-bad control: a binary that links what nobody allowed");
    cc = binary_compiler(&session);
    if (cc == NULL)
    {
        WARN("There is no C compiler on the agent: no control");
    }
    else
    {
        tapi_binscan_info cinfo;

        control_built = binary_build_c(&session, cc, LIBS_CONTROL_SRC,
                                       LIBS_CONTROL_BIN,
                                       "-O2 -Wl,--no-as-needed -lresolv "
                                       "-lutil",
                                       "int main(void) { return 0; }",
                                       &log);
        if (!control_built)
        {
            RING("Control build output:\n%s", te_string_value(&log));
            TEST_VERDICT("Cannot build the known-bad control binary");
        }

        CHECK_RC(tapi_binscan_inspect(session.ta, LIBS_CONTROL_BIN, &cinfo));
        for (k = 0; k < cinfo.n_needed; k++)
            RING("control needs %s", cinfo.needed[k]);
        i = lib_check_allowed(&report, BINARY_CONTROL_NAME, &cinfo);
        TEST_ARTIFACT("control: %zu NEEDED, %u unexpected", cinfo.n_needed,
                      i);

        /* libresolv is the planted one; its soname carries a version. */
        {
            te_string subject = TE_STRING_INIT;

            te_string_append(&subject, "%s/", BINARY_CONTROL_NAME);
            for (k = 0; k < cinfo.n_needed; k++)
            {
                if (strncmp(cinfo.needed[k], "libresolv.", 10) == 0)
                {
                    te_string_append(&subject, "%s", cinfo.needed[k]);
                    break;
                }
            }
            if (k == cinfo.n_needed)
                te_string_append(&subject, "libresolv");
            tsapi_mde_report_expect(&report, "binary.unexpected-lib",
                                    subject.ptr);
            te_string_free(&subject);
        }

        for (k = 0; k < cinfo.n_needed; k++)
        {
            te_string subject = TE_STRING_INIT;

            te_string_append(&subject, "%s/%s", BINARY_CONTROL_NAME,
                             cinfo.needed[k]);
            tsapi_mde_report_drop_subject(&report, subject.ptr);
            te_string_free(&subject);
        }
        tapi_binscan_info_free(&cinfo);
    }

    TEST_STEP("Read what every artifact links");
    for (i = 0; i < binary_n_artifacts() && i < BINARY_N_ARTIFACTS; i++)
    {
        const char        *name = binary_artifact_name(i);
        te_string          path = TE_STRING_INIT;
        te_string          list = TE_STRING_INIT;
        te_string          joined = TE_STRING_INIT;
        tapi_binscan_info  info;
        unsigned int       unexpected;
        unsigned int       links = 0;
        size_t             j;

        TEST_SUBSTEP("What %s links", name);
        binary_artifact_path(&dut, name, &path);
        if (!tsapi_mde_exists(&session, path.ptr))
        {
            TEST_ARTIFACT("%s: not built", name);
            te_string_free(&path);
            continue;
        }

        CHECK_RC(tapi_binscan_inspect(session.ta, path.ptr, &info));

        for (j = 0; j < info.n_needed; j++)
            te_string_append(&joined, "%s%s", j == 0 ? "" : " ",
                             info.needed[j]);
        TEST_ARTIFACT("%s needs: %s", name,
                      info.n_needed == 0 ? "(nothing)" : joined.ptr);

        unexpected = lib_check_allowed(&report, name, &info);
        n_unexpected += unexpected;

        for (j = 0; j < TE_ARRAY_LEN(ring_links); j++)
        {
            te_string subject = TE_STRING_INIT;

            if (strcmp(ring_links[j].from, name) != 0)
                continue;
            if (lib_needed(&info, ring_links[j].to))
            {
                links++;
                continue;
            }

            te_string_append(&subject, "%s/%s", name, ring_links[j].to);
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                     "binary.missing-ring-link",
                                     subject.ptr,
                                     "the example documents a build-time "
                                     "link from %s to %s, and DT_NEEDED "
                                     "does not have it", name,
                                     ring_links[j].to);
            te_string_free(&subject);
            n_missing_links++;
        }

        if (have_readelf && lib_readelf_needed(&session, path.ptr, &list))
        {
            bool same = lib_list_count(list.ptr) == info.n_needed;

            for (j = 0; same && j < info.n_needed; j++)
                same = lib_list_has(list.ptr, info.needed[j]);

            if (!same)
            {
                te_string subject = TE_STRING_INIT;

                te_string_append(&subject, "%s:needed", name);
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_MEDIUM,
                                         "binary.view-mismatch",
                                         subject.ptr,
                                         "tapi_binscan reads '%s', readelf "
                                         "reads '%s'", joined.ptr,
                                         te_string_value(&list));
                te_string_free(&subject);
            }
        }

        names[n] = name;
        vals[0 * BINARY_N_ARTIFACTS + n] = (double)info.n_needed;
        vals[1 * BINARY_N_ARTIFACTS + n] = unexpected;
        vals[2 * BINARY_N_ARTIFACTS + n] = links;
        n++;

        tapi_binscan_info_free(&info);
        te_string_free(&path);
        te_string_free(&list);
        te_string_free(&joined);
    }

    if (n == 0)
        TEST_SKIP("None of the artifacts is built");

    TEST_STEP("Chart the libraries per artifact");
    for (i = 1; i < 3; i++)
    {
        unsigned int j;

        for (j = 0; j < n; j++)
            vals[i * n + j] = vals[i * BINARY_N_ARTIFACTS + j];
    }
    binary_mi_matrix("binscan", "libs",
                     "Libraries per artifact: needed, unexpected, "
                     "ring links present", n, names, TE_ARRAY_LEN(lines),
                     lines, vals);
    TEST_ARTIFACT("%u artifact(s): %u unexpected librar(ies), %u missing "
                  "ring link(s)", n, n_unexpected, n_missing_links);

    TEST_STEP("Decide");
    TSAPI_MDE_REPORT_GATE(&report, "binary", min_sev);

    TEST_SUCCESS;

cleanup:

    if (control_built)
        binary_rm(&session, LIBS_CONTROL_SRC " " LIBS_CONTROL_BIN);
    if (report_up)
        tsapi_mde_report_free(&report);
    te_string_free(&log);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

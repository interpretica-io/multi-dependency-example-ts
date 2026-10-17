/** @file
 * @brief Graph Group
 *
 * Check that the ring libraries are linked into the cyclic graph the way the
 * build intends - no running code involved, only the libraries' own metadata
 * (readelf -d / nm -D on ELF, otool -L / nm on Mach-O).
 *
 * The cycle is broken at build time by two tricks (see the example's README):
 * Python and C# bind late and link against no ring library, Go leaves
 * cpp_weight undefined, and the rest link normally:
 *
 *   libcppcore  -> librustcore, libpycore
 *   librustcore -> libgocore, libcscore
 *   libgocore   -> libcscore              (cpp_weight undefined)
 *   libcscore, libpycore -> nothing of the ring
 *
 * Each iteration keeps the historical verdict of its relation, and checks
 * the whole edge table of all five libraries on top: missing and unexpected
 * edges, the cycle-break symbol and where it resolves, and (on ELF) that
 * every ring dependency resolves to a file through ldd.
 *
 * These are properties of the build, not of the arithmetic, so the injected
 * defect does not change them: this group passes on the as-shipped example.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "graph/links"

#include "graph_common.h"

typedef enum graph_relation {
    GRAPH_RUST,     /**< librustcore links libgocore and libcscore. */
    GRAPH_CPP,      /**< libcppcore links librustcore and libpycore. */
    GRAPH_GO,       /**< libgocore links libcscore. */
    GRAPH_GO_UNDEF, /**< libgocore leaves cpp_weight undefined. */
} graph_relation;

#define GRAPH_RELATION_LIST \
    { "rust",     GRAPH_RUST     }, \
    { "cpp",      GRAPH_CPP      }, \
    { "go",       GRAPH_GO       }, \
    { "go-undef", GRAPH_GO_UNDEF }

/** Whether the build intends a load-time edge @p from -> @p to. */
static bool
links_expected(tsapi_mde_stage from, tsapi_mde_stage to)
{
    switch (from)
    {
        case TSAPI_MDE_STAGE_CPP:
            return to == TSAPI_MDE_STAGE_RUST || to == TSAPI_MDE_STAGE_PY;
        case TSAPI_MDE_STAGE_RUST:
            return to == TSAPI_MDE_STAGE_GO || to == TSAPI_MDE_STAGE_CS;
        case TSAPI_MDE_STAGE_GO:
            return to == TSAPI_MDE_STAGE_CS;
        default:
            return false;
    }
}

/**
 * Check the whole load-time edge table into the report; subjects are
 * "<prefix><from>-><to>".
 */
static void
links_check_edges(const graph_libs *libs, const char *prefix,
                  tapi_cybersec_report *cyber)
{
    unsigned int from;
    unsigned int to;
    char         subject[96];

    for (from = 0; from < TSAPI_MDE_STAGE_N; from++)
    {
        const graph_lib *lib = &libs->lib[from];

        if (!lib->present)
            continue;

        for (to = 0; to < TSAPI_MDE_STAGE_N; to++)
        {
            bool want = links_expected(from, to);
            bool have = to != from && graph_needs(lib, to);

            TE_SPRINTF(subject, "%s%s->%s", prefix,
                       tsapi_mde_stage2str(from), tsapi_mde_stage2str(to));
            if (want && !have)
            {
                tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                         "graph.missing-edge", subject,
                                         "%s does not need lib%score",
                                         lib->name, tsapi_mde_stage2str(to));
            }
            else if (!want && have)
            {
                /* go -> cpp at load time would undo the cycle break. */
                bool breaks = from == TSAPI_MDE_STAGE_GO &&
                              to == TSAPI_MDE_STAGE_CPP;

                tapi_cybersec_report_add(cyber,
                                         breaks ? TAPI_CYBERSEC_SEV_HIGH :
                                                  TAPI_CYBERSEC_SEV_MEDIUM,
                                         "graph.unexpected-edge", subject,
                                         "%s needs lib%score, the build "
                                         "does not intend it", lib->name,
                                         tsapi_mde_stage2str(to));
            }
        }
    }
}

int
main(int argc, char **argv)
{
    graph_relation     relation;
    tsapi_mde_session  session;
    bool               session_up = false;
    tsapi_mde_dut      dut = { .root = NULL };
    tsapi_mde_report   report;
    bool               report_up = false;
    graph_libs         libs;
    graph_libs         planted;
    bool               libs_up = false;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    tsapi_mde_stage    self = TSAPI_MDE_STAGE_GO;
    tsapi_mde_stage    deps[2] = { TSAPI_MDE_STAGE_CS, TSAPI_MDE_STAGE_CS };
    unsigned int       n_deps = 0;
    bool               relation_bad = false;
    const char        *why;
    unsigned int       i;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;
    graph_libs_init(&libs);
    graph_libs_init(&planted);
    libs_up = true;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(relation, GRAPH_RELATION_LIST);
    switch (relation)
    {
        case GRAPH_RUST:
            self = TSAPI_MDE_STAGE_RUST;
            deps[n_deps++] = TSAPI_MDE_STAGE_GO;
            deps[n_deps++] = TSAPI_MDE_STAGE_CS;
            break;

        case GRAPH_CPP:
            self = TSAPI_MDE_STAGE_CPP;
            deps[n_deps++] = TSAPI_MDE_STAGE_RUST;
            deps[n_deps++] = TSAPI_MDE_STAGE_PY;
            break;

        case GRAPH_GO:
            self = TSAPI_MDE_STAGE_GO;
            deps[n_deps++] = TSAPI_MDE_STAGE_CS;
            break;

        case GRAPH_GO_UNDEF:
            self = TSAPI_MDE_STAGE_GO;
            break;

        default:
            TEST_FAIL("Unknown relation value: %d", relation);
    }

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "graph", dut, session_up);

    TEST_STEP("Skip unless the binary tools are available");
    why = graph_tools_unavailable(&session,
                                  strcmp(dut.dylib_ext, "dylib") == 0);
    if (why != NULL)
        TEST_SKIP("%s", why);

    TEST_STEP("Read the linkage of every ring library");
    CHECK_RC(graph_libs_load(&session, &dut, &libs));
    if (!libs.lib[self].present)
        TEST_SKIP("%s is missing - build the example first",
                  libs.lib[self].name);
    graph_chart_counts(&libs);
    for (i = 0; i < TSAPI_MDE_STAGE_N; i++)
    {
        if (!libs.lib[i].present)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "graph.missing-lib", libs.lib[i].name,
                                     "not built");
        }
        TEST_ARTIFACT("%s: %u NEEDED, %u undefined, %u exported",
                      libs.lib[i].name, libs.lib[i].n_needed,
                      libs.lib[i].n_undef, libs.lib[i].n_exports);
    }

    TEST_STEP("Known-bad control: librustcore without libgocore must give "
              "graph.missing-edge");
    planted.macho = libs.macho;
    for (i = 0; i < TSAPI_MDE_STAGE_N; i++)
    {
        planted.lib[i].stage = i;
        planted.lib[i].present = true;
        graph_lib_name(i, planted.lib[i].name, sizeof(planted.lib[i].name));
    }
    te_string_append(&planted.lib[TSAPI_MDE_STAGE_RUST].needed,
                     "\nlibcscore.so\nlibc.so.6\n");
    links_check_edges(&planted, "control/", &report.cyber);
    tsapi_mde_report_expect(&report, "graph.missing-edge",
                            "control/rust->go");
    graph_report_drop_prefix(&report, "control/");

    TEST_STEP("Check the relation under test");
    for (i = 0; i < n_deps; i++)
    {
        bool have = graph_needs(&libs.lib[self], deps[i]);

        RING("%s -> lib%score: %s", libs.lib[self].name,
             tsapi_mde_stage2str(deps[i]), have ? "linked" : "NOT linked");
        if (!have && !relation_bad)
        {
            char dep[32];

            graph_lib_name(deps[i], dep, sizeof(dep));
            ERROR_VERDICT("%s does not link %s", libs.lib[self].name, dep);
            relation_bad = true;
        }
    }
    if (relation == GRAPH_GO_UNDEF &&
        !graph_list_has(&libs.lib[TSAPI_MDE_STAGE_GO].undef, "cpp_weight"))
    {
        ERROR_VERDICT("libgocore does not leave cpp_weight undefined "
                      "(the build-time cycle break is gone)");
        relation_bad = true;
    }

    TEST_STEP("Check every library's load-time edges");
    links_check_edges(&libs, "", &report.cyber);

    TEST_STEP("Check the cycle-break symbol and where it resolves");
    if (libs.lib[TSAPI_MDE_STAGE_GO].present &&
        !graph_list_has(&libs.lib[TSAPI_MDE_STAGE_GO].undef, "cpp_weight"))
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "graph.cycle-break", "libgocore:cpp_weight",
                                 "cpp_weight is not left undefined");
    }
    if (libs.lib[TSAPI_MDE_STAGE_CPP].present &&
        !graph_list_has(&libs.lib[TSAPI_MDE_STAGE_CPP].exports,
                        "cpp_weight"))
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "graph.unresolvable", "libcppcore:cpp_weight",
                                 "libgocore's undefined cpp_weight has no "
                                 "exporter");
    }

    if (!libs.macho && tsapi_mde_have(&session, "ldd"))
    {
        TEST_STEP("Second view (ldd): every ring dependency resolves");
        for (i = 0; i < TSAPI_MDE_STAGE_N; i++)
        {
            te_string path = TE_STRING_INIT;
            char      subject[64];

            if (!libs.lib[i].present || libs.lib[i].n_needed == 0)
                continue;

            tsapi_mde_dut_lib_path(&dut, libs.lib[i].name, &path);
            if (tsapi_mde_sh(&session, 20000, &res, "ldd '%s' | grep core",
                             path.ptr) == 0)
            {
                RING("ldd %s (ring part):\n%s", libs.lib[i].name,
                     graph_str(&res.out));
                if (strstr(graph_str(&res.out), "not found") != NULL)
                {
                    TE_SPRINTF(subject, "%s", libs.lib[i].name);
                    tapi_cybersec_report_add(&report.cyber,
                                             TAPI_CYBERSEC_SEV_HIGH,
                                             "graph.unresolved-needed",
                                             subject,
                                             "ldd cannot find a ring "
                                             "dependency");
                }
            }
            te_string_free(&path);
        }
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "graph", TAPI_CYBERSEC_SEV_HIGH);
    if (relation_bad)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&res);
    if (libs_up)
    {
        graph_libs_free(&libs);
        graph_libs_free(&planted);
    }
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

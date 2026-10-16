/** @file
 * @brief Graph Group
 *
 * Check that the ring libraries are linked into the cyclic graph the way the
 * build intends - no running code involved, only the libraries' own metadata.
 *
 * The cycle is broken at build time by two tricks (see the example's README):
 * Python and C# bind late and link against nothing, Go leaves cpp_weight
 * undefined, and the rest link normally. This test confirms the two load-time
 * edges that must be present and the one symbol that must stay undefined:
 *
 *   librustcore -> libgocore, libcscore   (otool -L)
 *   libcppcore  -> librustcore, libpycore (otool -L)
 *   libgocore   : _cpp_weight undefined   (nm -u)
 *
 * These are properties of the build, not of the arithmetic, so the injected
 * defect does not change them: this group passes on the as-shipped example.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "graph/links"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_mde.h"

typedef enum graph_relation {
    GRAPH_RUST,     /**< librustcore links libgocore and libcscore. */
    GRAPH_CPP,      /**< libcppcore links librustcore and libpycore. */
    GRAPH_GO_UNDEF, /**< libgocore leaves cpp_weight undefined. */
} graph_relation;

#define GRAPH_RELATION_LIST \
    { "rust",    GRAPH_RUST     }, \
    { "cpp",     GRAPH_CPP      }, \
    { "go-undef", GRAPH_GO_UNDEF }

/* Count how many output lines of a tool mention a given pattern. */
static unsigned int
graph_count(tsapi_mde_session *session, const char *tool, const char *flag,
            const char *lib_path, const char *pattern)
{
    const char           *argv[] = { tool, flag, lib_path, NULL };
    tsapi_mde_run_result  res;

    if (tsapi_mde_run(session, tool, argv, 20000, pattern, NULL, &res) != 0)
        return 0;
    if (!res.started || res.status.type != TAPI_JOB_STATUS_EXITED)
        return 0;

    return res.match_count;
}

/* Whether a tool can be run on the agent at all. */
static bool
graph_tool_ok(tsapi_mde_session *session, const char *tool)
{
    const char           *argv[] = { tool, "--version", NULL };
    tsapi_mde_run_result  res;

    if (tsapi_mde_run(session, tool, argv, 10000, NULL, NULL, &res) != 0)
        return false;

    return res.started && res.status.type == TAPI_JOB_STATUS_EXITED;
}

int
main(int argc, char **argv)
{
    graph_relation     relation;
    const char        *src;
    te_string          lib = TE_STRING_INIT;
    tsapi_mde_session  session;
    bool               session_up = false;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(relation, GRAPH_RELATION_LIST);

    TEST_STEP("Locate the example under test");
    src = tsapi_mde_src();
    if (src == NULL)
        TEST_SKIP("TE_TS_MDE_SRC is not set");

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "graph"));
    session_up = true;

    TEST_STEP("Skip unless the Mach-O tools are available");
    /*
     * The example as shipped is built on macOS, so the linkage is expressed in
     * Mach-O and read with otool/nm. Where those tools are absent (e.g. the
     * Linux build container), there is nothing to inspect: skip.
     */
    if (!graph_tool_ok(&session, "otool") || !graph_tool_ok(&session, "nm"))
        TEST_SKIP("otool/nm are not available - not a Mach-O host");

    switch (relation)
    {
        case GRAPH_RUST:
        case GRAPH_CPP:
        {
            const char *self;
            const char *deps[2];
            size_t      i;

            if (relation == GRAPH_RUST)
            {
                self = "librustcore";
                deps[0] = "libgocore";
                deps[1] = "libcscore";
            }
            else
            {
                self = "libcppcore";
                deps[0] = "librustcore";
                deps[1] = "libpycore";
            }

            te_string_append(&lib, "%s/dist/lib/%s.dylib", src, self);
            if (!tsapi_mde_exists(&session, lib.ptr))
                TEST_SKIP("%s is missing - build the example first", lib.ptr);

            TEST_STEP("Check the two load-time edges of %s", self);
            for (i = 0; i < 2; i++)
            {
                te_string pat = TE_STRING_INIT;
                unsigned int n;

                te_string_append(&pat, "%s\\.dylib", deps[i]);
                n = graph_count(&session, "otool", "-L", lib.ptr, pat.ptr);
                te_string_free(&pat);

                RING("%s -> %s: %u reference(s)", self, deps[i], n);
                if (n == 0)
                    TEST_VERDICT("%s does not link %s", self, deps[i]);
            }
            break;
        }

        case GRAPH_GO_UNDEF:
        {
            unsigned int n;

            te_string_append(&lib, "%s/dist/lib/libgocore.dylib", src);
            if (!tsapi_mde_exists(&session, lib.ptr))
                TEST_SKIP("%s is missing - build the example first", lib.ptr);

            TEST_STEP("Check libgocore leaves cpp_weight undefined");
            /* nm -u lists undefined symbols; the Mach-O name is _cpp_weight. */
            n = graph_count(&session, "nm", "-u", lib.ptr, "cpp_weight");
            RING("libgocore undefined cpp_weight: %u match(es)", n);
            if (n == 0)
            {
                TEST_VERDICT("libgocore does not leave cpp_weight undefined "
                             "(the build-time cycle break is gone)");
            }
            break;
        }

        default:
            TEST_FAIL("Unknown relation value: %d", relation);
    }

    TEST_SUCCESS;

cleanup:

    te_string_free(&lib);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T6, why tests of the suite skip (H3 and H4 partly)
 *
 * Every test of the suite that can skip, or end on a missing tool, names
 * a reason string and what that reason needs on the agent. This test
 * prints each reason, says which container or tool it is about, and says
 * whether that thing is on the agent now (the group prologues install
 * them, so a thing that is still missing is a cause that survived the
 * install). It also records whether the built example is in place. It
 * only makes the causes readable and always passes.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t6_skip_causes"

#include "te_config.h"

#include "webdeps_lib.h"

/** What a reason needs. */
typedef enum need_kind { NEED_TOOL, NEED_PATH, NEED_CONTAINER } need_kind;

typedef struct skip_t {
    const char *test;       /**< Test that can skip. */
    const char *reason;     /**< Reason string it prints. */
    need_kind   kind;
    const char *need;       /**< Tool name or path. */
} skip_t;

#define PW "/opt/playwright"

static const skip_t skips[] = {
    { "devtool/make_stub", "make is not installed on the agent",
      NEED_TOOL, "make" },
    { "devtool/make_stub", "cc is not installed on the agent", NEED_TOOL,
      "cc" },
    { "devtool/rebuild_pycore", "cc is not installed on the agent",
      NEED_TOOL, "cc" },
    { "devtool/rebuild_pycore", "python3-config is missing (no python3-dev)",
      NEED_TOOL, "python3-config" },
    { "devtool/rebuild_pycore", "binutils are missing on the agent",
      NEED_TOOL, "nm" },
    { "devtool/reproducible", "python3-config is missing (no python3-dev)",
      NEED_TOOL, "python3-config" },
    { "devtool/reproducible", "readelf or sha256sum is missing on the agent",
      NEED_TOOL, "sha256sum" },
    { "devtool/*", "The example is not built in TE_TS_MDE_SRC", NEED_PATH,
      "dist/bin/cpp-demo" },
    { "exposure/reachability, listeners, egress, h3_endpoints",
      "There is no curl on the agent", NEED_TOOL, "curl" },
    { "exposure/sniff", "There is no tcpdump on the agent", NEED_TOOL,
      "tcpdump" },
    { "exposure/sniff", "The agent cannot run tcpdump through sudo",
      NEED_TOOL, "sudo" },
    { "exposure/frida", "Frida is not installed on the agent", NEED_TOOL,
      "frida" },
    { "http/methods, headers, redirects, load_curve",
      "There is no curl on the agent", NEED_TOOL, "curl" },
    { "http/methods, headers, redirects",
      "There is no python3 on the agent for the control endpoint",
      NEED_TOOL, "python3" },
    { "fuzz/ring_abi, replay",
      "clang with -fsanitize=fuzzer,address is not available on the agent",
      NEED_TOOL, "clang" },
    { "browser/*", "Node.js is not installed on the agent", NEED_TOOL,
      "node" },
    { "browser/pw_project", "npx is not installed on the agent", NEED_TOOL,
      "npx" },
    { "browser/*", "The playwright npm package is not installed in " PW,
      NEED_PATH, PW "/node_modules/playwright" },
    { "browser/*", "No Playwright browsers are installed in " PW "/browsers",
      NEED_PATH, PW "/browsers" },
    { "binary/disasm_defect", "There is no objdump on the agent", NEED_TOOL,
      "objdump" },
    { "package/dut_runtime_deps", "readelf or ldd is missing on the agent",
      NEED_TOOL, "ldd" },
    { "graph/cycle_closure", "strings is not available on the agent",
      NEED_TOOL, "strings" },
    { "fs/integrity", "curl is not available on the agent", NEED_TOOL,
      "curl" },
    { "container/prologue", "No container runtime on the agent",
      NEED_CONTAINER, "docker" },
    { "container/ring_inside",
      "No container runtime with file copy on the agent", NEED_CONTAINER,
      "docker" },
};

int
main(int argc, char **argv)
{
    res_t               res = { .kind = R_PASS };
    tsapi_mde_session   session = { .ta = NULL };
    unsigned            n_missing = 0;
    char                gone[900] = "";
    size_t              i;

    TEST_START;
    t_report_begin();

    TEST_STEP("Open a session on the agent");
    if (tsapi_mde_session_init(&session, "t6_skip_causes") != 0)
    {
        RING("webdeps verdict H3/H4: cannot open a session on the agent; "
             "the skip causes below are listed without a probe");
    }

    TEST_STEP("Print every skip reason and what it needs");
    for (i = 0; i < TE_ARRAY_LEN(skips); i++)
    {
        const skip_t *s = &skips[i];
        char          abs_path[600];
        const char   *kind = s->kind == NEED_TOOL ? "tool" :
                             s->kind == NEED_PATH ? "file or directory" :
                             "container runtime";
        bool          probed = session.pco != NULL;
        bool          present = false;

        if (probed && s->kind == NEED_PATH)
        {
            snprintf(abs_path, sizeof(abs_path), "%s%s%s",
                     s->need[0] == '/' ? "" : (src_root != NULL ? src_root :
                                               (src_root = tsapi_mde_src())),
                     s->need[0] == '/' ? "" : "/", s->need);
            present = tsapi_mde_exists(&session, abs_path);
        }
        else if (probed)
            present = tsapi_mde_have(&session, s->need);

        if (probed && !present)
        {
            n_missing++;
            append(gone, sizeof(gone), "%s ", s->need);
        }
        RING("webdeps skip: %s: reason \"%s\"; missing %s: %s; on the agent "
             "now: %s", s->test, s->reason, kind, s->need,
             !probed ? "unknown" : present ? "present" : "ABSENT");
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "suite.skip-cause", s->test,
                  "reason \"%s\"; %s %s %s", s->reason, kind, s->need,
                  !probed ? "unknown" : present ? "present" : "absent");
    }

    res_set(&res, R_PASS, "H3/H4 INFO: %zu skip reasons listed, %u of them "
            "still name something absent on the agent%s%s (always a pass; "
            "see the lines above for each test and its reason)",
            TE_ARRAY_LEN(skips), n_missing, n_missing > 0 ? ": " : "", gone);

    tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H3/H4");

cleanup:
    cleanup_all();
    TEST_END;
}

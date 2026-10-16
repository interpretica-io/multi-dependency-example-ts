/** @file
 * @brief Ring Group
 *
 * Enter the native FFI ring from one language and count how many stages a
 * value actually travels through. Correct code carries it through hops+1
 * stages; the injected always-true defect stops it after the first.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ring/propagation"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"

/* Entry point into the ring: which demo binary enters the cycle and where. */
typedef enum ring_entry {
    RING_ENTRY_CPP,     /**< cpp-demo: enters at the Rust stage. */
    RING_ENTRY_RUST,    /**< rust-demo: enters at the C++ stage. */
    RING_ENTRY_PY,      /**< python demo: enters at the C++ stage. */
} ring_entry;

#define RING_ENTRY_LIST \
    { "cpp",  RING_ENTRY_CPP  }, \
    { "rust", RING_ENTRY_RUST }, \
    { "py",   RING_ENTRY_PY   }

/* Any stage's trace line: "  [rust] hops=7 ... "; the name is padded. */
#define RING_STAGE_RE   "\\[\\s*(cpp|rust|go|cs|py)\\s*\\]\\s+hops="
/* The demo's final line: "cpp-demo: result = 20.0735". */
#define RING_RESULT_RE  "result = (-?[0-9]+\\.[0-9]+)"

int
main(int argc, char **argv)
{
    ring_entry           entry;
    int                  hops;
    const char          *src;
    const char          *value = "1";
    te_string            program = TE_STRING_INIT;
    te_string            script = TE_STRING_INIT;
    char                 hops_str[16];
    const char          *cmd[8];
    size_t               n = 0;
    tsapi_mde_session    session;
    bool                 session_up = false;
    tsapi_mde_run_result res;
    tsapi_evo_schart     chart;
    char                 metric[32];
    char                 xaxis[32];
    unsigned int         expected;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(entry, RING_ENTRY_LIST);
    TEST_GET_INT_PARAM(hops);

    TEST_STEP("Locate the example under test");
    src = tsapi_mde_src();
    if (src == NULL)
        TEST_SKIP("TE_TS_MDE_SRC is not set");

    TE_SPRINTF(hops_str, "%d", hops);

    switch (entry)
    {
        case RING_ENTRY_CPP:
            te_string_append(&program, "%s/dist/bin/cpp-demo", src);
            cmd[n++] = program.ptr;
            cmd[n++] = value;
            cmd[n++] = hops_str;
            break;

        case RING_ENTRY_RUST:
            te_string_append(&program, "%s/dist/bin/rust-demo", src);
            cmd[n++] = program.ptr;
            cmd[n++] = value;
            cmd[n++] = hops_str;
            break;

        case RING_ENTRY_PY:
            te_string_append(&program, "python3");
            cmd[n++] = program.ptr;
            /* argv[1] is the script; it lives in the source tree, not dist. */
            te_string_append(&script, "%s/python/demo.py", src);
            cmd[n++] = script.ptr;
            cmd[n++] = value;
            cmd[n++] = hops_str;
            break;

        default:
            TEST_FAIL("Unknown entry value: %d", entry);
    }
    cmd[n] = NULL;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "ring"));
    session_up = true;

    TEST_STEP("Skip unless the demo can be run");
    /*
     * For a native demo the binary itself must be there; for the Python demo
     * the script must be there (python3 is resolved through PATH) and the ring
     * libraries it dlopen()s must have been built. cpp-demo is the sentinel
     * for "the example is built": it is produced by the same ./build.sh run
     * as every library, so its presence implies dist/lib is populated too
     * (an empty dist/lib directory left over from a clean must not pass).
     */
    if (entry == RING_ENTRY_PY)
    {
        te_string sentinel = TE_STRING_INIT;
        bool      have;

        te_string_append(&sentinel, "%s/dist/bin/cpp-demo", src);
        have = tsapi_mde_exists(&session, cmd[1]) &&
               tsapi_mde_exists(&session, sentinel.ptr);
        te_string_free(&sentinel);
        if (!have)
            TEST_SKIP("Python demo or the built ring libraries are missing");
    }
    else if (!tsapi_mde_exists(&session, program.ptr))
    {
        TEST_SKIP("%s is missing - build the example first", program.ptr);
    }

    TEST_STEP("Run the demo and count the stages the value visits");
    CHECK_RC(tsapi_mde_run(&session, cmd[0], cmd, 30000,
                           RING_STAGE_RE, RING_RESULT_RE, &res));
    if (!res.started)
        TEST_FAIL("The demo could not be started");

    RING("Demo exited (type=%d value=%d); %u stage(s) traced; result=%s %g",
         res.status.type, res.status.value, res.match_count,
         res.have_value ? "" : "(none)", res.have_value ? res.value : 0.0);

    TEST_STEP("Record the propagation depth");
    tsapi_evo_analysis_hint(
        "Stages visited should equal hops+1. A value of 1 means the value "
        "stopped at the entry stage - the injected always-true defect.");
    tsapi_evo_schart_init(&chart, "Ring propagation",
                          "Stages visited / Entry+hops", "0", "stages");
    TE_SPRINTF(xaxis, "%s/hops=%d",
               entry == RING_ENTRY_CPP ? "cpp" :
               entry == RING_ENTRY_RUST ? "rust" : "py", hops);
    TE_SPRINTF(metric, "%u", res.match_count);
    tsapi_evo_schart_add_metric(&chart, xaxis, metric, NULL);
    tsapi_evo_schart_print(&chart);
    tsapi_evo_schart_fini(&chart);

    TEST_STEP("Check that the value reached every stage");
    expected = (unsigned int)hops + 1;
    if (res.match_count != expected)
    {
        TEST_VERDICT("Ring propagated through %u stage(s), expected %u",
                     res.match_count, expected);
    }

    TEST_SUCCESS;

cleanup:

    te_string_free(&program);
    te_string_free(&script);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

/** @file
 * @brief dummy Group
 *
 * The TE_EXT_REPO machinery, checked through tsf-dummy's two components.
 *
 * check=greeting: tapi_dummy_greeting(), the engine-side TAPI linked into
 * this test, returns its documented static string - non-NULL, the exact
 * text, well formed, and the very same static buffer on every call.
 *
 * check=agent: dummy_agent, the external Test Agent type the Builder was
 * asked to build (TE_TA_TYPE dummy), is installed where TE installs agent
 * types, is a binary for this machine, runs, says it is alive on its
 * platform and exits - it is not an RCF agent and must not stay up.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "dummy/greeting"

#include "te_config.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_dummy.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/** What the greeting must be (tsf-dummy tapi_dummy.c). */
#define DUMMY_GREETING  "Greetings from the external tsf-dummy repository!"

/** What dummy_agent prints before its platform name (dummy_agent/main.c). */
#define DUMMY_ALIVE     "dummy_agent is alive on platform "

/** Most call results charted. */
#define DUMMY_MAX_CHART 100

/** Most words of the greeting charted. */
#define DUMMY_MAX_WORDS 16

/** What is checked. */
typedef enum dummy_check {
    DUMMY_CHECK_GREETING,
    DUMMY_CHECK_AGENT,
} dummy_check;

#define DUMMY_CHECK_LIST \
    { "greeting", DUMMY_CHECK_GREETING }, \
    { "agent",    DUMMY_CHECK_AGENT }

/* The greeting part. */
static void
check_greeting(int calls)
{
    const char   *first;
    const char   *g;
    double        lengths[DUMMY_MAX_CHART];
    double        words_len[DUMMY_MAX_WORDS];
    char         *words[DUMMY_MAX_WORDS];
    char         *copy;
    char         *save = NULL;
    char         *w;
    size_t        n_words = 0;
    size_t        n_chart = 0;
    size_t        len;
    size_t        i;
    double        started;
    double        elapsed;
    int           call;

    TEST_STEP("Call tapi_dummy_greeting() once and check its contract");
    first = tapi_dummy_greeting();
    if (first == NULL)
        TEST_VERDICT("tapi_dummy_greeting() returned NULL");
    len = strlen(first);
    TEST_ARTIFACT("Greeting (%zu chars): %s", len, first);
    if (strcmp(first, DUMMY_GREETING) != 0)
        TEST_VERDICT("tapi_dummy_greeting() returned an unexpected greeting");

    TEST_SUBSTEP("Formatting: one printable line, a sentence");
    for (i = 0; i < len; i++)
    {
        if (!isprint((unsigned char)first[i]))
            TEST_VERDICT("The greeting has a non-printable character");
    }
    if (len == 0 || isspace((unsigned char)first[0]) ||
        isspace((unsigned char)first[len - 1]))
        TEST_VERDICT("The greeting has leading or trailing blanks");
    if (!isupper((unsigned char)first[0]) || first[len - 1] != '!')
        TEST_VERDICT("The greeting is not a capitalised exclamation");
    if (strstr(first, "tsf-dummy") == NULL)
        TEST_VERDICT("The greeting does not name its repository");

    TEST_STEP("Call it again and again: the same static buffer each time");
    started = tsapi_mde_now();
    for (call = 0; call < calls; call++)
    {
        g = tapi_dummy_greeting();
        if (g != first)
            TEST_VERDICT("tapi_dummy_greeting() is not a static string");
        if ((size_t)call < DUMMY_MAX_CHART)
            lengths[n_chart++] = (double)strlen(g);
    }
    elapsed = tsapi_mde_now() - started;
    if (strcmp(first, DUMMY_GREETING) != 0)
        TEST_VERDICT("The greeting changed between calls");
    TEST_ARTIFACT("%d call(s) in %.9f s, the same pointer every time", calls,
                  elapsed);

    TEST_STEP("Chart the greeting");
    copy = strdup(first);
    for (w = strtok_r(copy, " ", &save);
         w != NULL && n_words < DUMMY_MAX_WORDS;
         w = strtok_r(NULL, " ", &save))
    {
        words[n_words] = w;
        words_len[n_words] = (double)strlen(w);
        n_words++;
    }
    tsapi_mde_mi_series("dummy", "Greeting length per call",
                        TE_MI_MEAS_UNITLESS_VALUE, "length", n_chart, lengths,
                        TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("dummy", "Greeting word lengths",
                      TE_MI_MEAS_UNITLESS_VALUE, "length", n_words,
                      (const char * const *)words, words_len,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("dummy", "Time per tapi_dummy_greeting() call",
                       TE_MI_MEAS_TIME, "call", elapsed / calls,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    free(copy);
}

int
main(int argc, char **argv)
{
    dummy_check         check;
    int                 calls = 0;
    const char         *install;
    const char         *agents;
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string           ta = TE_STRING_INIT;
    te_string           machine = TE_STRING_INIT;
    const char         *out;
    const char         *platform;
    double              started;
    double              run_s;
    double              size_bytes;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(check, DUMMY_CHECK_LIST);

    if (check == DUMMY_CHECK_GREETING)
    {
        TEST_GET_INT_PARAM(calls);
        if (calls <= 0)
            TEST_FAIL("calls must be positive");
        check_greeting(calls);
        TEST_SUCCESS;
    }

    TEST_STEP("Open a session on the agent");
    rc = tsapi_mde_session_init(&session, "dummy_agent");
    session_up = true;
    if (rc != 0)
        TEST_FAIL("Cannot open a session on the agent: %r", rc);

    TEST_STEP("Find dummy_agent where TE installs agent types");
    install = getenv("TE_INSTALL");
    agents = getenv("TE_AGENTS_INST");
    TEST_ARTIFACT("TE_INSTALL=%s TE_AGENTS_INST=%s",
                  install != NULL ? install : "(unset)",
                  agents != NULL ? agents : "(unset)");
    if (install != NULL)
    {
        te_string_append(&ta, "%s/agents/dummy/ta", install);
        if (!tsapi_mde_exists(&session, ta.ptr))
            te_string_reset(&ta);
    }
    if (te_string_value(&ta)[0] == '\0' && agents != NULL)
    {
        te_string_append(&ta, "%s/dummy/ta", agents);
        if (!tsapi_mde_exists(&session, ta.ptr))
            te_string_reset(&ta);
    }
    if (te_string_value(&ta)[0] == '\0' && install != NULL)
    {
        /* The layout may differ: look for any agents/dummy/ta. */
        CHECK_RC(tsapi_mde_sh(&session, 60000, &sh,
                              "find '%s' -path '*/agents/dummy/ta' -type f "
                              "2>/dev/null | head -n1", install));
        te_string_append(&ta, "%s", te_string_value(&sh.out));
        te_string_chop(&ta, "\n");
    }
    if (te_string_value(&ta)[0] == '\0')
        TEST_SKIP("dummy_agent is not found under the TE install tree");
    TEST_ARTIFACT("dummy_agent: %s", ta.ptr);

    TEST_STEP("It is an executable for this machine");
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "test -x '%s' && stat -c %%s '%s' && "
                          "sha256sum '%s' | cut -d' ' -f1",
                          ta.ptr, ta.ptr, ta.ptr));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_VERDICT("dummy_agent is installed but not executable");
    size_bytes = strtod(te_string_value(&sh.out), NULL);
    TEST_ARTIFACT("dummy_agent size and sha256: %s", te_string_value(&sh.out));

    if (tsapi_mde_have(&session, "readelf"))
    {
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                              "uname -m; readelf -h '%s' | "
                              "sed -n 's/^ *Machine: *//p'", ta.ptr));
        te_string_append(&machine, "%s", te_string_value(&sh.out));
        TEST_ARTIFACT("Host machine and dummy_agent machine: %s",
                      machine.ptr);
        if ((strstr(machine.ptr, "x86_64") != NULL &&
             strstr(machine.ptr, "X86-64") == NULL) ||
            (strstr(machine.ptr, "aarch64") != NULL &&
             strstr(machine.ptr, "AArch64") == NULL))
            TEST_VERDICT("dummy_agent is built for another machine");
    }

    TEST_STEP("Run it: it says it is alive and exits");
    started = tsapi_mde_now();
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "'%s'", ta.ptr));
    run_s = tsapi_mde_now() - started;
    out = te_string_value(&sh.out);
    RING("dummy_agent printed:\n%s", out);
    if (!sh.started || sh.status.type != TAPI_JOB_STATUS_EXITED)
        TEST_VERDICT("dummy_agent did not exit on its own");
    if (sh.status.value != 0)
        TEST_VERDICT("dummy_agent exited with a non-zero status");
    platform = strstr(out, DUMMY_ALIVE);
    if (platform == NULL)
        TEST_VERDICT("dummy_agent did not say it is alive");
    platform += strlen(DUMMY_ALIVE);
    if (*platform == '\0' || *platform == '\n')
        TEST_VERDICT("dummy_agent did not name its platform");
    TEST_ARTIFACT("dummy_agent: %s", out);

    tsapi_mde_mi_point("dummy", "dummy_agent size", TE_MI_MEAS_MEMORY,
                       "size", size_bytes, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("dummy", "dummy_agent run time", TE_MI_MEAS_TIME,
                       "run", run_s, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    te_string_free(&ta);
    te_string_free(&machine);
    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

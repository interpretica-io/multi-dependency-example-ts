/** @file
 * @brief AI Group
 *
 * ai group prologue: record which of the AI settings the run carries -
 * TSF_AI_KEY (only whether it is there, and for which provider; the key
 * itself is never logged), TSF_AI_PROVIDER, TSF_AI_MODEL,
 * TSF_AI_BASE_URL - whether python3 is on the agent, and whether the
 * browser group left a screenshot to grade; chart it.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ai/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "ai_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session session;
    bool              session_up = false;
    te_string         key = TE_STRING_INIT;
    te_string         value = TE_STRING_INIT;
    const char       *labels[] = { "TSF_AI_KEY", "TSF_AI_PROVIDER",
                                   "TSF_AI_MODEL", "TSF_AI_BASE_URL",
                                   "python3", "kept screenshot" };
    double            found[6];

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "ai_prologue"));
    session_up = true;

    TEST_STEP("Inventory the AI settings of the run");
    found[0] = ai_setting(session.ta, "TSF_AI_KEY", &key);
    if (found[0] > 0)
    {
        TEST_ARTIFACT("TSF_AI_KEY is set (%zu characters), for %s",
                      key.len,
                      tapi_ai_provider2str(ai_key_provider(session.ta,
                                                           key.ptr)));
    }
    else
    {
        TEST_ARTIFACT("TSF_AI_KEY is not set: the AI tests will skip");
    }
    te_string_free(&key);

    found[1] = ai_setting(session.ta, "TSF_AI_PROVIDER", &value);
    if (found[1] > 0)
        TEST_ARTIFACT("TSF_AI_PROVIDER=%s", value.ptr);
    te_string_reset(&value);
    found[2] = ai_setting(session.ta, "TSF_AI_MODEL", &value);
    if (found[2] > 0)
        TEST_ARTIFACT("TSF_AI_MODEL=%s", value.ptr);
    te_string_reset(&value);
    found[3] = ai_setting(session.ta, "TSF_AI_BASE_URL", &value);
    if (found[3] > 0)
        TEST_ARTIFACT("TSF_AI_BASE_URL=%s", value.ptr);
    found[4] = tsapi_mde_have(&session, "python3");
    found[5] = tsapi_mde_exists(&session, "/tmp/mde-browser-walk-h5.png");

    TEST_STEP("Chart the inventory");
    tsapi_mde_mi_bars("ai", "AI settings of the run (1 = present)",
                      TE_MI_MEAS_UNITLESS_VALUE, "present",
                      TE_ARRAY_LEN(labels), labels, found,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    te_string_free(&key);
    te_string_free(&value);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

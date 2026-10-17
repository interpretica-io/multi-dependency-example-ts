/** @file
 * @brief net Group
 *
 * net group prologue: chart how many instances the /agent/vpn and
 * /agent/wifi subtrees present, which is the first proof that the
 * external ta_vpn and ta_wifi agent libraries were linked and their
 * models loaded.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "net/prologue"

#include "te_config.h"

#include "tapi_test.h"
#include "conf_api.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "net_common.h"

int
main(int argc, char **argv)
{
    static const char *subtrees[] = { "vpn", "wifi" };
    tsapi_mde_session  session;
    bool               session_up = false;
    const char        *labels[TE_ARRAY_LEN(subtrees)];
    double             counts[TE_ARRAY_LEN(subtrees)];
    unsigned int       i;

    TEST_START;

    TEST_STEP("Count the Configurator subtrees the agent libraries register");
    CHECK_RC(tsapi_mde_session_init(&session, "net_prologue"));
    session_up = true;

    for (i = 0; i < TE_ARRAY_LEN(subtrees); i++)
    {
        unsigned int n = 0;
        char         pattern[64];
        char         root[64];

        TE_SPRINTF(pattern, "/agent:%s/%s:*", NET_TA, subtrees[i]);
        TE_SPRINTF(root, "/agent:%s/%s:", NET_TA, subtrees[i]);
        (void)net_count_pattern(pattern, root, &n);
        labels[i] = subtrees[i];
        counts[i] = n;
        TEST_ARTIFACT("/agent/%s: %u instance(s) registered", subtrees[i], n);
    }
    tsapi_mde_mi_bars("net", "Configurator instances per external subtree",
                      TE_MI_MEAS_UNITLESS_VALUE, "instances",
                      TE_ARRAY_LEN(subtrees), labels, counts,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

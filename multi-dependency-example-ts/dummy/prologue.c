/** @file
 * @brief dummy Group
 *
 * dummy group prologue: record what the TE_EXT_REPO machinery delivered -
 * the greeting of the engine-side TAPI and where agent types are
 * installed. Never skips.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "dummy/prologue"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "tapi_dummy.h"
#include "tsapi_mde_mi.h"

int
main(int argc, char **argv)
{
    const char *greeting;
    const char *install;

    TEST_START;

    TEST_STEP("Record what tsf-dummy provides");
    greeting = tapi_dummy_greeting();
    install = getenv("TE_INSTALL");
    TEST_ARTIFACT("tapi_dummy greeting: %s",
                  greeting != NULL ? greeting : "(NULL)");
    TEST_ARTIFACT("Agent types are installed under %s/agents",
                  install != NULL ? install : "(TE_INSTALL unset)");
    tsapi_mde_mi_point("dummy", "Greeting length",
                       TE_MI_MEAS_UNITLESS_VALUE, "length",
                       greeting != NULL ? (double)strlen(greeting) : 0,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    TEST_END;
}

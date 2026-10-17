/** @file
 * @brief bench Group
 *
 * Switching a device's power off and on is a hardware act: a PDU, an
 * HTTP relay or a switchable USB hub. There is none here, so this skips
 * with the concrete reason and charts nothing - there is nothing to
 * measure.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "bench/power_switch"

#include "te_config.h"

#include "tapi_test.h"
#include "tsapi_mde.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("There is no programmable outlet on this bench");
    TEST_SKIP("tsf-power switches power through an SNMP PDU, an HTTP relay "
              "(DLI, NETIO, Tasmota, Shelly) or a switchable USB hub "
              "(uhubctl); none of these is present or reachable, so the "
              "device's power cannot be cycled");

    TEST_SUCCESS;

cleanup:

    TEST_END;
}

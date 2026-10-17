/** @file
 * @brief net Group
 *
 * The /agent/wifi subtree that tsf-wifi's ta_wifi registers, driven
 * without bringing a radio up: the station is described through the
 * subtree and every field is read back, so the external agent library is
 * exercised node by node. The interface is never enabled, so the commit
 * each set triggers applies nothing - no hostapd, no wpa_supplicant.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "net/wifi_tree"

#include "te_config.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "conf_api.h"
#include "tapi_cfg_wifi.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "net_common.h"

#define WIFI_PORT       "0"
#define WIFI_SSID       "0"
#define WIFI_IFNAME     "mdewlan0"
#define WIFI_NAME       "mde-net"
#define WIFI_PASS       "ring-pass-12345"
#define WIFI_CHANNEL    6

int
main(int argc, char **argv)
{
    tsapi_mde_session session;
    bool              session_up = false;
    bool              port_added = false;
    unsigned int      n_root;
    unsigned int      ports_before;
    unsigned int      ports_after;
    uint8_t           channel = 0;
    uint32_t          width = 0;
    double            stages[2];
    double            nodes[2];

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "net_wifi_tree"));
    session_up = true;

    TEST_STEP("The /agent/wifi subtree must be registered");
    CHECK_RC(net_count_pattern("/agent:" NET_TA "/wifi:*",
                               "/agent:" NET_TA "/wifi:", &n_root));
    if (n_root == 0)
    {
        TEST_VERDICT("The /agent/wifi subtree is not registered - ta_wifi "
                     "was not linked into the agent or cm_wifi.yml not "
                     "loaded");
    }
    TEST_ARTIFACT("/agent/wifi is registered: %u instance(s) before adding "
                  "a port", n_root);

    TEST_STEP("Describe a station through the subtree, leaving it disabled");
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING,
             tapi_cfg_wifi_configurator_from_value(
                 TAPI_CFG_WIFI_CFG_HOSTAPD_WPA_SUPPLICANT)),
             "/agent:" NET_TA "/wifi:/configurator:"));

    CHECK_RC(net_count_pattern("/agent:" NET_TA "/wifi:/port:*",
                               "/agent:" NET_TA "/wifi:", &ports_before));
    CHECK_RC(cfg_add_instance_fmt(NULL, CFG_VAL(NONE, NULL),
             "/agent:" NET_TA "/wifi:/port:%s", WIFI_PORT));
    port_added = true;
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING, WIFI_IFNAME),
             "/agent:" NET_TA "/wifi:/port:%s/ifname:", WIFI_PORT));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING,
             tapi_cfg_wifi_standard_from_value(TAPI_CFG_WIFI_STANDARD_N)),
             "/agent:" NET_TA "/wifi:/port:%s/standard:", WIFI_PORT));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(UINT8, WIFI_CHANNEL),
             "/agent:" NET_TA "/wifi:/port:%s/channel:", WIFI_PORT));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(UINT32,
             (uint32_t)TAPI_CFG_WIFI_WIDTH_40),
             "/agent:" NET_TA "/wifi:/port:%s/width:", WIFI_PORT));

    CHECK_RC(cfg_add_instance_fmt(NULL, CFG_VAL(NONE, NULL),
             "/agent:" NET_TA "/wifi:/port:%s/ssid:%s", WIFI_PORT, WIFI_SSID));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING, WIFI_NAME),
             "/agent:" NET_TA "/wifi:/port:%s/ssid:%s/name:", WIFI_PORT,
             WIFI_SSID));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING,
             tapi_cfg_wifi_mode_from_value(TAPI_CFG_WIFI_MODE_STA)),
             "/agent:" NET_TA "/wifi:/port:%s/ssid:%s/mode:", WIFI_PORT,
             WIFI_SSID));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING,
             tapi_cfg_wifi_security_from_value(TAPI_CFG_WIFI_SECURITY_WPA2)),
             "/agent:" NET_TA "/wifi:/port:%s/ssid:%s/security:", WIFI_PORT,
             WIFI_SSID));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING,
             tapi_cfg_wifi_protocol_from_value(TAPI_CFG_WIFI_PROTOCOL_CCMP)),
             "/agent:" NET_TA "/wifi:/port:%s/ssid:%s/protocol:", WIFI_PORT,
             WIFI_SSID));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING, WIFI_PASS),
             "/agent:" NET_TA "/wifi:/port:%s/ssid:%s/passphrase:", WIFI_PORT,
             WIFI_SSID));

    TEST_STEP("Read every field back through the subtree (deep check)");
    if (!net_str_roundtrips(WIFI_IFNAME,
            "/agent:" NET_TA "/wifi:/port:%s/ifname:", WIFI_PORT))
        TEST_VERDICT("The port ifname did not round-trip");
    if (!net_str_roundtrips(
            tapi_cfg_wifi_standard_from_value(TAPI_CFG_WIFI_STANDARD_N),
            "/agent:" NET_TA "/wifi:/port:%s/standard:", WIFI_PORT))
        TEST_VERDICT("The port standard did not round-trip");
    CHECK_RC(cfg_get_uint8(&channel,
             "/agent:" NET_TA "/wifi:/port:%s/channel:", WIFI_PORT));
    if (channel != WIFI_CHANNEL)
        TEST_VERDICT("The channel did not round-trip");
    CHECK_RC(cfg_get_uint32(&width,
             "/agent:" NET_TA "/wifi:/port:%s/width:", WIFI_PORT));
    if (width != (uint32_t)TAPI_CFG_WIFI_WIDTH_40)
        TEST_VERDICT("The channel width did not round-trip");
    if (!net_str_roundtrips(WIFI_NAME,
            "/agent:" NET_TA "/wifi:/port:%s/ssid:%s/name:", WIFI_PORT,
            WIFI_SSID))
        TEST_VERDICT("The SSID name did not round-trip");
    if (!net_str_roundtrips(
            tapi_cfg_wifi_mode_from_value(TAPI_CFG_WIFI_MODE_STA),
            "/agent:" NET_TA "/wifi:/port:%s/ssid:%s/mode:", WIFI_PORT,
            WIFI_SSID))
        TEST_VERDICT("The SSID mode did not round-trip");
    if (!net_str_roundtrips(
            tapi_cfg_wifi_security_from_value(TAPI_CFG_WIFI_SECURITY_WPA2),
            "/agent:" NET_TA "/wifi:/port:%s/ssid:%s/security:", WIFI_PORT,
            WIFI_SSID))
        TEST_VERDICT("The SSID security did not round-trip");
    if (!net_str_roundtrips(WIFI_PASS,
            "/agent:" NET_TA "/wifi:/port:%s/ssid:%s/passphrase:", WIFI_PORT,
            WIFI_SSID))
        TEST_VERDICT("The SSID passphrase did not round-trip");
    TEST_ARTIFACT("/agent/wifi: ifname, standard, channel, width and the "
                  "SSID name, mode, security and passphrase all read back "
                  "unchanged through the live ta_wifi handlers");

    TEST_STEP("Control: a bad enum value must be refused");
    rc = cfg_set_instance_fmt(CFG_VAL(STRING, "zz"),
             "/agent:" NET_TA "/wifi:/port:%s/standard:", WIFI_PORT);
    if (rc == 0)
        TEST_VERDICT("The subtree accepted a WiFi standard it does not know");
    TEST_ARTIFACT("/agent/wifi: an unknown standard 'zz' was refused (%r)",
                  rc);

    TEST_STEP("Count the ports and chart the growth");
    CHECK_RC(net_count_pattern("/agent:" NET_TA "/wifi:/port:*",
                               "/agent:" NET_TA "/wifi:", &ports_after));
    if (ports_after != ports_before + 1)
        TEST_VERDICT("Adding a port did not add exactly one node");
    TEST_ARTIFACT("/agent/wifi/port: %u before, %u after describing one "
                  "station", ports_before, ports_after);

    stages[0] = 0;
    nodes[0] = ports_before;
    stages[1] = 1;
    nodes[1] = ports_after;
    {
        te_mi_logger *logger;

        CHECK_RC(tsapi_mde_mi_create("tapi_cfg_wifi", &logger));
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "stage", TE_MI_MEAS_AGGR_SINGLE, stages[0],
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "nodes", TE_MI_MEAS_AGGR_SINGLE, nodes[0],
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "stage", TE_MI_MEAS_AGGR_SINGLE, stages[1],
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "nodes", TE_MI_MEAS_AGGR_SINGLE, nodes[1],
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        tsapi_mde_mi_line(logger, "wifi_nodes",
                          "WiFi subtree instances (0 = empty, 1 = one "
                          "station)", "stage", "nodes", NULL);
        te_mi_logger_destroy(logger);
    }

    TEST_SUCCESS;

cleanup:

    if (port_added)
        CLEANUP_CHECK_RC(cfg_del_instance_fmt(true,
                         "/agent:" NET_TA "/wifi:/port:%s", WIFI_PORT));
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

/** @file
 * @brief net Group
 *
 * Purely Configurator, and deliberately kernel-free: prove the
 * /agent/vpn subtree that tsf-tunnel's ta_vpn registers is there and
 * answers. Its very presence proves ta_vpn was linked whole and
 * cm_vpn.yml loaded. The backend node is read and written through the
 * real agent handler (its commit over an empty model touches no kernel);
 * a WireGuard interface is added and removed. Configuring and committing
 * an interface needs the wireguard module and is the job of wg_tunnel.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "net/vpn_tree"

#include "te_config.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "conf_api.h"
#include "tapi_cfg_vpn.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "net_common.h"

#define WG_IF   "mdewg0"

int
main(int argc, char **argv)
{
    tsapi_mde_session session;
    bool              session_up = false;
    bool              wg_added = false;
    unsigned int      n_root;
    unsigned int      wg_before;
    unsigned int      wg_after;
    double            stages[2];
    double            nodes[2];
    const char       *backends[] = { "kernel", "wg-quick", "swanctl" };
    unsigned int      i;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "net_vpn_tree"));
    session_up = true;

    TEST_STEP("The /agent/vpn subtree must be registered");
    CHECK_RC(net_count_pattern("/agent:" NET_TA "/vpn:*",
                               "/agent:" NET_TA "/vpn:", &n_root));
    if (n_root == 0)
    {
        TEST_VERDICT("The /agent/vpn subtree is not registered - ta_vpn was "
                     "not linked into the agent or cm_vpn.yml not loaded");
    }
    TEST_ARTIFACT("/agent/vpn is registered: %u instance(s) before adding "
                  "anything", n_root);

    TEST_STEP("The backend node reads its default and round-trips each value");
    if (!net_str_roundtrips("kernel", "/agent:" NET_TA "/vpn:/backend:"))
        TEST_VERDICT("/agent/vpn/backend did not read back its default");
    /*
     * Setting the backend reaches the real agent handler; its commit runs
     * over an empty model, so it touches no kernel. This is the live proof
     * that ta_vpn's handlers answer, not only that the model was loaded.
     */
    for (i = 0; i < TE_ARRAY_LEN(backends); i++)
    {
        CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING, backends[i]),
                                      "/agent:" NET_TA "/vpn:/backend:"));
        if (!net_str_roundtrips(backends[i], "/agent:" NET_TA "/vpn:/backend:"))
            TEST_VERDICT("The /agent/vpn/backend value did not round-trip");
    }
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING, "kernel"),
                                  "/agent:" NET_TA "/vpn:/backend:"));
    TEST_ARTIFACT("/agent/vpn/backend round-tripped kernel, wg-quick and "
                  "swanctl through the live ta_vpn handler");

    TEST_STEP("Add a WireGuard interface (read_create, no commit)");
    CHECK_RC(net_count_pattern(
                 "/agent:" NET_TA "/vpn:/wireguard:*",
                 "/agent:" NET_TA "/vpn:", &wg_before));
    CHECK_RC(tapi_cfg_vpn_wg_add(NET_TA, WG_IF));
    wg_added = true;
    CHECK_RC(net_count_pattern(
                 "/agent:" NET_TA "/vpn:/wireguard:*",
                 "/agent:" NET_TA "/vpn:", &wg_after));
    if (wg_after != wg_before + 1)
        TEST_VERDICT("Adding a WireGuard interface did not add exactly one "
                     "node to the subtree");
    TEST_ARTIFACT("/agent/vpn/wireguard: %u interface(s) before, %u after "
                  "adding one", wg_before, wg_after);

    stages[0] = 0;
    nodes[0] = wg_before;
    stages[1] = 1;
    nodes[1] = wg_after;
    {
        te_mi_logger *logger;

        CHECK_RC(tsapi_mde_mi_create("tapi_cfg_vpn", &logger));
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
        tsapi_mde_mi_line(logger, "vpn_nodes",
                          "VPN subtree instances (0 = empty, 1 = one "
                          "interface)", "stage", "nodes", NULL);
        te_mi_logger_destroy(logger);
    }

    TEST_SUCCESS;

cleanup:

    if (wg_added)
        CLEANUP_CHECK_RC(tapi_cfg_vpn_wg_del(NET_TA, WG_IF));
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

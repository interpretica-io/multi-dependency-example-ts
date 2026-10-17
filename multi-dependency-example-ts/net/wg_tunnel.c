/** @file
 * @brief net Group
 *
 * A real WireGuard tunnel through the /agent/vpn subtree, when the kernel
 * can carry one. The test first probes whether a WireGuard interface can
 * be created at all (NET_ADMIN and the wireguard module); if not it skips
 * with the concrete reason. When it can, it asks the agent to generate a
 * key, configures an interface and a peer, commits, reads the applied
 * state back and rolls the interface away again.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "net/wg_tunnel"

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

#define WG_IF       "mdewg0"
#define PEER_PUB    "hPYK+Z6tE4bAht+L3WDVbyDqZtQ0h0W1Dc5q9m8ua0s="
#define PEER_EP     "203.0.113.7:51820"
#define PEER_AIPS   "10.9.0.2/32"
#define LISTEN_PORT 51823

/* Can this kernel create a WireGuard interface at all? */
static bool
wg_probe(tsapi_mde_session *session)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    (void)tsapi_mde_sh(session, 20000, &res,
                       "sudo -n ip link add dev mdewgprobe type wireguard "
                       "2>&1 && echo OK; "
                       "sudo -n ip link del dev mdewgprobe 2>/dev/null; true");
    ok = res.started && strstr(te_string_value(&res.out), "OK") != NULL;
    if (!ok)
        RING("WireGuard probe output: %s", te_string_value(&res.out));
    tsapi_mde_sh_result_free(&res);

    return ok;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session session;
    bool              session_up = false;
    bool              wg_added = false;
    char              pub[TAPI_CFG_VPN_KEY_LEN] = "";
    int32_t           port = 0;
    bool              up = false;
    int               handshake = 0;
    te_mi_logger     *logger = NULL;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "net_wg_tunnel"));
    session_up = true;

    TEST_STEP("The /agent/vpn subtree must be registered");
    {
        unsigned int n;

        CHECK_RC(net_count_pattern("/agent:" NET_TA "/vpn:*",
                                   "/agent:" NET_TA "/vpn:", &n));
        if (n == 0)
            TEST_VERDICT("The /agent/vpn subtree is not registered");
    }

    TEST_STEP("Probe whether a WireGuard interface can be created");
    if (!wg_probe(&session))
    {
        TEST_SKIP("Cannot create a WireGuard interface: the wireguard "
                  "kernel module is absent or passwordless sudo for "
                  "'ip link add type wireguard' is not permitted, so no "
                  "tunnel can be committed on this host");
    }
    TEST_ARTIFACT("WireGuard: the kernel can create an interface; committing "
                  "a real tunnel");

    TEST_STEP("Configure an interface with a generated key and a peer");
    CHECK_RC(tapi_cfg_vpn_set_backend(NET_TA, TAPI_CFG_VPN_KERNEL));
    CHECK_RC(tapi_cfg_vpn_wg_add(NET_TA, WG_IF));
    wg_added = true;
    CHECK_RC(tapi_cfg_vpn_wg_genkey(NET_TA, WG_IF, pub));
    if (!net_is_wg_key(pub))
        TEST_VERDICT("The agent did not return a base64 WireGuard public key");
    TEST_ARTIFACT("WireGuard: generated public key %s", pub);
    CHECK_RC(tapi_cfg_vpn_wg_set_listen_port(NET_TA, WG_IF, LISTEN_PORT));
    CHECK_RC(tapi_cfg_vpn_wg_set_address(NET_TA, WG_IF, "10.9.0.1/24"));
    CHECK_RC(tapi_cfg_vpn_wg_peer_add(NET_TA, WG_IF, PEER_PUB));
    CHECK_RC(tapi_cfg_vpn_wg_peer_set_endpoint(NET_TA, WG_IF, PEER_PUB,
                                               PEER_EP));
    CHECK_RC(tapi_cfg_vpn_wg_peer_set_allowed_ips(NET_TA, WG_IF, PEER_PUB,
                                                  PEER_AIPS));

    TEST_STEP("Commit and read the applied state back");
    CHECK_RC(tapi_cfg_vpn_commit(NET_TA));

    CHECK_RC(cfg_get_instance_int_fmt(&port,
             "/agent:" NET_TA "/vpn:/wireguard:%s/listen_port:", WG_IF));
    if (port != LISTEN_PORT)
        TEST_VERDICT("The listen port did not round-trip through the subtree");
    if (!net_str_roundtrips(PEER_EP,
            "/agent:" NET_TA "/vpn:/wireguard:%s/peer:%s/endpoint:",
            WG_IF, PEER_PUB))
        TEST_VERDICT("The peer endpoint did not round-trip");
    if (!net_str_roundtrips(PEER_AIPS,
            "/agent:" NET_TA "/vpn:/wireguard:%s/peer:%s/allowed_ips:",
            WG_IF, PEER_PUB))
        TEST_VERDICT("The peer allowed_ips did not round-trip");

    CHECK_RC(tapi_cfg_vpn_wg_get_status(NET_TA, WG_IF, &up));
    if (!up)
        TEST_VERDICT("The committed WireGuard interface is not up");
    TEST_ARTIFACT("WireGuard: %s is up with its listen port and peer "
                  "applied", WG_IF);

    /* No live far end, so the handshake has not happened: -1 is correct. */
    CHECK_RC(tapi_cfg_vpn_wg_peer_handshake(NET_TA, WG_IF, PEER_PUB,
                                            &handshake));
    TEST_ARTIFACT("WireGuard: seconds since the peer's handshake = %d "
                  "(-1 means never, expected with no far end)", handshake);

    CHECK_RC(tsapi_mde_mi_create("tapi_cfg_vpn", &logger));
    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                          "interface_up", TE_MI_MEAS_AGGR_SINGLE, up ? 1 : 0,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                          "listen_port", TE_MI_MEAS_AGGR_SINGLE, port,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    /*
     * Several single values: a line graph over the sequence
     * number draws each as a point (a point view takes one).
     */
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               "wg", "WireGuard tunnel applied state");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH,
                                          "wg", TE_MI_GRAPH_AXIS_X,
                                          TE_MI_GRAPH_AUTO_SEQNO);
    te_mi_logger_destroy(logger);
    logger = NULL;

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    if (wg_added)
        CLEANUP_CHECK_RC(tapi_cfg_vpn_wg_del(NET_TA, WG_IF));
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

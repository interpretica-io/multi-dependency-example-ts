/** @file
 * @brief net Group
 *
 * The /agent/vpn/ipsec model of tsf-tunnel. The point of the subtree
 * being low-level is that it can describe a security association that is
 * wrong on purpose, and the one that matters is the null-encrypted SA:
 * no encryption, so no confidentiality. A freshly added SA is exactly
 * that - ESP, tunnel mode, no enc clause - which this test adds several
 * of and reads back field by field through the Configurator.
 *
 * It stays kernel-free: an SA is only *created* in the model (the add
 * handler sets the defaults and does not commit), never applied, because
 * applying one needs the xfrm kernel this container does not have, and
 * rendering the actual "ip xfrm state add ..." text is done by the
 * agent-side ta_vpn builder, which is not linked into the engine test.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "net/ipsec_builder"

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

static const char *labels[] = { "mde-sa-a", "mde-sa-b", "mde-sa-c" };

/* Read one string field of an SA and compare it. */
static bool
sa_reads(const char *label, const char *field, const char *want)
{
    char    *got = NULL;
    bool     ok;
    te_errno rc;

    rc = cfg_get_instance_string_fmt(&got,
             "/agent:" NET_TA "/vpn:/ipsec:%s/%s:", label, field);
    ok = rc == 0 && got != NULL && strcmp(got, want) == 0;
    if (!ok)
        ERROR("ipsec %s/%s: wanted '%s', got '%s' (%r)", label, field, want,
              got != NULL ? got : "(null)", rc);
    free(got);

    return ok;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session session;
    bool              session_up = false;
    bool              added[TE_ARRAY_LEN(labels)] = { false };
    double            encrypted[TE_ARRAY_LEN(labels)];
    unsigned int      before;
    unsigned int      after;
    unsigned int      i;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "net_ipsec_builder"));
    session_up = true;

    TEST_STEP("The /agent/vpn subtree must be registered");
    {
        unsigned int n;

        CHECK_RC(net_count_pattern("/agent:" NET_TA "/vpn:*",
                                   "/agent:" NET_TA "/vpn:", &n));
        if (n == 0)
            TEST_VERDICT("The /agent/vpn subtree is not registered");
    }

    TEST_STEP("Add several IPsec SAs (read_create, no commit, no kernel)");
    CHECK_RC(net_count_pattern("/agent:" NET_TA "/vpn:/ipsec:*",
                               "/agent:" NET_TA "/vpn:", &before));
    for (i = 0; i < TE_ARRAY_LEN(labels); i++)
    {
        CHECK_RC(cfg_add_instance_fmt(NULL, CFG_VAL(NONE, NULL),
                 "/agent:" NET_TA "/vpn:/ipsec:%s", labels[i]));
        added[i] = true;
    }
    CHECK_RC(cfg_synchronize_fmt(true, "/agent:" NET_TA "/vpn:"));
    CHECK_RC(net_count_pattern("/agent:" NET_TA "/vpn:/ipsec:*",
                               "/agent:" NET_TA "/vpn:", &after));
    if (after != before + TE_ARRAY_LEN(labels))
        TEST_VERDICT("Adding the IPsec SAs did not grow the subtree by the "
                     "right amount");
    TEST_ARTIFACT("/agent/vpn/ipsec: %u SA(s) before, %u after adding %zu",
                  before, after, TE_ARRAY_LEN(labels));

    TEST_STEP("Read each SA back: ESP, tunnel, and null-encrypted by default");
    for (i = 0; i < TE_ARRAY_LEN(labels); i++)
    {
        if (!sa_reads(labels[i], "proto", "esp"))
            TEST_VERDICT("A new IPsec SA did not default to the ESP protocol");
        if (!sa_reads(labels[i], "mode", "tunnel"))
            TEST_VERDICT("A new IPsec SA did not default to tunnel mode");
        /*
         * The finding the low-level subtree exists to make catchable: an SA
         * with no encryption algorithm is null-encrypted - integrity, if any,
         * but no confidentiality. A freshly created SA is exactly that.
         */
        if (!sa_reads(labels[i], "enc_alg", ""))
            TEST_VERDICT("A new IPsec SA has an encryption clause it was "
                         "never given");
        encrypted[i] = 0;
        TEST_ARTIFACT("ipsec %s: proto esp, mode tunnel, enc_alg empty "
                      "(null encryption - no confidentiality)", labels[i]);
    }

    tsapi_mde_mi_bars("tapi_cfg_vpn", "IPsec SA encryption present per SA "
                      "(1 = has enc_alg, 0 = null-encrypted)",
                      TE_MI_MEAS_UNITLESS_VALUE, "encrypted",
                      TE_ARRAY_LEN(labels), labels, encrypted,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("ipsec: rendering the 'ip xfrm state add ...' text for a "
                  "configured SA (including the null-encryption variant with "
                  "no enc clause) is done by the agent-side ta_vpn builder, "
                  "which is not linked into the engine test, and applying an "
                  "SA needs the xfrm kernel this container lacks; both are "
                  "out of reach here");

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < TE_ARRAY_LEN(labels); i++)
    {
        if (added[i])
            CLEANUP_CHECK_RC(cfg_del_instance_fmt(false,
                             "/agent:" NET_TA "/vpn:/ipsec:%s", labels[i]));
    }
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

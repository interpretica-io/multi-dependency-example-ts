/** @file
 * @brief IoT Group
 *
 * The DUT has no Bluetooth adapter, so this charts what each backend of
 * tsf-bluetooth supports - the support matrix the README documents - and
 * checks the address normaliser against vectors; the live adapter work is
 * skipped with the concrete reason.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "iot/bluetooth"

#include "te_config.h"

#include <string.h>

#include "tapi_test.h"
#include "tapi_bt.h"
#include "tapi_bt_audit.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"

static const tapi_bt_backend backends[] = {
    TAPI_BT_BLUEZ, TAPI_BT_HCI, TAPI_BT_MACOS, TAPI_BT_WINDOWS,
};

/* The features in the README's columns, in table order. */
static const struct {
    const char  *name;
    unsigned int flag;
} feature_rows[] = {
    { "adapter",      TAPI_BT_FEAT_ADAPTER },
    { "power",        TAPI_BT_FEAT_POWER },
    { "discoverable", TAPI_BT_FEAT_DISCOVERABLE },
    { "scan",         TAPI_BT_FEAT_SCAN },
    { "known",        TAPI_BT_FEAT_KNOWN },
    { "pair",         TAPI_BT_FEAT_PAIR },
    { "connect",      TAPI_BT_FEAT_CONNECT },
    { "rssi",         TAPI_BT_FEAT_RSSI },
    { "hci_trace",    TAPI_BT_FEAT_HCI_TRACE },
    { "l2_sdp",       TAPI_BT_FEAT_L2_SDP },
};

int
main(int argc, char **argv)
{
    tsapi_mde_session session;
    bool              session_up = false;
    double            counts[TE_ARRAY_LEN(backends)];
    const char       *labels[TE_ARRAY_LEN(backends)];
    unsigned int      i;
    unsigned int      j;

    TEST_START;

    TEST_STEP("Chart the support matrix each backend declares");
    for (i = 0; i < TE_ARRAY_LEN(backends); i++)
    {
        unsigned int f = tapi_bt_features(backends[i]);
        unsigned int n = 0;
        te_mi_logger *logger;

        labels[i] = tapi_bt_backend2str(backends[i]);
        CHECK_RC(tsapi_mde_mi_create("tapi_bt", &logger));
        te_mi_logger_add_meas_key(logger, NULL, "backend", "%s", labels[i]);
        for (j = 0; j < TE_ARRAY_LEN(feature_rows); j++)
        {
            bool has = (f & feature_rows[j].flag) != 0;
            char key[32];

            if (has)
                n++;
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "feature", TE_MI_MEAS_AGGR_SINGLE, j,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "supported", TE_MI_MEAS_AGGR_SINGLE,
                                  has ? 1 : 0, TE_MI_MEAS_MULTIPLIER_PLAIN);
            TE_SPRINTF(key, "x%u", j);
            te_mi_logger_add_meas_key(logger, NULL, key, "%s",
                                      feature_rows[j].name);
        }
        tsapi_mde_mi_line(logger, "matrix", "Bluetooth feature support",
                          "feature", "supported", NULL);
        te_mi_logger_destroy(logger);
        counts[i] = n;
        TEST_ARTIFACT("Bluetooth backend %s supports %u of %zu features",
                      labels[i], n, TE_ARRAY_LEN(feature_rows));
    }
    tsapi_mde_mi_bars("tapi_bt", "Features supported per Bluetooth backend",
                      TE_MI_MEAS_UNITLESS_VALUE, "features",
                      TE_ARRAY_LEN(backends), labels, counts,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Every backend must at least read its own adapter");
    for (i = 0; i < TE_ARRAY_LEN(backends); i++)
    {
        if (!tapi_bt_supports(backends[i], TAPI_BT_FEAT_ADAPTER))
            TEST_VERDICT("A Bluetooth backend cannot even read its adapter");
    }
    /* Only BlueZ has the complete set, per the README. */
    if (tapi_bt_features(TAPI_BT_BLUEZ) != (unsigned int)(
            TAPI_BT_FEAT_ADAPTER | TAPI_BT_FEAT_POWER |
            TAPI_BT_FEAT_DISCOVERABLE | TAPI_BT_FEAT_SCAN |
            TAPI_BT_FEAT_KNOWN | TAPI_BT_FEAT_PAIR | TAPI_BT_FEAT_CONNECT |
            TAPI_BT_FEAT_RSSI | TAPI_BT_FEAT_HCI_TRACE | TAPI_BT_FEAT_L2_SDP))
    {
        TEST_VERDICT("The BlueZ backend no longer supports the whole set");
    }

    TEST_STEP("Check the address normaliser against known vectors");
    {
        static const struct {
            const char *in;
            const char *out;
            bool        ok;
        } vectors[] = {
            { "20:15:82:EF:D2:5D", "20:15:82:EF:D2:5D", true },
            { "20-15-82-ef-d2-5d", "20:15:82:EF:D2:5D", true },
            { "aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", true },
            { "not an address",    "",                  false },
            { "20:15:82:EF:D2",    "",                  false },
        };

        for (i = 0; i < TE_ARRAY_LEN(vectors); i++)
        {
            char dest[TAPI_BT_ADDR_LEN] = "";
            bool ok = tapi_bt_addr_normalize(vectors[i].in, dest);

            if (ok != vectors[i].ok)
                TEST_VERDICT("The address normaliser accepted or rejected a "
                             "vector it should not have");
            if (ok && strcmp(dest, vectors[i].out) != 0)
                TEST_VERDICT("The address normaliser produced the wrong "
                             "canonical form");
        }
        TEST_ARTIFACT("Bluetooth: %zu address-normalisation vectors agree "
                      "(BlueZ colons, blueutil dashes, lower case, two bad "
                      "ones rejected)", TE_ARRAY_LEN(vectors));
    }

    TEST_STEP("Skip the live adapter work: there is none here");
    CHECK_RC(tsapi_mde_session_init(&session, "iot_bt"));
    session_up = true;
    if (!tapi_bt_available(session.factory, TAPI_BT_AUTO, 10000))
    {
        TEST_SKIP("No Bluetooth adapter on the agent: btmgmt and hciconfig "
                  "report none and there is no AF_BLUETOOTH stack in this "
                  "container, so the adapter read, scan and audit cannot run");
    }

    TEST_STEP("An adapter appeared unexpectedly: read and audit it");
    {
        tapi_bt_adapter        adapter;
        tapi_cybersec_report   cyber;
        tapi_bt_backend        backend;

        tapi_cybersec_report_init(&cyber);
        CHECK_RC(tapi_bt_detect(session.factory, 10000, &backend));
        CHECK_RC(tapi_bt_adapter_get(session.factory, backend, 10000,
                                     &adapter));
        tapi_bt_adapter_log(&adapter);
        TEST_ARTIFACT("Bluetooth adapter %s found through %s",
                      adapter.address, tapi_bt_backend2str(backend));
        (void)tapi_bt_audit(session.factory, backend,
                            &tapi_bt_default_policy, 10000, &cyber);
        tapi_cybersec_report_log(&cyber);
        tapi_bt_adapter_free(&adapter);
        tapi_cybersec_report_free(&cyber);
    }

    TEST_SUCCESS;

cleanup:

    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

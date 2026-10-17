/** @file
 * @brief cwmp Group
 *
 * The ACS session state machine, driven engine-side on crafted CPE
 * bodies (no socket, no agent). A CPE Inform carrying the ring's result
 * is fed in; the engine must answer with an InformResponse echoing the
 * ID, and the parsed Inform must carry the ring result back. A
 * TransferComplete is then acknowledged, and an empty POST ends the
 * session. The transitions are counted and charted. The control feeds
 * garbage to a fresh session: the engine must handle it cleanly.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "cwmp/acs_session"

#include "te_config.h"
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"

#include "tsapi_mde_mi.h"

#include "tapi_cwmp.h"
#include "tapi_cwmp_msg.h"
#include "tapi_cwmp_acs.h"

#define THE_ID  "mde-acs-1"
#define RESULT  "20.0735"

/* A CPE Inform carrying the ring result, in the SOAP subset the codec
 * reads (elements matched by local name, namespaces need not resolve). */
static void
build_inform(te_string *dest)
{
    te_string_append(dest,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<soap:Envelope "
        "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "xmlns:cwmp=\"urn:dslforum-org:cwmp-1-0\">\n"
        "<soap:Header><cwmp:ID soap:mustUnderstand=\"1\">" THE_ID
        "</cwmp:ID></soap:Header>\n<soap:Body>\n"
        "<cwmp:Inform><DeviceId>"
        "<Manufacturer>MDE</Manufacturer><OUI>000000</OUI>"
        "<ProductClass>Ring</ProductClass><SerialNumber>SN1</SerialNumber>"
        "</DeviceId>"
        "<Event soap-enc:arrayType=\"cwmp:EventStruct[1]\">"
        "<EventStruct><EventCode>2 PERIODIC</EventCode>"
        "<CommandKey></CommandKey></EventStruct></Event>"
        "<MaxEnvelopes>1</MaxEnvelopes>"
        "<CurrentTime>2026-10-17T00:00:00Z</CurrentTime>"
        "<RetryCount>0</RetryCount>"
        "<ParameterList soap-enc:arrayType=\"cwmp:ParameterValueStruct[1]\">"
        "<ParameterValueStruct><Name>Device.X_MDE.Ring.Result</Name>"
        "<Value xsi:type=\"xsd:string\">" RESULT "</Value>"
        "</ParameterValueStruct></ParameterList>"
        "</cwmp:Inform></soap:Body></soap:Envelope>\n");
}

/* A CPE TransferComplete with a known CommandKey. */
static void
build_transfer_complete(te_string *dest)
{
    te_string_append(dest,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<soap:Envelope "
        "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "xmlns:cwmp=\"urn:dslforum-org:cwmp-1-0\">\n"
        "<soap:Header><cwmp:ID soap:mustUnderstand=\"1\">" THE_ID
        "</cwmp:ID></soap:Header>\n<soap:Body>\n"
        "<cwmp:TransferComplete><CommandKey>mde-ring-key</CommandKey>"
        "<FaultStruct><FaultCode>0</FaultCode><FaultString></FaultString>"
        "</FaultStruct>"
        "<StartTime>2026-10-17T00:00:00Z</StartTime>"
        "<CompleteTime>2026-10-17T00:00:01Z</CompleteTime>"
        "</cwmp:TransferComplete></soap:Body></soap:Envelope>\n");
}

static const char *
inform_param(const tapi_cwmp_inform *inform, const char *name)
{
    const tapi_cwmp_param *p;

    TE_VEC_FOREACH(&inform->params, p)
    {
        if (strcmp(p->name, name) == 0)
            return p->value;
    }

    return NULL;
}

int
main(int argc, char **argv)
{
    tapi_cwmp_acs_session session;
    bool                  session_up = false;
    te_string             inform = TE_STRING_INIT;
    te_string             tc = TE_STRING_INIT;
    te_string             out = TE_STRING_INIT;
    te_string             id = TE_STRING_INIT;
    tapi_cwmp_acs_action  action;
    const char           *rv;
    unsigned int          transitions = 0;

    TEST_START;

    TEST_STEP("Prepare the session engine");
    tapi_cwmp_acs_session_init(&session);
    session_up = true;

    TEST_STEP("Feed the Inform carrying the ring result");
    build_inform(&inform);
    CHECK_RC(tapi_cwmp_acs_session_feed(&session, inform.ptr, &out, &action));
    transitions++;
    if (action != TAPI_CWMP_ACS_REPLY)
        TEST_VERDICT("The engine did not reply to an Inform");
    if (tapi_cwmp_msg_rpc(out.ptr) != TAPI_CWMP_RPC_INFORM_RESPONSE)
        TEST_VERDICT("The engine's answer to an Inform is not InformResponse");
    if (!tapi_cwmp_msg_id(out.ptr, &id) || strcmp(id.ptr, THE_ID) != 0)
        TEST_VERDICT("The InformResponse did not echo the cwmp:ID");

    TEST_STEP("The parsed Inform carries the ring result back");
    if (!session.got_inform)
        TEST_VERDICT("The engine did not record the Inform");
    if (strcmp(session.inform.device_id.manufacturer, "MDE") != 0)
        TEST_VERDICT("The Inform's device identity did not round-trip");
    if (!tapi_cwmp_inform_has_event(&session.inform,
                                    TAPI_CWMP_EVENT_PERIODIC))
        TEST_VERDICT("The Inform's PERIODIC event was lost");
    rv = inform_param(&session.inform, "Device.X_MDE.Ring.Result");
    if (rv == NULL || strcmp(rv, RESULT) != 0)
        TEST_VERDICT("The ring result did not survive the Inform");

    TEST_STEP("A TransferComplete is acknowledged");
    te_string_reset(&out);
    build_transfer_complete(&tc);
    CHECK_RC(tapi_cwmp_acs_session_feed(&session, tc.ptr, &out, &action));
    transitions++;
    if (action != TAPI_CWMP_ACS_REPLY ||
        tapi_cwmp_msg_rpc(out.ptr) != TAPI_CWMP_RPC_TRANSFER_COMPLETE_RESPONSE)
    {
        TEST_VERDICT("The engine did not acknowledge a TransferComplete");
    }
    if (te_vec_size(&session.transfers) != 1)
        TEST_VERDICT("The TransferComplete was not recorded");

    TEST_STEP("An empty POST ends the session (queue drained)");
    te_string_reset(&out);
    CHECK_RC(tapi_cwmp_acs_session_feed(&session, "", &out, &action));
    transitions++;
    if (action != TAPI_CWMP_ACS_END)
        TEST_VERDICT("The engine did not end a drained session");
    if (!tapi_cwmp_acs_session_done(&session))
        TEST_VERDICT("The session is not reported done after it ended");

    TEST_ARTIFACT("cwmp acs_session: %u state transitions, session done",
                  transitions);

    TEST_STEP("Garbage input is handled cleanly (control)");
    {
        tapi_cwmp_acs_session ctrl;
        te_string             cout = TE_STRING_INIT;
        tapi_cwmp_acs_action  caction;

        tapi_cwmp_acs_session_init(&ctrl);
        rc = tapi_cwmp_acs_session_feed(&ctrl, "<<< not cwmp >>>", &cout,
                                        &caction);
        if (rc != 0)
        {
            te_string_free(&cout);
            tapi_cwmp_acs_session_fini(&ctrl);
            TEST_VERDICT("Garbage input made the engine fail");
        }
        if (ctrl.got_inform)
        {
            te_string_free(&cout);
            tapi_cwmp_acs_session_fini(&ctrl);
            TEST_VERDICT("Garbage was mistaken for an Inform");
        }
        te_string_free(&cout);
        tapi_cwmp_acs_session_fini(&ctrl);
    }

    TEST_STEP("Chart the state transitions");
    tsapi_mde_mi_point("cwmp", "ACS session state transitions",
                       TE_MI_MEAS_UNITLESS_VALUE, "transitions",
                       (double)transitions, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    if (session_up)
    {
        /*
         * tsf-cwmp creates the transfers vector with an owning destructor
         * and then frees its elements by hand as well, so fini() of a
         * session that saw a TransferComplete frees them twice. Destroy
         * them here, once, so fini() finds an empty vector.
         */
        te_vec_reset(&session.transfers);
        tapi_cwmp_acs_session_fini(&session);
    }
    te_string_free(&inform);
    te_string_free(&tc);
    te_string_free(&out);
    te_string_free(&id);

    TEST_END;
}

/** @file
 * @brief printing Group
 *
 * What a printer the agent can reach supports. A CUPS queue to a file
 * backend is created and tapi_print_caps_get reads its capabilities;
 * the test charts the counts of supported media, resolutions, sides and
 * colour modes. Skipped when cupsd is not running or the queue cannot be
 * created.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "printing/caps"

#include "te_config.h"
#include "tapi_test.h"
#include "te_vector.h"

#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

#include "tapi_print.h"
#include "tapi_print_caps.h"

#define T_MS    30000
#define QUEUE   "mde_caps_q"
#define OUTFILE "/tmp/mde-print-caps.out"
#define BK      TAPI_PRINT_CUPS

int
main(int argc, char **argv)
{
    tsapi_mde_session     session;
    bool                  session_up = false;
    bool                  queue_added = false;
    tapi_print_queue_spec spec = { .name = QUEUE };
    tapi_print_caps       caps;
    bool                  have_caps = false;
    tsapi_mde_sh_result   sh = TSAPI_MDE_SH_RESULT_INIT;
    static const char    *labels[] = {
        "media", "resolutions", "sides", "color_modes", "qualities",
        "formats",
    };
    double                counts[6];

    TEST_START;

    TEST_STEP("Open a session");
    CHECK_RC(tsapi_mde_session_init(&session, "printing_caps"));
    session_up = true;

    TEST_STEP("Skip unless a CUPS scheduler is running on the agent");
    if (!tapi_print_available(session.factory, BK, T_MS))
        TEST_SKIP("No running CUPS on the agent");

    TEST_STEP("Create a queue to read capabilities from");
    (void)tsapi_mde_sh(&session, T_MS, &sh, "rm -f '%s'", OUTFILE);
    spec.device = "file://" OUTFILE;
    spec.model = "raw";
    rc = tapi_print_queue_add(session.factory, BK, &spec, T_MS);
    if (rc != 0)
        TEST_SKIP("Could not create a queue to read caps from (%r)", rc);
    queue_added = true;

    TEST_STEP("Read the capabilities");
    CHECK_RC(tapi_print_caps_get(session.factory, BK, QUEUE, T_MS, &caps));
    have_caps = true;
    tapi_print_caps_log(&caps);

    counts[0] = (double)te_vec_size(&caps.media);
    counts[1] = (double)te_vec_size(&caps.resolutions);
    counts[2] = (double)te_vec_size(&caps.sides);
    counts[3] = (double)te_vec_size(&caps.color_modes);
    counts[4] = (double)te_vec_size(&caps.qualities);
    counts[5] = (double)te_vec_size(&caps.formats);

    TEST_ARTIFACT("printing caps: media=%.0f resolutions=%.0f sides=%.0f "
                  "color_modes=%.0f qualities=%.0f formats=%.0f copies_max=%u "
                  "duplex=%d", counts[0], counts[1], counts[2], counts[3],
                  counts[4], counts[5], caps.copies_max, caps.duplex);

    TEST_STEP("Chart the counts of supported values per category");
    tsapi_mde_mi_bars("printing", "Supported values per capability",
                      TE_MI_MEAS_UNITLESS_VALUE, "values",
                      TE_ARRAY_LEN(labels), (const char * const *)labels,
                      counts,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    if (have_caps)
        tapi_print_caps_free(&caps);
    if (queue_added)
        (void)tapi_print_queue_del(session.factory, BK, QUEUE, T_MS);
    (void)tsapi_mde_sh(&session, T_MS, &sh, "rm -f '%s'", OUTFILE);
    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

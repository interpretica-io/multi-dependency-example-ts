/** @file
 * @brief printing Group
 *
 * The ring's trace as a print job. A CUPS queue is created to a file
 * backend (lpadmin -v file://..., which needs FileDevice yes) with the
 * generic PostScript driver CUPS ships - a raw queue completes its jobs
 * without writing anything to a file: device on CUPS 2.4, so it is only
 * the fallback. The ring trace text is printed to it, the job is followed
 * to completion, and the backend's output file is checked to exist and
 * be non-empty (the scheduler writes it as root, so its size is read
 * from the directory, not from its contents). IPP Validate-Job is asked
 * on a supported job and on one in a document format nobody supports -
 * the latter must be rejected (control; CUPS checks the format, not the
 * job template values). Skipped when cupsd is not running or the file
 * backend is not permitted.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "printing/ring_report_job"

#include "te_config.h"
#include <stdlib.h>
#include "tapi_test.h"
#include "te_string.h"

#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

#include "tapi_print.h"
#include "tapi_print_job.h"
#include "tapi_print_caps.h"

#define T_MS    30000
#define QUEUE   "mde_ring_q"
#define OUTFILE "/tmp/mde-print-ring.out"
#define BK      TAPI_PRINT_CUPS
/** The generic PostScript printer of CUPS's sample driver. */
#define GENERIC "drv:///sample.drv/generic.ppd"
/** A document format no printer supports, for the Validate-Job control. */
#define BOGUS_FORMAT "application/x-mde-bogus"

int
main(int argc, char **argv)
{
    tsapi_mde_session     session;
    bool                  session_up = false;
    bool                  queue_added = false;
    tapi_print_queue_spec spec = { .name = QUEUE };
    tsapi_mde_sh_result   sh = TSAPI_MDE_SH_RESULT_INIT;
    tapi_print_opts       opts = TAPI_PRINT_OPTS_INIT;
    tapi_print_job        job;
    bool                  have_job = false;
    bool                  raw = false;
    unsigned int          id;
    double                job_time;
    double                out_size = 0.0;

    TEST_START;

    TEST_STEP("Open a session");
    CHECK_RC(tsapi_mde_session_init(&session, "printing_ring_job"));
    session_up = true;

    TEST_STEP("Skip unless a CUPS scheduler is running on the agent");
    if (!tapi_print_available(session.factory, BK, T_MS))
        TEST_SKIP("No running CUPS on the agent");

    TEST_STEP("Create a queue to a file backend (needs FileDevice yes)");
    (void)tsapi_mde_sh(&session, T_MS, &sh,
                       "rm -f '%s' 2>/dev/null || sudo -n rm -f '%s'",
                       OUTFILE, OUTFILE);
    spec.device = "file://" OUTFILE;
    spec.model = GENERIC;
    spec.info = "mde ring report";
    rc = tapi_print_queue_add(session.factory, BK, &spec, T_MS);
    if (rc != 0)
    {
        RING("No queue with the generic driver (%r), trying a raw one", rc);
        spec.model = "raw";
        raw = true;
        rc = tapi_print_queue_add(session.factory, BK, &spec, T_MS);
    }
    if (rc != 0)
        TEST_SKIP("The file backend is not permitted on this CUPS (%r)", rc);
    queue_added = true;

    TEST_STEP("Validate a supported job, and reject an unsupported one");
    if (tapi_print_supports(BK, TAPI_PRINT_FEAT_VALIDATE))
    {
        te_string reason = TE_STRING_INIT;

        opts.copies = 1;
        rc = tapi_print_validate(session.factory, BK, QUEUE, &opts, T_MS,
                                 NULL);
        if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_ENOENT)
        {
            te_string_free(&reason);
            TEST_VERDICT("Validate-Job refused a supported job: %r", rc);
        }
        if (rc == 0)
        {
            tapi_print_opts bad = TAPI_PRINT_OPTS_INIT;

            bad.document_format = BOGUS_FORMAT;
            rc = tapi_print_validate(session.factory, BK, QUEUE, &bad, T_MS,
                                     &reason);
            if (TE_RC_GET_ERROR(rc) != TE_EINVAL)
            {
                te_string_free(&reason);
                TEST_VERDICT("An unsupported document format was not "
                             "rejected: %r", rc);
            }
            RING("Validate-Job rejected the bad job: %s", reason.ptr);
        }
        else
        {
            RING("No ipptool on the agent, Validate-Job not exercised");
        }
        te_string_free(&reason);
    }

    TEST_STEP("Print the ring trace text as a job and wait for it");
    opts = (tapi_print_opts)TAPI_PRINT_OPTS_INIT;
    opts.job_name = "mde ring trace";
    opts.raw = raw;
    job_time = tsapi_mde_now();
    CHECK_RC(tapi_print_text(session.factory, BK, QUEUE,
                             "mde ring trace\n"
                             "cpp -> rust -> go -> cs -> py -> cpp\n",
                             &opts, T_MS, &id));
    CHECK_RC(tapi_print_job_wait(session.factory, BK, QUEUE, id, 60000,
                                 &job));
    have_job = true;
    job_time = tsapi_mde_now() - job_time;
    tapi_print_job_log(&job);

    TEST_STEP("Its final state must be a completion, not a failure");
    if (job.state != TAPI_PRINT_JOB_COMPLETED &&
        job.state != TAPI_PRINT_JOB_ENDED)
    {
        TEST_VERDICT("The ring report job ended %s",
                     tapi_print_job_state2str(job.state));
    }

    TEST_STEP("The backend's output file exists and is non-empty");
    tsapi_mde_sh_result_free(&sh);
    CHECK_RC(tsapi_mde_sh(&session, T_MS, &sh,
                          "test -s '%s' && ls -ln '%s' | awk '{ print $5 }'",
                          OUTFILE, OUTFILE));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_VERDICT("The print backend wrote no output file");
    out_size = (double)strtoul(te_string_value(&sh.out), NULL, 10);
    RING("The job wrote %.0f bytes to %s", out_size, OUTFILE);

    TEST_ARTIFACT("printing ring_report_job: job %u ended %s, %.0f bytes, "
                  "%.3f s", id, tapi_print_job_state2str(job.state), out_size,
                  job_time);

    TEST_STEP("Chart the job time and the output size");
    tsapi_mde_mi_point("printing", "Ring report job time", TE_MI_MEAS_TIME,
                       "job_time", job_time, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("printing", "Ring report output size",
                       TE_MI_MEAS_MEMORY, "output_bytes", out_size,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    if (have_job)
        tapi_print_job_free(&job);
    if (queue_added)
        (void)tapi_print_queue_del(session.factory, BK, QUEUE, T_MS);
    (void)tsapi_mde_sh(&session, T_MS, &sh,
                       "rm -f '%s' 2>/dev/null || sudo -n rm -f '%s'",
                       OUTFILE, OUTFILE);
    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

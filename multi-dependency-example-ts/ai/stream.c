/** @file
 * @brief AI Group
 *
 * A streamed answer from the model: ask it to count from 1 to N, take
 * the answer piece by piece as it is generated, and check the pieces put
 * together are exactly "1 2 ... N" in order. The same prompt asked
 * without streaming must give the same numbers - two independent
 * readings. Chunk sizes and arrival times are charted over the chunk
 * index, with the time to the first chunk and the token counts.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ai/stream"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_ai.h"
#include "tapi_ai_stream.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "ai_common.h"

/* Chunks charted at most. */
#define MAX_CHUNKS  1024

/* Time to wait for one chunk. */
#define CHUNK_TIMEOUT_MS    60000

/*
 * Check that a text holds exactly the numbers 1..n in order, separated by
 * anything that is not a digit. Returns how many numbers were in order
 * from the start.
 */
static unsigned int
stream_count_ok(const char *text, int n, bool *exact)
{
    const char  *p = text;
    unsigned int good = 0;
    int          want = 1;

    *exact = true;
    while (p != NULL && *p != '\0')
    {
        char *end;
        long  v;

        if (*p < '0' || *p > '9')
        {
            p++;
            continue;
        }
        v = strtol(p, &end, 10);
        p = end;
        if (v != want)
        {
            *exact = false;
            return good;
        }
        good++;
        want++;
    }
    if (want != n + 1)
        *exact = false;

    return good;
}

int
main(int argc, char **argv)
{
    tapi_ai_provider       provider = TAPI_AI_ANTHROPIC;
    int                    count;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tapi_ai_conn           conn;
    bool                   conn_up = false;
    tapi_ai_opts           opts = TAPI_AI_OPTS_INIT;
    tapi_ai_stream         stream;
    bool                   stream_up = false;
    tapi_ai_usage          usage;
    tapi_ai_reply          reply;
    te_string              model = TE_STRING_INIT;
    te_string              prompt = TE_STRING_INIT;
    te_string              piece = TE_STRING_INIT;
    te_string              whole = TE_STRING_INIT;
    tsapi_mde_report       report;
    double                 sizes[MAX_CHUNKS];
    double                 arrivals[MAX_CHUNKS];
    unsigned int           n_chunks = 0;
    size_t                 sum = 0;
    unsigned int           good_stream;
    unsigned int           good_ask;
    bool                   exact_stream;
    bool                   exact_ask;
    double                 t0;
    double                 t_first = -1;
    double                 t_total;
    double                 t_ask;

    TEST_START;
    memset(&conn, 0, sizeof(conn));
    memset(&stream, 0, sizeof(stream));
    memset(&usage, 0, sizeof(usage));
    memset(&reply, 0, sizeof(reply));
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(provider, AI_PROVIDER_MAPPING_LIST);
    TEST_GET_INT_PARAM(count);
    TEST_GET_MDE_SEVERITY(min_severity);

    TEST_STEP("Open a session and connect to the model");
    CHECK_RC(tsapi_mde_session_init(&session, "ai_stream"));
    session_up = true;
    if (!tapi_ai_supports(provider, TAPI_AI_FEAT_STREAM))
        TEST_SKIP("The provider does not stream");
    ai_open(&session, provider, &conn, &conn_up, &model);
    opts.model = model.len > 0 ? model.ptr : NULL;
    opts.temperature_pct = 0;
    opts.max_tokens = 400;
    te_string_append(&prompt, "Count from 1 to %d. Write only the numbers, "
                     "separated by single spaces, on one line, and nothing "
                     "else.", count);

    TEST_STEP("Stream the answer piece by piece");
    t0 = tsapi_mde_now();
    ai_check_rc(tapi_ai_stream_start(&conn, prompt.ptr, &opts, &stream),
                "Starting the stream");
    stream_up = true;
    while ((rc = tapi_ai_stream_next(&stream, CHUNK_TIMEOUT_MS,
                                     &piece)) == 0)
    {
        double now = tsapi_mde_now() - t0;

        if (t_first < 0)
            t_first = now;
        if (n_chunks < MAX_CHUNKS)
        {
            sizes[n_chunks] = piece.len;
            arrivals[n_chunks] = now;
        }
        n_chunks++;
        sum += piece.len;
        te_string_append(&whole, "%s", piece.ptr != NULL ? piece.ptr : "");
        te_string_reset(&piece);
    }
    if (TE_RC_GET_ERROR(rc) == TE_ETIMEDOUT)
        TEST_VERDICT("The stream stalled before it ended");
    if (TE_RC_GET_ERROR(rc) != TE_ENODATA)
        TEST_FAIL("The stream ended with %r", rc);
    ai_check_rc(tapi_ai_stream_finish(&stream, &usage), "Finishing the stream");
    t_total = tsapi_mde_now() - t0;

    TEST_ARTIFACT("Stream: %u chunk(s), %zu byte(s), first after %.2f s, "
                  "whole in %.2f s: '%s'", n_chunks, sum, t_first, t_total,
                  whole.ptr != NULL ? whole.ptr : "");

    TEST_STEP("The pieces put together are the answer, in order");
    if (n_chunks == 0)
        TEST_VERDICT("The stream delivered no piece of the answer");
    if (sum != whole.len)
        TEST_VERDICT("The pieces do not add up to the answer");
    good_stream = stream_count_ok(whole.ptr, count, &exact_stream);
    TEST_ARTIFACT("Streamed answer: %u of %d numbers in order%s", good_stream,
                  count, exact_stream ? ", exact" : "");
    if (!exact_stream)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "ai.stream-content", "stream",
                                 "the streamed answer is not 1..%d in order "
                                 "(%u in order from the start)", count,
                                 good_stream);
    }
    if (usage.output_tokens == 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                 "ai.stream-usage", "stream",
                                 "the stream reported 0 output tokens for "
                                 "a non-empty answer");
    }

    TEST_STEP("Ask the same without streaming: a second reading");
    t0 = tsapi_mde_now();
    ai_check_rc(tapi_ai_ask(&conn, NULL, prompt.ptr, &opts, AI_TIMEOUT_MS,
                            &reply), "Asking without streaming");
    t_ask = tsapi_mde_now() - t0;
    tapi_ai_reply_log(&reply);
    good_ask = stream_count_ok(reply.text != NULL ? reply.text : "", count,
                               &exact_ask);
    TEST_ARTIFACT("Non-streamed answer: %u of %d numbers in order%s",
                  good_ask, count, exact_ask ? ", exact" : "");
    if (exact_ask != exact_stream || good_ask != good_stream)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                 "ai.disagrees", "stream/vs-ask",
                                 "streamed and non-streamed answers differ: "
                                 "%u vs %u numbers in order", good_stream,
                                 good_ask);
    }

    TEST_STEP("Chart the stream");
    tsapi_mde_mi_series("ai", "Chunk size over chunk index",
                        TE_MI_MEAS_MEMORY, "chunk",
                        n_chunks < MAX_CHUNKS ? n_chunks : MAX_CHUNKS, sizes,
                        TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_series("ai", "Chunk arrival time over chunk index",
                        TE_MI_MEAS_TIME, "arrival",
                        n_chunks < MAX_CHUNKS ? n_chunks : MAX_CHUNKS,
                        arrivals, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("ai", "Time to the first chunk", TE_MI_MEAS_TIME,
                       "ttfc", t_first, TE_MI_MEAS_MULTIPLIER_PLAIN);
    ai_chart_cost("stream", t_total, &usage);
    ai_chart_cost("same prompt, not streamed", t_ask, &reply.usage);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "ai", min_severity);

    TEST_SUCCESS;

cleanup:

    if (stream_up)
        tapi_ai_stream_free(&stream);
    tapi_ai_reply_free(&reply);
    if (conn_up)
        tapi_ai_conn_fini(&conn);
    te_string_free(&model);
    te_string_free(&prompt);
    te_string_free(&piece);
    te_string_free(&whole);
    tsapi_mde_report_free(&report);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

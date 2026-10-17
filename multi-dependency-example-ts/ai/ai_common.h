/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief AI group helpers
 *
 * Where the AI key comes from and which provider it belongs to, opening
 * a connection or skipping with the reason, and reading the small JSON
 * object a model is asked to answer with (tolerant of spaces and of text
 * around the object, as models write it).
 *
 * The key: tsf-ai hands it to the helper on the agent in the TSF_AI_KEY
 * environment variable of the job, never in argv. The test has to hold
 * it to give it to tapi_ai_conn_init(): it is taken from the engine's
 * environment, or else from the agent's environment through
 * /agent/env:TSF_AI_KEY. It is never logged.
 *
 * Everything here is @c static @c inline: each test is one C file.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_AI_COMMON_H__
#define __MDE_AI_COMMON_H__

#include "te_config.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "tapi_test.h"
#include "te_string.h"
#include "conf_api.h"
#include "tapi_ai.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/** Timeout of one request to a model. */
#define AI_TIMEOUT_MS   120000

/** Values of the @c provider parameter. */
#define AI_PROVIDER_MAPPING_LIST \
    { "anthropic", TAPI_AI_ANTHROPIC }, \
    { "openai",    TAPI_AI_OPENAI }

/**
 * Read a setting: the engine's environment first, then the agent's
 * (/agent/env).
 *
 * @param[in]  ta       Agent.
 * @param[in]  name     Variable name.
 * @param[out] value    String to append the value to.
 *
 * @return @c true if set and not empty.
 */
static inline bool
ai_setting(const char *ta, const char *name, te_string *value)
{
    const char *engine = getenv(name);
    char       *agent = NULL;
    bool        ok = false;

    if (engine != NULL && *engine != '\0')
    {
        te_string_append(value, "%s", engine);
        return true;
    }

    if (cfg_find_fmt(NULL, "/agent:%s/env:%s", ta, name) == 0 &&
        cfg_get_string(&agent, "/agent:%s/env:%s", ta, name) == 0 &&
        agent != NULL && *agent != '\0')
    {
        te_string_append(value, "%s", agent);
        ok = true;
    }
    free(agent);

    return ok;
}

/**
 * Which provider a key is for: TSF_AI_PROVIDER when set, else the key's
 * prefix (Anthropic keys start with "sk-ant-").
 *
 * @param ta    Agent.
 * @param key   The key.
 *
 * @return Provider.
 */
static inline tapi_ai_provider
ai_key_provider(const char *ta, const char *key)
{
    te_string        name = TE_STRING_INIT;
    tapi_ai_provider provider;

    if (ai_setting(ta, "TSF_AI_PROVIDER", &name))
    {
        if (strcasecmp(name.ptr, "anthropic") == 0 ||
            strcasecmp(name.ptr, "claude") == 0)
            provider = TAPI_AI_ANTHROPIC;
        else if (strcasecmp(name.ptr, "gemini") == 0)
            provider = TAPI_AI_GEMINI;
        else if (strcasecmp(name.ptr, "xai") == 0)
            provider = TAPI_AI_XAI;
        else
            provider = TAPI_AI_OPENAI;
    }
    else
    {
        provider = strncmp(key, "sk-ant-", 7) == 0 ? TAPI_AI_ANTHROPIC :
                                                      TAPI_AI_OPENAI;
    }
    te_string_free(&name);

    return provider;
}

/**
 * Open a connection to @p provider with the run's key, or skip the test
 * with the reason: no key, a key for another provider, no python3, the
 * provider out of reach.
 *
 * @param[in]  session  Session (its RPC job factory runs the helper).
 * @param[in]  provider Provider of this iteration.
 * @param[out] conn     Connection; release with tapi_ai_conn_fini().
 * @param[out] conn_up  Set once @p conn needs releasing.
 * @param[out] model    String to put the model name into (TSF_AI_MODEL),
 *                      left empty for the module's default.
 */
static inline void
ai_open(tsapi_mde_session *session, tapi_ai_provider provider,
        tapi_ai_conn *conn, bool *conn_up, te_string *model)
{
    te_string key = TE_STRING_INIT;
    te_string base = TE_STRING_INIT;
    te_errno  rc;
    bool      have_base;

    if (!ai_setting(session->ta, "TSF_AI_KEY", &key))
        TEST_SKIP("TSF_AI_KEY is not set");

    if (ai_key_provider(session->ta, key.ptr) != provider)
    {
        te_string_free(&key);
        TEST_SKIP("TSF_AI_KEY is for another provider than this iteration");
    }

    if (!tsapi_mde_have(session, "python3"))
    {
        te_string_free(&key);
        TEST_SKIP("python3 is not installed on the agent");
    }

    have_base = ai_setting(session->ta, "TSF_AI_BASE_URL", &base);
    ai_setting(session->ta, "TSF_AI_MODEL", model);

    rc = tapi_ai_conn_init(session->factory, provider,
                           have_base ? base.ptr : NULL, key.ptr, conn);
    te_string_free(&key);
    te_string_free(&base);
    if (rc != 0)
        TEST_FAIL("Cannot open a connection to %s: %r",
                  tapi_ai_provider2str(provider), rc);
    *conn_up = true;

    if (!tapi_ai_available(conn, 10000))
        TEST_SKIP("The agent cannot reach the AI provider");

    RING("AI provider %s, model %s", tapi_ai_provider2str(provider),
         model->len > 0 ? model->ptr : "(module default)");
}

/**
 * Turn the status of a request into the test's outcome: a rejected key
 * or an unreachable endpoint is the environment (skip), a timeout is a
 * verdict, anything else fails.
 *
 * @param rc    Status of tapi_ai_ask() & co.
 * @param what  What was asked, for the log.
 */
static inline void
ai_check_rc(te_errno rc, const char *what)
{
    if (rc == 0)
        return;

    switch (TE_RC_GET_ERROR(rc))
    {
        case TE_EACCES:
            TEST_SKIP("The AI provider rejected TSF_AI_KEY");
            break;

        case TE_ECOMM:
            TEST_SKIP("The agent cannot reach the AI provider");
            break;

        case TE_ETIMEDOUT:
            TEST_VERDICT("The AI provider did not answer in time");
            break;

        default:
            TEST_FAIL("%s failed: %r", what, rc);
    }
}

/**
 * Copy the first JSON object of a model's answer (from the first '{' to
 * its matching '}', strings respected).
 *
 * @param[in]  text     Answer.
 * @param[out] obj      String to put the object into.
 *
 * @return @c true if an object was found.
 */
static inline bool
ai_json_object(const char *text, te_string *obj)
{
    const char *start = (text != NULL) ? strchr(text, '{') : NULL;
    const char *p;
    int         depth = 0;
    bool        in_str = false;

    if (start == NULL)
        return false;

    for (p = start; *p != '\0'; p++)
    {
        if (in_str)
        {
            if (*p == '\\' && p[1] != '\0')
                p++;
            else if (*p == '"')
                in_str = false;
            continue;
        }
        if (*p == '"')
            in_str = true;
        else if (*p == '{')
            depth++;
        else if (*p == '}' && --depth == 0)
        {
            te_string_reset(obj);
            te_string_append(obj, "%.*s", (int)(p - start + 1), start);
            return true;
        }
    }

    return false;
}

/**
 * Find the value of @c "key" in a JSON object, spaces allowed around the
 * colon.
 *
 * @param obj   Object text.
 * @param key   Key.
 *
 * @return Pointer to the first character of the value, or @c NULL.
 */
static inline const char *
ai_json_value(const char *obj, const char *key)
{
    te_string   needle = TE_STRING_INIT;
    const char *p;

    te_string_append(&needle, "\"%s\"", key);
    p = strstr(obj, needle.ptr);
    if (p != NULL)
        p += needle.len;
    te_string_free(&needle);
    if (p == NULL)
        return NULL;

    while (isspace((unsigned char)*p))
        p++;
    if (*p != ':')
        return NULL;
    p++;
    while (isspace((unsigned char)*p))
        p++;

    return p;
}

/**
 * Read an integer value (a number, or a number in quotes).
 *
 * @param[in]  obj    Object text.
 * @param[in]  key    Key.
 * @param[out] value  Value.
 *
 * @return @c true if found.
 */
static inline bool
ai_json_int(const char *obj, const char *key, long *value)
{
    const char *p = ai_json_value(obj, key);
    char       *end;
    long        v;

    if (p == NULL)
        return false;
    if (*p == '"')
        p++;
    v = strtol(p, &end, 10);
    if (end == p)
        return false;

    *value = v;
    return true;
}

/**
 * Read a boolean value (true/false, also in quotes).
 *
 * @param[in]  obj    Object text.
 * @param[in]  key    Key.
 * @param[out] value  Value.
 *
 * @return @c true if found.
 */
static inline bool
ai_json_bool(const char *obj, const char *key, bool *value)
{
    const char *p = ai_json_value(obj, key);

    if (p == NULL)
        return false;
    if (*p == '"')
        p++;
    if (strncasecmp(p, "true", 4) == 0)
        *value = true;
    else if (strncasecmp(p, "false", 5) == 0)
        *value = false;
    else
        return false;

    return true;
}

/**
 * Read a string value (escapes are kept as they are, except \").
 *
 * @param[in]  obj    Object text.
 * @param[in]  key    Key.
 * @param[out] value  String to append the value to.
 *
 * @return @c true if found.
 */
static inline bool
ai_json_str(const char *obj, const char *key, te_string *value)
{
    const char *p = ai_json_value(obj, key);

    if (p == NULL || *p != '"')
        return false;

    for (p++; *p != '\0' && *p != '"'; p++)
    {
        if (*p == '\\' && p[1] != '\0')
            p++;
        te_string_append(value, "%c", *p);
    }

    return true;
}

/**
 * Chart the cost of one request: latency and token counts (those the
 * provider reported).
 *
 * @param what      Label of the request.
 * @param secs      Latency in seconds.
 * @param usage     Token usage.
 */
static inline void
ai_chart_cost(const char *what, double secs, const tapi_ai_usage *usage)
{
    te_string   title = TE_STRING_INIT;
    const char *labels[3] = { "input", "output", "total" };
    double      tokens[3];

    te_string_append(&title, "AI latency: %s", what);
    tsapi_mde_mi_point("ai", title.ptr, TE_MI_MEAS_TIME, "latency", secs,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    tokens[0] = usage->input_tokens;
    tokens[1] = usage->output_tokens;
    tokens[2] = usage->total_tokens;
    TEST_ARTIFACT("%s: %.2f s, tokens in %d, out %d, total %d (-1 = not "
                  "reported)", what, secs, usage->input_tokens,
                  usage->output_tokens, usage->total_tokens);
    if (usage->input_tokens >= 0 || usage->output_tokens >= 0)
    {
        te_string_reset(&title);
        te_string_append(&title, "AI tokens: %s", what);
        tsapi_mde_mi_bars("ai", title.ptr, TE_MI_MEAS_UNITLESS_VALUE,
                          "tokens", 3, labels, tokens,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    te_string_free(&title);
}

#endif /* !__MDE_AI_COMMON_H__ */

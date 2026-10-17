/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Browser group helpers
 *
 * What every browser test needs: the check that Playwright and Chromium
 * are on the agent, a browser session with the suite's options, a
 * counter of the web tier's node lines, a reader of the captured network
 * log (the runner's JSON, walked without a JSON library), and the
 * evidence of a file left on the agent (size, SHA-256, magic bytes).
 *
 * Everything here is @c static @c inline: each test is one C file and
 * uses only a part of it.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_BROWSER_COMMON_H__
#define __MDE_BROWSER_COMMON_H__

#include "te_config.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "tapi_test.h"
#include "te_string.h"
#include "rcf_api.h"
#include "tapi_file.h"
#include "tapi_playwright.h"
#include "tsapi_mde.h"

/** Where the container keeps node_modules/playwright. */
#define BROWSER_PW_DIR          "/opt/playwright"
/** Where the container keeps the browsers Playwright downloaded. */
#define BROWSER_PW_BROWSERS     "/opt/playwright/browsers"
/** The runner script, relative to TE_INSTALL. */
#define BROWSER_RUNNER_REL \
    "default/share/tsf-playwright/te_playwright_runner.cjs"

/** Number of node names of the web tier. */
#define BROWSER_N_NODES 3

/**
 * Name of a node of the web tier, in contract order.
 *
 * @param i     Index below #BROWSER_N_NODES.
 *
 * @return A static string.
 */
static inline const char *
browser_node_name(unsigned int i)
{
    switch (i)
    {
        case 0:
            return "gateway-rs";
        case 1:
            return "service-go";
        case 2:
            return "service-cs";
        default:
            return "?";
    }
}

/**
 * Skip the test unless Node.js, the playwright package, the browsers and
 * the runner script installed with tsf-playwright are all there.
 *
 * @param session   Session.
 */
static inline void
browser_skip_unless_ready(tsapi_mde_session *session)
{
    const char *install = getenv("TE_INSTALL");
    te_string   runner = TE_STRING_INIT;
    bool        have_runner;

    if (!tsapi_mde_have(session, "node"))
        TEST_SKIP("Node.js is not installed on the agent");
    if (!tsapi_mde_exists(session, BROWSER_PW_DIR "/node_modules/playwright"))
    {
        TEST_SKIP("The playwright npm package is not installed in "
                  BROWSER_PW_DIR);
    }
    if (!tsapi_mde_exists(session, BROWSER_PW_BROWSERS))
        TEST_SKIP("No Playwright browsers are installed in "
                  BROWSER_PW_BROWSERS);
    if (install == NULL)
        TEST_SKIP("TE_INSTALL is not set, the Playwright runner is unknown");

    te_string_append(&runner, "%s/" BROWSER_RUNNER_REL, install);
    have_runner = access(runner.ptr, R_OK) == 0;
    te_string_free(&runner);
    if (!have_runner)
        TEST_SKIP("The tsf-playwright runner script is not installed");
}

/**
 * Create and start a headless Chromium session on the agent.
 *
 * @param[in]  session  Session (its RPC job factory runs the runner).
 * @param[in]  capture  Keep the network log.
 * @param[in]  har      Record a HAR (copied to the engine on stop).
 * @param[in]  trace    Record a Playwright trace.
 * @param[out] pw       Handle; the caller destroys it, whatever happens.
 */
static inline void
browser_open(tsapi_mde_session *session, bool capture, bool har, bool trace,
             tapi_playwright **pw)
{
    tapi_playwright_opts opts = tapi_playwright_default_opts;
    te_errno             rc;

    opts.playwright_dir = BROWSER_PW_DIR;
    opts.browsers_path = BROWSER_PW_BROWSERS;
    opts.capture_network = capture;
    opts.record_har = har;
    opts.record_trace = trace;

    rc = tapi_playwright_create(session->factory, &opts, pw);
    if (rc != 0)
        TEST_FAIL("Cannot create a Playwright session: %r", rc);

    rc = tapi_playwright_start(*pw);
    if (rc != 0)
        TEST_VERDICT("Playwright could not launch Chromium on the agent");
}

/**
 * Count the node step lines of a web tier answer:
 * @c "[gateway-rs] hops=5 ..." and the same for the other two nodes.
 * The @c "[gateway-rs] upstream ... unreachable" line is not a step.
 *
 * @param[in]  text      Body text.
 * @param[out] per_node  Counts per node, #BROWSER_N_NODES of them, or
 *                       @c NULL.
 *
 * @return Total number of step lines.
 */
static inline unsigned int
browser_count_nodes(const char *text, unsigned int *per_node)
{
    const char  *line = text;
    unsigned int total = 0;
    unsigned int i;

    if (per_node != NULL)
    {
        for (i = 0; i < BROWSER_N_NODES; i++)
            per_node[i] = 0;
    }

    while (line != NULL && *line != '\0')
    {
        const char *nl = strchr(line, '\n');
        const char *p = line;

        while (*p == ' ' || *p == '\t')
            p++;

        if (*p == '[')
        {
            for (i = 0; i < BROWSER_N_NODES; i++)
            {
                const char *name = browser_node_name(i);
                size_t      len = strlen(name);
                const char *q;

                if (strncmp(p + 1, name, len) != 0 || p[1 + len] != ']')
                    continue;

                q = p + 2 + len;
                while (*q == ' ' || *q == '\t')
                    q++;
                if (strncmp(q, "hops=", 5) == 0)
                {
                    total++;
                    if (per_node != NULL)
                        per_node[i]++;
                }
                break;
            }
        }

        line = (nl == NULL) ? NULL : nl + 1;
    }

    return total;
}

/**
 * Copy the @c "value=..." line of a web tier answer (without the
 * newline).
 *
 * @param[in]  text     Body text.
 * @param[out] line     String to append the line to.
 *
 * @return @c true if the line was there.
 */
static inline bool
browser_value_line(const char *text, te_string *line)
{
    const char *p = text;

    while (p != NULL && *p != '\0')
    {
        const char *nl = strchr(p, '\n');

        if (strncmp(p, "value=", 6) == 0)
        {
            size_t len = (nl == NULL) ? strlen(p) : (size_t)(nl - p);

            while (len > 0 && p[len - 1] == '\r')
                len--;
            te_string_append(line, "%.*s", (int)len, p);
            return true;
        }
        p = (nl == NULL) ? NULL : nl + 1;
    }

    return false;
}

/**
 * Size and SHA-256 of a file on the agent.
 *
 * @param[in]  session  Session.
 * @param[in]  path     File on the agent.
 * @param[out] size     Size in bytes.
 * @param[out] sha      String to append the hex digest to.
 *
 * @return @c true if both were read.
 */
static inline bool
browser_file_evidence(tsapi_mde_session *session, const char *path,
                      unsigned long *size, te_string *sha)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    char                hash[65];
    unsigned long       sz;
    bool                ok = false;

    if (tsapi_mde_sh(session, 30000, &res,
                     "stat -c %%s '%s' && sha256sum '%s'", path, path) == 0 &&
        tsapi_mde_sh_ok(&res) && res.out.ptr != NULL &&
        sscanf(res.out.ptr, "%lu %64s", &sz, hash) == 2)
    {
        *size = sz;
        te_string_append(sha, "%s", hash);
        ok = true;
    }
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * Read the first bytes of a file on the agent.
 *
 * @param[in]  session  Session.
 * @param[in]  path     File on the agent.
 * @param[in]  max      Bytes wanted (at most 64).
 * @param[out] buf      Bytes.
 *
 * @return Number of bytes read.
 */
static inline unsigned int
browser_head_bytes(tsapi_mde_session *session, const char *path,
                   unsigned int max, uint8_t *buf)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    unsigned int        n = 0;

    if (max > 64)
        max = 64;

    if (tsapi_mde_sh(session, 30000, &res,
                     "head -c %u '%s' | od -An -v -tx1", max, path) == 0 &&
        tsapi_mde_sh_ok(&res) && res.out.ptr != NULL)
    {
        const char *p = res.out.ptr;

        while (n < max)
        {
            char         *end;
            unsigned long v;

            while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r')
                p++;
            if (*p == '\0')
                break;
            v = strtoul(p, &end, 16);
            if (end == p)
                break;
            buf[n++] = (uint8_t)v;
            p = end;
        }
    }
    tsapi_mde_sh_result_free(&res);

    return n;
}

/**
 * Check the PNG signature of a file on the agent and read its size from
 * the IHDR chunk.
 *
 * @param[in]  session  Session.
 * @param[in]  path     File on the agent.
 * @param[out] width    Width in pixels.
 * @param[out] height   Height in pixels.
 *
 * @return @c true if it is a PNG.
 */
static inline bool
browser_png_dims(tsapi_mde_session *session, const char *path,
                 unsigned int *width, unsigned int *height)
{
    static const uint8_t sig[8] = { 0x89, 'P', 'N', 'G', '\r', '\n',
                                    0x1a, '\n' };
    uint8_t              b[24];

    if (browser_head_bytes(session, path, sizeof(b), b) != sizeof(b) ||
        memcmp(b, sig, sizeof(sig)) != 0 || memcmp(b + 12, "IHDR", 4) != 0)
    {
        return false;
    }

    *width = ((unsigned int)b[16] << 24) | ((unsigned int)b[17] << 16) |
             ((unsigned int)b[18] << 8) | (unsigned int)b[19];
    *height = ((unsigned int)b[20] << 24) | ((unsigned int)b[21] << 16) |
              ((unsigned int)b[22] << 8) | (unsigned int)b[23];
    return true;
}

/**
 * Find the newest file on the engine whose name ends with @p suffix in
 * TE_LOG_DIR (or TE_TMP), modified at or after @p since - where the
 * module puts the HAR and the trace it copies off the agent.
 *
 * @param[in]  suffix   Name suffix, e.g. @c "_session.har".
 * @param[in]  since    Lower bound of the modification time.
 * @param[out] found    String to put the path into.
 *
 * @return @c true if a file was found.
 */
static inline bool
browser_find_engine_file(const char *suffix, time_t since, te_string *found)
{
    const char *dirs[2];
    size_t      slen = strlen(suffix);
    time_t      best = 0;
    bool        ok = false;
    unsigned int i;

    dirs[0] = getenv("TE_LOG_DIR");
    dirs[1] = getenv("TE_TMP");

    for (i = 0; i < TE_ARRAY_LEN(dirs) && !ok; i++)
    {
        DIR           *d;
        struct dirent *e;

        if (dirs[i] == NULL)
            continue;
        d = opendir(dirs[i]);
        if (d == NULL)
            continue;

        while ((e = readdir(d)) != NULL)
        {
            size_t      len = strlen(e->d_name);
            te_string   p = TE_STRING_INIT;
            struct stat st;

            if (len < slen || strcmp(e->d_name + len - slen, suffix) != 0)
                continue;

            te_string_append(&p, "%s/%s", dirs[i], e->d_name);
            if (stat(p.ptr, &st) == 0 && st.st_mtime >= since &&
                st.st_mtime >= best)
            {
                best = st.st_mtime;
                te_string_reset(found);
                te_string_append(found, "%s", p.ptr);
                ok = true;
            }
            te_string_free(&p);
        }
        closedir(d);
    }

    return ok;
}

/**
 * Decode a JSON string whose opening quote is just before @p p.
 *
 * @param[in]  p    First character of the string body.
 * @param[out] out  String to append the decoded text to (may be @c NULL
 *                  to skip the string).
 *
 * @return Pointer after the closing quote, or @c NULL if malformed.
 */
static inline const char *
browser_json_decode(const char *p, te_string *out)
{
    while (*p != '"')
    {
        if (*p == '\0')
            return NULL;

        if (*p != '\\')
        {
            if (out != NULL)
                te_string_append(out, "%c", *p);
            p++;
            continue;
        }

        p++;
        switch (*p)
        {
            case '\0':
                return NULL;

            case 'n':
                if (out != NULL)
                    te_string_append(out, "\n");
                break;

            case 'r':
                if (out != NULL)
                    te_string_append(out, "\r");
                break;

            case 't':
                if (out != NULL)
                    te_string_append(out, "\t");
                break;

            case 'b':
                if (out != NULL)
                    te_string_append(out, "\b");
                break;

            case 'f':
                if (out != NULL)
                    te_string_append(out, "\f");
                break;

            case 'u':
            {
                unsigned long code = 0;
                unsigned int  k;

                for (k = 1; k <= 4; k++)
                {
                    char c = p[k];

                    code <<= 4;
                    if (c >= '0' && c <= '9')
                        code |= (unsigned long)(c - '0');
                    else if (c >= 'a' && c <= 'f')
                        code |= (unsigned long)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F')
                        code |= (unsigned long)(c - 'A' + 10);
                    else
                        return NULL;
                }
                p += 4;

                if (out == NULL)
                    break;
                if (code < 0x80)
                {
                    te_string_append(out, "%c", (int)code);
                }
                else if (code < 0x800)
                {
                    te_string_append(out, "%c%c",
                                     (int)(0xC0 | (code >> 6)),
                                     (int)(0x80 | (code & 0x3F)));
                }
                else
                {
                    te_string_append(out, "%c%c%c",
                                     (int)(0xE0 | (code >> 12)),
                                     (int)(0x80 | ((code >> 6) & 0x3F)),
                                     (int)(0x80 | (code & 0x3F)));
                }
                break;
            }

            default:
                /* \" \\ \/ */
                if (out != NULL)
                    te_string_append(out, "%c", *p);
                break;
        }
        p++;
    }

    return p + 1;
}

/**
 * Find @c "key":"..." in a JSON text and decode the string value. The
 * first occurrence wins; a key inside a string value is escaped there
 * and never matches.
 *
 * @param[in]  obj  JSON text.
 * @param[in]  key  Key.
 * @param[out] out  String to append the value to.
 *
 * @return @c true if found.
 */
static inline bool
browser_json_str(const char *obj, const char *key, te_string *out)
{
    te_string   needle = TE_STRING_INIT;
    const char *p;

    te_string_append(&needle, "\"%s\":\"", key);
    p = strstr(obj, needle.ptr);
    if (p != NULL)
        p += needle.len;
    te_string_free(&needle);

    return p != NULL && browser_json_decode(p, out) != NULL;
}

/**
 * Find @c "key":<integer> in a JSON text.
 *
 * @param[in]  obj    JSON text.
 * @param[in]  key    Key.
 * @param[out] value  Value.
 *
 * @return @c true if found.
 */
static inline bool
browser_json_int(const char *obj, const char *key, long *value)
{
    te_string   needle = TE_STRING_INIT;
    const char *p;
    char       *end;
    long        v;

    te_string_append(&needle, "\"%s\":", key);
    p = strstr(obj, needle.ptr);
    if (p != NULL)
        p += needle.len;
    te_string_free(&needle);
    if (p == NULL)
        return false;

    while (*p == ' ')
        p++;
    v = strtol(p, &end, 10);
    if (end == p)
        return false;

    *value = v;
    return true;
}

/**
 * Take the next element (an object) of the top-level JSON array the
 * runner's network_dump returns.
 *
 * @param[in,out] cursor  Position in the array text; start at its '['.
 * @param[out]    entry   String to put the element's text into.
 *
 * @return @c true if an element was taken.
 */
static inline bool
browser_net_next(const char **cursor, te_string *entry)
{
    const char *p = *cursor;
    const char *start;
    int         depth = 0;

    while (*p == '[' || *p == ',' || *p == ' ' || *p == '\n' ||
           *p == '\r' || *p == '\t')
    {
        p++;
    }
    if (*p != '{')
        return false;

    start = p;
    do {
        if (*p == '"')
        {
            p = browser_json_decode(p + 1, NULL);
            if (p == NULL)
                return false;
            continue;
        }
        if (*p == '{')
            depth++;
        else if (*p == '}')
            depth--;
        else if (*p == '\0')
            return false;
        p++;
    } while (depth > 0);

    te_string_reset(entry);
    te_string_append(entry, "%.*s", (int)(p - start), start);
    *cursor = p;

    return true;
}

/**
 * Split a URL into its host part ("127.0.0.1:8081") and its path
 * ("/ring"), dropping the query. A URL without "://" (data:, about:)
 * has its scheme as the host and an empty path.
 *
 * @param[in]  url   URL.
 * @param[out] host  String to append the host to.
 * @param[out] path  String to append the path to (may be @c NULL).
 */
static inline void
browser_url_split(const char *url, te_string *host, te_string *path)
{
    const char *p = strstr(url, "://");
    size_t      len;

    if (p == NULL)
    {
        const char *colon = strchr(url, ':');

        len = (colon == NULL) ? strlen(url) : (size_t)(colon - url + 1);
        te_string_append(host, "%.*s", (int)len, url);
        return;
    }

    p += 3;
    len = strcspn(p, "/?#");
    te_string_append(host, "%.*s", (int)len, p);
    p += len;

    if (path != NULL)
    {
        len = strcspn(p, "?#");
        if (len == 0)
            te_string_append(path, "/");
        else
            te_string_append(path, "%.*s", (int)len, p);
    }
}

/**
 * Count the occurrences of @p needle in @p hay.
 *
 * @param hay       Text.
 * @param needle    Substring (not empty).
 *
 * @return Count.
 */
static inline unsigned int
browser_count_substr(const char *hay, const char *needle)
{
    size_t       len = strlen(needle);
    unsigned int n = 0;
    const char  *p = hay;

    if (len == 0 || hay == NULL)
        return 0;

    while ((p = strstr(p, needle)) != NULL)
    {
        n++;
        p += len;
    }

    return n;
}

/**
 * Take a screenshot and leave a copy on the agent.
 *
 * The published tsf-playwright copies a screenshot to the engine (and
 * logs it); a check that runs on the agent needs it back there, so it is
 * put to /tmp/mde-shot-<name>.png on @p ta.
 *
 * @param pw        Playwright session.
 * @param ta        Agent to put the copy on.
 * @param name      Screenshot name.
 * @param remote    Where the agent copy is (appended).
 *
 * @return Status code.
 */
static inline te_errno
browser_screenshot_ta(tapi_playwright *pw, const char *ta, const char *name,
                      te_string *remote)
{
    te_string local = TE_STRING_INIT;
    te_errno  rc;

    rc = tapi_playwright_screenshot(pw, name, &local);
    if (rc == 0)
    {
        te_string_append(remote, "/tmp/mde-shot-%s.png", name);
        rc = rcf_ta_put_file(ta, 0, local.ptr, remote->ptr);
    }
    te_string_free(&local);

    return rc;
}

#endif /* !__MDE_BROWSER_COMMON_H__ */

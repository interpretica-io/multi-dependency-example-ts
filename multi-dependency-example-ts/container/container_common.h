/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Container group helpers
 *
 * What the container tests do the same way: make sure Docker answers and
 * the image is there, start a long-lived container with a stable name,
 * hash and size files on the agent and inside the container, run a shell
 * line inside, and chart two series side by side.
 *
 * The agent drives the host's Docker through its socket, so a container
 * is a sibling of the agent: bind mounts of agent paths would point at
 * the host. Files go in and out with tapi_container_copy_in/out only.
 *
 * Everything here is static inline: each test is built from one C file
 * and an unused static function would break the -Werror build.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_CONTAINER_COMMON_H__
#define __MDE_CONTAINER_COMMON_H__

#include "te_config.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "te_mi_log.h"
#include "logger_api.h"
#include "tapi_cybersec.h"
#include "tapi_container.h"
#include "tapi_container_audit.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"

/** Pulling an image the first time is slow. */
/*
 * The platform the example was built for. The agent runs on the engine's
 * host, so it is the test binary's own. Without it Docker on a host of
 * another architecture (Apple silicon) runs the native variant of a
 * multi-arch image and the copied example cannot start in it.
 */
#if defined(__x86_64__)
#define MDE_CT_PLATFORM "linux/amd64"
#elif defined(__aarch64__)
#define MDE_CT_PLATFORM "linux/arm64"
#else
#define MDE_CT_PLATFORM NULL
#endif

/** Run arguments that pin the image to #MDE_CT_PLATFORM. */
#define MDE_CT_PLATFORM_ARGS "--platform", MDE_CT_PLATFORM

#define MDE_CT_PULL_TIMEOUT_MS  300000
/** Any other runtime command. */
#define MDE_CT_TIMEOUT_MS       60000
/** Copying the whole dist/ tree. */
#define MDE_CT_COPY_TIMEOUT_MS  180000
/** Image used where the image does not matter. */
#define MDE_CT_DEFAULT_IMAGE    "debian:bookworm-slim"

/**
 * Remove a container left over by an earlier run under the same name.
 *
 * @param session   Session.
 * @param name      Container name.
 */
static inline void
mde_ct_forget(tsapi_mde_session *session, const char *name)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;

    (void)tsapi_mde_sh(session, MDE_CT_TIMEOUT_MS, &res,
                       "docker rm -f '%s' >/dev/null 2>&1; true", name);
    tsapi_mde_sh_result_free(&res);
}

/**
 * Strip trailing whitespace in place.
 *
 * @param s     String.
 */
static inline void
mde_ct_chomp(te_string *s)
{
    while (s->len > 0 && (s->ptr[s->len - 1] == '\n' ||
                          s->ptr[s->len - 1] == '\r' ||
                          s->ptr[s->len - 1] == ' ' ||
                          s->ptr[s->len - 1] == '\t'))
        te_string_cut(s, 1);
}

/**
 * Take the first whitespace-separated word of a text.
 *
 * @param text  Text.
 * @param dest  String to append the word to.
 */
static inline void
mde_ct_first_word(const char *text, te_string *dest)
{
    size_t len;

    while (*text == ' ' || *text == '\t' || *text == '\n')
        text++;
    len = strcspn(text, " \t\r\n");
    te_string_append(dest, "%.*s", (int)len, text);
}

/**
 * SHA-256 of a file on the agent.
 *
 * @param session   Session.
 * @param path      Path on the agent.
 * @param hash      String to append the hex digest to.
 *
 * @return Status code; @c TE_ENOENT if it could not be hashed.
 */
static inline te_errno
mde_ct_sha256_agent(tsapi_mde_session *session, const char *path,
                    te_string *hash)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    te_errno            rc;

    rc = tsapi_mde_sh(session, MDE_CT_TIMEOUT_MS, &res,
                      "sha256sum '%s'", path);
    if (rc == 0 && !tsapi_mde_sh_ok(&res))
        rc = TE_RC(TE_TAPI, TE_ENOENT);
    if (rc == 0)
        mde_ct_first_word(te_string_value(&res.out), hash);
    tsapi_mde_sh_result_free(&res);

    return rc;
}

/**
 * Size of a file on the agent, bytes.
 *
 * @param session   Session.
 * @param path      Path on the agent.
 *
 * @return The size, or @c -1 if it could not be read.
 */
static inline double
mde_ct_size_agent(tsapi_mde_session *session, const char *path)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    double              size = -1.0;

    if (tsapi_mde_sh(session, MDE_CT_TIMEOUT_MS, &res,
                     "stat -c %%s '%s'", path) == 0 &&
        tsapi_mde_sh_ok(&res))
        size = strtod(te_string_value(&res.out), NULL);
    tsapi_mde_sh_result_free(&res);

    return size;
}

/**
 * Run a shell line inside a container.
 *
 * @param[in]  c        Container.
 * @param[in]  cmd      Command line for @c "sh -c".
 * @param[out] out      Standard output (appended), or @c NULL.
 * @param[out] code     Exit status of the line.
 *
 * @return Status code of running it.
 */
static inline te_errno
mde_ct_sh(tapi_container *c, const char *cmd, te_string *out, int *code)
{
    const char *argv[] = { "sh", "-c", cmd };

    return tapi_container_exec(c, argv, TE_ARRAY_LEN(argv),
                               MDE_CT_TIMEOUT_MS, out, code);
}

/**
 * SHA-256 of a file inside a container.
 *
 * @param c         Container.
 * @param path      Path inside.
 * @param hash      String to append the hex digest to.
 *
 * @return Status code; @c TE_ENOENT if it could not be hashed.
 */
static inline te_errno
mde_ct_sha256_inside(tapi_container *c, const char *path, te_string *hash)
{
    const char *argv[] = { "sha256sum", path };
    te_string   out = TE_STRING_INIT;
    int         code = -1;
    te_errno    rc;

    rc = tapi_container_exec(c, argv, TE_ARRAY_LEN(argv), MDE_CT_TIMEOUT_MS,
                             &out, &code);
    if (rc == 0 && code != 0)
        rc = TE_RC(TE_TAPI, TE_ENOENT);
    if (rc == 0)
        mde_ct_first_word(te_string_value(&out), hash);
    te_string_free(&out);

    return rc;
}

/**
 * Make sure Docker answers on the agent.
 *
 * @param session   Session.
 * @param opt       Options to fill with the defaults for Docker.
 *
 * @return @c true when the runtime is usable.
 */
static inline bool
mde_ct_docker(tsapi_mde_session *session, tapi_container_opt *opt)
{
    *opt = tapi_container_default_opt;
    opt->runtime = TAPI_CONTAINER_DOCKER;

    if (!tapi_container_supports(opt->runtime, TAPI_CONTAINER_FEAT_COPY))
        return false;

    return tapi_container_available(session->factory, opt,
                                    MDE_CT_TIMEOUT_MS);
}

/**
 * Size of an image as Docker reports it, bytes.
 *
 * @param session   Session.
 * @param image     Image reference.
 *
 * @return The size, or @c -1.
 */
static inline double
mde_ct_image_size(tsapi_mde_session *session, const char *image)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    double              size = -1.0;

    if (tsapi_mde_sh(session, MDE_CT_TIMEOUT_MS, &res,
                     "docker image inspect -f '{{.Size}}' '%s'",
                     image) == 0 && tsapi_mde_sh_ok(&res))
        size = strtod(te_string_value(&res.out), NULL);
    tsapi_mde_sh_result_free(&res);

    return size;
}

/**
 * Turn an image reference into something usable in a subject or a file
 * name: everything but letters, digits, dots and dashes becomes '-'.
 *
 * @param image     Image reference.
 * @param dest      String to append to.
 */
static inline void
mde_ct_image_slug(const char *image, te_string *dest)
{
    const char *p;

    for (p = image; *p != '\0'; p++)
    {
        char ch = *p;

        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '.' || ch == '-'))
            ch = '-';
        te_string_append(dest, "%c", ch);
    }
}

/**
 * Chart two labelled series side by side over the label index.
 *
 * @param tool      Source label.
 * @param view      View id.
 * @param title     Caption.
 * @param type      Metric type of both series.
 * @param name1     First series name.
 * @param name2     Second series name.
 * @param n         Number of labels.
 * @param labels    Labels.
 * @param v1        First series.
 * @param v2        Second series.
 */
static inline void
mde_ct_bars2(const char *tool, const char *view, const char *title,
             te_mi_meas_type type, const char *name1, const char *name2,
             size_t n, const char * const *labels, const double *v1,
             const double *v2)
{
    te_mi_logger *logger;
    char          key[16];
    size_t        i;

    if (n == 0 || tsapi_mde_mi_create(tool, &logger) != 0)
        return;

    for (i = 0; i < n; i++)
    {
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "index", TE_MI_MEAS_AGGR_SINGLE, (double)i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, type, name1,
                              TE_MI_MEAS_AGGR_SINGLE, v1[i],
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, type, name2,
                              TE_MI_MEAS_AGGR_SINGLE, v2[i],
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        TE_SPRINTF(key, "x%zu", i);
        te_mi_logger_add_meas_key(logger, NULL, key, "%s", labels[i]);
    }

    tsapi_mde_mi_line(logger, view, title, "index", name1, name2, NULL);
    te_mi_logger_destroy(logger);
}

#endif /* !__MDE_CONTAINER_COMMON_H__ */

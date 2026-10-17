/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief net group helpers
 *
 * The Configurator subtrees the external tsf-tunnel and tsf-wifi agent
 * libraries register (@c /agent/vpn and @c /agent/wifi): counting the
 * instances under one, and the two probes that say whether a WireGuard
 * commit could even be attempted on this kernel.
 *
 * Everything here is static inline: each test is one .c file and must
 * not trip -Werror=unused-function.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_NET_COMMON_H__
#define __MDE_NET_COMMON_H__

#include "te_config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "conf_api.h"
#include "logger_api.h"
#include "tsapi_mde.h"

/** The agent this suite works on. */
#define NET_TA  "Agt_A"

/**
 * Count the Configurator instances matching a pattern, after syncing the
 * subtree so the agent's live nodes are present.
 *
 * @param[in]  pattern  Instance pattern, e.g. @c "/agent:Agt_A/vpn:*".
 * @param[in]  sync     Subtree to synchronize first (or @c NULL).
 * @param[out] count    Number matched.
 *
 * @return Status code.
 */
static inline te_errno
net_count_pattern(const char *pattern, const char *sync, unsigned int *count)
{
    cfg_handle  *handles = NULL;
    te_errno     rc;

    *count = 0;
    if (sync != NULL)
        (void)cfg_synchronize_fmt(true, "%s", sync);

    rc = cfg_find_pattern_fmt(count, &handles, "%s", pattern);
    free(handles);

    return rc;
}

/**
 * Read a string instance and compare it with what was set. The OID is
 * built here from a literal format, so the printf-checked Configurator
 * call always sees a @c "%s".
 *
 * @param[in]  want     Expected value.
 * @param[in]  oid_fmt  Instance OID format (a literal at the call site).
 * @param[in]  ...      Format arguments.
 *
 * @return @c true when the read-back value equals @p want.
 */
static inline bool
net_str_roundtrips(const char *want, const char *oid_fmt, ...)
    TE_LIKE_PRINTF(2, 3);

static inline bool
net_str_roundtrips(const char *want, const char *oid_fmt, ...)
{
    char    *got = NULL;
    char     oid[256];
    va_list  ap;
    bool     ok;
    te_errno rc;

    va_start(ap, oid_fmt);
    vsnprintf(oid, sizeof(oid), oid_fmt, ap);
    va_end(ap);

    rc = cfg_get_instance_string_fmt(&got, "%s", oid);
    ok = rc == 0 && got != NULL && strcmp(got, want) == 0;
    if (!ok)
        ERROR("Read-back mismatch at %s: wanted '%s', got '%s' (%r)", oid,
              want, got != NULL ? got : "(null)", rc);
    free(got);

    return ok;
}

/** Looks like a 44-character base64 WireGuard public key. */
static inline bool
net_is_wg_key(const char *s)
{
    size_t i;

    if (s == NULL || strlen(s) != 44)
        return false;
    for (i = 0; i < 44; i++)
    {
        char c = s[i];

        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/' ||
              (i == 43 && c == '=')))
            return false;
    }

    return true;
}

#endif /* !__MDE_NET_COMMON_H__ */

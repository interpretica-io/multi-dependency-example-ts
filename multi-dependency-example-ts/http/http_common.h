/** @file
 * @brief HTTP Group
 *
 * Helpers shared by the tests of the http group: which service of the web
 * tier an iteration talks to, and how to read the body a node of the tier
 * answers with. Static inline only - every test is one C file.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_HTTP_COMMON_H__
#define __MDE_HTTP_COMMON_H__

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_string.h"
#include "tsapi_mde.h"
#include "tsapi_mde_web.h"

/** Timeout of one request, ms. */
#define MDE_HTTP_TIMEOUT_MS     30000

/** A service of the web tier, in contract order. */
typedef enum mde_http_service {
    MDE_HTTP_GATEWAY = 0,   /**< gateway-rs :8081 */
    MDE_HTTP_GO,            /**< service-go :8082 */
    MDE_HTTP_CS,            /**< service-cs :8083 */
} mde_http_service;

/** Mapping of the @c service parameter. */
#define MDE_HTTP_SERVICE_LIST \
    { "gateway-rs", MDE_HTTP_GATEWAY }, \
    { "service-go", MDE_HTTP_GO },      \
    { "service-cs", MDE_HTTP_CS }

/**
 * Name of a service of the tier.
 *
 * @param svc   Service.
 *
 * @return Static string.
 */
static inline const char *
mde_http_service_name(mde_http_service svc)
{
    switch (svc)
    {
        case MDE_HTTP_GATEWAY:
            return "gateway-rs";
        case MDE_HTTP_GO:
            return "service-go";
        case MDE_HTTP_CS:
            return "service-cs";
    }

    return "unknown";
}

/**
 * Port of a service, from web/contract/services.tab (contract order).
 *
 * @param svc   Service.
 *
 * @return Port.
 */
static inline unsigned int
mde_http_service_port(mde_http_service svc)
{
    return TSAPI_MDE_WEB_GATEWAY_PORT + (unsigned int)svc;
}

/**
 * Count the node trace lines of a /ring body:
 * @c "[service-go] hops=4 ..." - the "upstream unreachable" lines the
 * nodes print instead of a forwarded trace carry no @c "hops=" and do
 * not count.
 *
 * @param body  Body text.
 *
 * @return Number of node lines.
 */
static inline unsigned int
mde_http_count_nodes(const char *body)
{
    static const char *const nodes[] = {
        "[gateway-rs]", "[service-go]", "[service-cs]",
    };
    const char   *line = body;
    unsigned int  n = 0;

    while (line != NULL && *line != '\0')
    {
        const char *eol = strchr(line, '\n');
        unsigned int i;

        for (i = 0; i < TE_ARRAY_LEN(nodes); i++)
        {
            const char *hops;

            if (strncmp(line, nodes[i], strlen(nodes[i])) != 0)
                continue;

            hops = strstr(line, " hops=");
            if (hops != NULL && (eol == NULL || hops < eol))
                n++;
            break;
        }

        line = (eol != NULL) ? eol + 1 : NULL;
    }

    return n;
}

/**
 * Read the @c "value=X" line every node ends its body with.
 *
 * @param[in]  body     Body text.
 * @param[out] value    The value.
 *
 * @return @c true if the line is there and parses.
 */
static inline bool
mde_http_body_value(const char *body, double *value)
{
    const char *found = NULL;
    const char *pos = body;
    char       *end = NULL;

    /* The last one: the trace lines never start with "value=". */
    while (pos != NULL && *pos != '\0')
    {
        if (strncmp(pos, "value=", 6) == 0)
            found = pos;
        pos = strchr(pos, '\n');
        if (pos != NULL)
            pos++;
    }

    if (found == NULL)
        return false;

    *value = strtod(found + 6, &end);

    return end != found + 6;
}

#endif /* !__MDE_HTTP_COMMON_H__ */

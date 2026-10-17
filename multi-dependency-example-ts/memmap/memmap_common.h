/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Memory map group helpers
 *
 * What several tests of the memory map group need: where a binary or a
 * library of the example is, what readelf says about its program headers
 * (the second view of what tsf-memorymap parses), and a known-bad binary
 * built on the agent with an executable stack and a writable, executable
 * segment.
 *
 * Everything here is static inline: each test is built from one C file
 * and an unused static function would break the -Werror build.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_MEMMAP_COMMON_H__
#define __MDE_MEMMAP_COMMON_H__

#include "te_config.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"
#include "tapi_memmap.h"
#include "tsapi_mde.h"

/** Where the known-bad control is built on the agent. */
#define MEMMAP_CTL_DIR  "/tmp/mde-memmap-ctl"
/** The known-bad control binary. */
#define MEMMAP_CTL_BIN  MEMMAP_CTL_DIR "/wx-execstack"
/** Most program headers read from readelf. */
#define MEMMAP_MAX_PH   64

/** One program header as readelf prints it. */
typedef struct memmap_ph {
    bool         load;      /**< LOAD (else GNU_STACK). */
    uint64_t     vaddr;     /**< Virtual address. */
    uint64_t     filesz;    /**< Size in the file. */
    uint64_t     memsz;     /**< Size in memory. */
    unsigned int perms;     /**< TAPI_MEMMAP_R/W/X. */
} memmap_ph;

/**
 * Path of a binary (under dist/bin) or a ring library (under dist/lib,
 * a name starting with "lib") of the example.
 *
 * @param dut       Example.
 * @param name      Name without the extension.
 * @param path      String to append the path to.
 */
static inline void
memmap_artifact_path(const tsapi_mde_dut *dut, const char *name,
                     te_string *path)
{
    if (strncmp(name, "lib", 3) == 0)
        tsapi_mde_dut_lib_path(dut, name, path);
    else
        te_string_append(path, "%s/%s", dut->bin, name);
}

/**
 * Read the LOAD and GNU_STACK program headers of a file with
 * @c readelf @c -lW on the agent.
 *
 * @param[in]  session  Session.
 * @param[in]  path     File on the agent.
 * @param[out] phs      Headers, in file order.
 * @param[out] n_phs    Number of headers.
 * @param[out] raw      String to append what readelf printed to (may be
 *                      @c NULL).
 *
 * @return @c true if readelf ran and printed a program header table.
 */
static inline bool
memmap_readelf(tsapi_mde_session *session, const char *path,
               memmap_ph phs[MEMMAP_MAX_PH], unsigned int *n_phs,
               te_string *raw)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const char         *p;
    bool                ok;

    *n_phs = 0;
    ok = tsapi_mde_sh(session, 30000, &res, "readelf -lW '%s'", path) == 0 &&
         tsapi_mde_sh_ok(&res);
    if (raw != NULL)
        te_string_append(raw, "%s", te_string_value(&res.out));

    for (p = te_string_value(&res.out); ok && *p != '\0'; )
    {
        const char *eol = strchr(p, '\n');
        size_t      len = eol != NULL ? (size_t)(eol - p) : strlen(p);
        te_string   line = TE_STRING_INIT;
        const char *t;
        uint64_t    off;
        uint64_t    paddr;
        memmap_ph   ph;
        int         used = 0;

        te_string_append_buf(&line, p, len);
        p += len + (eol != NULL ? 1 : 0);

        for (t = te_string_value(&line); *t == ' '; t++)
            ;
        memset(&ph, 0, sizeof(ph));
        if (strncmp(t, "LOAD ", 5) == 0)
            ph.load = true;
        else if (strncmp(t, "GNU_STACK ", 10) != 0)
        {
            te_string_free(&line);
            continue;
        }
        t = strchr(t, ' ');
        if (t != NULL &&
            sscanf(t, " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64
                   " %" SCNx64 "%n", &off, &ph.vaddr, &paddr, &ph.filesz,
                   &ph.memsz, &used) == 5 && *n_phs < MEMMAP_MAX_PH)
        {
            /* Flags up to the alignment, e.g. "R E 0x1000". */
            for (t += used; *t != '\0' && *t != '0'; t++)
            {
                if (*t == 'R')
                    ph.perms |= TAPI_MEMMAP_R;
                else if (*t == 'W')
                    ph.perms |= TAPI_MEMMAP_W;
                else if (*t == 'E')
                    ph.perms |= TAPI_MEMMAP_X;
            }
            phs[(*n_phs)++] = ph;
        }
        te_string_free(&line);
    }

    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * Build the known-bad control on the agent: a program linked with an
 * executable stack and, where the linker allows it (@c -N), text and data
 * in one writable, executable segment.
 *
 * @param session   Session.
 *
 * @return @c true if it was built.
 */
static inline bool
memmap_build_control(tsapi_mde_session *session)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    ok = tsapi_mde_sh(session, 120000, &res,
                      "rm -rf " MEMMAP_CTL_DIR " && mkdir -p " MEMMAP_CTL_DIR
                      " && printf '%%s\\n' 'int main(void) { return 0; }' > "
                      MEMMAP_CTL_DIR "/ctl.c && "
                      "{ gcc -no-pie -Wl,-N -z execstack -o " MEMMAP_CTL_BIN
                      " " MEMMAP_CTL_DIR "/ctl.c || "
                      "gcc -z execstack -o " MEMMAP_CTL_BIN " "
                      MEMMAP_CTL_DIR "/ctl.c; }") == 0 &&
         tsapi_mde_sh_ok(&res);
    if (!ok)
        RING("The control could not be built: %s",
             te_string_value(&res.err));
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * Remove the control.
 *
 * @param session   Session.
 */
static inline void
memmap_drop_control(tsapi_mde_session *session)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;

    (void)tsapi_mde_sh(session, 20000, &res, "rm -rf " MEMMAP_CTL_DIR);
    tsapi_mde_sh_result_free(&res);
}

#endif /* !__MDE_MEMMAP_COMMON_H__ */

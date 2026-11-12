/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T4, hardening flags of the built binaries (settles H4)
 *
 * After T3, run tapi_binscan on every binary T3 built in H3_OUT: the Rust
 * core library, the Rust demo, gateway-rs, the Go library, service-go,
 * service-cs and the C++ and C libraries. Each missing flag (NX, PIE,
 * RELRO, canary, fortify) is added to the tapi_cybersec_report as its own
 * finding, and each binary is logged by name whether it was read or not.
 * The test fails on any missing flag. A binary that is absent, or that
 * binscan cannot read, is never skipped silently: it is logged by name
 * and fails the test. The managed C# assembly is not a native image: it
 * is logged by name as such.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t4_binscan"

#include "webdeps_lib.h"

static const struct {
    const char *path;
    bool        managed;    /**< A .NET assembly, not a native image. */
} scan_paths[] = {
    { H3_OUT "/rust-core/release/librustcore.so", false },
    { H3_OUT "/rust-demo/release/rust-demo", false },
    { H3_OUT "/gateway-rs/release/gateway-rs", false },
    { H3_OUT "/libgocore.so", false },
    { H3_OUT "/service-go", false },
    { H3_OUT "/cscore/cscore.dll", true },
    { H3_OUT "/service-cs/service-cs", false },
    { H3_OUT "/libcppcore.so", false },
    { H3_OUT "/libpycore.so", false },
};

/**
 * Scan one binary; @p missing receives the flags it lacks ("" if none).
 * Returns false when it could not be scanned (@p why says why).
 */
static bool
scan_one(tsapi_mde_session *session, const char *rel, char *missing,
         size_t size, char *why, size_t why_size)
{
    tapi_binscan_info info;
    char              path[700];
    te_errno          rc;
    bool              pie;

    missing[0] = '\0';
    snprintf(path, sizeof(path), "%s", rel);
    if (access(path, R_OK) != 0)
    {
        snprintf(why, why_size, "%s was not built by T3", rel);
        return false;
    }
    rc = tapi_binscan_inspect(session->ta, path, &info);
    if (rc != 0)
    {
        snprintf(why, why_size, "tapi_binscan cannot read %s (rc %d)", rel,
                 (int)rc);
        return false;
    }
    if (!info.elf)
    {
        tapi_binscan_info_free(&info);
        snprintf(why, why_size, "tapi_binscan: %s is not an ELF file", rel);
        return false;
    }
    tapi_binscan_info_log(&info, path);
    pie = info.kind == TAPI_BINSCAN_KIND_PIE ||
          info.kind == TAPI_BINSCAN_KIND_SHARED;
#define MISSING(_flag, ...) \
    do {                                                                    \
        append(missing, size, "%s ", _flag);                                \
        T_FINDING(TAPI_CYBERSEC_SEV_MEDIUM, "binary.missing-flag", rel,     \
                  "missing %s " __VA_ARGS__, _flag);                        \
    } while (0)

    if (!info.nx || info.nx_unknown)
        MISSING("NX", "");
    if (!pie)
        MISSING("PIE", "");
    if (info.relro != TAPI_BINSCAN_RELRO_FULL)
        MISSING("RELRO", "(%s, not full)", tapi_binscan_relro2str(info.relro));
    if (!info.canary)
        MISSING("canary", "");
    if (!info.fortify)
        MISSING("fortify", "");
#undef MISSING
    T_FINDING(missing[0] == '\0' ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_MEDIUM, "binary.hardening", rel,
              "kind %s, missing: %s%s", tapi_binscan_kind2str(info.kind),
              missing[0] != '\0' ? missing : "nothing",
              info.stripped ? " (stripped: canary and fortify are guesses)" :
              "");
    tapi_binscan_info_free(&info);
    return true;
}

int
main(int argc, char **argv)
{
    res_t               res = { .kind = R_PASS };
    tsapi_mde_session   session = { .ta = NULL };
    char                missing[200];
    char                why[300];
    char                bad[1000] = "";
    char                absent[600] = "";
    unsigned            n_bad = 0;
    unsigned            n_absent = 0;
    size_t              i;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;

    if (tsapi_mde_session_init(&session, "t4_binscan") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for tapi_binscan");
        goto verdict;
    }

    for (i = 0; i < TE_ARRAY_LEN(scan_paths); i++)
    {
        const char *path = scan_paths[i].path;

        TEST_STEP("tapi_binscan on %s", path);
        if (scan_paths[i].managed && access(path, R_OK) == 0)
        {
            T_FINDING(TAPI_CYBERSEC_SEV_INFO, "binary.managed", path,
                      "a .NET assembly, not a native image: binscan has no "
                      "flags to read");
            RING("webdeps: %s: managed assembly, no native flags", path);
            continue;
        }
        if (!scan_one(&session, path, missing, sizeof(missing), why,
                      sizeof(why)))
        {
            n_absent++;
            append(absent, sizeof(absent), "%s; ", why);
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "binary.not-scanned", path,
                      "%s", why);
            RING("webdeps: %s: not scanned: %s", path, why);
            continue;
        }
        RING("webdeps: %s: missing flags: %s", path,
             missing[0] != '\0' ? missing : "none");
        if (missing[0] != '\0')
        {
            n_bad++;
            append(bad, sizeof(bad), "%s lacks %s| ", path, missing);
        }
    }

    if (n_bad > 0)
        res_set(&res, R_FAIL, "H4 FAIL: %u of %zu binaries lack hardening "
                "flags: %s%s%s", n_bad, TE_ARRAY_LEN(scan_paths), bad,
                n_absent > 0 ? "not scanned: " : "", absent);
    else if (n_absent > 0)
        res_set(&res, R_FAIL, "H4 FAIL: no scanned binary lacks a flag but "
                "%u of %zu could not be scanned: %s", n_absent,
                TE_ARRAY_LEN(scan_paths), absent);
    else
        res_set(&res, R_PASS, "H4 PASS: all %zu binaries have NX, PIE, full "
                "RELRO, a stack canary and fortify", TE_ARRAY_LEN(scan_paths));

verdict:
    tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}

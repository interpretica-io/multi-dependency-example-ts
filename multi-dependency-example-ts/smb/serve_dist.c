/** @file
 * @brief smb Group
 *
 * The built example served over SMB and read back. The agent serves
 * $TE_TS_MDE_SRC/dist as a read-only usershare, connects back to it,
 * copies every ring library off the share, and compares the sha256 of
 * each copy against the original on disk - a deep round-trip over SMB.
 * The control of the share's mode is a write attempt to the read-only
 * share, which must be refused. The share is reached with a null session
 * where the server maps it to guest, and otherwise with the account the
 * group prologue made on the smbd it started.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "smb/serve_dist"

#include "te_config.h"
#include <stdlib.h>
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"

#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

#include "tapi_smb.h"
#include "tapi_smb_file.h"
#include "tapi_smb_share.h"

#include "smb_common.h"

#define T_MS    30000
#define SHARE   "mdedist"
/* The copy of dist the agent owns and serves. */
#define SERVED_COPY "/tmp/mde-smb-dist"
#define BK      TAPI_SMB_SAMBA

/* The leading whitespace-delimited token of a string (a sha256 sum). */
static void
first_token(const char *s, te_string *dest)
{
    while (*s == ' ' || *s == '\t' || *s == '\n')
        s++;
    while (*s != '\0' && *s != ' ' && *s != '\t' && *s != '\n')
    {
        te_string_append_buf(dest, s, 1);
        s++;
    }
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tapi_smb_served     served = TAPI_SMB_SERVED_INIT;
    tapi_smb_target     target = TAPI_SMB_TARGET_INIT;
    bool                serving = false;
    te_string           dist = TE_STRING_INIT;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string           user = TE_STRING_INIT;
    te_string           password = TE_STRING_INIT;
    double              size_bytes[16] = { 0 };
    double              xfer_s[16] = { 0 };
    const char         *labels[16];
    unsigned int        n = 0;
    unsigned int        ok = 0;
    unsigned int        i;

    TEST_START;

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "smb_serve_dist", dut, session_up);

    TEST_STEP("Skip unless the agent has Samba and can serve a usershare");
    if (!tapi_smb_available(session.factory, BK, T_MS))
        TEST_SKIP("There is no SMB client on the agent");
    if (!tapi_smb_can_serve(session.factory, BK, T_MS))
        TEST_SKIP("The agent may not serve a usershare");

    TEST_STEP("Serve dist read-only");
    /*
     * Samba lets a user share only directories the user owns, and the
     * example's tree may belong to someone else (a bind mount). Serve a
     * copy the agent owns; what comes back over SMB is still compared with
     * the original libraries below.
     */
    te_string_append(&dist, "%s", SERVED_COPY);
    CHECK_RC(tsapi_mde_sh(&session, T_MS, &sh,
                          "rm -rf '%s' && cp -r '%s/dist' '%s' && "
                          "chmod -R a+rX '%s'", dist.ptr, dut.root, dist.ptr,
                          dist.ptr));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot make the copy of dist to serve");
    served.name = SHARE;
    served.path = dist.ptr;
    served.comment = "mde dist, read-only";
    served.writable = false;
    rc = tapi_smb_serve(session.factory, BK, &served, T_MS);
    if (TE_RC_GET_ERROR(rc) == TE_EPERM ||
        TE_RC_GET_ERROR(rc) == TE_EOPNOTSUPP)
    {
        TEST_SKIP("The agent may not serve this share: %r", rc);
    }
    if (rc != 0)
        TEST_FAIL("Serving dist over SMB failed: %r", rc);
    serving = true;

    target.server = "localhost";
    /* A null session first: enough where the server maps it to guest. */
    target.user = NULL;
    target.password = NULL;

    TEST_STEP("Skip unless the served share can be reached");
    if (!tapi_smb_can_connect(session.factory, BK, &target, SHARE, T_MS,
                              NULL))
    {
        if (!smb_suite_account(&session, &user, &password))
        {
            TEST_SKIP("The served share cannot be reached (no guest "
                      "mapping, no account)");
        }
        RING("A null session is refused; using the account %s the group "
             "prologue made", user.ptr);
        target.user = user.ptr;
        target.password = password.ptr;
        if (!tapi_smb_can_connect(session.factory, BK, &target, SHARE,
                                  T_MS, NULL))
        {
            TEST_SKIP("The served share cannot be reached, with a null "
                      "session or with the suite's account");
        }
    }

    TEST_STEP("List the share over SMB");
    {
        te_vec entries = TE_VEC_INIT(tapi_smb_dirent);
        tapi_smb_dirent *e;

        CHECK_RC(tapi_smb_ls(session.factory, BK, &target, SHARE, "", T_MS,
                             &entries));
        TE_VEC_FOREACH(&entries, e)
            RING("share entry: %s %s", e->name, e->is_dir ? "(dir)" : "");
        tapi_smb_dirents_free(&entries);
    }

    TEST_STEP("Copy every ring library off the share and sha256-compare");
    for (i = 0; i < tsapi_mde_dut_n_libs && n < TE_ARRAY_LEN(labels); i++)
    {
        const char *name = tsapi_mde_dut_libs[i];
        te_string   orig = TE_STRING_INIT;
        te_string   remote = TE_STRING_INIT;
        te_string   local = TE_STRING_INIT;
        te_string   h_orig = TE_STRING_INIT;
        te_string   h_copy = TE_STRING_INIT;
        double      t0;
        te_errno    grc;

        tsapi_mde_dut_lib_path(&dut, name, &orig);
        te_string_append(&remote, "lib/%s.%s", name, dut.dylib_ext);
        te_string_append(&local, "/tmp/mde-smb-%s.%s", name, dut.dylib_ext);

        t0 = tsapi_mde_now();
        grc = tapi_smb_get(session.factory, BK, &target, SHARE, remote.ptr,
                           local.ptr, T_MS);
        xfer_s[n] = tsapi_mde_now() - t0;

        if (grc == 0)
        {
            tsapi_mde_sh_result s1 = TSAPI_MDE_SH_RESULT_INIT;
            tsapi_mde_sh_result s2 = TSAPI_MDE_SH_RESULT_INIT;
            tsapi_mde_sh_result s3 = TSAPI_MDE_SH_RESULT_INIT;

            (void)tsapi_mde_sh(&session, T_MS, &s1, "sha256sum '%s'",
                               orig.ptr);
            (void)tsapi_mde_sh(&session, T_MS, &s2, "sha256sum '%s'",
                               local.ptr);
            (void)tsapi_mde_sh(&session, T_MS, &s3, "wc -c < '%s'",
                               local.ptr);
            first_token(te_string_value(&s1.out), &h_orig);
            first_token(te_string_value(&s2.out), &h_copy);
            size_bytes[n] = (double)strtoul(te_string_value(&s3.out), NULL,
                                            10);

            if (h_orig.len == 64 && h_copy.len == 64 &&
                strcmp(h_orig.ptr, h_copy.ptr) == 0)
            {
                ok++;
                RING("%s: %s round-tripped over SMB (%.0f bytes, %.3f s)",
                     name, h_copy.ptr, size_bytes[n], xfer_s[n]);
            }
            else
            {
                RING("%s: sha256 mismatch - disk %s, over SMB %s", name,
                     h_orig.len == 64 ? h_orig.ptr : "(none)",
                     h_copy.len == 64 ? h_copy.ptr : "(none)");
            }
            tsapi_mde_sh_result_free(&s1);
            tsapi_mde_sh_result_free(&s2);
            tsapi_mde_sh_result_free(&s3);
            (void)tsapi_mde_sh(&session, T_MS, &sh, "rm -f '%s'", local.ptr);
        }
        else
        {
            RING("%s: could not be copied off the share: %r", name, grc);
        }

        labels[n] = name;
        n++;
        te_string_free(&orig);
        te_string_free(&remote);
        te_string_free(&local);
        te_string_free(&h_orig);
        te_string_free(&h_copy);
    }

    TEST_ARTIFACT("smb serve_dist: %u of %u ring libraries round-tripped "
                  "byte-exact over SMB", ok, n);

    TEST_STEP("Chart the bytes and the transfer time per file");
    tsapi_mde_mi_bars("smb", "Bytes read over SMB per file",
                      TE_MI_MEAS_MEMORY, "bytes", n,
                      (const char * const *)labels, size_bytes,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("smb", "Transfer time per file", TE_MI_MEAS_TIME,
                      "transfer_time", n, (const char * const *)labels,
                      xfer_s, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Every library must round-trip identically");
    if (ok != n || n == 0)
        TEST_VERDICT("SMB round-trip verified %u of %u libraries", ok, n);

    TEST_STEP("A write to the read-only share must be refused (control)");
    {
        te_errno wrc = tapi_smb_write(session.factory, BK, &target, SHARE,
                                      "tsf_write_probe.txt", "x", 1, T_MS);

        if (wrc == 0)
        {
            (void)tapi_smb_unlink(session.factory, BK, &target, SHARE,
                                  "tsf_write_probe.txt", T_MS);
            TEST_VERDICT("A write to a read-only share was accepted");
        }
        RING("A write to the read-only share was refused: %r", wrc);
    }

    TEST_SUCCESS;

cleanup:

    if (serving)
        (void)tapi_smb_unserve(session.factory, BK, SHARE, T_MS);
    if (session_up)
        (void)tsapi_mde_sh(&session, T_MS, &sh, "rm -rf '%s'", SERVED_COPY);
    te_string_free(&dist);
    te_string_free(&user);
    te_string_free(&password);
    tsapi_mde_sh_result_free(&sh);
    if (session_up)
    {
        tsapi_mde_dut_free(&dut);
        tsapi_mde_session_fini(&session);
    }

    TEST_END;
}

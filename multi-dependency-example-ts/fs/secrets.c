/** @file
 * @brief Filesystem Group
 *
 * Secrets at rest in the example tree: private keys (tsf-fs), AWS access
 * key ids and MD5-crypt password hashes (grep on the agent), and the
 * accounts of the agent (weak hashes, empty passwords). Every scanner has
 * a known-bad control planted in a directory of its own on the agent - a
 * PEM private key, the documented example AWS key id, an MD5-crypt hash,
 * a unique marker - and must find it; the controls' findings are dropped
 * before the gate. The marker is also looked for in the example, where it
 * must not be: a scanner that finds what is not there is as broken as
 * one that misses what is.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "fs/secrets"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_fs.h"
#include "tapi_fs_secrets.h"
#include "fs_common.h"

/** The control directory on the agent. */
#define SEC_CTL         "/tmp/mde-fs-secrets-ctl"
#define SEC_CTL_KEY     SEC_CTL "/id_planted.pem"
#define SEC_CTL_AWS     SEC_CTL "/aws.conf"
#define SEC_CTL_HASH    SEC_CTL "/shadow.bak"
#define SEC_CTL_CANARY  SEC_CTL "/app.log"
/** A marker that occurs nowhere else. */
#define SEC_CANARY      "MDE-CANARY-7f3c9a1e5b"
/** The control account of the engine-side accounts audit. */
#define SEC_CTL_USER    "mdectl"

/** An AWS access key id: AKIA and 16 upper-case letters or digits. */
#define SEC_AWS_RE      "AKIA[0-9A-Z]{16}"
/** An MD5-crypt hash: $1$salt$22 characters. */
#define SEC_MD5_RE      "\\$1\\$[./0-9A-Za-z]{1,8}\\$[./0-9A-Za-z]{22}"

/** Paths the example tree is not scanned under. */
#define SEC_EXCLUDES \
    "--exclude-dir=.git --exclude-dir=target --exclude-dir=obj " \
    "--exclude-dir=node_modules"

/**
 * grep -rlsIE a pattern under a root and add a finding per file.
 *
 * @return Number of files.
 */
static unsigned int
sec_grep(tsapi_mde_session *session, tsapi_mde_report *report,
         const char *root, const char *re, const char *check)
{
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    const char         *p;
    unsigned int        n = 0;

    if (tsapi_mde_sh(session, 600000, &sh,
                     "grep -rlsIE " SEC_EXCLUDES " -e '%s' -- '%s'",
                     re, root) != 0)
        TEST_FAIL("grep could not be run on the agent");

    for (p = te_string_value(&sh.out); *p != '\0'; )
    {
        const char *eol = strchr(p, '\n');
        size_t      len = eol != NULL ? (size_t)(eol - p) : strlen(p);

        if (len > 0)
        {
            te_string path = TE_STRING_INIT;

            te_string_append_buf(&path, p, len);
            tapi_cybersec_report_add(&report->cyber,
                                     fs_check_severity(check), check,
                                     path.ptr, "matches %s", re);
            te_string_free(&path);
            n++;
        }
        p += len + (eol != NULL ? 1 : 0);
    }
    tsapi_mde_sh_result_free(&sh);

    return n;
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity min_sev;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    tapi_kernel_issues     issues;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    te_vec                 keys = TE_VEC_INIT(tapi_fs_key);
    te_vec                 ctl_keys = TE_VEC_INIT(tapi_fs_key);
    const char            *dut_roots[1];
    const char            *ctl_roots[] = { SEC_CTL };
    unsigned long          n_files = 0;
    unsigned int           n_keys;
    unsigned int           n_aws;
    unsigned int           n_md5;
    unsigned int           n_canary;
    unsigned int           n_accounts;
    double                 t0;
    double                 scan_s;

    TEST_START;
    tsapi_mde_report_init(&report);
    tapi_kernel_issues_init(&issues);
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "fssecrets", dut, session_up);
    dut_roots[0] = dut.root;

    TEST_STEP("Count the files the scan covers");
    CHECK_RC(tsapi_mde_sh(&session, 120000, &sh,
                          "find '%s' \\( -name .git -o -name target -o "
                          "-name obj -o -name node_modules \\) -prune -o "
                          "-type f -print | wc -l", dut.root));
    n_files = strtoul(te_string_value(&sh.out), NULL, 10);
    TEST_ARTIFACT("files under the example: %lu", n_files);

    TEST_STEP("Scan the example tree");
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_fs_keys_find(session.factory, dut_roots, 1, &keys));
    CHECK_RC(tapi_fs_keys_check(&keys, NULL, 0, &issues));
    n_keys = fs_issues_to_report(&issues, &report);
    n_aws = sec_grep(&session, &report, dut.root, SEC_AWS_RE, "fs.aws-key");
    n_md5 = sec_grep(&session, &report, dut.root, SEC_MD5_RE,
                     "fs.weak-hash-file");
    CHECK_RC(tapi_fs_canary_check(session.factory, dut_roots, 1, SEC_CANARY,
                                  NULL, 0, &issues));
    n_canary = fs_issues_to_report(&issues, &report);
    scan_s = tsapi_mde_now() - t0;
    TEST_ARTIFACT("example: %zu private key file(s), %u key finding(s), "
                  "%u AWS key file(s), %u MD5-crypt file(s), %u marker "
                  "file(s), %.2f s", te_vec_size(&keys), n_keys, n_aws,
                  n_md5, n_canary, scan_s);
    if (n_canary != 0)
        TEST_VERDICT("The marker of the control was found in the example "
                     "before it was planted");

    TEST_STEP("Audit the accounts of the agent");
    CHECK_RC(tapi_fs_accounts_audit(session.factory, &issues));
    n_accounts = fs_issues_to_report(&issues, &report);
    TEST_ARTIFACT("agent accounts: %u finding(s)", n_accounts);

    TEST_STEP("Chart files scanned against findings");
    {
        static const char *labels[] = {
            "files_scanned", "private_keys", "aws_keys", "md5_hashes",
            "account_findings",
        };
        double vals[TE_ARRAY_LEN(labels)];

        vals[0] = n_files;
        vals[1] = n_keys;
        vals[2] = n_aws;
        vals[3] = n_md5;
        vals[4] = n_accounts;
        tsapi_mde_mi_bars("fs/secrets", "Example files scanned and findings",
                          TE_MI_MEAS_UNITLESS_VALUE, "count",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    tsapi_mde_mi_point("fs/secrets", "Time to scan the example",
                       TE_MI_MEAS_TIME, "scan_s", scan_s,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    fs_chart_by_dir(&report, dut.root, "fs/secrets",
                    "Secret findings per directory of the example");

    TEST_STEP("Plant the known-bad controls");
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh,
                          "rm -rf " SEC_CTL " && mkdir -p " SEC_CTL " && "
                          "printf '%%s\\n' '-----BEGIN RSA PRIVATE KEY-----' "
                          "'MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu' "
                          "'-----END RSA PRIVATE KEY-----' > " SEC_CTL_KEY
                          " && chmod 0644 " SEC_CTL_KEY " && "
                          "echo 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE' > "
                          SEC_CTL_AWS " && "
                          "echo '" SEC_CTL_USER ":$1$saltsalt$qjXMvbEw8oaL.CzflDugX/"
                          ":19000:0:99999:7:::' > " SEC_CTL_HASH " && "
                          "echo 'login password=" SEC_CANARY "' > "
                          SEC_CTL_CANARY));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("The controls could not be planted: %s",
                  te_string_value(&sh.err));

    TEST_STEP("Run every scanner on the controls");
    CHECK_RC(tapi_fs_keys_find(session.factory, ctl_roots, 1, &ctl_keys));
    CHECK_RC(tapi_fs_keys_check(&ctl_keys, NULL, 0, &issues));
    (void)fs_issues_to_report(&issues, &report);
    (void)sec_grep(&session, &report, SEC_CTL, SEC_AWS_RE, "fs.aws-key");
    (void)sec_grep(&session, &report, SEC_CTL, SEC_MD5_RE,
                   "fs.weak-hash-file");
    CHECK_RC(tapi_fs_canary_check(session.factory, ctl_roots, 1, SEC_CANARY,
                                  NULL, 0, &issues));
    (void)fs_issues_to_report(&issues, &report);
    CHECK_RC(tapi_fs_accounts_audit_parse(
                 SEC_CTL_USER ":x:4242:4242::/nonexistent:/bin/false\n",
                 SEC_CTL_USER ":$1$saltsalt$qjXMvbEw8oaL.CzflDugX/"
                 ":19000:0:99999:7:::\n", &issues));
    (void)fs_issues_to_report(&issues, &report);

    tsapi_mde_report_expect(&report, "fs.private-key", SEC_CTL_KEY);
    tsapi_mde_report_expect(&report, "fs.aws-key", SEC_CTL_AWS);
    tsapi_mde_report_expect(&report, "fs.weak-hash-file", SEC_CTL_HASH);
    tsapi_mde_report_expect(&report, "fs.canary", SEC_CTL_CANARY);
    tsapi_mde_report_expect(&report, "fs.weak-hash", SEC_CTL_USER);
    tsapi_mde_report_drop_subject(&report, SEC_CTL_KEY);
    tsapi_mde_report_drop_subject(&report, SEC_CTL_AWS);
    tsapi_mde_report_drop_subject(&report, SEC_CTL_HASH);
    tsapi_mde_report_drop_subject(&report, SEC_CTL_CANARY);
    tsapi_mde_report_drop_subject(&report, SEC_CTL_USER);

    TEST_STEP("Decide over the secrets found");
    TSAPI_MDE_REPORT_GATE(&report, "fs", min_sev);

    TEST_SUCCESS;

cleanup:

    if (session_up)
    {
        (void)tsapi_mde_sh(&session, 20000, &sh, "rm -rf " SEC_CTL);
        tsapi_mde_dut_free(&dut);
    }
    tapi_fs_keys_free(&keys);
    tapi_fs_keys_free(&ctl_keys);
    tapi_kernel_issues_free(&issues);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

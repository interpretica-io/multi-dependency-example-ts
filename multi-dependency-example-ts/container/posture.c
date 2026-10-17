/** @file
 * @brief Container Group
 *
 * Start a container with a security profile decided here, audit it with
 * tsf-container, and read the same facts a second way from inside: the
 * effective capabilities, no_new_privs and seccomp from the container's
 * own /proc/self/status, and whether the root filesystem really refuses
 * a write. The privileged profile is the known-bad control: the audit
 * must call it privileged, and its findings are then dropped.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "container/posture"

#include "te_config.h"
#include "tapi_test.h"
#include "container_common.h"

/** Security profile of the container under audit. */
typedef enum posture_profile {
    PROFILE_DEFAULT,        /**< Docker's defaults. */
    PROFILE_HARDENED,       /**< No caps, read-only, no-new-privileges. */
    PROFILE_PRIVILEGED,     /**< --privileged: the known-bad control. */
} posture_profile;

#define PROFILE_LIST \
    { "default",    PROFILE_DEFAULT },    \
    { "hardened",   PROFILE_HARDENED },   \
    { "privileged", PROFILE_PRIVILEGED }

/** User the hardened profile runs as (nobody). */
#define POSTURE_HARDENED_UID 65534

/**
 * Read a field of /proc/self/status.
 *
 * @param status    Text of the file.
 * @param key       Field name with the colon, e.g. "CapEff:".
 * @param base      Number base of the value.
 * @param value     Where to put it.
 *
 * @return @c true if the field was there.
 */
static bool
posture_status_field(const char *status, const char *key, int base,
                     uint64_t *value)
{
    const char *p = strstr(status, key);

    if (p == NULL)
        return false;
    *value = strtoull(p + strlen(key), NULL, base);
    return true;
}

/** Number of bits set. */
static unsigned int
posture_popcount(uint64_t mask)
{
    unsigned int n = 0;

    while (mask != 0)
    {
        n += (unsigned int)(mask & 1);
        mask >>= 1;
    }
    return n;
}

/** Record a disagreement between the audit and the second view. */
static void
posture_disagree(tsapi_mde_report *report, const char *profile,
                 const char *field, const char *detail)
{
    te_string subject = TE_STRING_INIT;

    te_string_append(&subject, "%s:%s", profile, field);
    tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                             "container.posture-disagrees", subject.ptr,
                             "%s", detail);
    te_string_free(&subject);
}

/** Record a profile setting the kernel did not apply. */
static void
posture_not_applied(tsapi_mde_report *report, const char *profile,
                    const char *what, const char *detail)
{
    te_string subject = TE_STRING_INIT;

    te_string_append(&subject, "%s:%s", profile, what);
    tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                             "container.profile-not-applied", subject.ptr,
                             "%s", detail);
    te_string_free(&subject);
}

int
main(int argc, char **argv)
{
    posture_profile         profile;
    const char             *profile_name;
    tapi_cybersec_severity  min_sev;
    tsapi_mde_session       session;
    bool                    session_up = false;
    tsapi_mde_report        report;
    tapi_container_opt      opt;
    tapi_container         *container = NULL;
    tapi_container_posture  posture;
    const char             *command[] = { "sleep", "infinity" };
    const char             *drop_all[] = { "ALL" };
    const char             *nnp[] = { MDE_CT_PLATFORM_ARGS,
                                      "--security-opt", "no-new-privileges" };
    const char             *platform_args[] = { MDE_CT_PLATFORM_ARGS };
    const char             *cat_status[] = { "cat", "/proc/self/status" };
    te_string               name = TE_STRING_INIT;
    te_string               status = TE_STRING_INIT;
    te_string               probe = TE_STRING_INIT;
    te_string               caps = TE_STRING_INIT;
    uint64_t                cap_eff = 0;
    uint64_t                nnp_val = 0;
    uint64_t                seccomp = 0;
    bool                    have_cap;
    bool                    write_failed;
    bool                    erofs;
    unsigned int            n_findings;
    int                     code = -1;
    double                  t0;
    double                  t_audit;

    TEST_START;
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(profile, PROFILE_LIST);
    TEST_GET_MDE_SEVERITY(min_sev);
    profile_name = profile == PROFILE_DEFAULT ? "default" :
                   profile == PROFILE_HARDENED ? "hardened" : "privileged";

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "ct_posture"));
    session_up = true;

    if (!mde_ct_docker(&session, &opt))
        TEST_SKIP("No container runtime on the agent");

    opt.image = MDE_CT_DEFAULT_IMAGE;
    if (tapi_container_pull(session.factory, &opt,
                            MDE_CT_PULL_TIMEOUT_MS) != 0)
        TEST_SKIP("Cannot pull the image - no registry access");

    TEST_STEP("Start a container with the profile of this iteration");
    te_string_append(&name, "mde-posture-%s", profile_name);
    mde_ct_forget(&session, name.ptr);
    opt.name = name.ptr;
    opt.command = command;
    opt.n_command = TE_ARRAY_LEN(command);
    opt.extra_args = platform_args;
    opt.n_extra_args = TE_ARRAY_LEN(platform_args);
    switch (profile)
    {
        case PROFILE_HARDENED:
            opt.user = "65534:65534";
            opt.read_only = true;
            opt.caps_drop = drop_all;
            opt.n_caps_drop = TE_ARRAY_LEN(drop_all);
            opt.extra_args = nnp;
            opt.n_extra_args = TE_ARRAY_LEN(nnp);
            break;

        case PROFILE_PRIVILEGED:
            opt.privileged = true;
            break;

        case PROFILE_DEFAULT:
            break;
    }
    CHECK_RC(tapi_container_run(session.factory, &opt, MDE_CT_TIMEOUT_MS,
                                &container));

    TEST_STEP("Audit it and read the posture the audit saw");
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_container_audit(container, NULL, &report.cyber));
    t_audit = tsapi_mde_now() - t0;
    CHECK_RC(tapi_container_posture_get(container, NULL, &posture));
    if (!posture.probed)
        TEST_VERDICT("The audit could not probe the container from inside");
    tapi_container_caps_str(posture.cap_eff, &caps);
    TEST_ARTIFACT("%s: CapEff 0x%016" PRIx64 " (%u caps: %s), uid %d, "
                  "seccomp %d, no_new_privs %d, read-only root %s",
                  profile_name, posture.cap_eff,
                  posture_popcount(posture.cap_eff),
                  caps.len > 0 ? caps.ptr : "none", posture.uid,
                  posture.seccomp, posture.no_new_privs,
                  posture.read_only_root ? "yes" : "no");

    TEST_STEP("Read the same facts from inside: /proc/self/status");
    CHECK_RC(tapi_container_exec(container, cat_status,
                                 TE_ARRAY_LEN(cat_status), MDE_CT_TIMEOUT_MS,
                                 &status, &code));
    if (code != 0)
        TEST_VERDICT("Cannot read /proc/self/status inside the container");
    RING("/proc/self/status inside:\n%s", te_string_value(&status));

    have_cap = posture_status_field(te_string_value(&status), "CapEff:", 16,
                                    &cap_eff);
    if (!have_cap || cap_eff != posture.cap_eff)
        posture_disagree(&report, profile_name, "CapEff",
                         "CapEff in /proc/self/status differs from the "
                         "audit's");
    if (posture_status_field(te_string_value(&status), "NoNewPrivs:", 10,
                             &nnp_val) &&
        (int)nnp_val != posture.no_new_privs)
        posture_disagree(&report, profile_name, "NoNewPrivs",
                         "NoNewPrivs differs from the audit's");
    if (posture_status_field(te_string_value(&status), "Seccomp:", 10,
                             &seccomp) &&
        (int)seccomp != posture.seccomp)
        posture_disagree(&report, profile_name, "Seccomp",
                         "Seccomp mode differs from the audit's");

    TEST_STEP("Try to write to the root filesystem");
    CHECK_RC(mde_ct_sh(container,
                       "touch /tmp/mde-posture-probe 2>&1; echo rc=$?",
                       &probe, &code));
    RING("Write probe: %s", te_string_value(&probe));
    write_failed = strstr(te_string_value(&probe), "rc=0") == NULL;
    erofs = strstr(te_string_value(&probe), "Read-only") != NULL;
    TEST_ARTIFACT("%s: write to /tmp %s%s", profile_name,
                  write_failed ? "refused" : "accepted",
                  erofs ? " (read-only file system)" : "");
    if (posture.read_only_root != erofs)
        posture_disagree(&report, profile_name, "read-only-root",
                         "the audit and a real write disagree on whether "
                         "the root filesystem is read-only");

    TEST_STEP("Check the profile was applied as asked");
    switch (profile)
    {
        case PROFILE_HARDENED:
            if (cap_eff != 0)
                posture_not_applied(&report, profile_name, "cap-drop",
                                    "capabilities remain after "
                                    "--cap-drop ALL");
            if (!erofs)
                posture_not_applied(&report, profile_name, "read-only",
                                    "the root filesystem accepts writes");
            if (posture.no_new_privs != 1)
                posture_not_applied(&report, profile_name,
                                    "no-new-privileges",
                                    "no_new_privs is not set");
            if (posture.uid != POSTURE_HARDENED_UID)
                posture_not_applied(&report, profile_name, "user",
                                    "the process does not run as nobody");
            if (tapi_cybersec_report_count(&report.cyber,
                                           TAPI_CYBERSEC_SEV_MEDIUM) > 0)
                posture_not_applied(&report, profile_name, "audit",
                                    "the audit still finds weaknesses of "
                                    "medium severity or worse");
            break;

        case PROFILE_DEFAULT:
            /*
             * Docker's defaults are not hardened; the audit must say so,
             * or it is blind (these are medium/low and do not fail a
             * high or critical gate).
             */
            tsapi_mde_report_expect(&report, "container.root-user",
                                    name.ptr);
            tsapi_mde_report_expect(&report, "container.writable-rootfs",
                                    name.ptr);
            if (write_failed)
                posture_not_applied(&report, profile_name, "writable",
                                    "a default container refused a write "
                                    "to /tmp");
            break;

        case PROFILE_PRIVILEGED:
            /* Known-bad control: found, then dropped. */
            tsapi_mde_report_expect(&report, "container.privileged",
                                    name.ptr);
            tsapi_mde_report_expect(&report, "container.no-seccomp",
                                    name.ptr);
            if (posture_popcount(cap_eff) < 30)
                posture_disagree(&report, profile_name, "cap-count",
                                 "a privileged container holds fewer than "
                                 "30 capabilities in /proc/self/status");
            tsapi_mde_report_drop_subject(&report, name.ptr);
            break;
    }

    TEST_STEP("Chart what was measured");
    n_findings = (unsigned int)te_vec_size(&report.cyber.findings);
    {
        const char *labels[] = { "audit", "proc" };
        double      counts[] = { posture_popcount(posture.cap_eff),
                                 posture_popcount(cap_eff) };

        tsapi_mde_mi_bars("container/posture",
                          "Effective capabilities: audit vs /proc",
                          TE_MI_MEAS_UNITLESS_VALUE, "caps",
                          TE_ARRAY_LEN(counts), labels, counts,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    tsapi_mde_mi_point("container/posture", "Findings left after controls",
                       TE_MI_MEAS_UNITLESS_VALUE, "findings", n_findings,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("container/posture", "Audit time", TE_MI_MEAS_TIME,
                       "audit_s", t_audit, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on the report");
    TSAPI_MDE_REPORT_GATE(&report, "container", min_sev);

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_container_remove(container, MDE_CT_TIMEOUT_MS));
    tsapi_mde_report_free(&report);
    te_string_free(&name);
    te_string_free(&status);
    te_string_free(&probe);
    te_string_free(&caps);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

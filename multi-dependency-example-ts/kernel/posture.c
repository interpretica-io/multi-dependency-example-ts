/** @file
 * @brief Kernel Group
 *
 * Take the hardening posture of the kernel the example runs on: log every
 * field as an artifact, chart the boolean flags and the raw sysctls, rank
 * what is weak as findings (a container shares the host kernel, so most of
 * it is informational and the min_severity parameter decides), and check
 * that two independent views of the same facts agree: the kernel release
 * as tsf-kernel reports it against @c uname -r, and the sysctls as the
 * posture read them against a plain @c cat on the agent.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "kernel/posture"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_kernel.h"
#include "tapi_kernel_security.h"
#include "kernel_common.h"

/** A posture flag as a 1/0 bar. */
typedef struct posture_flag {
    const char *label;  /**< Bar label. */
    bool        good;   /**< Hardened. */
} posture_flag;

/** Rank a weak sysctl. ABSENT knobs are not reported. */
static void
posture_sysctl(tsapi_mde_report *report, const char *name, int value,
               bool weak, tapi_cybersec_severity sev, const char *why)
{
    te_string check = TE_STRING_INIT;

    if (value == TAPI_KERNEL_SYSCTL_ABSENT || !weak)
        return;

    te_string_append(&check, "kernel.posture.%s", name);
    tapi_cybersec_report_add(&report->cyber, sev, check.ptr, name,
                             "kernel.%s = %d: %s", name, value, why);
    te_string_free(&check);
}

/** Strip trailing whitespace in place. */
static void
posture_chomp(te_string *s)
{
    while (s->len > 0 && (s->ptr[s->len - 1] == '\n' ||
                          s->ptr[s->len - 1] == '\r' ||
                          s->ptr[s->len - 1] == ' '))
        te_string_cut(s, 1);
}

int
main(int argc, char **argv)
{
    static const char *vulns[] = {
        TAPI_KERNEL_VULN_SPECTRE_V1, TAPI_KERNEL_VULN_SPECTRE_V2,
        TAPI_KERNEL_VULN_MELTDOWN, TAPI_KERNEL_VULN_MDS,
        TAPI_KERNEL_VULN_L1TF, TAPI_KERNEL_VULN_TAA,
        TAPI_KERNEL_VULN_SRBDS, TAPI_KERNEL_VULN_RETBLEED,
        TAPI_KERNEL_VULN_SPEC_STORE_BYPASS,
    };
    static const char *mac_lsms[] = {
        "selinux", "apparmor", "smack", "tomoyo",
    };
    tapi_cybersec_severity       min_sev;
    tsapi_mde_session            session;
    bool                         session_up = false;
    tapi_kernel_security_posture posture;
    bool                         posture_up = false;
    tsapi_mde_report             report;
    tsapi_mde_sh_result          sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string                    taint = TE_STRING_INIT;
    te_string                    cmdline = TE_STRING_INIT;
    te_string                    uname_r = TE_STRING_INIT;
    te_string                    osrelease = TE_STRING_INIT;
    posture_flag                 flags[12];
    const char                  *labels[TE_ARRAY_LEN(flags)];
    double                       vals[TE_ARRAY_LEN(flags)];
    const char                  *sysctl_labels[8];
    double                       sysctl_vals[8];
    const char                  *vuln_labels[TE_ARRAY_LEN(vulns)];
    double                       vuln_vals[TE_ARRAY_LEN(vulns)];
    unsigned int                 n_flags = 0;
    unsigned int                 n_good = 0;
    unsigned int                 i;
    bool                         mac = false;
    int                          cat_aslr = 0;
    int                          cat_dmesg = 0;
    int                          cat_kptr = 0;
    double                       t0;

    TEST_START;
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "kposture"));
    session_up = true;

    TEST_STEP("Take the hardening posture of the kernel");
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_kernel_security_posture_get(session.factory, &posture));
    posture_up = true;
    tsapi_mde_mi_point("kernel/posture", "Time to take the posture",
                       TE_MI_MEAS_TIME, "posture_s", tsapi_mde_now() - t0,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tapi_kernel_security_posture_log(&posture);
    tapi_kernel_security_taint2str(posture.taint, &taint);

    TEST_STEP("Log every field of the posture as an artifact");
    TEST_ARTIFACT("kernel release: %s",
                  posture.release != NULL ? posture.release : "?");
    TEST_ARTIFACT("lockdown: %s", tapi_kernel_lockdown2str(posture.lockdown));
    TEST_ARTIFACT("security modules: %s",
                  posture.lsm != NULL ? posture.lsm : "(unknown)");
    TEST_ARTIFACT("module signatures: %s",
                  !posture.sig_enforced_known ? "(not exposed)" :
                  posture.sig_enforced ? "enforced" : "not enforced");
    TEST_ARTIFACT("taint: 0x%" PRIx64 " (%s)", posture.taint, taint.ptr);
    TEST_ARTIFACT("kptr_restrict=%d dmesg_restrict=%d perf_event_paranoid=%d "
                  "unprivileged_bpf_disabled=%d ptrace_scope=%d "
                  "randomize_va_space=%d modules_disabled=%d "
                  "kexec_load_disabled=%d (%d = absent)",
                  posture.kptr_restrict, posture.dmesg_restrict,
                  posture.perf_event_paranoid,
                  posture.unprivileged_bpf_disabled, posture.ptrace_scope,
                  posture.randomize_va_space, posture.modules_disabled,
                  posture.kexec_load_disabled, TAPI_KERNEL_SYSCTL_ABSENT);

    TEST_STEP("Compare the release with uname -r and osrelease");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh, "uname -r"));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("uname -r failed on the agent");
    te_string_append(&uname_r, "%s", te_string_value(&sh.out));
    posture_chomp(&uname_r);
    CHECK_RC(tapi_kernel_read(session.factory, &osrelease,
                              "/proc/sys/kernel/osrelease"));
    posture_chomp(&osrelease);
    TEST_ARTIFACT("release views: tsf-kernel '%s', uname -r '%s', "
                  "osrelease '%s'",
                  posture.release != NULL ? posture.release : "?",
                  te_string_value(&uname_r), te_string_value(&osrelease));
    if (posture.release == NULL ||
        strcmp(posture.release, te_string_value(&uname_r)) != 0)
        TEST_VERDICT("Kernel release reported by the agent differs from "
                     "uname -r");
    if (strcmp(te_string_value(&uname_r), te_string_value(&osrelease)) != 0)
        TEST_VERDICT("uname -r differs from /proc/sys/kernel/osrelease");

    TEST_STEP("Compare the posture sysctls with a plain read of /proc/sys");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh,
                          "for k in randomize_va_space dmesg_restrict "
                          "kptr_restrict; do "
                          "v=$(cat /proc/sys/kernel/$k 2>/dev/null) || "
                          "v=absent; echo \"$k=$v\"; done"));
    RING("Sysctls read with cat:\n%s", te_string_value(&sh.out));
    {
        const char *out = te_string_value(&sh.out);
        const char *p;

        cat_aslr = cat_dmesg = cat_kptr = TAPI_KERNEL_SYSCTL_ABSENT;
        if ((p = strstr(out, "randomize_va_space=")) != NULL &&
            p[strlen("randomize_va_space=")] != 'a')
            cat_aslr = atoi(p + strlen("randomize_va_space="));
        if ((p = strstr(out, "dmesg_restrict=")) != NULL &&
            p[strlen("dmesg_restrict=")] != 'a')
            cat_dmesg = atoi(p + strlen("dmesg_restrict="));
        if ((p = strstr(out, "kptr_restrict=")) != NULL &&
            p[strlen("kptr_restrict=")] != 'a')
            cat_kptr = atoi(p + strlen("kptr_restrict="));
    }
    if (cat_aslr != posture.randomize_va_space ||
        cat_dmesg != posture.dmesg_restrict ||
        cat_kptr != posture.kptr_restrict)
    {
        ERROR("posture: aslr=%d dmesg=%d kptr=%d; cat: aslr=%d dmesg=%d "
              "kptr=%d", posture.randomize_va_space, posture.dmesg_restrict,
              posture.kptr_restrict, cat_aslr, cat_dmesg, cat_kptr);
        TEST_VERDICT("Posture sysctls differ from a plain read of /proc/sys");
    }

    TEST_STEP("Read the kernel command line");
    rc = tapi_kernel_cmdline(session.factory, &cmdline);
    if (rc == 0)
    {
        TEST_ARTIFACT("kernel command line: %s", te_string_value(&cmdline));
        if (tapi_kernel_cmdline_has(te_string_value(&cmdline), "nokaslr"))
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "kernel.posture.cmdline", "nokaslr",
                                     "the kernel was booted without KASLR");
        if (strstr(te_string_value(&cmdline), "mitigations=off") != NULL)
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "kernel.posture.cmdline",
                                     "mitigations=off",
                                     "CPU vulnerability mitigations are off");
    }
    else
    {
        RING("The kernel command line is not readable: %r", rc);
    }

    TEST_STEP("Rank the weak parts of the posture");
    posture_sysctl(&report, "randomize_va_space", posture.randomize_va_space,
                   posture.randomize_va_space < 2, TAPI_CYBERSEC_SEV_HIGH,
                   "address space randomization is not full, so the "
                   "example's binaries load at guessable addresses");
    posture_sysctl(&report, "kptr_restrict", posture.kptr_restrict,
                   posture.kptr_restrict < 1, TAPI_CYBERSEC_SEV_MEDIUM,
                   "kernel pointers are visible to unprivileged users");
    posture_sysctl(&report, "perf_event_paranoid",
                   posture.perf_event_paranoid,
                   posture.perf_event_paranoid < 2, TAPI_CYBERSEC_SEV_MEDIUM,
                   "unprivileged users may profile the kernel");
    posture_sysctl(&report, "unprivileged_bpf_disabled",
                   posture.unprivileged_bpf_disabled,
                   posture.unprivileged_bpf_disabled < 1,
                   TAPI_CYBERSEC_SEV_MEDIUM,
                   "unprivileged users may load BPF programs");
    posture_sysctl(&report, "dmesg_restrict", posture.dmesg_restrict,
                   posture.dmesg_restrict < 1, TAPI_CYBERSEC_SEV_LOW,
                   "the kernel log is readable by anyone");
    posture_sysctl(&report, "ptrace_scope", posture.ptrace_scope,
                   posture.ptrace_scope < 1, TAPI_CYBERSEC_SEV_LOW,
                   "any process may ptrace any other of the same user");
    posture_sysctl(&report, "modules_disabled", posture.modules_disabled,
                   posture.modules_disabled < 1, TAPI_CYBERSEC_SEV_INFO,
                   "module loading is still open");
    posture_sysctl(&report, "kexec_load_disabled",
                   posture.kexec_load_disabled,
                   posture.kexec_load_disabled < 1, TAPI_CYBERSEC_SEV_INFO,
                   "a new kernel may still be loaded with kexec");
    if (posture.lockdown != TAPI_KERNEL_LOCKDOWN_INTEGRITY &&
        posture.lockdown != TAPI_KERNEL_LOCKDOWN_CONFIDENTIALITY)
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                 "kernel.posture.lockdown", "lockdown",
                                 "lockdown is %s",
                                 tapi_kernel_lockdown2str(posture.lockdown));
    if (posture.sig_enforced_known && !posture.sig_enforced)
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                 "kernel.posture.module-sig", "module.sig_enforce",
                                 "unsigned modules are accepted");
    for (i = 0; i < TE_ARRAY_LEN(mac_lsms); i++)
    {
        if (posture.lsm != NULL && strstr(posture.lsm, mac_lsms[i]) != NULL)
            mac = true;
    }
    if (!mac)
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                 "kernel.posture.no-mac-lsm", "lsm",
                                 "no mandatory access control module is "
                                 "active (%s)",
                                 posture.lsm != NULL ? posture.lsm : "unknown");
    if ((posture.taint & (TAPI_KERNEL_TAINT_DIE | TAPI_KERNEL_TAINT_WARN |
                          TAPI_KERNEL_TAINT_BAD_PAGE |
                          TAPI_KERNEL_TAINT_SOFTLOCKUP |
                          TAPI_KERNEL_TAINT_MACHINE_CHECK)) != 0)
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "kernel.posture.taint", "taint",
                                 "the kernel has seen something go wrong "
                                 "since boot: %s", taint.ptr);

    TEST_STEP("Chart the boolean posture flags");
#define FLAG(_label, _good) \
    do {                                                    \
        flags[n_flags].label = (_label);                    \
        flags[n_flags].good = (_good);                      \
        n_flags++;                                          \
    } while (0)
    FLAG("lockdown", posture.lockdown == TAPI_KERNEL_LOCKDOWN_INTEGRITY ||
                     posture.lockdown == TAPI_KERNEL_LOCKDOWN_CONFIDENTIALITY);
    FLAG("sig_enforced", posture.sig_enforced_known && posture.sig_enforced);
    FLAG("kptr_restrict", posture.kptr_restrict >= 1);
    FLAG("dmesg_restrict", posture.dmesg_restrict >= 1);
    FLAG("perf_paranoid>=2", posture.perf_event_paranoid >= 2);
    FLAG("unpriv_bpf_off", posture.unprivileged_bpf_disabled >= 1);
    FLAG("ptrace_scope>=1", posture.ptrace_scope >= 1);
    FLAG("aslr_full", posture.randomize_va_space >= 2);
    FLAG("modules_disabled", posture.modules_disabled >= 1);
    FLAG("kexec_disabled", posture.kexec_load_disabled >= 1);
    FLAG("mac_lsm", mac);
    FLAG("untainted", posture.taint == 0);
#undef FLAG
    for (i = 0; i < n_flags; i++)
    {
        labels[i] = flags[i].label;
        vals[i] = flags[i].good ? 1 : 0;
        if (flags[i].good)
            n_good++;
    }
    tsapi_mde_mi_bars("kernel/posture", "Hardening flags (1 = hardened)",
                      TE_MI_MEAS_UNITLESS_VALUE, "hardened", n_flags, labels,
                      vals, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("kernel/posture", "Hardening flags set",
                       TE_MI_MEAS_PERCENTAGE, "hardened_pct",
                       100.0 * n_good / n_flags,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("hardening flags set: %u of %u", n_good, n_flags);

    TEST_STEP("Chart the raw sysctl values (-1 = absent)");
#define SYSCTL(_idx, _label, _v) \
    do {                                                                \
        sysctl_labels[_idx] = (_label);                                 \
        sysctl_vals[_idx] = (_v) == TAPI_KERNEL_SYSCTL_ABSENT ? -1 : (_v); \
    } while (0)
    SYSCTL(0, "kptr_restrict", posture.kptr_restrict);
    SYSCTL(1, "dmesg_restrict", posture.dmesg_restrict);
    SYSCTL(2, "perf_event_paranoid", posture.perf_event_paranoid);
    SYSCTL(3, "unprivileged_bpf_disabled", posture.unprivileged_bpf_disabled);
    SYSCTL(4, "ptrace_scope", posture.ptrace_scope);
    SYSCTL(5, "randomize_va_space", posture.randomize_va_space);
    SYSCTL(6, "modules_disabled", posture.modules_disabled);
    SYSCTL(7, "kexec_load_disabled", posture.kexec_load_disabled);
#undef SYSCTL
    tsapi_mde_mi_bars("kernel/posture", "Kernel sysctls (-1 = absent)",
                      TE_MI_MEAS_UNITLESS_VALUE, "value",
                      TE_ARRAY_LEN(sysctl_vals), sysctl_labels, sysctl_vals,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Read what the kernel says about CPU vulnerabilities");
    for (i = 0; i < TE_ARRAY_LEN(vulns); i++)
    {
        tapi_kernel_vuln_state state = TAPI_KERNEL_VULN_UNKNOWN;
        te_string              detail = TE_STRING_INIT;

        rc = tapi_kernel_security_vuln(session.factory, vulns[i], &state,
                                       &detail);
        if (rc != 0)
            RING("Vulnerability %s cannot be read: %r", vulns[i], rc);
        vuln_labels[i] = vulns[i];
        vuln_vals[i] = state;
        TEST_ARTIFACT("cpu vulnerability %s: %s (%s)", vulns[i],
                      tapi_kernel_vuln2str(state), te_string_value(&detail));
        if (state == TAPI_KERNEL_VULN_VULNERABLE)
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "kernel.vuln", vulns[i],
                                     "the kernel reports: %s",
                                     te_string_value(&detail));
        te_string_free(&detail);
    }
    tsapi_mde_mi_bars("kernel/posture",
                      "CPU vulnerabilities (0 unknown, 1 not affected, "
                      "2 mitigated, 3 vulnerable)",
                      TE_MI_MEAS_UNITLESS_VALUE, "state",
                      TE_ARRAY_LEN(vulns), vuln_labels, vuln_vals,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide over the posture findings");
    TSAPI_MDE_REPORT_GATE(&report, "kernel", min_sev);

    TEST_SUCCESS;

cleanup:

    if (posture_up)
        tapi_kernel_security_posture_free(&posture);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&taint);
    te_string_free(&cmdline);
    te_string_free(&uname_r);
    te_string_free(&osrelease);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

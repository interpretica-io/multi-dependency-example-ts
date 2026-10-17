/** @file
 * @brief package Group
 *
 * Inventory of the tools the suite's modules drive on the agent, seen two
 * independent ways: the package manager (tapi_package: is the package that
 * should provide the tool installed, which package owns the file on PATH,
 * which version it is) and the agent itself (command -v, the tool's own
 * version banner). The two views must agree; where they do not, that is a
 * finding. A missing tool is information, never a failure.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "package/inventory"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_package.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"

/** One tool and where it should come from. */
typedef struct inv_tool {
    const char *tool;     /**< Program name looked up through PATH. */
    const char *pkg;      /**< Debian package expected to own it, or NULL. */
    const char *ver_args; /**< Arguments that make it print its version. */
} inv_tool;

static const inv_tool inv_core[] = {
    { "python3",  "python3",  "--version" },
    { "curl",     "curl",     "--version" },
    { "readelf",  "binutils", "--version" },
    { "nm",       "binutils", "--version" },
    { "objdump",  "binutils", "--version" },
    { "strace",   "strace",   "-V" },
    { "gdb",      "gdb",      "--version" },
    { "lsof",     "lsof",     "-v" },
    { "openssl",  "openssl",  "version" },
    { "clang",    "clang",    "--version" },
    { "gcc",      "gcc",      "--version" },
    { "make",     "make",     "--version" },
};

static const inv_tool inv_network[] = {
    { "mosquitto",     "mosquitto",          "-h" },
    { "mosquitto_pub", "mosquitto-clients",  "--help" },
    { "smbclient",     "smbclient",          "--version" },
    { "smbd",          "samba",              "--version" },
    { "lpstat",        "cups-client",        "--help" },
    { "ipptool",       "cups-ipp-utils",     "--version" },
    { "wg",            "wireguard-tools",    "--version" },
    { "swanctl",       "strongswan-swanctl", "--version" },
    { "nmap",          "nmap",               "--version" },
    { "tcpdump",       "tcpdump",            "--version" },
    { "faketime",      "faketime",           "--version" },
};

static const inv_tool inv_radio[] = {
    { "rtl_433",      "rtl-433",        "-V" },
    { "rtl_sdr",      "rtl-sdr",        "-h" },
    { "hackrf_info",  "hackrf",         "" },
    { "SoapySDRUtil", "soapysdr-tools", "--info" },
    { "candump",      "can-utils",      "-h" },
    { "cansend",      "can-utils",      "-h" },
    { "bluetoothctl", "bluez",          "--version" },
    { "btmon",        "bluez",          "--version" },
};

static const inv_tool inv_bench[] = {
    { "openocd",            "openocd",         "--version" },
    { "flashrom",           "flashrom",        "--version" },
    { "dfu-util",           "dfu-util",        "--version" },
    { "esptool",            "esptool",         "version" },
    { "fastboot",           "fastboot",        "--version" },
    { "sigrok-cli",         "sigrok-cli",      "--version" },
    { "qemu-system-x86_64", "qemu-system-x86", "--version" },
};

static const inv_tool inv_ui[] = {
    { "node",   "nodejs",    "--version" },
    { "npx",    "nodejs",    "--version" },
    { "adb",    "adb",       "version" },
    { "appium", NULL,        "--version" },
    { "docker", "docker.io", "--version" },
};

/** Tool sets, one per iteration. */
typedef enum inv_set {
    INV_CORE,
    INV_NETWORK,
    INV_RADIO,
    INV_BENCH,
    INV_UI,
} inv_set;

#define INV_SET_LIST \
    { "core",    INV_CORE },    \
    { "network", INV_NETWORK }, \
    { "radio",   INV_RADIO },   \
    { "bench",   INV_BENCH },   \
    { "ui",      INV_UI }

/** Largest set plus the two controls. */
#define INV_MAX_TOOLS   16

/*
 * What the agent says about one tool, one tagged line each:
 *   P <path on PATH or ->     R <resolved path>
 *   O <owning package or ->   V <version lines of the tool's banner>
 * sbin directories are added: a non-root agent's PATH often lacks them,
 * and a daemon there is still installed.
 */
#define INV_SCRIPT \
    "PATH=\"$PATH:/usr/local/sbin:/usr/sbin:/sbin\"; export PATH; "          \
    "p=$(command -v '%s' 2>/dev/null) || { echo 'P -'; exit 0; }; "          \
    "echo \"P $p\"; r=$(readlink -f \"$p\"); echo \"R $r\"; o=-; "           \
    "for x in \"$p\" \"$r\"; do "                                            \
    "for y in \"$x\" \"${x#/usr}\" \"/usr$x\"; do "                          \
    "[ \"$o\" = - ] || break; "                                              \
    "q=$(dpkg -S \"$y\" 2>/dev/null | grep -v '^diversion' | head -n1 | "    \
    "cut -d: -f1); [ -n \"$q\" ] && o=$q; done; done; echo \"O $o\"; "       \
    "v=$(timeout 20 \"$p\" %s </dev/null 2>&1 | "                            \
    "grep -E '[0-9]+[.][0-9]+' | head -n3 | tr '\\n' ' '); echo \"V $v\""

/* Copy the rest of the first line "<tag> ..." of @p text into @p buf. */
static bool
line_value(const char *text, const char *tag, char *buf, size_t len)
{
    size_t      tlen = strlen(tag);
    const char *p = text;

    buf[0] = '\0';
    while (p != NULL && *p != '\0')
    {
        const char *eol = strchr(p, '\n');
        size_t      llen = (eol != NULL) ? (size_t)(eol - p) : strlen(p);

        if (llen > tlen && strncmp(p, tag, tlen) == 0 && p[tlen] == ' ')
        {
            size_t n = llen - tlen - 1;

            if (n >= len)
                n = len - 1;
            memcpy(buf, p + tlen + 1, n);
            buf[n] = '\0';
            while (n > 0 && (buf[n - 1] == ' ' || buf[n - 1] == '\r'))
                buf[--n] = '\0';
            return true;
        }
        p = (eol != NULL) ? eol + 1 : NULL;
    }

    return false;
}

/* Upstream part of a package version: no epoch, no Debian revision. */
static void
upstream_version(const char *ver, char *buf, size_t len)
{
    const char *colon = strchr(ver, ':');
    const char *p = (colon != NULL) ? colon + 1 : ver;
    size_t      n = strcspn(p, "-+~");

    if (n >= len)
        n = len - 1;
    memcpy(buf, p, n);
    buf[n] = '\0';
}

/*
 * Inventory one tool: both views, their agreement, the findings.
 * @p on_path tells whether the agent can run it, @p banner is what it
 * printed about its version.
 */
static te_errno
inventory_one(tsapi_mde_session *session, const tapi_package_ctx *ctx,
              tsapi_mde_report *report, const inv_tool *t, bool *on_path,
              char *banner, size_t banner_len)
{
    tsapi_mde_sh_result      sh = TSAPI_MDE_SH_RESULT_INIT;
    tapi_package_info        exp_pkg;
    tapi_package_info        own_pkg;
    const tapi_package_info *own = NULL;
    char                     path[512];
    char                     real[512];
    char                     owner[256];
    char                     up[128];
    bool                     owner_known;
    te_errno                 rc;

    memset(&exp_pkg, 0, sizeof(exp_pkg));
    memset(&own_pkg, 0, sizeof(own_pkg));
    *on_path = false;
    banner[0] = '\0';

    rc = tsapi_mde_sh(session, 60000, &sh, INV_SCRIPT, t->tool, t->ver_args);
    if (rc != 0)
        goto out;
    if (!tsapi_mde_sh_ok(&sh))
    {
        ERROR("The probe of %s did not finish cleanly: %s", t->tool,
              te_string_value(&sh.err));
        rc = TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }
    RING("Agent view of %s:\n%s", t->tool, te_string_value(&sh.out));

    line_value(te_string_value(&sh.out), "P", path, sizeof(path));
    line_value(te_string_value(&sh.out), "R", real, sizeof(real));
    line_value(te_string_value(&sh.out), "O", owner, sizeof(owner));
    line_value(te_string_value(&sh.out), "V", banner, banner_len);
    *on_path = (path[0] != '\0' && strcmp(path, "-") != 0);
    owner_known = (owner[0] != '\0' && strcmp(owner, "-") != 0);

    /* The package manager's view: the package expected to provide it. */
    if (t->pkg != NULL)
    {
        rc = tapi_package_query(session->factory, ctx, t->pkg, &exp_pkg);
        if (rc != 0)
            goto out;
    }

    if (!*on_path)
    {
        if (exp_pkg.installed)
        {
            tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "package.view-mismatch", t->tool,
                                     "package %s %s is installed, yet %s is "
                                     "not on PATH", t->pkg,
                                     exp_pkg.version != NULL ?
                                        exp_pkg.version : "?", t->tool);
        }
        else
        {
            tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_INFO,
                                     "package.missing", t->tool,
                                     "not on PATH; package %s is not "
                                     "installed",
                                     t->pkg != NULL ? t->pkg : "(none)");
        }
        TEST_ARTIFACT("%s: missing (package %s: %s)", t->tool,
                      t->pkg != NULL ? t->pkg : "(none)",
                      exp_pkg.installed ? "installed" : "not installed");
        goto out;
    }

    /* The owner of the file on PATH, as the package database says. */
    if (owner_known)
    {
        if (t->pkg != NULL && strcmp(owner, t->pkg) == 0)
        {
            own = &exp_pkg;
        }
        else
        {
            rc = tapi_package_query(session->factory, ctx, owner, &own_pkg);
            if (rc != 0)
                goto out;
            own = &own_pkg;
            if (t->pkg != NULL)
            {
                RING("%s is owned by %s, not by the expected %s", t->tool,
                     owner, t->pkg);
            }
        }

        if (!own->installed)
        {
            tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "package.view-mismatch", t->tool,
                                     "%s belongs to %s per dpkg -S, but the "
                                     "package manager says %s is not "
                                     "installed", path, owner, owner);
        }
    }
    else
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_INFO,
                                 "package.unowned", t->tool,
                                 "%s (%s) is on PATH but no package owns it",
                                 path, real);
    }

    /* The version the package claims against the one the tool prints. */
    if (own != NULL && own->installed && own->version != NULL &&
        banner[0] != '\0')
    {
        upstream_version(own->version, up, sizeof(up));
        if (up[0] != '\0' && strstr(banner, up) == NULL)
        {
            tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_LOW,
                                     "package.version-disagree", t->tool,
                                     "package %s is %s, the tool says '%s'",
                                     owner, own->version, banner);
        }
    }

    TEST_ARTIFACT("%s: %s, package %s %s, reports '%s'", t->tool, path,
                  owner_known ? owner : "(none)",
                  (own != NULL && own->version != NULL) ? own->version : "-",
                  banner[0] != '\0' ? banner : "-");

out:
    tapi_package_info_free(&exp_pkg);
    tapi_package_info_free(&own_pkg);
    tsapi_mde_sh_result_free(&sh);

    return rc;
}

int
main(int argc, char **argv)
{
    static const char * const set_names[] = {
        "core", "network", "radio", "bench", "ui",
    };
    inv_set                set;
    tapi_cybersec_severity min_sev;
    const inv_tool        *tools = NULL;
    size_t                 n_tools = 0;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tapi_package_ctx       ctx;
    bool                   ctx_up = false;
    tsapi_mde_report       report;
    bool                   report_up = false;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string              ctl_dir = TE_STRING_INIT;
    te_string              ctl_tool = TE_STRING_INIT;
    inv_tool               ctl_unowned;
    inv_tool               ctl_missing;
    const char            *labels[INV_MAX_TOOLS];
    double                 present[INV_MAX_TOOLS];
    double                 probe_s[INV_MAX_TOOLS];
    unsigned int           n_present = 0;
    char                   banner[512];
    char                   title[128];
    bool                   on_path;
    double                 started;
    double                 coverage;
    size_t                 i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(set, INV_SET_LIST);
    TEST_GET_MDE_SEVERITY(min_sev);

    switch (set)
    {
        case INV_CORE:
            tools = inv_core;
            n_tools = TE_ARRAY_LEN(inv_core);
            break;

        case INV_NETWORK:
            tools = inv_network;
            n_tools = TE_ARRAY_LEN(inv_network);
            break;

        case INV_RADIO:
            tools = inv_radio;
            n_tools = TE_ARRAY_LEN(inv_radio);
            break;

        case INV_BENCH:
            tools = inv_bench;
            n_tools = TE_ARRAY_LEN(inv_bench);
            break;

        case INV_UI:
            tools = inv_ui;
            n_tools = TE_ARRAY_LEN(inv_ui);
            break;

        default:
            TEST_FAIL("Unknown tool set: %d", (int)set);
    }
    if (n_tools > INV_MAX_TOOLS)
        TEST_FAIL("Tool set is larger than the chart arrays");

    TEST_STEP("Open a session on the agent");
    rc = tsapi_mde_session_init(&session, "pkg_inventory");
    session_up = true;
    if (rc != 0)
        TEST_FAIL("Cannot open a session on the agent: %r", rc);

    TEST_STEP("Detect the package manager");
    rc = tapi_package_ctx_init(session.factory, &ctx);
    if (rc != 0)
        TEST_SKIP("No package manager on the agent");
    ctx_up = true;
    TEST_ARTIFACT("Package manager: %s",
                  tapi_package_manager2str(ctx.manager));

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Ask both views about every tool of the set");
    for (i = 0; i < n_tools; i++)
    {
        started = tsapi_mde_now();
        CHECK_RC(inventory_one(&session, &ctx, &report, &tools[i], &on_path,
                               banner, sizeof(banner)));
        probe_s[i] = tsapi_mde_now() - started;
        labels[i] = tools[i].tool;
        present[i] = on_path ? 1 : 0;
        if (on_path)
            n_present++;
    }

    TEST_STEP("Known-bad controls: a tool that does not exist, and a tool "
              "on PATH that no package owns");
    te_string_append(&ctl_dir, "/tmp/mde-package-inventory-%s",
                     set_names[set]);
    te_string_append(&ctl_tool, "%s/mde-ctl-tool", ctl_dir.ptr);
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                          "rm -rf '%s' && mkdir -p '%s' && "
                          "printf '#!/bin/sh\\n"
                          "echo \"mde-ctl-tool 1.2.3\"\\n' "
                          "> '%s' && chmod 755 '%s'",
                          ctl_dir.ptr, ctl_dir.ptr, ctl_tool.ptr,
                          ctl_tool.ptr));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot plant the control tool: %s",
                  te_string_value(&sh.err));

    ctl_missing.tool = "mde-no-such-tool";
    ctl_missing.pkg = "mde-no-such-package";
    ctl_missing.ver_args = "--version";
    CHECK_RC(inventory_one(&session, &ctx, &report, &ctl_missing, &on_path,
                           banner, sizeof(banner)));
    if (on_path)
        TEST_VERDICT("A tool that does not exist was found on PATH");
    tsapi_mde_report_expect(&report, "package.missing", ctl_missing.tool);

    ctl_unowned.tool = ctl_tool.ptr;
    ctl_unowned.pkg = NULL;
    ctl_unowned.ver_args = "--version";
    CHECK_RC(inventory_one(&session, &ctx, &report, &ctl_unowned, &on_path,
                           banner, sizeof(banner)));
    if (!on_path)
        TEST_VERDICT("The planted control tool was not found");
    if (strstr(banner, "1.2.3") == NULL)
        TEST_VERDICT("The version banner of the control tool was misread");
    tsapi_mde_report_expect(&report, "package.unowned", ctl_unowned.tool);

    tsapi_mde_report_drop_subject(&report, ctl_missing.tool);
    tsapi_mde_report_drop_subject(&report, ctl_unowned.tool);

    TEST_STEP("Chart the inventory");
    coverage = 100.0 * n_present / (double)n_tools;
    TEST_ARTIFACT("Tool set %s: %u of %zu tools present (%.1f percent)",
                  set_names[set], n_present, n_tools, coverage);

    TE_SPRINTF(title, "Tools installed (%s set)", set_names[set]);
    tsapi_mde_mi_bars("package", title, TE_MI_MEAS_UNITLESS_VALUE,
                      "installed", n_tools, labels, present,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    TE_SPRINTF(title, "Probe time per tool (%s set)", set_names[set]);
    tsapi_mde_mi_bars("package", title, TE_MI_MEAS_TIME, "probe", n_tools,
                      labels, probe_s, TE_MI_MEAS_MULTIPLIER_PLAIN);
    TE_SPRINTF(title, "Tool coverage (%s set)", set_names[set]);
    tsapi_mde_mi_point("package", title, TE_MI_MEAS_PERCENTAGE, "coverage",
                       coverage, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "package", min_sev);

    TEST_SUCCESS;

cleanup:

    if (session_up && ctl_dir.ptr != NULL)
    {
        tsapi_mde_sh_result rm = TSAPI_MDE_SH_RESULT_INIT;

        tsapi_mde_sh(&session, 30000, &rm, "rm -rf '%s'", ctl_dir.ptr);
        tsapi_mde_sh_result_free(&rm);
    }
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&ctl_dir);
    te_string_free(&ctl_tool);
    if (report_up)
        tsapi_mde_report_free(&report);
    if (ctx_up)
        tapi_package_ctx_fini(&ctx);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

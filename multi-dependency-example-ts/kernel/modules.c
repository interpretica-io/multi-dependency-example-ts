/** @file
 * @brief Kernel Group
 *
 * Read-only inventory of the kernel the example runs on: the modules it
 * holds (tapi_kmod_list, cross-checked with a plain line count of
 * /proc/modules and with tapi_kmod_is_loaded) and the hardening options
 * of its configuration (tapi_kernel_config_enabled), charted as 1/0
 * bars. Missing hardening is ranked low to medium: in a container the
 * kernel belongs to the host, so it is context for the example, and the
 * min_severity parameter decides.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "kernel/modules"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_kernel.h"
#include "tapi_kmod.h"
#include "kernel_common.h"

/** A configuration option and what its state means. */
typedef struct mod_option {
    const char            *name;    /**< CONFIG_... */
    bool                   want;    /**< Hardened when enabled (or not). */
    tapi_cybersec_severity sev;     /**< Severity when not as wanted. */
} mod_option;

/** Most modules charted by size. */
#define MOD_TOP 20

int
main(int argc, char **argv)
{
    static const mod_option options[] = {
        { "CONFIG_STRICT_KERNEL_RWX",       true,  TAPI_CYBERSEC_SEV_MEDIUM },
        { "CONFIG_STRICT_MODULE_RWX",       true,  TAPI_CYBERSEC_SEV_LOW },
        { "CONFIG_STACKPROTECTOR_STRONG",   true,  TAPI_CYBERSEC_SEV_MEDIUM },
        { "CONFIG_RANDOMIZE_BASE",          true,  TAPI_CYBERSEC_SEV_MEDIUM },
        { "CONFIG_HARDENED_USERCOPY",       true,  TAPI_CYBERSEC_SEV_LOW },
        { "CONFIG_FORTIFY_SOURCE",          true,  TAPI_CYBERSEC_SEV_LOW },
        { "CONFIG_SLAB_FREELIST_HARDENED",  true,  TAPI_CYBERSEC_SEV_LOW },
        { "CONFIG_SLAB_FREELIST_RANDOM",    true,  TAPI_CYBERSEC_SEV_LOW },
        { "CONFIG_SECCOMP_FILTER",          true,  TAPI_CYBERSEC_SEV_LOW },
        { "CONFIG_SECURITY_YAMA",           true,  TAPI_CYBERSEC_SEV_LOW },
        { "CONFIG_PAGE_TABLE_ISOLATION",    true,  TAPI_CYBERSEC_SEV_INFO },
        { "CONFIG_MODULE_SIG",              true,  TAPI_CYBERSEC_SEV_INFO },
        { "CONFIG_INIT_ON_ALLOC_DEFAULT_ON", true, TAPI_CYBERSEC_SEV_INFO },
        { "CONFIG_DEVMEM",                  false, TAPI_CYBERSEC_SEV_LOW },
        { "CONFIG_PROC_KCORE",              false, TAPI_CYBERSEC_SEV_INFO },
    };
    tapi_cybersec_severity min_sev;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_report       report;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string              config = TE_STRING_INIT;
    te_vec                 modules;
    bool                   listed = false;
    long                   n_proc = -1;
    uint64_t               total_size = 0;
    const tapi_kmod_entry *e;
    const char            *opt_labels[TE_ARRAY_LEN(options)];
    double                 opt_vals[TE_ARRAY_LEN(options)];
    unsigned int           n_hardened = 0;
    unsigned int           i;

    TEST_START;
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "kmod"));
    session_up = true;

    TEST_STEP("Count /proc/modules lines with the shell");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh,
                          "test -r /proc/modules && wc -l < /proc/modules"));
    if (tsapi_mde_sh_ok(&sh))
        n_proc = strtol(te_string_value(&sh.out), NULL, 10);
    TEST_ARTIFACT("/proc/modules: %s",
                  n_proc < 0 ? "not readable" : te_string_value(&sh.out));

    TEST_STEP("List the modules with tsf-kernel and cross-check the count");
    if (n_proc > 0)
    {
        const tapi_kmod_entry *top[MOD_TOP] = { NULL };
        const char            *top_labels[MOD_TOP];
        double                 top_sizes[MOD_TOP];
        double                 top_refs[MOD_TOP];
        unsigned int           n_top = 0;
        unsigned int           j;
        bool                   loaded = false;

        rc = tapi_kmod_list(session.factory, &modules);
        if (rc != 0)
        {
            /*
             * /proc/modules prints '-' as the use count of a module that
             * cannot be unloaded; a parser that wants a number there
             * cannot list such a kernel at all.
             */
            TEST_VERDICT("tapi_kmod_list cannot parse /proc/modules: %s",
                         te_rc_err2str(rc));
        }
        listed = true;
        TEST_ARTIFACT("modules: %zu listed, %ld lines in /proc/modules",
                      te_vec_size(&modules), n_proc);
        if (te_vec_size(&modules) != (size_t)n_proc)
            TEST_VERDICT("tapi_kmod_list and /proc/modules disagree on the "
                         "number of modules");

        TE_VEC_FOREACH(&modules, e)
        {
            total_size += e->size;

            /* Keep the MOD_TOP biggest, sorted by size, largest first. */
            for (j = 0; j < n_top && top[j]->size >= e->size; j++)
                ;
            if (j < MOD_TOP)
            {
                unsigned int k;

                if (n_top < MOD_TOP)
                    n_top++;
                for (k = n_top - 1; k > j; k--)
                    top[k] = top[k - 1];
                top[j] = e;
            }
        }
        for (j = 0; j < n_top; j++)
        {
            top_labels[j] = top[j]->name;
            top_sizes[j] = (double)top[j]->size;
            top_refs[j] = top[j]->refcnt;
        }
        TEST_ARTIFACT("modules: total size %" PRIu64 " bytes, largest %s "
                      "(%" PRIu64 " bytes)", total_size,
                      n_top > 0 ? top[0]->name : "-",
                      n_top > 0 ? top[0]->size : 0);
        tsapi_mde_mi_bars("kernel/modules", "Largest modules",
                          TE_MI_MEAS_MEMORY, "size", n_top, top_labels,
                          top_sizes, TE_MI_MEAS_MULTIPLIER_PLAIN);
        tsapi_mde_mi_bars("kernel/modules",
                          "References of the largest modules",
                          TE_MI_MEAS_UNITLESS_VALUE, "refcnt", n_top,
                          top_labels, top_refs, TE_MI_MEAS_MULTIPLIER_PLAIN);

        TEST_SUBSTEP("A listed module must read as loaded");
        e = te_vec_get(&modules, 0);
        CHECK_RC(tapi_kmod_is_loaded(session.factory, e->name, &loaded));
        if (!loaded)
            TEST_VERDICT("A module of /proc/modules does not read as loaded "
                         "in /sys/module");
        if (tapi_kmod_list_find(&modules, e->name) != e)
            TEST_VERDICT("tapi_kmod_list_find() does not find a listed "
                         "module");
    }
    else
    {
        RING("The kernel shows no modules here (a container often sees "
             "none): nothing to cross-check");
    }
    tsapi_mde_mi_point("kernel/modules", "Modules held by the kernel",
                       TE_MI_MEAS_UNITLESS_VALUE, "modules",
                       n_proc > 0 ? (double)n_proc : 0,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Read the kernel configuration and its hardening options");
    rc = tapi_kernel_config_read(session.factory, &config);
    if (rc != 0)
    {
        RING("The kernel does not publish its configuration (%r): the "
             "hardening options are charted as unknown (-1)", rc);
        TEST_ARTIFACT("kernel configuration: not available");
    }
    else
    {
        TEST_ARTIFACT("kernel configuration: %zu bytes", config.len);
    }
    for (i = 0; i < TE_ARRAY_LEN(options); i++)
    {
        bool on;

        opt_labels[i] = options[i].name;
        if (rc != 0)
        {
            opt_vals[i] = -1;
            continue;
        }

        on = tapi_kernel_config_enabled(config.ptr, options[i].name);
        opt_vals[i] = on ? 1 : 0;
        TEST_ARTIFACT("%s: %s", options[i].name, on ? "enabled" : "not set");
        if (on == options[i].want)
        {
            n_hardened++;
            continue;
        }
        tapi_cybersec_report_add(&report.cyber, options[i].sev,
                                 options[i].want ? "kernel.config.missing" :
                                                   "kernel.config.weakening",
                                 options[i].name, "%s is %s",
                                 options[i].name,
                                 on ? "enabled" : "not set");
    }
    tsapi_mde_mi_bars("kernel/modules",
                      "Hardening options (1 enabled, 0 not set, -1 unknown)",
                      TE_MI_MEAS_UNITLESS_VALUE, "enabled",
                      TE_ARRAY_LEN(options), opt_labels, opt_vals,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (rc == 0)
        TEST_ARTIFACT("hardening options as wanted: %u of %zu", n_hardened,
                      TE_ARRAY_LEN(options));

    TEST_STEP("Decide over the configuration findings");
    TSAPI_MDE_REPORT_GATE(&report, "kernel", min_sev);

    TEST_SUCCESS;

cleanup:

    if (listed)
        tapi_kmod_list_free(&modules);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&config);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

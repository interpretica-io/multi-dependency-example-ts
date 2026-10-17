/** @file
 * @brief Memory Map Group
 *
 * The RAM budget of the ring: every ring library's ELF image is placed in
 * a RAM region of the iteration's size by tsf-memorymap, and what is left
 * after loading all five, one after another, is charted - the question a
 * firmware author asks of an image, asked of the example. Each placement
 * is checked against the image itself (used + overflow equals the sum of
 * the PT_LOAD memory sizes, no segment overlaps another), the footprint is
 * set against the memory the agent has available, and the calculator gets
 * a known-bad control: a region half the size of a library must be
 * reported as overflowing.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "memmap/ram"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_memmap.h"
#include "tapi_memmap_elf.h"
#include "tapi_memmap_ram.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "memmap_common.h"

/** Most ring libraries. */
#define RAM_MAX_LIBS    8

int
main(int argc, char **argv)
{
    unsigned int        budget_mb;
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tsapi_mde_report    report;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    tapi_memmap_image   images[RAM_MAX_LIBS];
    bool                image_up[RAM_MAX_LIBS];
    tapi_memmap_region  ram;
    const char         *labels[RAM_MAX_LIBS];
    double              footprint[RAM_MAX_LIBS];
    double              free_after[RAM_MAX_LIBS];
    uint64_t            budget;
    uint64_t            total = 0;
    unsigned long       avail_kb = 0;
    unsigned int        n = 0;
    unsigned int        i;

    TEST_START;
    tsapi_mde_report_init(&report);
    memset(&dut, 0, sizeof(dut));
    memset(image_up, 0, sizeof(image_up));

    TEST_STEP("Parse test parameters");
    TEST_GET_UINT_PARAM(budget_mb);
    budget = (uint64_t)budget_mb * 1024 * 1024;

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "mmram", dut, session_up);
    if (strcmp(dut.dylib_ext, "so") != 0)
        TEST_SKIP("The example is built as Mach-O, not ELF");

    TEST_STEP("Place every ring library in the budget");
    memset(&ram, 0, sizeof(ram));
    ram.base = 0;
    ram.size = budget;
    ram.name = "RAM";
    for (i = 0; i < tsapi_mde_dut_n_libs && n < RAM_MAX_LIBS; i++)
    {
        te_string              path = TE_STRING_INIT;
        tapi_memmap_usage      usage;
        const tapi_memmap_seg *seg;
        uint64_t               sum = 0;
        uint64_t               lfree = 0;
        uint64_t               lsize = 0;

        tsapi_mde_dut_lib_path(&dut, tsapi_mde_dut_libs[i], &path);
        if (!tsapi_mde_exists(&session, path.ptr))
        {
            RING("%s is not built", path.ptr);
            te_string_free(&path);
            continue;
        }
        rc = tapi_memmap_elf_read(session.factory, path.ptr,
                                  TAPI_MEMMAP_TIMEOUT_MS, &images[n]);
        te_string_free(&path);
        if (rc != 0)
            TEST_FAIL("Cannot read the image of %s: %r",
                      tsapi_mde_dut_libs[i], rc);
        image_up[n] = true;

        TAPI_MEMMAP_FOREACH_LOAD(&images[n], seg)
            sum += seg->memsz;

        CHECK_RC(tapi_memmap_ram_usage(&images[n], &ram, 1,
                                       TAPI_MEMMAP_BY_VADDR, &usage));
        tapi_memmap_usage_log(&usage);
        (void)tapi_memmap_ram_largest_free(&usage, NULL, &lsize);
        lfree = usage.free;
        TEST_ARTIFACT("%s: PT_LOAD %" PRIu64 " bytes; in %u MB: used %"
                      PRIu64 ", free %" PRIu64 ", largest free span %"
                      PRIu64 ", %s%s", tsapi_mde_dut_libs[i], sum,
                      budget_mb, usage.used, lfree, lsize,
                      usage.fits ? "fits" : "overflows",
                      usage.overlap ? ", segments overlap" : "");

        if (usage.overlap)
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "memmap.segment-overlap",
                                     tsapi_mde_dut_libs[i],
                                     "two PT_LOAD segments overlap");
        else if (usage.used + usage.overflow != sum)
        {
            tapi_memmap_usage_free(&usage);
            TEST_VERDICT("The RAM placement does not account for every "
                         "PT_LOAD byte of a ring library");
        }
        if (usage.total != budget || usage.used + usage.free != budget)
        {
            tapi_memmap_usage_free(&usage);
            TEST_VERDICT("The RAM placement does not add up to the region");
        }
        tapi_memmap_usage_free(&usage);

        labels[n] = tsapi_mde_dut_libs[i];
        footprint[n] = (double)sum;
        total += sum;
        free_after[n] = (double)budget - (double)total;
        n++;
    }
    if (n == 0)
        TEST_SKIP("No ring library is built");

    TEST_STEP("Chart the footprint and what the budget has left");
    tsapi_mde_mi_bars("memmap/ram", "PT_LOAD memory per ring library",
                      TE_MI_MEAS_MEMORY, "footprint", n, labels, footprint,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("memmap/ram",
                      "RAM left in the budget after loading each library",
                      TE_MI_MEAS_MEMORY, "free", n, labels, free_after,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("ring: %u librar(ies), %" PRIu64 " bytes of PT_LOAD; "
                  "budget %u MB leaves %.0f bytes", n, total, budget_mb,
                  (double)budget - (double)total);
    if (total > budget)
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "memmap.ram-budget", "ring",
                                 "the ring needs %" PRIu64 " bytes, the "
                                 "budget is %u MB", total, budget_mb);

    TEST_STEP("Set the footprint against the memory the agent has");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh,
                          "awk '/^MemAvailable:/{print $2}' /proc/meminfo"));
    avail_kb = strtoul(te_string_value(&sh.out), NULL, 10);
    TEST_ARTIFACT("agent MemAvailable: %lu kB; ring footprint %.1f%% of it",
                  avail_kb, avail_kb > 0 ?
                      100.0 * (double)total / (avail_kb * 1024.0) : 0.0);
    {
        static const char *alabels[] = {
            "ring_footprint", "budget", "agent_available",
        };
        double avals[TE_ARRAY_LEN(alabels)];

        avals[0] = (double)total;
        avals[1] = (double)budget;
        avals[2] = (double)avail_kb * 1024.0;
        tsapi_mde_mi_bars("memmap/ram", "Ring footprint against memory",
                          TE_MI_MEAS_MEMORY, "bytes", TE_ARRAY_LEN(alabels),
                          alabels, avals, TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Known-bad control: a region half the size of a library");
    {
        tapi_memmap_region small;
        tapi_memmap_usage  usage;

        memset(&small, 0, sizeof(small));
        small.base = 0;
        small.size = (uint64_t)footprint[0] / 2;
        small.name = "half";
        if (small.size == 0)
            TEST_VERDICT("The first ring library has no PT_LOAD memory");
        CHECK_RC(tapi_memmap_ram_usage(&images[0], &small, 1,
                                       TAPI_MEMMAP_BY_VADDR, &usage));
        TEST_ARTIFACT("control: %s in %" PRIu64 " bytes: %s, overflow %"
                      PRIu64, labels[0], small.size,
                      usage.fits ? "fits" : "overflows", usage.overflow);
        if (usage.fits || usage.overflow == 0)
        {
            tapi_memmap_usage_free(&usage);
            TEST_VERDICT("The RAM budget calculation missed an overflow");
        }
        tapi_memmap_usage_free(&usage);
    }

    TEST_STEP("Decide over the budget findings");
    TSAPI_MDE_REPORT_GATE(&report, "memmap", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < RAM_MAX_LIBS; i++)
    {
        if (image_up[i])
            tapi_memmap_image_free(&images[i]);
    }
    if (session_up)
        tsapi_mde_dut_free(&dut);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

/** @file
 * @brief bench Group
 *
 * There is no flash programmer here, so use flashrom's emulated @c dummy
 * programmer, which keeps the "chip" in a file. An image is built from
 * the ring's own shared libraries, written through tsf-flash, read back
 * and verified by SHA-256 (deep round trip); the chip is erased and
 * checked all-0xFF; and, as a control, the backing file is corrupted
 * between write and verify so the verify must fail.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "bench/flash_emulated"

#include "te_config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_flash.h"
#include "tapi_flash_rom.h"
#include "tapi_kernel_issue.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/*
 * W25Q128FV: 128 Mbit = 16 MiB. Debian's flashrom emulates it with the
 * dummy programmer (MX25L6436 is not in its emulation list).
 */
#define CHIP_NAME       "W25Q128FV"
#define CHIP_SIZE       (16 * 1024 * 1024)
#define BACKING_FILE    "/tmp/mde-flash.bin"
#define IMAGE_FILE      "/tmp/mde-flash-image.bin"
#define READBACK_FILE   "/tmp/mde-flash-readback.bin"

/* Context for the verify read-back callback. */
typedef struct rom_ctx {
    tapi_job_factory_t   *factory;
    const tapi_flash_rom *rom;
} rom_ctx;

/* Read the whole emulated chip into @p dest for tapi_flash_verify. */
static te_errno
rom_read_region(void *ctx, const char *dest, uint64_t size)
{
    rom_ctx          *c = ctx;
    tapi_flash_result result;
    te_errno          rc;

    (void)size;
    tapi_flash_result_init(&result);
    rc = tapi_flash_rom_read(c->factory, c->rom, dest, &result);
    if (rc == 0 && !result.ok)
        rc = TE_RC(TE_TAPI, TE_EFAIL);
    tapi_flash_result_free(&result);

    return rc;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tapi_flash_tools    tools;
    tapi_flash_rom      rom = tapi_flash_rom_default;
    tapi_flash_image    image;
    bool                image_up = false;
    tapi_kernel_issues  issues;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    te_string           programmer = TE_STRING_INIT;
    rom_ctx             ctx;
    tapi_flash_result   wr;
    bool                matched = false;
    bool                detected = false;
    te_mi_logger       *logger = NULL;
    double              t0;
    double              write_s;
    double              read_s;
    double              verify_s;

    TEST_START;

    tapi_kernel_issues_init(&issues);
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "bench_flash", dut, session_up);

    TEST_STEP("Skip unless flashrom is installed");
    CHECK_RC(tapi_flash_tools_probe(session.factory, &tools));
    if (!tools.flashrom)
        TEST_SKIP("flashrom is not installed on the agent");

    te_string_append(&programmer, "dummy:emulate=%s,image=%s", CHIP_NAME,
                     BACKING_FILE);
    rom.programmer = programmer.ptr;

    TEST_STEP("Skip unless this flashrom build knows the emulated chip");
    (void)tsapi_mde_sh(&session, 10000, &res, "rm -f '%s'", BACKING_FILE);
    tsapi_mde_sh_result_free(&res);
    {
        te_string found = TE_STRING_INIT;

        CHECK_RC(tapi_flash_rom_probe(session.factory, &rom, &found,
                                      &detected));
        RING("flashrom probe:\n%s", found.ptr != NULL ? found.ptr : "");
        te_string_free(&found);
    }
    if (!detected)
        TEST_SKIP("This flashrom build does not support the emulated chip "
                  "%s with the dummy programmer", CHIP_NAME);
    TEST_ARTIFACT("flashrom: the dummy programmer emulates %s (%d bytes)",
                  CHIP_NAME, CHIP_SIZE);

    TEST_STEP("Build an image from the ring's libraries, padded to the chip");
    CHECK_RC(tsapi_mde_sh(&session, 60000, &res,
        "set -e; tmp=$(mktemp); "
        "for f in '%s'/*.%s; do [ -e \"$f\" ] && cat \"$f\" >> \"$tmp\"; "
        "done; "
        "head -c %d /dev/zero | tr '\\0' '\\377' > '%s'; "
        "dd if=\"$tmp\" of='%s' conv=notrunc bs=65536 2>/dev/null; "
        "truncate -s %d '%s'; rm -f \"$tmp\"; stat -c %%s '%s'",
        dut.lib, dut.dylib_ext, CHIP_SIZE, IMAGE_FILE, IMAGE_FILE,
        CHIP_SIZE, IMAGE_FILE, IMAGE_FILE));
    if (!tsapi_mde_sh_ok(&res))
        TEST_FAIL("Could not build the flash image: %s",
                  te_string_value(&res.err));

    CHECK_RC(tapi_flash_image_init(session.factory, IMAGE_FILE, "bin",
                                   &image));
    image_up = true;
    if (image.size != (uint64_t)CHIP_SIZE)
        TEST_VERDICT("The built image is not the chip size");
    TEST_ARTIFACT("flash image: %s, %" PRIu64 " bytes, sha256 %s", IMAGE_FILE,
                  image.size, image.digest);

    TEST_STEP("Write the image, then read it back and verify the SHA-256");
    ctx.factory = session.factory;
    ctx.rom = &rom;
    rom.no_verify = true;   /* we verify ourselves, by hash */

    tapi_flash_result_init(&wr);
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_flash_rom_write(session.factory, &rom, &image, &wr));
    write_s = tsapi_mde_now() - t0;
    if (!wr.ok)
    {
        tapi_flash_result_free(&wr);
        TEST_VERDICT("flashrom could not write the emulated chip");
    }
    tapi_flash_result_free(&wr);

    t0 = tsapi_mde_now();
    CHECK_RC(tapi_flash_verify(session.factory, &image, READBACK_FILE,
                               rom_read_region, &ctx, &issues, &matched));
    verify_s = tsapi_mde_now() - t0;
    if (!matched || tapi_kernel_issues_count(&issues) > 0)
        TEST_VERDICT("The emulated chip does not hold what was written");
    TEST_ARTIFACT("flash: write and read-back SHA-256 match (%s)",
                  image.digest);

    /* Time a bare read for the chart. */
    {
        tapi_flash_result rd;

        tapi_flash_result_init(&rd);
        t0 = tsapi_mde_now();
        CHECK_RC(tapi_flash_rom_read(session.factory, &rom, READBACK_FILE,
                                     &rd));
        read_s = tsapi_mde_now() - t0;
        tapi_flash_result_free(&rd);
    }

    TEST_STEP("Erase the chip and check it reads back all 0xFF");
    {
        tapi_flash_result er;

        tapi_flash_result_init(&er);
        CHECK_RC(tapi_flash_rom_erase(session.factory, &rom, &er));
        if (!er.ok)
        {
            tapi_flash_result_free(&er);
            TEST_VERDICT("flashrom could not erase the emulated chip");
        }
        tapi_flash_result_free(&er);

        CHECK_RC(tapi_flash_rom_read(session.factory, &rom, READBACK_FILE,
                                     &er));
        (void)tsapi_mde_sh(&session, 30000, &res,
            "head -c %d /dev/zero | tr '\\0' '\\377' | cmp - '%s' && echo FF",
            CHIP_SIZE, READBACK_FILE);
        if (!tsapi_mde_sh_ok(&res) ||
            strstr(te_string_value(&res.out), "FF") == NULL)
        {
            TEST_VERDICT("The erased chip is not all 0xFF");
        }
        tapi_flash_result_free(&er);
    }
    TEST_ARTIFACT("flash: after erase the chip reads back all 0xFF");

    TEST_STEP("Control: corrupt the backing file so a verify must fail");
    {
        tapi_flash_result wr2;
        bool              matched2 = true;

        tapi_flash_result_init(&wr2);
        CHECK_RC(tapi_flash_rom_write(session.factory, &rom, &image, &wr2));
        tapi_flash_result_free(&wr2);
        /* Flip one byte of the emulated chip behind flashrom's back. */
        CHECK_RC(tsapi_mde_sh(&session, 20000, &res,
            "printf '\\x00' | dd of='%s' bs=1 seek=1024 count=1 "
            "conv=notrunc 2>/dev/null && echo DONE", BACKING_FILE));
        if (!tsapi_mde_sh_ok(&res))
            TEST_FAIL("Could not corrupt the backing file");
        CHECK_RC(tapi_flash_verify(session.factory, &image, READBACK_FILE,
                                   rom_read_region, &ctx, &issues,
                                   &matched2));
        if (matched2)
            TEST_VERDICT("A verify of a corrupted chip still matched");
    }
    /* The control planted a flash.verify issue; drop it before the gate. */
    {
        size_t i;

        for (i = tapi_kernel_issues_count(&issues); i-- > 0; )
        {
            tapi_kernel_issue *k = te_vec_get(&issues.items, i);

            /* The issue list owns its strings: removal frees them. */
            if (strcmp(k->check, "flash.verify") == 0)
                te_vec_remove_index(&issues.items, i);
        }
    }
    TEST_ARTIFACT("flash control: a one-byte corruption of the backing file "
                  "made the SHA-256 verify fail, as it must");

    CHECK_RC(tsapi_mde_mi_create("tapi_flash", &logger));
    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "write_s",
                          TE_MI_MEAS_AGGR_SINGLE, write_s,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "read_s",
                          TE_MI_MEAS_AGGR_SINGLE, read_s,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "verify_s",
                          TE_MI_MEAS_AGGR_SINGLE, verify_s,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_MEMORY, "image_bytes",
                          TE_MI_MEAS_AGGR_SINGLE, (double)image.size,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    /*
     * Several single values: a line graph over the sequence
     * number draws each as a point (a point view takes one).
     */
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               "flash", "Flash write / read / verify time and size");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                          TE_MI_MEAS_VIEW_LINE_GRAPH,
                                          "flash", TE_MI_GRAPH_AXIS_X,
                                          TE_MI_GRAPH_AUTO_SEQNO);
    te_mi_logger_destroy(logger);
    logger = NULL;

    TEST_STEP("The emulated run is done; raw MTD needs kernel modules "
              "this container lacks");
    TEST_ARTIFACT("flash: tapi_flash MTD over mtdram/nandsim is not "
                  "attempted - loading kernel modules is not possible in "
                  "this container");

    if (tapi_kernel_issues_count(&issues) > 0)
    {
        te_string verdict = TE_STRING_INIT;

        tapi_kernel_issues_verdict(&issues, &verdict);
        ERROR_VERDICT("%s", verdict.ptr);
        te_string_free(&verdict);
        TEST_STOP;
    }

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    if (image_up)
        tapi_flash_image_free(&image);
    if (session_up)
    {
        (void)tsapi_mde_sh(&session, 20000, &res, "rm -f '%s' '%s' '%s'",
                           BACKING_FILE, IMAGE_FILE, READBACK_FILE);
    }
    tsapi_mde_sh_result_free(&res);
    te_string_free(&programmer);
    tapi_kernel_issues_free(&issues);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

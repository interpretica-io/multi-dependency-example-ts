/** @file
 * @brief Emulator Group
 *
 * Boot the group's tiny multiboot guest with -kernel and wait for the
 * line it writes without any operating system: "MDE-OK" on COM1, COM2
 * and the debug console. COM1 is the module's console (QEMU's stdio),
 * which tapi_emu only drains when the machine stops; COM2 and the debug
 * console go to files on the agent and are read while the guest runs.
 * The two files must hold exactly the line, and the guest must still be
 * alive afterwards (its counter moves, ECX and memory agree).
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "emu/serial_console"

#include "te_config.h"
#include "tapi_test.h"
#include "emu_common.h"

/** How long the guest gets to print under TCG, ms. */
#define SERIAL_WAIT_MS  60000
/** How often the files are read, ms. */
#define SERIAL_POLL_MS  250

int
main(int argc, char **argv)
{
    const char         *machine;
    tsapi_mde_session   session;
    bool                session_up = false;
    tapi_emu_opt        opt;
    tapi_emu_vm        *vm = NULL;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string           elf = TE_STRING_INIT;
    te_string           com2 = TE_STRING_INIT;
    te_string           dbg = TE_STRING_INIT;
    te_string           com2_arg = TE_STRING_INIT;
    te_string           dbg_arg = TE_STRING_INIT;
    te_string           dbg_text = TE_STRING_INIT;
    te_string           com2_text = TE_STRING_INIT;
    te_string           console = TE_STRING_INIT;
    const char         *extra[4];
    uint32_t            ecx1 = 0;
    uint32_t            ecx2 = 0;
    uint32_t            mem2 = 0;
    bool                seen = false;
    int                 waited;
    double              t0;
    double              t_boot = 0.0;
    double              t_line = 0.0;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_STRING_PARAM(machine);

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "emu_serial"));
    session_up = true;
    if (!tapi_emu_available(session.factory, NULL, MDE_EMU_TIMEOUT_MS))
        TEST_SKIP("qemu-system-x86_64 is not available on the agent");
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("QMP needs python3 on the agent");

    TEST_STEP("Assemble and link the guest");
    if (mde_emu_build_kernel(&session, &elf) != 0)
        TEST_SKIP("Cannot build a 32-bit multiboot guest on the agent");

    te_string_append(&com2, MDE_EMU_DIR "/com2-%s.log", machine);
    te_string_append(&dbg, MDE_EMU_DIR "/debugcon-%s.log", machine);
    te_string_append(&com2_arg, "file:%s", com2.ptr);
    te_string_append(&dbg_arg, "file:%s", dbg.ptr);
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh, "rm -f '%s' '%s'", com2.ptr,
                          dbg.ptr));

    TEST_STEP("Boot it with COM2 and the debug console going to files");
    mde_emu_opt_init(&opt, machine);
    opt.kernel = elf.ptr;
    extra[0] = "-serial";
    extra[1] = com2_arg.ptr;
    extra[2] = "-debugcon";
    extra[3] = dbg_arg.ptr;
    opt.extra_args = extra;
    opt.n_extra_args = TE_ARRAY_LEN(extra);
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_emu_start(session.factory, &opt, MDE_EMU_START_TIMEOUT_MS,
                            &vm));
    t_boot = tsapi_mde_now() - t0;

    TEST_STEP("Wait for the line on the debug console");
    for (waited = 0; waited < SERIAL_WAIT_MS; waited += SERIAL_POLL_MS)
    {
        CHECK_RC(tsapi_mde_sh(&session, 10000, &sh, "cat '%s' 2>/dev/null",
                              dbg.ptr));
        if (strstr(te_string_value(&sh.out), MDE_EMU_LINE) != NULL)
        {
            seen = true;
            break;
        }
        te_msleep(SERIAL_POLL_MS);
    }
    t_line = tsapi_mde_now() - t0;
    if (!seen)
        TEST_VERDICT("The guest did not write MDE-OK to its ports");
    te_string_append(&dbg_text, "%s", te_string_value(&sh.out));
    TEST_ARTIFACT("machine %s: QMP after %.3f s, MDE-OK after %.3f s",
                  machine, t_boot, t_line);

    TEST_STEP("COM2 and the debug console hold exactly the line");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh, "cat '%s' 2>/dev/null",
                          com2.ptr));
    te_string_append(&com2_text, "%s", te_string_value(&sh.out));
    RING("COM2: '%s'\ndebugcon: '%s'", te_string_value(&com2_text),
         te_string_value(&dbg_text));
    if (strcmp(te_string_value(&dbg_text), MDE_EMU_LINE) != 0)
        TEST_VERDICT("The debug console holds more or less than the line");
    if (strcmp(te_string_value(&com2_text), te_string_value(&dbg_text)) != 0)
        TEST_VERDICT("COM2 and the debug console disagree");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &sh, "sha256sum '%s' '%s'",
                          com2.ptr, dbg.ptr));
    TEST_ARTIFACT("serial evidence:\n%s", te_string_value(&sh.out));

    TEST_STEP("What the module's own console holds while the guest runs");
    CHECK_RC(tapi_emu_console(vm, &console));
    TEST_ARTIFACT("tapi_emu_console() while running: %zu bytes%s",
                  console.len,
                  strstr(te_string_value(&console), "MDE-OK") != NULL ?
                      ", carries the line" :
                      " (COM1 is drained when the machine stops)");

    TEST_STEP("The guest is alive after printing: its counter moves");
    CHECK_RC(tapi_emu_pause(vm, MDE_EMU_TIMEOUT_MS));
    CHECK_RC(mde_emu_reg(vm, "ECX", &ecx1));
    CHECK_RC(tapi_emu_resume(vm, MDE_EMU_TIMEOUT_MS));
    te_msleep(500);
    CHECK_RC(tapi_emu_pause(vm, MDE_EMU_TIMEOUT_MS));
    CHECK_RC(mde_emu_reg(vm, "ECX", &ecx2));
    CHECK_RC(mde_emu_word(vm, MDE_EMU_COUNTER_ADDR, &mem2));
    TEST_ARTIFACT("counter: ECX %" PRIu32 " -> %" PRIu32 ", memory %" PRIu32,
                  ecx1, ecx2, mem2);
    if (ecx2 <= ecx1)
        TEST_VERDICT("The guest stopped counting after it printed");
    if (ecx2 - mem2 > 1)
        TEST_VERDICT("ECX and the counter in memory disagree");

    TEST_STEP("Chart the timings and the counter");
    {
        const char *labels[] = { "qmp_up", "line_seen" };
        double      times[] = { t_boot, t_line };
        const char *clabels[] = { "ecx_before", "ecx_after", "memory" };
        double      counts[] = { ecx1, ecx2, mem2 };

        tsapi_mde_mi_bars("emu/serial_console", "Boot to serial line",
                          TE_MI_MEAS_TIME, "boot_s", TE_ARRAY_LEN(times),
                          labels, times, TE_MI_MEAS_MULTIPLIER_PLAIN);
        tsapi_mde_mi_bars("emu/serial_console", "Guest counter",
                          TE_MI_MEAS_UNITLESS_VALUE, "counter",
                          TE_ARRAY_LEN(counts), clabels, counts,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_emu_stop(vm, MDE_EMU_STOP_TIMEOUT_MS));
    if (session_up && com2.len > 0)
        (void)tsapi_mde_sh(&session, 10000, &sh, "rm -f '%s' '%s'",
                           com2.ptr, dbg.ptr);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&elf);
    te_string_free(&com2);
    te_string_free(&dbg);
    te_string_free(&com2_arg);
    te_string_free(&dbg_arg);
    te_string_free(&dbg_text);
    te_string_free(&com2_text);
    te_string_free(&console);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

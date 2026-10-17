/** @file
 * @brief Emulator Group
 *
 * Save a running machine, let it move on, and load it back. The guest is
 * the group's tiny counting kernel, so the state is visible: ECX and the
 * word at 0x500 keep growing while it runs. After loadvm both must be
 * exactly what they were at savevm - two views of one restored state.
 * The snapshot must also be listed both by the monitor and by qemu-img
 * reading the qcow2 file, and loading a name that was never saved must
 * be refused (known-bad control).
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "emu/snapshot"

#include "te_config.h"
#include "tapi_test.h"
#include "emu_common.h"

/** The disk that holds the snapshots. */
#define SNAP_DISK       MDE_EMU_DIR "/snap.qcow2"
/** Snapshot name. */
#define SNAP_NAME       "mde-snap"
/** Most cycles charted. */
#define SNAP_MAX_CYCLES 8

/** Whether both the monitor and qemu-img list the snapshot. */
static void
snap_listed(tapi_emu_vm *vm, tsapi_mde_session *session, bool *in_hmp,
            bool *in_img)
{
    te_string           text = TE_STRING_INIT;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;

    *in_hmp = tapi_emu_hmp(vm, "info snapshots", MDE_EMU_TIMEOUT_MS,
                           &text) == 0 &&
              strstr(te_string_value(&text), SNAP_NAME) != NULL;
    /* -U: QEMU holds the image open; read it without the lock. */
    *in_img = tsapi_mde_sh(session, MDE_EMU_TIMEOUT_MS, &sh,
                           "qemu-img snapshot -U -l " SNAP_DISK) == 0 &&
              tsapi_mde_sh_ok(&sh) &&
              strstr(te_string_value(&sh.out), SNAP_NAME) != NULL;
    RING("info snapshots:\n%s\nqemu-img:\n%s", te_string_value(&text),
         te_string_value(&sh.out));
    te_string_free(&text);
    tsapi_mde_sh_result_free(&sh);
}

int
main(int argc, char **argv)
{
    int                 cycles;
    tsapi_mde_session   session;
    bool                session_up = false;
    tapi_emu_opt        opt;
    tapi_emu_vm        *vm = NULL;
    const char         *drives[] = {
        "file=" SNAP_DISK ",format=qcow2,if=virtio",
    };
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string           elf = TE_STRING_INIT;
    double              t_save[SNAP_MAX_CYCLES] = { 0 };
    double              t_load[SNAP_MAX_CYCLES] = { 0 };
    double              c_saved[SNAP_MAX_CYCLES] = { 0 };
    double              c_moved[SNAP_MAX_CYCLES] = { 0 };
    double              c_restored[SNAP_MAX_CYCLES] = { 0 };
    uint32_t            ecx_s = 0;
    uint32_t            mem_s = 0;
    uint32_t            ecx_t = 0;
    uint32_t            ecx_r = 0;
    uint32_t            mem_r = 0;
    bool                in_hmp;
    bool                in_img;
    int                 i;
    int                 waited;
    double              t0;
    double              t_del;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(cycles);
    if (cycles > SNAP_MAX_CYCLES)
        cycles = SNAP_MAX_CYCLES;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "emu_snap"));
    session_up = true;
    if (!tapi_emu_available(session.factory, NULL, MDE_EMU_TIMEOUT_MS))
        TEST_SKIP("qemu-system-x86_64 is not available on the agent");
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("QMP needs python3 on the agent");
    if (!tsapi_mde_have(&session, "qemu-img"))
        TEST_SKIP("qemu-img is needed for a qcow2 disk to hold snapshots");

    TEST_STEP("Build the counting guest and a 16M qcow2 disk");
    if (mde_emu_build_kernel(&session, &elf) != 0)
        TEST_SKIP("Cannot build a 32-bit multiboot guest on the agent");
    CHECK_RC(tsapi_mde_sh(&session, MDE_EMU_TIMEOUT_MS, &sh,
                          "rm -f " SNAP_DISK "; qemu-img create -q -f qcow2 "
                          SNAP_DISK " 16M"));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_VERDICT("qemu-img cannot create the qcow2 disk");

    TEST_STEP("Start the machine and wait for the guest to count");
    mde_emu_opt_init(&opt, "pc");
    opt.kernel = elf.ptr;
    opt.drives = drives;
    opt.n_drives = TE_ARRAY_LEN(drives);
    CHECK_RC(tapi_emu_start(session.factory, &opt, MDE_EMU_START_TIMEOUT_MS,
                            &vm));
    for (waited = 0; waited < 60000; waited += 500)
    {
        if (mde_emu_word(vm, MDE_EMU_COUNTER_ADDR, &mem_s) == 0 &&
            mem_s > 0)
            break;
        te_msleep(500);
    }
    if (mem_s == 0)
        TEST_VERDICT("The guest never started counting");

    for (i = 0; i < cycles; i++)
    {
        TEST_STEP("Cycle %d: stop, read the state, savevm", i + 1);
        CHECK_RC(tapi_emu_pause(vm, MDE_EMU_TIMEOUT_MS));
        CHECK_RC(mde_emu_reg(vm, "ECX", &ecx_s));
        CHECK_RC(mde_emu_word(vm, MDE_EMU_COUNTER_ADDR, &mem_s));
        if (ecx_s - mem_s > 1)
            TEST_VERDICT("ECX and the counter in memory disagree");

        t0 = tsapi_mde_now();
        rc = tapi_emu_snapshot_save(vm, SNAP_NAME, MDE_EMU_TIMEOUT_MS);
        if (rc != 0)
            TEST_VERDICT("savevm was refused on a qcow2 disk");
        t_save[i] = tsapi_mde_now() - t0;
        snap_listed(vm, &session, &in_hmp, &in_img);
        if (!in_hmp || !in_img)
            TEST_VERDICT("The saved snapshot is not listed by %s",
                         !in_hmp ? "the monitor" : "qemu-img");

        TEST_STEP("Cycle %d: let the guest run on", i + 1);
        CHECK_RC(tapi_emu_resume(vm, MDE_EMU_TIMEOUT_MS));
        te_msleep(1000);
        CHECK_RC(tapi_emu_pause(vm, MDE_EMU_TIMEOUT_MS));
        CHECK_RC(mde_emu_reg(vm, "ECX", &ecx_t));
        if (ecx_t == ecx_s)
            TEST_VERDICT("The guest did not move after cont");

        TEST_STEP("Cycle %d: loadvm and compare with what was saved", i + 1);
        t0 = tsapi_mde_now();
        CHECK_RC(tapi_emu_snapshot_load(vm, SNAP_NAME, MDE_EMU_TIMEOUT_MS));
        t_load[i] = tsapi_mde_now() - t0;
        CHECK_RC(mde_emu_reg(vm, "ECX", &ecx_r));
        CHECK_RC(mde_emu_word(vm, MDE_EMU_COUNTER_ADDR, &mem_r));
        TEST_ARTIFACT("cycle %d: saved ECX=%" PRIu32 " mem=%" PRIu32
                      ", moved to ECX=%" PRIu32 ", restored ECX=%" PRIu32
                      " mem=%" PRIu32 "; savevm %.3f s, loadvm %.3f s",
                      i + 1, ecx_s, mem_s, ecx_t, ecx_r, mem_r, t_save[i],
                      t_load[i]);
        c_saved[i] = ecx_s;
        c_moved[i] = ecx_t;
        c_restored[i] = ecx_r;
        if (ecx_r != ecx_s)
            TEST_VERDICT("loadvm did not restore the CPU register");
        if (mem_r != mem_s)
            TEST_VERDICT("loadvm did not restore guest memory");

        CHECK_RC(tapi_emu_resume(vm, MDE_EMU_TIMEOUT_MS));
        te_msleep(200);
    }

    TEST_STEP("Known-bad control: loading a snapshot never saved is refused");
    CHECK_RC(tapi_emu_pause(vm, MDE_EMU_TIMEOUT_MS));
    if (tapi_emu_snapshot_load(vm, "mde-never-saved",
                               MDE_EMU_TIMEOUT_MS) == 0)
        TEST_VERDICT("loadvm of a snapshot that does not exist succeeded");

    TEST_STEP("Delete the snapshot; neither view lists it any more");
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_emu_snapshot_delete(vm, SNAP_NAME, MDE_EMU_TIMEOUT_MS));
    t_del = tsapi_mde_now() - t0;
    snap_listed(vm, &session, &in_hmp, &in_img);
    if (in_hmp || in_img)
        TEST_VERDICT("A deleted snapshot is still listed");

    TEST_STEP("Chart snapshot times and the counter");
    tsapi_mde_mi_series("emu/snapshot", "savevm time per cycle",
                        TE_MI_MEAS_TIME, "savevm_s", (size_t)cycles, t_save,
                        TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_series("emu/snapshot", "loadvm time per cycle",
                        TE_MI_MEAS_TIME, "loadvm_s", (size_t)cycles, t_load,
                        TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("emu/snapshot", "delvm time", TE_MI_MEAS_TIME,
                       "delvm_s", t_del, TE_MI_MEAS_MULTIPLIER_PLAIN);
    {
        te_mi_logger *logger;

        if (tsapi_mde_mi_create("emu/snapshot", &logger) == 0)
        {
            for (i = 0; i < cycles; i++)
            {
                te_mi_logger_add_meas(logger, NULL,
                                      TE_MI_MEAS_UNITLESS_VALUE, "saved",
                                      TE_MI_MEAS_AGGR_SINGLE, c_saved[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(logger, NULL,
                                      TE_MI_MEAS_UNITLESS_VALUE, "moved",
                                      TE_MI_MEAS_AGGR_SINGLE, c_moved[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(logger, NULL,
                                      TE_MI_MEAS_UNITLESS_VALUE, "restored",
                                      TE_MI_MEAS_AGGR_SINGLE, c_restored[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
            }
            tsapi_mde_mi_line(logger, "counter",
                              "Guest counter: saved, moved on, restored",
                              TE_MI_GRAPH_AUTO_SEQNO, "saved", "moved",
                              "restored", NULL);
            te_mi_logger_destroy(logger);
        }
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_emu_stop(vm, MDE_EMU_STOP_TIMEOUT_MS));
    if (session_up)
        (void)tsapi_mde_sh(&session, MDE_EMU_TIMEOUT_MS, &sh,
                           "rm -f " SNAP_DISK);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&elf);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

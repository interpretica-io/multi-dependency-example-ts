/** @file
 * @brief Emulator Group
 *
 * Emulator group prologue: is there a QEMU and the python3 its QMP helper
 * needs, which versions, and is there KVM (there is not in the build
 * container, so the group runs TCG). Skips the group without QEMU.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "emu/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "emu_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    bool                kvm;
    bool                qemu_img;
    double              t0;
    double              t_probe;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "emu_prologue"));
    session_up = true;

    TEST_STEP("Check that QEMU and python3 are there");
    t0 = tsapi_mde_now();
    if (!tapi_emu_available(session.factory, NULL, MDE_EMU_TIMEOUT_MS))
        TEST_SKIP("qemu-system-x86_64 is not available on the agent");
    t_probe = tsapi_mde_now() - t0;
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("QMP needs python3 on the agent");
    tsapi_mde_mi_point("emu/prologue", "qemu --version answer time",
                       TE_MI_MEAS_TIME, "probe_s", t_probe,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Record versions and acceleration");
    CHECK_RC(tsapi_mde_sh(&session, MDE_EMU_TIMEOUT_MS, &sh,
                          "qemu-system-x86_64 --version | head -n 1"));
    TEST_ARTIFACT("qemu: %s", te_string_value(&sh.out));

    qemu_img = tsapi_mde_have(&session, "qemu-img");
    if (qemu_img)
    {
        CHECK_RC(tsapi_mde_sh(&session, MDE_EMU_TIMEOUT_MS, &sh,
                              "qemu-img --version | head -n 1"));
        TEST_ARTIFACT("qemu-img: %s", te_string_value(&sh.out));
    }
    else
    {
        TEST_ARTIFACT("qemu-img: absent (emu/snapshot will skip)");
    }

    kvm = tsapi_mde_exists(&session, "/dev/kvm");
    TEST_ARTIFACT("/dev/kvm: %s; the group runs %s", kvm ? "present" :
                  "absent", "TCG (accel=tcg)");
    tsapi_mde_mi_point("emu/prologue", "KVM present (1/0)",
                       TE_MI_MEAS_UNITLESS_VALUE, "kvm", kvm ? 1 : 0,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    CHECK_RC(tsapi_mde_sh(&session, MDE_EMU_TIMEOUT_MS, &sh,
                          "mkdir -p " MDE_EMU_DIR));

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

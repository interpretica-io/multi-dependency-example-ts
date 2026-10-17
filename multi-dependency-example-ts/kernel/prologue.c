/** @file
 * @brief Kernel Group
 *
 * kernel group prologue: record which kernel the example runs on and a
 * summary of its hardening posture, so that every run of the group
 * carries it.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "kernel/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_kernel.h"
#include "tapi_kernel_security.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session            session;
    bool                         session_up = false;
    tapi_kernel_security_posture posture;
    bool                         posture_up = false;
    te_string                    release = TE_STRING_INIT;
    te_string                    taint = TE_STRING_INIT;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "kprologue"));
    session_up = true;

    TEST_STEP("Record the kernel release");
    CHECK_RC(tapi_kernel_release(session.ta, &release));
    TEST_ARTIFACT("kernel release: %s", release.ptr);

    TEST_STEP("Record a summary of the hardening posture");
    rc = tapi_kernel_security_posture_get(session.factory, &posture);
    if (rc != 0)
    {
        RING("The posture could not be taken: %r", rc);
    }
    else
    {
        posture_up = true;
        tapi_kernel_security_posture_log(&posture);
        tapi_kernel_security_taint2str(posture.taint, &taint);
        TEST_ARTIFACT("posture: lockdown %s, lsm %s, aslr %d, taint %s",
                      tapi_kernel_lockdown2str(posture.lockdown),
                      posture.lsm != NULL ? posture.lsm : "(unknown)",
                      posture.randomize_va_space, taint.ptr);
        tsapi_mde_mi_point("kernel/prologue", "Address space randomization",
                           TE_MI_MEAS_UNITLESS_VALUE, "randomize_va_space",
                           posture.randomize_va_space ==
                               TAPI_KERNEL_SYSCTL_ABSENT ?
                               -1 : posture.randomize_va_space,
                           TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_SUCCESS;

cleanup:

    if (posture_up)
        tapi_kernel_security_posture_free(&posture);
    te_string_free(&release);
    te_string_free(&taint);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

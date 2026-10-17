/** @file
 * @brief Emulator Group
 *
 * Drive a QEMU machine with no disk through its run states over QMP and
 * check every transition three ways: tapi_emu_state_get(), the raw
 * query-status reply, and the human monitor's "info status". A reset is
 * checked by where the CPU stands afterwards (the x86 reset vector), the
 * QEMU version by QMP against the binary's --version, and a screendump by
 * its PPM header against its size.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "emu/qmp_lifecycle"

#include "te_config.h"
#include "tapi_test.h"
#include "emu_common.h"

/** Where the screen goes. */
#define QMP_SCREEN      "/tmp/mde-emu-screen.ppm"
/** Most timed commands kept for the chart. */
#define QMP_MAX_TIMES   64

/** What the module calls a stopped machine that never ran or was reset. */
static bool
qmp_is_stopped(tapi_emu_state state)
{
    return state == TAPI_EMU_PAUSED || state == TAPI_EMU_PRELAUNCH;
}

/**
 * Check the three views of the run state agree and match what was
 * expected; stop the test with a stable verdict otherwise.
 *
 * @return @c true on agreement.
 */
static bool
qmp_check_state(tapi_emu_vm *vm, const char *step, bool want_running)
{
    tapi_emu_state state = TAPI_EMU_GONE;
    te_string      status = TE_STRING_INIT;
    te_string      hmp = TE_STRING_INIT;
    bool           running = false;
    bool           ok;

    if (mde_emu_views(vm, &state, &status, &running, &hmp) != 0)
    {
        ERROR_VERDICT("Cannot read the run state after %s", step);
        ok = false;
    }
    else
    {
        bool mod_running = (state == TAPI_EMU_RUNNING);
        bool hmp_running = strstr(te_string_value(&hmp), "running") != NULL;

        RING("After %s: module %s, query-status %s/%s, HMP '%s'", step,
             tapi_emu_state2str(state), te_string_value(&status),
             running ? "running" : "not running", te_string_value(&hmp));
        TEST_ARTIFACT("state after %s: %s", step, tapi_emu_state2str(state));

        ok = true;
        if (mod_running != running || hmp_running != running ||
            (!running && !qmp_is_stopped(state)))
        {
            ERROR_VERDICT("The three views of the run state disagree after "
                          "%s", step);
            ok = false;
        }
        else if (running != want_running)
        {
            ERROR_VERDICT("The machine is %s after %s",
                          running ? "running" : "stopped", step);
            ok = false;
        }
    }

    te_string_free(&status);
    te_string_free(&hmp);

    return ok;
}

/** Parse "major.minor.micro" after a marker. */
static bool
qmp_version_after(const char *text, const char *marker, int *maj, int *min,
                  int *mic)
{
    const char *p = strstr(text, marker);

    if (p == NULL)
        return false;
    return sscanf(p + strlen(marker), "%d.%d.%d", maj, min, mic) == 3;
}

/** Read an integer field from a QMP reply. */
static bool
qmp_int_field(const char *reply, const char *key, int *value)
{
    char        pattern[32];
    const char *p;

    TE_SPRINTF(pattern, "\"%s\":", key);
    p = strstr(reply, pattern);
    if (p == NULL)
        return false;
    *value = atoi(p + strlen(pattern));
    return true;
}

int
main(int argc, char **argv)
{
    const char         *machine;
    int                 cycles;
    tsapi_mde_session   session;
    bool                session_up = false;
    tapi_emu_opt        opt;
    tapi_emu_vm        *vm = NULL;
    const char         *devices[] = { "VGA" };
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string           reply = TE_STRING_INIT;
    const char         *labels[QMP_MAX_TIMES] = { NULL };
    double              times[QMP_MAX_TIMES] = { 0 };
    unsigned int        n_times = 0;
    uint32_t            eip = 0;
    int                 q_maj = 0, q_min = 0, q_mic = 0;
    int                 b_maj = 0, b_min = 0, b_mic = 0;
    int                 i;
    int                 waited;
    double              t0;
    double              t_start;

#define QMP_TIMED(_label, _expr) \
    do {                                                        \
        double t_ = tsapi_mde_now();                            \
                                                                \
        CHECK_RC(_expr);                                        \
        if (n_times < QMP_MAX_TIMES)                            \
        {                                                       \
            labels[n_times] = (_label);                         \
            times[n_times++] = tsapi_mde_now() - t_;            \
        }                                                       \
    } while (0)

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_STRING_PARAM(machine);
    TEST_GET_INT_PARAM(cycles);

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "emu_qmp"));
    session_up = true;
    if (!tapi_emu_available(session.factory, NULL, MDE_EMU_TIMEOUT_MS))
        TEST_SKIP("qemu-system-x86_64 is not available on the agent");
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("QMP needs python3 on the agent");

    TEST_STEP("Start a machine with no disk, stopped (-S)");
    mde_emu_opt_init(&opt, machine);
    opt.paused = true;
    opt.devices = devices;
    opt.n_devices = TE_ARRAY_LEN(devices);
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_emu_start(session.factory, &opt, MDE_EMU_START_TIMEOUT_MS,
                            &vm));
    t_start = tsapi_mde_now() - t0;
    TEST_ARTIFACT("machine %s up in %.3f s, QMP on %s", machine, t_start,
                  tapi_emu_qmp_socket(vm));
    tsapi_mde_mi_point("emu/qmp_lifecycle", "Time until QMP answers",
                       TE_MI_MEAS_TIME, "start_s", t_start,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (!qmp_check_state(vm, "start with -S", false))
        TEST_STOP;

    TEST_STEP("QEMU version: QMP query-version against --version");
    QMP_TIMED("query-version",
              tapi_emu_qmp(vm, "query-version", NULL, MDE_EMU_TIMEOUT_MS,
                           &reply));
    CHECK_RC(tsapi_mde_sh(&session, MDE_EMU_TIMEOUT_MS, &sh,
                          "qemu-system-x86_64 --version"));
    if (!qmp_int_field(te_string_value(&reply), "major", &q_maj) ||
        !qmp_int_field(te_string_value(&reply), "minor", &q_min) ||
        !qmp_int_field(te_string_value(&reply), "micro", &q_mic) ||
        !qmp_version_after(te_string_value(&sh.out), "version ", &b_maj,
                           &b_min, &b_mic))
        TEST_VERDICT("Cannot read the QEMU version both ways");
    TEST_ARTIFACT("QEMU %d.%d.%d (QMP), %d.%d.%d (--version)", q_maj, q_min,
                  q_mic, b_maj, b_min, b_mic);
    if (q_maj != b_maj || q_min != b_min || q_mic != b_mic)
        TEST_VERDICT("QMP and --version report different QEMU versions");

    for (i = 0; i < cycles; i++)
    {
        TEST_STEP("Cycle %d: cont -> running", i + 1);
        QMP_TIMED("cont", tapi_emu_resume(vm, MDE_EMU_TIMEOUT_MS));
        if (!qmp_check_state(vm, "cont", true))
            TEST_STOP;

        TEST_STEP("Cycle %d: stop -> paused", i + 1);
        QMP_TIMED("stop", tapi_emu_pause(vm, MDE_EMU_TIMEOUT_MS));
        if (!qmp_check_state(vm, "stop", false))
            TEST_STOP;

        TEST_STEP("Cycle %d: system_reset puts the CPU at the reset vector",
                  i + 1);
        QMP_TIMED("system_reset", tapi_emu_reset(vm, MDE_EMU_TIMEOUT_MS));
        /* The reset request is served by QEMU's main loop: poll for it. */
        for (waited = 0; waited < 5000; waited += 250)
        {
            CHECK_RC(mde_emu_reg(vm, "EIP", &eip));
            if (eip == 0xfff0)
                break;
            te_msleep(250);
        }
        TEST_ARTIFACT("EIP after reset: 0x%08" PRIx32, eip);
        if (eip != 0xfff0)
            TEST_VERDICT("The CPU is not at the reset vector after "
                         "system_reset");
        if (!qmp_check_state(vm, "system_reset", false))
            TEST_STOP;
    }

    TEST_STEP("Run again and time a query-status");
    QMP_TIMED("cont", tapi_emu_resume(vm, MDE_EMU_TIMEOUT_MS));
    te_string_reset(&reply);
    QMP_TIMED("query-status",
              tapi_emu_qmp(vm, "query-status", NULL, MDE_EMU_TIMEOUT_MS,
                           &reply));
    if (!qmp_check_state(vm, "final cont", true))
        TEST_STOP;

    TEST_STEP("Take a screendump and check it is a whole PPM image");
    (void)tsapi_mde_sh(&session, 10000, &sh, "rm -f " QMP_SCREEN);
    t0 = tsapi_mde_now();
    rc = tapi_emu_screendump(vm, QMP_SCREEN, MDE_EMU_TIMEOUT_MS);
    if (rc == 0 && n_times < QMP_MAX_TIMES)
    {
        labels[n_times] = "screendump";
        times[n_times++] = tsapi_mde_now() - t0;
    }
    if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
    {
        TEST_ARTIFACT("screendump: the machine has no console to capture");
    }
    else
    {
        unsigned int w = 0;
        unsigned int h = 0;
        unsigned long size = 0;
        unsigned long hdr = 0;

        CHECK_RC(rc);
        CHECK_RC(tsapi_mde_sh(&session, 10000, &sh,
                              "stat -c %%s " QMP_SCREEN "; "
                              "head -c 64 " QMP_SCREEN " | head -n 3 | "
                              "wc -c; head -n 2 " QMP_SCREEN " | tail -n 1; "
                              "sha256sum " QMP_SCREEN));
        RING("screendump:\n%s", te_string_value(&sh.out));
        if (sscanf(te_string_value(&sh.out), "%lu %lu %u %u", &size, &hdr,
                   &w, &h) != 4)
            TEST_VERDICT("Cannot read the screendump back");
        TEST_ARTIFACT("screendump %s: %lu bytes, %ux%u", QMP_SCREEN, size,
                      w, h);
        if (size != hdr + (unsigned long)w * h * 3)
            TEST_VERDICT("The screendump size does not match its PPM "
                         "header");
        tsapi_mde_mi_point("emu/qmp_lifecycle", "Screendump size",
                           TE_MI_MEAS_MEMORY, "screen_bytes", (double)size,
                           TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Chart the time of every QMP command");
    tsapi_mde_mi_bars("emu/qmp_lifecycle", "QMP command latency",
                      TE_MI_MEAS_TIME, "qmp_s", n_times, labels, times,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_emu_stop(vm, MDE_EMU_STOP_TIMEOUT_MS));
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&reply);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
#undef QMP_TIMED
}

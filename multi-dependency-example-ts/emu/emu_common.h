/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Emulator group helpers
 *
 * What the emu tests share: the machine options (TCG, no disk unless a
 * test adds one), reading CPU registers and guest memory through the
 * human monitor, and a tiny guest that needs no operating system.
 *
 * The guest is a 32-bit multiboot ELF assembled on the agent. QEMU loads
 * it with -kernel. It writes "MDE-OK\n" to COM1 (0x3f8), COM2 (0x2f8) and
 * the debug console (0xe9), then counts forever in ECX and stores the
 * counter at physical address 0x500. That gives the tests a line to wait
 * for and a state that visibly moves, so a snapshot restore and a live
 * guest can both be checked through the monitor.
 *
 * Everything here is static inline: each test is built from one C file
 * and an unused static function would break the -Werror build.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_EMU_COMMON_H__
#define __MDE_EMU_COMMON_H__

#include "te_config.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"
#include "tapi_file.h"
#include "tapi_cc.h"
#include "tapi_binscan.h"
#include "tapi_emu.h"
#include "tapi_emu_qmp.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"

/** One QMP or HMP command. */
#define MDE_EMU_TIMEOUT_MS          30000
/** Bringing a machine up under TCG. */
#define MDE_EMU_START_TIMEOUT_MS    120000
/** How long tapi_emu_stop() waits for a guest that has no ACPI. */
#define MDE_EMU_STOP_TIMEOUT_MS     3000
/** Scratch directory on the agent. */
#define MDE_EMU_DIR                 "/tmp/mde-emu"
/** Physical address the guest stores its counter at. */
#define MDE_EMU_COUNTER_ADDR        "0x500"
/** What the guest prints. */
#define MDE_EMU_LINE                "MDE-OK\n"

/**
 * The guest: multiboot header, the line on three ports, a counter.
 *
 * @return The assembly source.
 */
static inline const char *
mde_emu_kernel_src(void)
{
    return
    "    .text\n"
    "    .code32\n"
    "    .globl _start\n"
    "    .align 4\n"
    "mb_header:\n"
    "    .long 0x1BADB002\n"
    "    .long 0x00000000\n"
    "    .long 0xE4524FFE\n"
    "_start:\n"
    "    cli\n"
    "    movl $msg, %esi\n"
    "1:\n"
    "    movb (%esi), %al\n"
    "    testb %al, %al\n"
    "    jz 2f\n"
    "    movw $0x3f8, %dx\n"
    "    outb %al, %dx\n"
    "    movw $0x2f8, %dx\n"
    "    outb %al, %dx\n"
    "    outb %al, $0xe9\n"
    "    incl %esi\n"
    "    jmp 1b\n"
    "2:\n"
    "    xorl %ecx, %ecx\n"
    "3:\n"
    "    incl %ecx\n"
    "    movl %ecx, 0x500\n"
    "    jmp 3b\n"
    "msg:\n"
    "    .asciz \"MDE-OK\\n\"\n";
}

/**
 * Options every machine of the group starts from.
 *
 * @param opt       Options to fill.
 * @param machine   @c -machine value, or @c NULL.
 */
static inline void
mde_emu_opt_init(tapi_emu_opt *opt, const char *machine)
{
    *opt = tapi_emu_default_opt;
    opt->machine = machine;
    /* There is no /dev/kvm on the agent; asking for TCG is deterministic. */
    opt->accel = "tcg";
    opt->memory_mb = 32;
}

/**
 * Assemble and link the guest on the agent and check it is what QEMU's
 * multiboot loader takes: a 32-bit i386 ELF.
 *
 * @param[in]  session  Session.
 * @param[out] elf      String to append the ELF path to.
 *
 * @return Status code; @c TE_ESHCMD when the toolchain cannot build it.
 */
static inline te_errno
mde_emu_build_kernel(tsapi_mde_session *session, te_string *elf)
{
    static const char *cflags[] = {
        "-m32", "-ffreestanding", "-nostdlib", "-static",
    };
    static const char *ldflags[] = {
        "-no-pie", "-Wl,--build-id=none", "-Wl,-N",
        "-Wl,-Ttext=0x100000", "-Wl,-e,_start",
    };
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    tapi_cc_opt         opt = tapi_cc_default_opt;
    tapi_cc_app        *app = NULL;
    tapi_binscan_info   info;
    const char         *sources[1];
    te_string           src = TE_STRING_INIT;
    te_errno            rc;

    (void)tsapi_mde_sh(session, 10000, &res, "mkdir -p " MDE_EMU_DIR);
    tsapi_mde_sh_result_free(&res);

    te_string_append(&src, MDE_EMU_DIR "/kernel.S");
    te_string_append(elf, MDE_EMU_DIR "/kernel.elf");

    rc = tapi_file_create_ta(session->ta, src.ptr, "%s",
                             mde_emu_kernel_src());
    if (rc != 0)
        goto out;

    sources[0] = src.ptr;
    opt.sources = sources;
    opt.n_sources = 1;
    opt.cflags = cflags;
    opt.n_cflags = TE_ARRAY_LEN(cflags);
    opt.ldflags = ldflags;
    opt.n_ldflags = TE_ARRAY_LEN(ldflags);
    opt.output = elf->ptr;

    rc = tapi_cc_do(session->factory, &opt, TAPI_DEVTOOL_TIMEOUT_MS, &app);
    (void)tapi_cc_destroy(app);
    if (rc != 0)
        goto out;

    /* A second view of what was built: the ELF header as tsf-cybersec
     * reads it. */
    rc = tapi_binscan_inspect(session->ta, elf->ptr, &info);
    if (rc != 0)
        goto out;
    RING("Guest kernel: ELF%u, machine %u, %s", info.elf_class,
         info.machine, tapi_binscan_kind2str(info.kind));
    if (!info.elf || info.elf_class != 32 || info.machine != 3)
    {
        ERROR("The guest is not a 32-bit i386 ELF");
        rc = TE_RC(TE_TAPI, TE_EBADMSG);
    }
    tapi_binscan_info_free(&info);

out:
    te_string_free(&src);
    return rc;
}

/**
 * Read a 32-bit register from the text of HMP "info registers".
 *
 * @param text      Monitor output.
 * @param name      Register, e.g. "ECX" or "EIP".
 * @param value     Where to put it.
 *
 * @return @c true if it was there.
 */
static inline bool
mde_emu_reg_parse(const char *text, const char *name, uint32_t *value)
{
    char        key[16];
    const char *p;

    TE_SPRINTF(key, "%s=", name);
    p = strstr(text, key);
    if (p == NULL)
        return false;
    *value = (uint32_t)strtoul(p + strlen(key), NULL, 16);
    return true;
}

/**
 * Read a register of the first CPU through the monitor.
 *
 * @param vm        Machine.
 * @param name      Register.
 * @param value     Where to put it.
 *
 * @return Status code; @c TE_ENOENT when the register is not printed.
 */
static inline te_errno
mde_emu_reg(tapi_emu_vm *vm, const char *name, uint32_t *value)
{
    te_string text = TE_STRING_INIT;
    te_errno  rc;

    rc = tapi_emu_hmp(vm, "info registers", MDE_EMU_TIMEOUT_MS, &text);
    if (rc == 0 && !mde_emu_reg_parse(te_string_value(&text), name, value))
    {
        ERROR("No %s in the register dump:\n%s", name,
              te_string_value(&text));
        rc = TE_RC(TE_TAPI, TE_ENOENT);
    }
    te_string_free(&text);

    return rc;
}

/**
 * Read one 32-bit word of guest physical memory through the monitor.
 *
 * @param vm        Machine.
 * @param addr      Address, as the monitor takes it ("0x500").
 * @param value     Where to put it.
 *
 * @return Status code.
 */
static inline te_errno
mde_emu_word(tapi_emu_vm *vm, const char *addr, uint32_t *value)
{
    te_string cmd = TE_STRING_INIT;
    te_string text = TE_STRING_INIT;
    const char *p;
    te_errno  rc;

    te_string_append(&cmd, "xp /1wx %s", addr);
    rc = tapi_emu_hmp(vm, cmd.ptr, MDE_EMU_TIMEOUT_MS, &text);
    if (rc == 0)
    {
        p = strstr(te_string_value(&text), ": 0x");
        if (p == NULL)
            rc = TE_RC(TE_TAPI, TE_ENOENT);
        else
            *value = (uint32_t)strtoul(p + 2, NULL, 16);
    }
    te_string_free(&cmd);
    te_string_free(&text);

    return rc;
}

/**
 * Read the run state three ways: tapi_emu_state_get(), the "status" and
 * "running" fields of query-status, and HMP "info status".
 *
 * @param[in]  vm       Machine.
 * @param[out] state    The module's view.
 * @param[out] status   query-status "status" (appended).
 * @param[out] running  query-status "running".
 * @param[out] hmp      HMP text (appended).
 *
 * @return Status code.
 */
static inline te_errno
mde_emu_views(tapi_emu_vm *vm, tapi_emu_state *state, te_string *status,
              bool *running, te_string *hmp)
{
    te_string reply = TE_STRING_INIT;
    te_errno  rc;

    rc = tapi_emu_state_get(vm, MDE_EMU_TIMEOUT_MS, state);
    if (rc == 0)
        rc = tapi_emu_qmp(vm, "query-status", NULL, MDE_EMU_TIMEOUT_MS,
                          &reply);
    if (rc == 0 &&
        !tapi_emu_qmp_str(te_string_value(&reply), "status", status))
        rc = TE_RC(TE_TAPI, TE_EPROTO);
    if (rc == 0)
    {
        /*
         * Read with the colon: tapi_emu_qmp_bool() looks for the quoted
         * key alone, and "running" is also the value of "status" that
         * comes first in the reply.
         */
        const char *p = strstr(te_string_value(&reply), "\"running\":");

        if (p == NULL)
        {
            rc = TE_RC(TE_TAPI, TE_EPROTO);
        }
        else
        {
            p += strlen("\"running\":");
            while (*p == ' ')
                p++;
            *running = strncmp(p, "true", 4) == 0;
        }
    }
    if (rc == 0)
        rc = tapi_emu_hmp(vm, "info status", MDE_EMU_TIMEOUT_MS, hmp);
    te_string_free(&reply);

    return rc;
}

#endif /* !__MDE_EMU_COMMON_H__ */

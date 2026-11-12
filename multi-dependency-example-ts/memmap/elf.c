/** @file
 * @brief Memory Map Group
 *
 * The memory image of one binary or library of the example, read out of
 * the ELF file by tsf-memorymap: its loadable segments and sections are
 * charted, the PT_LOAD segments are cross-checked one by one against
 * readelf -lW on the agent (address, file size, memory size, flags - two
 * independent parsers must agree), and the image is audited for W^X: no
 * segment both writable and executable, no executable stack. The audit
 * gets a known-bad control built on the agent with an executable stack
 * and a writable, executable segment.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "memmap/elf"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "te_mi_log.h"
#include "tapi_memmap.h"
#include "tapi_memmap_elf.h"
#include "tapi_memmap_audit.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "memmap_common.h"

/** SHF_ALLOC: the section occupies memory at run time. */
#define ELF_SHF_ALLOC   0x2
/** Most sections charted. */
#define ELF_MAX_SECS    48

/** Chart the loadable segments: memory and file size per segment. */
static void
elf_chart_loads(const tapi_memmap_image *image, const char *name)
{
    const tapi_memmap_seg *seg;
    te_mi_logger          *lg;
    te_string              title = TE_STRING_INIT;
    unsigned int           i = 0;

    if (tsapi_mde_mi_create("memmap/elf", &lg) != 0)
        return;

    TAPI_MEMMAP_FOREACH_LOAD(image, seg)
    {
        char perms[4];
        char key[16];

        tapi_memmap_perms2str(seg->perms, perms);
        te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_UNITLESS_VALUE, "segment",
                              TE_MI_MEAS_AGGR_SINGLE, i,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_MEMORY, "memsz",
                              TE_MI_MEAS_AGGR_SINGLE, (double)seg->memsz,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(lg, NULL, TE_MI_MEAS_MEMORY, "filesz",
                              TE_MI_MEAS_AGGR_SINGLE, (double)seg->filesz,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        TE_SPRINTF(key, "x%u", i);
        te_mi_logger_add_meas_key(lg, NULL, key, "LOAD %s @0x%" PRIx64,
                                  perms, seg->vaddr);
        i++;
    }
    te_mi_logger_add_meas_key(lg, NULL, "artifact", "%s", name);
    te_string_append(&title, "%s: PT_LOAD segments, memory and file size",
                     name);
    tsapi_mde_mi_line(lg, "loads", title.ptr, "segment", "memsz", "filesz",
                      NULL);
    te_mi_logger_destroy(lg);
    te_string_free(&title);
}

/** Chart the sizes of the sections that occupy memory. */
static void
elf_chart_sections(const tapi_memmap_image *image, const char *name)
{
    const tapi_memmap_sec *sec;
    const char            *labels[ELF_MAX_SECS];
    double                 sizes[ELF_MAX_SECS];
    te_string              title = TE_STRING_INIT;
    unsigned int           n = 0;

    TE_VEC_FOREACH(&image->sections, sec)
    {
        if ((sec->flags & ELF_SHF_ALLOC) == 0 || sec->size == 0 ||
            n >= ELF_MAX_SECS)
            continue;
        labels[n] = sec->name;
        sizes[n] = (double)sec->size;
        n++;
    }
    te_string_append(&title, "%s: sizes of the allocated sections", name);
    tsapi_mde_mi_bars("memmap/elf", title.ptr, TE_MI_MEAS_MEMORY, "size", n,
                      labels, sizes, TE_MI_MEAS_MULTIPLIER_PLAIN);
    te_string_free(&title);
}

/** Compare the PT_LOAD segments of an image with what readelf printed. */
static bool
elf_loads_agree(const tapi_memmap_image *image, const memmap_ph *phs,
                unsigned int n_phs)
{
    const tapi_memmap_seg *seg;
    unsigned int           j = 0;
    unsigned int           i;
    bool                   ok = true;

    TAPI_MEMMAP_FOREACH_LOAD(image, seg)
    {
        while (j < n_phs && !phs[j].load)
            j++;
        if (j >= n_phs)
        {
            ERROR("readelf has fewer LOAD segments than the parser");
            return false;
        }
        if (seg->vaddr != phs[j].vaddr || seg->filesz != phs[j].filesz ||
            seg->memsz != phs[j].memsz ||
            (seg->perms & (TAPI_MEMMAP_R | TAPI_MEMMAP_W | TAPI_MEMMAP_X)) !=
                phs[j].perms)
        {
            ERROR("LOAD @0x%" PRIx64 ": parser filesz %" PRIu64 " memsz %"
                  PRIu64 " perms %u; readelf @0x%" PRIx64 " filesz %" PRIu64
                  " memsz %" PRIu64 " perms %u", seg->vaddr, seg->filesz,
                  seg->memsz, seg->perms, phs[j].vaddr, phs[j].filesz,
                  phs[j].memsz, phs[j].perms);
            ok = false;
        }
        j++;
    }
    for (i = j; i < n_phs; i++)
    {
        if (phs[i].load)
        {
            ERROR("readelf has more LOAD segments than the parser");
            ok = false;
        }
    }

    return ok;
}

int
main(int argc, char **argv)
{
    const char            *artifact;
    tapi_cybersec_severity min_sev;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    tapi_memmap_image      image;
    bool                   image_up = false;
    tapi_memmap_image      ctl_image;
    bool                   ctl_up = false;
    te_string              path = TE_STRING_INIT;
    te_string              raw = TE_STRING_INIT;
    memmap_ph              phs[MEMMAP_MAX_PH];
    unsigned int           n_phs = 0;
    const tapi_memmap_seg *seg;
    uint64_t               load_mem = 0;
    uint64_t               load_file = 0;
    unsigned int           n_loads = 0;
    bool                   have_readelf;
    bool                   ctl_built = false;
    double                 t0;
    unsigned int           i;

    TEST_START;
    tsapi_mde_report_init(&report);
    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Parse test parameters");
    TEST_GET_STRING_PARAM(artifact);
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the artifact");
    TSAPI_MDE_OPEN_OR_SKIP(session, "mmelf", dut, session_up);
    if (strcmp(dut.dylib_ext, "so") != 0)
        TEST_SKIP("The example is built as Mach-O, not ELF");
    memmap_artifact_path(&dut, artifact, &path);
    if (!tsapi_mde_exists(&session, path.ptr))
        TEST_VERDICT("This artifact is not built");
    have_readelf = tsapi_mde_have(&session, "readelf");

    TEST_STEP("Read the ELF image");
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_memmap_elf_read(session.factory, path.ptr,
                                  TAPI_MEMMAP_TIMEOUT_MS, &image));
    image_up = true;
    tsapi_mde_mi_point("memmap/elf", "Time to fetch and parse the image",
                       TE_MI_MEAS_TIME, "read_s", tsapi_mde_now() - t0,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tapi_memmap_image_log(&image);
    TAPI_MEMMAP_FOREACH_LOAD(&image, seg)
    {
        load_mem += seg->memsz;
        load_file += seg->filesz;
        n_loads++;
    }
    TEST_ARTIFACT("%s: ELF%s %s, %s, type %u, entry 0x%" PRIx64 ", %zu "
                  "segment(s) (%u LOAD), %zu section(s)", artifact,
                  image.is64 ? "64" : "32",
                  image.big_endian ? "big-endian" : "little-endian",
                  tapi_memmap_machine2str(image.machine),
                  (unsigned int)image.elf_type, image.entry,
                  te_vec_size(&image.segments), n_loads,
                  te_vec_size(&image.sections));
    TEST_ARTIFACT("%s: PT_LOAD memory %" PRIu64 " bytes, file %" PRIu64
                  " bytes", artifact, load_mem, load_file);
    if (n_loads == 0)
        TEST_VERDICT("The image has no loadable segment");
    if (image.elf_type != 2 && image.elf_type != 3)
        TEST_VERDICT("The image is neither an executable nor a shared "
                     "object");

    TEST_STEP("Chart segments and sections");
    elf_chart_loads(&image, artifact);
    elf_chart_sections(&image, artifact);
    tsapi_mde_mi_point("memmap/elf", "PT_LOAD memory size", TE_MI_MEAS_MEMORY,
                       "load_memsz", (double)load_mem,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Two views: the parser and readelf -lW must agree");
    if (have_readelf)
    {
        if (!memmap_readelf(&session, path.ptr, phs, &n_phs, &raw))
            TEST_VERDICT("readelf could not read the image");
        RING("readelf -lW %s:\n%s", artifact, te_string_value(&raw));
        if (!elf_loads_agree(&image, phs, n_phs))
            TEST_VERDICT("The ELF parser and readelf disagree on PT_LOAD "
                         "segments");
        TEST_ARTIFACT("%s: %u LOAD segment(s) agree with readelf", artifact,
                      n_loads);
    }
    else
    {
        RING("readelf is not on the agent: the second view is skipped");
    }

    TEST_STEP("W^X audit of the image");
    CHECK_RC(tapi_memmap_audit_image(&image, artifact, &report.cyber));
    TAPI_MEMMAP_FOREACH_LOAD(&image, seg)
    {
        if ((seg->perms & TAPI_MEMMAP_W) && (seg->perms & TAPI_MEMMAP_X))
            RING("W+X LOAD @0x%" PRIx64 " memsz %" PRIu64, seg->vaddr,
                 seg->memsz);
    }

    TEST_STEP("Known-bad control: an executable stack and a W+X segment");
    if (tsapi_mde_have(&session, "gcc"))
        ctl_built = memmap_build_control(&session);
    if (ctl_built)
    {
        bool want_wx = false;
        bool want_xstack = false;

        CHECK_RC(tapi_memmap_elf_read(session.factory, MEMMAP_CTL_BIN,
                                      TAPI_MEMMAP_TIMEOUT_MS, &ctl_image));
        ctl_up = true;
        CHECK_RC(tapi_memmap_audit_image(&ctl_image, "control",
                                         &report.cyber));

        /* What the control really is comes from readelf, not the parser. */
        if (have_readelf)
        {
            te_string_reset(&raw);
            (void)memmap_readelf(&session, MEMMAP_CTL_BIN, phs, &n_phs, &raw);
            RING("readelf -lW control:\n%s", te_string_value(&raw));
            for (i = 0; i < n_phs; i++)
            {
                bool wx = (phs[i].perms & TAPI_MEMMAP_W) &&
                          (phs[i].perms & TAPI_MEMMAP_X);

                if (phs[i].load && wx)
                    want_wx = true;
                if (!phs[i].load && (phs[i].perms & TAPI_MEMMAP_X))
                    want_xstack = true;
            }
        }
        else
        {
            /* -z execstack is honoured by every linker gcc drives. */
            want_xstack = true;
        }
        TEST_ARTIFACT("control: W+X segment %s, executable stack %s",
                      want_wx ? "planted" : "not produced by the linker",
                      want_xstack ? "planted" : "not produced by the linker");
        if (want_xstack)
            tsapi_mde_report_expect(&report, "memmap.exec-stack", "control");
        if (want_wx)
            tsapi_mde_report_expect(&report, "memmap.wx-segment", "control");
        if (!want_wx && !want_xstack)
            TEST_VERDICT("The linker produced neither defect in the control");
        tsapi_mde_report_drop_subject(&report, "control");
    }
    else
    {
        WARN("No compiler to build the known-bad control: the W^X audit "
             "runs without one");
    }

    TEST_STEP("Decide over the W^X findings");
    TSAPI_MDE_REPORT_GATE(&report, "memmap", min_sev);

    TEST_SUCCESS;

cleanup:

    if (image_up)
        tapi_memmap_image_free(&image);
    if (ctl_up)
        tapi_memmap_image_free(&ctl_image);
    if (session_up)
    {
        memmap_drop_control(&session);
        tsapi_mde_dut_free(&dut);
    }
    tsapi_mde_report_free(&report);
    te_string_free(&path);
    te_string_free(&raw);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}

/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_ref_each_alone, each reference demo in its own
 *        process, to show whether one language crashes because of the shared
 *        native libraries (settles H1)
 *
 * Each reference (C++, Rust, Python, Go, C#) runs in a separate process with
 * the input 42 3 and a limit of 20 s. The C++ demo runs twice: the one
 * built by build.sh, linked with libcppcore, and one built in /tmp from the
 * C++ sources against the libraries of dist/lib. The file type of every .so
 * and demo is logged with file(1), with the CPU of the agent; a file type
 * that does not match the CPU fails the test as a CPU or library mismatch.
 * A planted crash, a planted hang and a planted wrong-architecture name
 * check the runner and the comparison. The test passes only when every run
 * exits 0 with 4 stage lines.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_ref_each_alone"

#include "tsr.h"

#define LIMIT   20

/** Machine name in file(1) output for a CPU name of uname -m, or NULL. */
static const char *
file_arch(const char *cpu)
{
    if (strcmp(cpu, "x86_64") == 0)
        return "x86-64";
    if (strcmp(cpu, "aarch64") == 0 || strcmp(cpu, "arm64") == 0)
        return "aarch64";
    return NULL;
}

/** True when the file(1) text @p t fits the CPU @p cpu. */
static bool
type_fits(const char *t, const char *cpu)
{
    const char *want = file_arch(cpu);

    if (strstr(t, "Mach-O") != NULL)
        return false;
    if (strstr(t, "ELF") == NULL)
        return true;        /* a script: no machine of its own */
    return want == NULL || strstr(t, want) != NULL;
}

int
main(int argc, char **argv)
{
    const char     *src = tsd_src();
    struct tsr_res  r[TSR_NREF];
    struct tsr_res  lk;
    struct tsr_res  cl;
    char            cpu[64];
    char            text[1500];
    char            what[400];
    char            cmd[1400];
    int             nbad = 0;
    int             i;

    TEST_START;
    memset(&lk, 0, sizeof(lk));
    memset(&cl, 0, sizeof(cl));

    TEST_STEP("Control: a planted crash, a planted hang and a planted "
              "good run are told apart");
    {
        struct tsr_res c;

        tsr_install();
        tsd_sh("/", "python3 -I /tmp/ts_refrun.py 20 /tmp/ts_ref_k1.out "
               "/tmp/ts_ref_k1.err /tmp/ts_ref_k1.res -- python3 -I -c "
               "'import os,signal;os.kill(os.getpid(),signal.SIGABRT)'", 30,
               "/tmp/ts_ra_c.log");
        tsr_read("k1", &c);
        if (c.sig != 6 || c.ok)
            TEST_FAIL("H1 NOT SETTLED: a planted SIGABRT was read as exit "
                      "%d signal %d", c.code, c.sig);
        tsd_sh("/", "python3 -I /tmp/ts_refrun.py 2 /tmp/ts_ref_k2.out "
               "/tmp/ts_ref_k2.err /tmp/ts_ref_k2.res -- sleep 30", 40,
               "/tmp/ts_ra_c.log");
        tsr_read("k2", &c);
        if (!c.timeout || c.ok)
            TEST_FAIL("H1 NOT SETTLED: a planted hang was not seen as a "
                      "time-out (exit %d signal %d)", c.code, c.sig);
        if (type_fits("ELF 64-bit LSB shared object, ARM aarch64", "x86_64") ||
            !type_fits("ELF 64-bit LSB shared object, x86-64", "x86_64") ||
            type_fits("Mach-O 64-bit dynamically linked shared library arm64",
                      "aarch64"))
            TEST_FAIL("H1 NOT SETTLED: the file type check is wrong");
        tsd_say("H1 control: planted SIGABRT, hang and mismatching file "
                "types are told apart");
    }

    TEST_STEP("The project root and the tools");
    if (src[0] == '\0' || access(src, X_OK) != 0)
        TEST_FAIL("H1 FAIL: TE_TS_MDE_SRC is [%s], not a directory", src);
    if (tsd_sh("/", "command -v file", 10, "/tmp/ts_ra_f.log") != 0)
        TEST_FAIL("H1 FAIL: file(1) is not on the agent; "
                  "scripts/midair-setup.sh installs it");

    TEST_STEP("The CPU of the agent");
    tsd_sh("/", "uname -m", 10, "/tmp/ts_ra_cpu.log");
    tsd_head("/tmp/ts_ra_cpu.log", cpu, sizeof(cpu));
    cpu[strcspn(cpu, "\n")] = '\0';
    tsd_sh("/", "{ grep -m1 -E 'model name|Model|Hardware' /proc/cpuinfo; "
           "grep -m1 -E 'flags|Features' /proc/cpuinfo | cut -c1-120; "
           "uname -srv; getconf LONG_BIT; } 2>&1", 10, "/tmp/ts_ra_cpui.log");
    tsd_head("/tmp/ts_ra_cpui.log", text, sizeof(text));
    tsd_say("H1 agent CPU: uname -m [%s]; %s", cpu, text);

    TEST_STEP("The file type of every .so and demo, and their CPU");
    snprintf(cmd, sizeof(cmd), "cd '%s' && for f in dist/lib/*.so dist/bin/* "
             "python/demo.py; do [ -e \"$f\" ] && file -b \"$f\" | "
             "sed \"s|^|$f: |\"; done", src);
    tsd_sh("/", cmd, 30, "/tmp/ts_ra_file.log");
    {
        FILE *f = fopen("/tmp/ts_ra_file.log", "r");
        char  line[600];
        int   n = 0;

        if (f == NULL)
            TEST_FAIL("H1 FAIL: file(1) wrote no output");
        while (fgets(line, sizeof(line), f) != NULL)
        {
            line[strcspn(line, "\n")] = '\0';
            tsd_say("H1 file type: %.300s", line);
            n++;
            if (strstr(line, ".so") != NULL || strstr(line, "dist/bin") != NULL)
            {
                if (!type_fits(line, cpu))
                {
                    tsd_bad("H1", "CPU or library mismatch", "%.200s does not "
                            "fit the CPU %s", line, cpu);
                    nbad++;
                }
            }
        }
        fclose(f);
        if (n == 0)
            tsd_bad("H1", "no file found", "dist/lib and dist/bin of %s hold "
                    "no file; build.sh did not make them", src);
    }
    tsd_sh(src, "for f in dist/bin/cpp-demo dist/lib/libcppcore.so; do "
           "echo \"== $f\"; readelf -d \"$f\" 2>&1 | grep -E 'NEEDED|RPATH|"
           "RUNPATH'; echo \"-- ldd\"; ldd \"$f\" 2>&1 | cut -c1-140; done", 20,
           "/tmp/ts_ra_ldd.log");
    tsr_tail("H1 cpp link (NEEDED, RPATH, ldd)", "/tmp/ts_ra_ldd.log", 30);
    if (tsd_sh(src, "ldd dist/bin/cpp-demo dist/lib/*.so 2>&1 | grep -E "
               "'not found'", 20, "/tmp/ts_ra_nf.log") == 0)
    {
        tsd_head("/tmp/ts_ra_nf.log", text, 500);
        tsd_say("H1 libraries not found by ldd without LD_LIBRARY_PATH: [%s]",
                text);
    }

    TEST_STEP("Each reference in a separate process, limit %d s", LIMIT);
    for (i = 0; i < TSR_NREF; i++)
    {
        char tag[48];
        char path[PATH_MAX];

        memset(&r[i], 0, sizeof(r[i]));
        r[i].code = -1;
        snprintf(path, sizeof(path), "%s/%s", src, tsr_refs[i].file);
        if (access(path, R_OK) != 0)
        {
            tsd_bad("H1", tsr_refs[i].name, "%s is missing", tsr_refs[i].file);
            nbad++;
            continue;
        }
        snprintf(tag, sizeof(tag), "alone_%s", tsr_refs[i].name);
        tsr_run(i, "42 3", tag, LIMIT, "dist/lib", &r[i]);
        tsr_describe(tsr_refs[i].name, &r[i], what, sizeof(what));
        tsd_say("H1 %s alone: exit=%d signal=%s(%d) timeout=%d stages=%d "
                "last stage [%.120s]", tsr_refs[i].name, r[i].code,
                tsr_signame(r[i].sig), r[i].sig, r[i].timeout, r[i].stages,
                r[i].last);
        if (r[i].ok)
        {
            tsd_say("H1 PASS for %s: %s", tsr_refs[i].name, what);
            continue;
        }
        nbad++;
        snprintf(path, sizeof(path), "/tmp/ts_ref_%s.err", tag);
        tsr_tail("H1 last 40 stderr lines", path, 40);
        tsd_bad("H1", what, "%s", what);
    }

    TEST_STEP("The C++ demo linked with libcppcore (as build.sh made it)");
    tsr_run(0, "42 3", "cpp_linked", LIMIT, "dist/lib", &lk);
    tsr_describe("cpp-demo linked", &lk, what, sizeof(what));
    tsd_say("H1 %s", what);
    if (!lk.ok)
    {
        nbad++;
        tsr_tail("H1 last 40 stderr lines", "/tmp/ts_ref_cpp_linked.err", 40);
        tsd_bad("H1", what, "%s", what);
    }

    TEST_STEP("The C++ demo from a clean build in /tmp");
    snprintf(cmd, sizeof(cmd),
        "rm -rf /tmp/ts_ref_clean && mkdir -p /tmp/ts_ref_clean && "
        "D=$PWD/dist/lib && g++ -std=c++17 -O1 -shared -fPIC -I cpp/include "
        "cpp/src/cppcore.cpp -o /tmp/ts_ref_clean/libcppcore.so "
        "-Wl,-rpath,$D -Wl,-rpath-link,$D $D/librustcore.so $D/libpycore.so "
        "&& g++ -std=c++17 -O1 -I cpp/include cpp/src/demo.cpp "
        "-o /tmp/ts_ref_clean/cpp-demo -L/tmp/ts_ref_clean "
        "-Wl,--no-as-needed -lcppcore -Wl,--as-needed $D/librustcore.so "
        "-Wl,-rpath,/tmp/ts_ref_clean -Wl,-rpath,$D -Wl,-rpath-link,$D");
    if (tsd_sh(src, cmd, 200, "/tmp/ts_ra_clean.log") != 0)
    {
        tsr_tail("H1 clean build output", "/tmp/ts_ra_clean.log", 30);
        tsd_bad("H1", "clean C++ build failed", "g++ could not build "
                "cppcore.cpp and demo.cpp against dist/lib; see the log");
        nbad++;
        cl.ok = false;
    }
    else
    {
        tsd_sh("/", "file -b /tmp/ts_ref_clean/libcppcore.so "
               "/tmp/ts_ref_clean/cpp-demo | cut -c1-160", 10,
               "/tmp/ts_ra_cf.log");
        tsd_head("/tmp/ts_ra_cf.log", text, 500);
        tsd_say("H1 clean build file types: [%s]", text);
        tsr_run_prog("/tmp/ts_ref_clean/cpp-demo", "42 3", "cpp_clean", LIMIT,
                     "/tmp/ts_ref_clean:dist/lib", &cl);
        tsr_describe("cpp-demo clean build", &cl, what, sizeof(what));
        tsd_say("H1 %s", what);
        if (!cl.ok)
        {
            nbad++;
            tsr_tail("H1 last 40 stderr lines", "/tmp/ts_ref_cpp_clean.err",
                     40);
            tsd_bad("H1", what, "%s", what);
        }
    }

    TEST_STEP("What the runs say about the shared libraries");
    {
        int ncrash = 0;

        for (i = 0; i < TSR_NREF; i++)
            ncrash += r[i].sig != 0 || (r[i].code > 128);
        if (ncrash == 0)
            tsd_say("H1 no reference crashed when run alone");
        else if (ncrash == TSR_NREF)
            tsd_say("H1 FINDING: every reference crashed when run alone, so "
                    "the cause is shared (the native libraries in dist/lib "
                    "or the stage hand-off), not one language");
        else
            tsd_say("H1 FINDING: %d of %d references crashed when run alone; "
                    "the others did not, so the cause is in the stages "
                    "those use", ncrash, TSR_NREF);
        if (!lk.ok && cl.ok)
            tsd_say("H1 FINDING: the clean C++ build runs and the linked one "
                    "does not: the link of cpp-demo is the cause");
        else if (!lk.ok && !cl.ok && lk.sig == cl.sig)
            tsd_say("H1 FINDING: the linked and the clean C++ build end the "
                    "same way (signal %d): the link of cpp-demo is not the "
                    "cause, the libraries are", lk.sig);
    }

    TSD_PASS("H1", "each reference ran in a separate process with a 20 s "
             "limit and exited 0 with 4 stage lines, the C++ demo linked "
             "and from a clean build too, and the file types match the CPU");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}

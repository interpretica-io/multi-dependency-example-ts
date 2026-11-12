/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T4, each language example builds and runs (settles H4)
 *
 * For Rust (rust/demo), Go (go), C# (csharp), C++ (cpp) and C
 * (python/src/pycore.c) run the build command, then run the demo binary.
 * A language passes when the build succeeds, the demo exits 0 and its
 * stdout is not empty. One verdict per language is printed and put in the
 * tapi_cybersec_report, named by the language. A failing build fails the
 * language; for cppcore.cpp and pycore.c the compiler error text is
 * printed, because the static analyser could not parse them. A language
 * with no demo entry point (the Go and C# stages are libraries) fails and
 * the verdict says so. The test fails when any language fails.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t4_language_builds"

#include "te_config.h"

#include "webdeps_lib.h"

#define BUILD_TO    1500    /**< s, longest build (NativeAOT is slow). */
#define DEMO_TO     60      /**< s, longest demo run. */

#define DIST_LIB_ENV \
    "CGO_LDFLAGS_ALLOW='-Wl,-(U|install_name),.*|-Wl,--unresolved-symbols=.*' "\
    "CGO_LDFLAGS=\"-L$PWD/dist/lib -lcscore -Wl,-rpath,$PWD/dist/lib\" "

typedef struct lang_t {
    const char *name;
    const char *src;        /**< Where the example lives, for the verdict. */
    const char *build;      /**< Build command, run in the example root. */
    const char *demo;       /**< Demo command, or NULL: no entry point. */
    bool        print_cc;   /**< Print the compiler error on a failed build. */
} lang_t;

static const lang_t langs[] = {
    { "rust", "rust/demo",
      "(cd rust && cargo build --release -p rustcore -p rust-demo) && "
      "mkdir -p dist/bin && cp rust/target/release/rust-demo dist/bin/",
      "dist/bin/rust-demo 1 1", false },
    { "go", "go",
      "mkdir -p dist/lib && cd go && " DIST_LIB_ENV
      "go build -buildmode=c-shared -o ../dist/lib/libgocore.so .",
      NULL, false },
    { "csharp", "csharp",
      "mkdir -p dist/lib && dotnet publish csharp/cscore.csproj -c Release "
      "-o csharp/out --nologo -v quiet -r "
      "linux-$([ \"$(uname -m)\" = x86_64 ] && echo x64 || echo arm64) && "
      "cp csharp/out/cscore.so dist/lib/libcscore.so",
      NULL, false },
    { "cpp", "cpp",
      "cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release && "
      "cmake --build cpp/build --parallel",
      "dist/bin/cpp-demo 1 1", true },
    { "c", "python/src/pycore.c",
      "mkdir -p dist/lib && cc -D_GNU_SOURCE -shared -fPIC -O2 "
      "$(python3-config --includes) \"-DRING_PY_DIR=\\\"$PWD/python\\\"\" "
      "python/src/pycore.c -o dist/lib/libpycore.so "
      "$(python3-config --ldflags --embed) "
      "-Wl,-soname,libpycore.so",
      "python3 python/demo.py 1 1", true },
};

/** Output of a finished command: head of stdout and stderr, flattened. */
static void
shown(proc_t *p, char *buf, size_t size, bool errors)
{
    char out[900];
    char err[900];

    file_tail(p->out, out, sizeof(out));
    file_tail(p->err, err, sizeof(err));
    snprintf(buf, size, "%s: [%s]", errors ? "stderr" : "stdout",
             errors ? (err[0] != '\0' ? err : out) : out);
}

/** Build and run one language; msg gets "<name> PASS|FAIL: ...". */
static bool
one_language(const lang_t *l, char *msg, size_t size)
{
    res_t   r = { .kind = R_PASS };
    char    label[48];
    char    text[1100];
    char    cmd[1200];
    proc_t *p;
    struct stat st;

    snprintf(label, sizeof(label), "%s-build", l->name);
    p = run_sh(&r, label, l->build, BUILD_TO);
    if (p == NULL)
    {
        snprintf(msg, size, "%s FAIL: the build did not finish: %s", l->name,
                 r.msg);
        return false;
    }
    if (!WIFEXITED(p->status) || WEXITSTATUS(p->status) != 0)
    {
        shown(p, text, sizeof(text), true);
        if (l->print_cc)
        {
            char full[4096] = "";
            FILE *f = fopen(p->err, "r");
            size_t n = f != NULL ? fread(full, 1, sizeof(full) - 1, f) : 0;

            if (f != NULL)
                fclose(f);
            full[n] = '\0';
            ERROR("webdeps: compiler error text of %s (%s):\n%s", l->name,
                  l->src, full);
        }
        snprintf(msg, size, "%s FAIL: build of %s failed (exit %d); %s",
                 l->name, l->src, WIFEXITED(p->status) ?
                 WEXITSTATUS(p->status) : -WTERMSIG(p->status), text);
        return false;
    }
    if (l->demo == NULL)
    {
        snprintf(msg, size, "%s FAIL: %s builds but has no demo entry point "
                 "(it is a library, nothing to run)", l->name, l->src);
        return false;
    }

    snprintf(label, sizeof(label), "%s-demo", l->name);
    snprintf(cmd, sizeof(cmd), "%s", l->demo);
    p = run_sh(&r, label, cmd, DEMO_TO);
    if (p == NULL)
    {
        snprintf(msg, size, "%s FAIL: the demo did not finish: %s", l->name,
                 r.msg);
        return false;
    }
    shown(p, text, sizeof(text), false);
    if (!WIFEXITED(p->status) || WEXITSTATUS(p->status) != 0)
    {
        char more[900];

        shown(p, more, sizeof(more), true);
        snprintf(msg, size, "%s FAIL: demo exit status %d instead of 0; "
                 "%s; %s", l->name, WIFEXITED(p->status) ?
                 WEXITSTATUS(p->status) : -WTERMSIG(p->status), text, more);
        return false;
    }
    if (stat(p->out, &st) != 0 || st.st_size == 0)
    {
        snprintf(msg, size, "%s FAIL: the demo exited 0 but printed nothing "
                 "on stdout", l->name);
        return false;
    }
    snprintf(msg, size, "%s PASS: built, demo exited 0, %s", l->name, text);
    return true;
}

int
main(int argc, char **argv)
{
    res_t   res = { .kind = R_PASS };
    char    msg[1400];
    char    failed[300] = "";
    char    summary[900] = "";
    size_t  i;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;

    for (i = 0; i < TE_ARRAY_LEN(langs); i++)
    {
        bool ok;

        TEST_STEP("Build and run the %s example", langs[i].name);
        ok = one_language(&langs[i], msg, sizeof(msg));
        RING("webdeps verdict H4 %s", msg);
        T_FINDING(ok ? TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH,
                  "example.language", langs[i].name, "%s", msg);
        append(summary, sizeof(summary), "%.*s; ",
               (int)(strchr(msg, ':') != NULL ? strchr(msg, ':') - msg :
                     0) , msg);
        if (!ok)
            append(failed, sizeof(failed), "%s %.120s; ", langs[i].name,
                   strchr(msg, ':') != NULL ? strchr(msg, ':') + 2 : msg);
    }

    if (failed[0] != '\0')
        res_set(&res, R_FAIL, "H4 FAIL: per language: %s| failing: %s",
                summary, failed);
    else
        res_set(&res, R_PASS, "H4 PASS: every language built, its demo exited "
                "0 and printed on stdout: %s", summary);

verdict:
    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}

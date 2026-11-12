/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T3, each language example builds (settles H3)
 *
 * Build every example with the tool of its own language: cargo build for
 * rust/core, rust/demo and gateway-rs, go build for go and service-go,
 * dotnet build for csharp and service-cs, and the C++ and C compilers for
 * cppcore.cpp and pycore.c. The outputs are put in H3_OUT so that T4 can
 * scan them. One pass or fail line is recorded per example, naming it, and
 * on a fail it carries the compiler error text. The test fails on any
 * build error.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t3_language_builds"

#include "te_config.h"

#include "webdeps_lib.h"

#define BUILD_TO    1500    /**< s, longest build. */

#define GO_ENV \
    "CGO_LDFLAGS_ALLOW='-Wl,-(U|install_name|rpath),.*|" \
    "-Wl,--unresolved-symbols=.*' "

typedef struct build_t {
    const char *name;
    const char *src;        /**< What is built, for the line. */
    const char *cmd;        /**< Build command, run in the example root. */
} build_t;

/* Every command writes only below H3_OUT or into the tool's own cache. */
static const build_t builds[] = {
    { "rust/core", "rust/core",
      "CARGO_TARGET_DIR=" H3_OUT "/rust-core "
      "cargo build --release --manifest-path rust/Cargo.toml -p rustcore" },
    { "rust/demo", "rust/demo",
      "CARGO_TARGET_DIR=" H3_OUT "/rust-demo "
      "cargo build --release --manifest-path rust/Cargo.toml -p rust-demo" },
    { "gateway-rs", "web/gateway-rs",
      "CARGO_TARGET_DIR=" H3_OUT "/gateway-rs "
      "cargo build --release --manifest-path web/gateway-rs/Cargo.toml" },
    { "go", "go",
      GO_ENV "CGO_LDFLAGS=\"-L$PWD/dist/lib -lcscore "
      "-Wl,-rpath,$PWD/dist/lib\" "
      "sh -c 'cd go && go build -buildmode=c-shared "
      "-o " H3_OUT "/libgocore.so .'" },
    { "service-go", "web/service-go",
      GO_ENV "ROOT=$PWD sh -c 'cd web/service-go && go build "
      "-ldflags \"-X main.contractPath=$ROOT/web/contract/services.tab\" "
      "-o " H3_OUT "/service-go .'" },
    { "csharp", "csharp",
      "dotnet build csharp/cscore.csproj -c Release --nologo -v quiet "
      "-o " H3_OUT "/cscore" },
    { "service-cs", "web/service-cs",
      "dotnet build web/service-cs/webcs.csproj -c Release --nologo -v quiet "
      "-o " H3_OUT "/service-cs" },
    { "cppcore.cpp", "cpp/src/cppcore.cpp",
      "c++ -std=c++17 -shared -fPIC -O2 -Icpp/include cpp/src/cppcore.cpp "
      "-o " H3_OUT "/libcppcore.so -Ldist/lib -lrustcore -lpycore "
      "-Wl,-rpath,$PWD/dist/lib" },
    { "pycore.c", "python/src/pycore.c",
      "cc -D_GNU_SOURCE -shared -fPIC -O2 $(python3-config --includes) "
      "\"-DRING_PY_DIR=\\\"$PWD/python\\\"\" python/src/pycore.c "
      "-o " H3_OUT "/libpycore.so $(python3-config --ldflags --embed)" },
};

/** Build one example; msg gets "<name> PASS|FAIL: ...". */
static bool
one_build(const build_t *b, char *msg, size_t size)
{
    res_t   r = { .kind = R_PASS };
    char    label[48];
    char    text[1100];
    proc_t *p;
    char   *q;

    snprintf(label, sizeof(label), "build-%.30s", b->name);
    for (q = label; *q != '\0'; q++)
    {
        if (*q == '/' || *q == '.')
            *q = '_';
    }
    p = run_sh(&r, label, b->cmd, BUILD_TO);
    if (p == NULL)
    {
        snprintf(msg, size, "%s FAIL: the build of %s did not finish: %s",
                 b->name, b->src, r.msg);
        return false;
    }
    if (!WIFEXITED(p->status) || WEXITSTATUS(p->status) != 0)
    {
        char full[4096] = "";
        FILE *f = fopen(p->err, "r");
        size_t n = f != NULL ? fread(full, 1, sizeof(full) - 1, f) : 0;

        if (f != NULL)
            fclose(f);
        full[n] = '\0';
        if (n == 0)
        {
            f = fopen(p->out, "r");
            n = f != NULL ? fread(full, 1, sizeof(full) - 1, f) : 0;
            if (f != NULL)
                fclose(f);
            full[n] = '\0';
        }
        ERROR("webdeps: compiler error text of %s (%s):\n%s", b->name, b->src,
              full);
        file_tail(n > 0 ? (p->err) : (p->out), text, sizeof(text));
        snprintf(msg, size, "%s FAIL: build of %s failed (exit %d); compiler "
                 "error: [%s]", b->name, b->src, WIFEXITED(p->status) ?
                 WEXITSTATUS(p->status) : -WTERMSIG(p->status), text);
        return false;
    }
    snprintf(msg, size, "%s PASS: %s built", b->name, b->src);
    return true;
}

int
main(int argc, char **argv)
{
    res_t   res = { .kind = R_PASS };
    char    msg[1400];
    char    failed[900] = "";
    char    summary[500] = "";
    size_t  i;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;

    mkdir(H3_OUT, 0755);
    for (i = 0; i < TE_ARRAY_LEN(builds); i++)
    {
        bool ok;

        TEST_STEP("Build %s with its own tool", builds[i].name);
        ok = one_build(&builds[i], msg, sizeof(msg));
        RING("webdeps verdict H3 %s", msg);
        T_FINDING(ok ? TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH,
                  "example.build", builds[i].name, "%s", msg);
        append(summary, sizeof(summary), "%s %s; ", builds[i].name,
               ok ? "pass" : "fail");
        if (!ok)
            append(failed, sizeof(failed), "%.200s | ", msg);
    }

    if (failed[0] != '\0')
        res_set(&res, R_FAIL, "H3 FAIL: %s-- failing: %s", summary, failed);
    else
        res_set(&res, R_PASS, "H3 PASS: every example built: %s", summary);

verdict:
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}

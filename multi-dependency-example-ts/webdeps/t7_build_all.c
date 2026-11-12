/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t7_build_all, every language example builds and runs
 *        (settles H3)
 *
 * One subtest per language, each with its own tool: cargo build (Rust:
 * rust/core, rust/demo, gateway-rs), go build (Go: go, service-go), dotnet
 * build (C#: csharp, service-cs), g++ (C++: cppcore.cpp and the demo), gcc
 * (C: pycore.c) and python3 (the Python demo and its byte-compilation).
 * gcc and g++ are named explicitly, not the cc and c++ alternatives, so
 * that a tcc standing in for cc cannot change the result.
 *
 * For every build the exit code and the first 20 error lines are logged;
 * a compiler that cannot parse cppcore.cpp or pycore.c shows up there. The
 * outputs are put in H3_OUT so that t4_binscan can scan them. When all the
 * builds of a language passed, its built demo is run: the exit code must be
 * 0 and the output not empty (for Go and C# the demo is the built service,
 * started and asked once; the exit code of the client stands in for the
 * exit code of a one-shot program).
 *
 * One verdict line "H3 <language> PASS|FAIL" is logged and recorded per
 * language; the test fails when any language fails.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t7_build_all"

#include "te_config.h"

#include "webdeps_lib.h"

#define BUILD_TO    1500    /**< s, longest build. */
#define RUN_TO      60      /**< s, longest demo. */
#define N_ERR       20      /**< error lines recorded per build. */

#define GO_ENV \
    "CGO_LDFLAGS_ALLOW='-Wl,-(U|install_name|rpath),.*|" \
    "-Wl,--unresolved-symbols=.*' "

/** A Python-aware C driver: loads the ring, then libpycore, calls once. */
#define C_DRIVER \
    "#include <dlfcn.h>\n#include <stdio.h>\n#include <math.h>\n" \
    "int main(void){\n" \
    "void*h;double(*f)(void);double v;\n" \
    "if(!dlopen(\"dist/lib/libcppcore.so\",RTLD_NOW|RTLD_GLOBAL)||\n" \
    "   !dlopen(\"dist/lib/libgocore.so\",RTLD_NOW|RTLD_GLOBAL)){\n" \
    "printf(\"dlopen of the ring failed: %s\\n\",dlerror());return 1;}\n" \
    "h=dlopen(\"" H3_OUT "/libpycore.so\",RTLD_NOW|RTLD_GLOBAL);\n" \
    "if(!h){printf(\"dlopen failed: %s\\n\",dlerror());return 1;}\n" \
    "f=(double(*)(void))dlsym(h,\"py_weight\");\n" \
    "if(!f){printf(\"dlsym failed: %s\\n\",dlerror());return 1;}\n" \
    "v=f();printf(\"py_weight() = %.6f\\n\",v);return isfinite(v)?0:1;}\n"

typedef struct build_t {
    const char *name;
    const char *src;        /**< What is built, for the line. */
    const char *cmd;        /**< Build command, run in the example root. */
} build_t;

typedef struct lang_t {
    const char *lang;
    const build_t *builds;
    size_t      n_builds;
    const char *demo_name;
    const char *demo_cmd;   /**< Run in the example root; NULL: set later. */
} lang_t;

static const build_t rust_builds[] = {
    { "rust/core", "rust/core",
      "CARGO_TARGET_DIR=" H3_OUT "/rust-core "
      "cargo build --release --manifest-path rust/Cargo.toml -p rustcore" },
    { "rust/demo", "rust/demo",
      "CARGO_TARGET_DIR=" H3_OUT "/rust-demo "
      "cargo build --release --manifest-path rust/Cargo.toml -p rust-demo" },
    { "gateway-rs", "web/gateway-rs",
      "CARGO_TARGET_DIR=" H3_OUT "/gateway-rs "
      "cargo build --release --manifest-path web/gateway-rs/Cargo.toml" },
};

static const build_t go_builds[] = {
    { "go", "go",
      GO_ENV "CGO_LDFLAGS=\"-L$PWD/dist/lib -lcscore "
      "-Wl,-rpath,$PWD/dist/lib\" "
      "sh -c 'cd go && go build -buildmode=c-shared "
      "-o " H3_OUT "/libgocore.so .'" },
    { "service-go", "web/service-go",
      GO_ENV "ROOT=$PWD sh -c 'cd web/service-go && go build "
      "-ldflags \"-X main.contractPath=$ROOT/web/contract/services.tab\" "
      "-o " H3_OUT "/service-go .'" },
};

static const build_t cs_builds[] = {
    { "csharp", "csharp",
      "dotnet build csharp/cscore.csproj -c Release --nologo -v quiet "
      "-o " H3_OUT "/cscore" },
    { "service-cs", "web/service-cs",
      "dotnet build web/service-cs/webcs.csproj -c Release --nologo -v quiet "
      "-o " H3_OUT "/service-cs" },
};

static const build_t cpp_builds[] = {
    { "cppcore.cpp", "cpp/src/cppcore.cpp",
      "g++ -std=c++17 -shared -fPIC -O2 -Icpp/include cpp/src/cppcore.cpp "
      "-o " H3_OUT "/libcppcore.so -Ldist/lib -lrustcore -lpycore "
      "-Wl,-rpath,$PWD/dist/lib" },
    { "demo.cpp", "cpp/src/demo.cpp",
      "g++ -std=c++17 -O2 -Icpp/include cpp/src/demo.cpp "
      "-o " H3_OUT "/cpp-demo -L" H3_OUT " -lcppcore -Ldist/lib -lrustcore "
      "-Wl,-rpath," H3_OUT " -Wl,-rpath,$PWD/dist/lib" },
};

static const build_t c_builds[] = {
    { "pycore.c", "python/src/pycore.c",
      "gcc -D_GNU_SOURCE -shared -fPIC -O2 $(python3-config --includes) "
      "\"-DRING_PY_DIR=\\\"$PWD/python\\\"\" python/src/pycore.c "
      "-o " H3_OUT "/libpycore.so $(python3-config --ldflags --embed)" },
    { "c-demo.c", H3_OUT "/c-demo.c",
      "printf '%s' \"$C_DRIVER_SRC\" > " H3_OUT "/c-demo.c && "
      "gcc -O2 " H3_OUT "/c-demo.c -o " H3_OUT "/c-demo -ldl -lm" },
};

static const build_t py_builds[] = {
    { "python", "python/*.py",
      "python3 -m py_compile python/ring_stage.py python/demo.py" },
};

static const lang_t langs[] = {
    { "rust", rust_builds, TE_ARRAY_LEN(rust_builds), "rust-demo 1 1",
      H3_OUT "/rust-demo/release/rust-demo 1 1" },
    { "go", go_builds, TE_ARRAY_LEN(go_builds), "service-go", NULL },
    { "csharp", cs_builds, TE_ARRAY_LEN(cs_builds), "service-cs", NULL },
    { "c++", cpp_builds, TE_ARRAY_LEN(cpp_builds), "cpp-demo 1 1",
      "LD_LIBRARY_PATH=" H3_OUT ":$PWD/dist/lib " H3_OUT "/cpp-demo 1 1" },
    { "c", c_builds, TE_ARRAY_LEN(c_builds), "c-demo",
      "LD_LIBRARY_PATH=$PWD/dist/lib " H3_OUT "/c-demo" },
    { "python", py_builds, TE_ARRAY_LEN(py_builds), "python3 python/demo.py 1 1",
      "python3 python/demo.py 1 1" },
};

/** The command that starts a built service and asks it once. */
static void
service_cmd(char *buf, size_t size, const char *bin, unsigned port)
{
    snprintf(buf, size,
             "%s & P=$!; sleep 3; "
             "curl -sS -m 20 'http://127.0.0.1:%u" REQUEST "'; RC=$?; "
             "kill $P 2>/dev/null; wait $P 2>/dev/null; exit $RC",
             bin, port);
}

/** Run a command; false with @p why set when it fails. */
static bool
run_step(const char *label, const char *cmd, int timeout_s, bool need_out,
         char *log, size_t log_size, char *why, size_t why_size)
{
    res_t   r = { .kind = R_PASS };
    proc_t *p;
    int     n;
    char    code[48];

    log[0] = '\0';
    p = run_sh(&r, label, cmd, timeout_s);
    if (p == NULL)
    {
        snprintf(why, why_size, "did not finish: %s", r.msg);
        return false;
    }
    n = first_error_lines(p->err, p->out, N_ERR, log, log_size);
    (void)n;
    exit_code_str(p, code, sizeof(code));
    if (!WIFEXITED(p->status) || WEXITSTATUS(p->status) != 0)
    {
        ERROR("webdeps H3: %s: exit code %s, first %d error lines:\n%s",
              label, code, n, log);
        snprintf(why, why_size, "exit code %s: [%.250s]", code, log);
        return false;
    }
    if (need_out)
    {
        FILE *f = fopen(p->out, "r");
        int   c = f != NULL ? fgetc(f) : EOF;

        if (f != NULL)
            fclose(f);
        if (c == EOF)
        {
            snprintf(why, why_size, "exit code 0 but the output is empty");
            return false;
        }
    }
    return true;
}

int
main(int argc, char **argv)
{
    res_t   res = { .kind = R_PASS };
    char    log[N_ERR * 400 + 64];
    char    why[1000];
    char    summary[1300] = "";
    char    cmd[2300];
    char    label[48];
    unsigned n_fail = 0;
    size_t  i;
    size_t  j;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;

    mkdir(H3_OUT, 0755);
    setenv("C_DRIVER_SRC", C_DRIVER, 1);

    for (i = 0; i < TE_ARRAY_LEN(langs); i++)
    {
        const lang_t *l = &langs[i];
        bool          ok = true;
        char          svc[512];

        why[0] = '\0';
        for (j = 0; j < l->n_builds && ok; j++)
        {
            const build_t *b = &l->builds[j];
            char          *q;

            TEST_STEP("Build %s (%s) with its own tool", b->name, l->lang);
            snprintf(label, sizeof(label), "build-%.30s", b->name);
            for (q = label; *q != '\0'; q++)
            {
                if (*q == '/' || *q == '.' || *q == '+')
                    *q = '_';
            }
            ok = run_step(label, b->cmd, BUILD_TO, false, log, sizeof(log),
                          svc, sizeof(svc));
            if (!ok)
                snprintf(why, sizeof(why), "build of %s (%s) failed, %s",
                         b->name, b->src, svc);
            RING("webdeps H3 %s: build %s: %s", l->lang, b->name,
                 ok ? "exit code 0" : why);
            T_FINDING(ok ? TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH,
                      "example.build", b->name, "%s",
                      ok ? "built, exit code 0" : why);
        }

        if (ok)
        {
            TEST_STEP("Run the built %s demo (%s)", l->lang, l->demo_name);
            if (l->demo_cmd != NULL)
                snprintf(cmd, sizeof(cmd), "%s", l->demo_cmd);
            else if (strcmp(l->lang, "go") == 0)
                service_cmd(cmd, sizeof(cmd), "LD_LIBRARY_PATH=$PWD/dist/lib "
                            H3_OUT "/service-go", tab_port[GO]);
            else
                service_cmd(cmd, sizeof(cmd), "LD_LIBRARY_PATH=$PWD/dist/lib "
                            H3_OUT "/service-cs/service-cs", tab_port[CS]);
            snprintf(label, sizeof(label), "demo-%.30s", l->lang);
            ok = run_step(label, cmd, RUN_TO, true, log, sizeof(log), svc,
                          sizeof(svc));
            if (!ok)
                snprintf(why, sizeof(why), "built but the demo %s failed: %s",
                         l->demo_name, svc);
            RING("webdeps H3 %s: demo %s: %s", l->lang, l->demo_name,
                 ok ? "exit code 0, output not empty" : why);
        }

        RING("webdeps verdict H3 %s %s%s%.600s", l->lang,
             ok ? "PASS" : "FAIL", ok ? "" : ": ", ok ? "" : why);
        T_FINDING(ok ? TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH,
                  "example.language", l->lang, "H3 %s %s%s%s", l->lang,
                  ok ? "PASS" : "FAIL", ok ? "" : ": ", ok ? "" : why);
        if (ok)
            append(summary, sizeof(summary), "%s PASS; ", l->lang);
        else
        {
            n_fail++;
            append(summary, sizeof(summary), "%s FAIL (%.180s); ", l->lang,
                   why);
        }
    }

    if (n_fail > 0)
        res_set(&res, R_FAIL, "H3 FAIL: %u of %zu languages: %s", n_fail,
                TE_ARRAY_LEN(langs), summary);
    else
        res_set(&res, R_PASS, "H3 PASS: every language built and its demo "
                "ran with exit code 0 and output: %s", summary);

verdict:
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}

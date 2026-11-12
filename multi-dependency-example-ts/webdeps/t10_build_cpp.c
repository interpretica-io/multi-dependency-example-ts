/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t10_build_cpp, the C++ example builds and runs with g++ (settles H4)
 *
 * Build cppcore.cpp and demo.cpp with g++ (not tcc), run cpp-demo once and
 * check exit code 0 and the "result =" line. cppcore.cpp is also checked
 * alone with -fsyntax-only, to say whether the 'Parsing failed' report
 * is a real syntax error or a gap of the tool that made it.
 * The commands, their exit codes and the first 40 lines of their output are
 * in the test log; the verdict names H4.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t10_build_cpp"

#include "te_config.h"

#include "t10_build.h"

static const t10_step steps[] = {
    { "cppcore.cpp", "cpp/src/cppcore.cpp",
      "g++ -std=c++17 -Wall -Wextra -shared -fPIC -O2 -Icpp/include "
      "cpp/src/cppcore.cpp -o " H3_OUT "/libcppcore.so -Ldist/lib "
      "-lrustcore -lpycore -Wl,-rpath,$PWD/dist/lib" },
    { "demo.cpp", "cpp/src/demo.cpp",
      "g++ -std=c++17 -Wall -Wextra -O2 -Icpp/include cpp/src/demo.cpp "
      "-o " H3_OUT "/cpp-demo -L" H3_OUT " -lcppcore -Ldist/lib -lrustcore "
      "-Wl,-rpath," H3_OUT " -Wl,-rpath,$PWD/dist/lib" },
};

static const t10_lang lang = {
    "c++", { "g++" }, steps, TE_ARRAY_LEN(steps), "cpp-demo 1 1",
    "LD_LIBRARY_PATH=" H3_OUT ":$PWD/dist/lib " H3_OUT "/cpp-demo 1 1",
    NULL, 0, "result =", NULL,
};

int
main(int argc, char **argv)
{
    res_t res = { .kind = R_PASS };

    TEST_START;

    t10_run(&res, &lang);
    if (res.kind != R_SKIP)
        t10_parse_alone("cpp/src/cppcore.cpp", "g++ -std=c++17 "
                        "-fsyntax-only -Icpp/include cpp/src/cppcore.cpp");

    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}

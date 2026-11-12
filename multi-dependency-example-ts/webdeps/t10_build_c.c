/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t10_build_c, the C example builds and runs with gcc (settles H4)
 *
 * Build pycore.c with gcc (not tcc) and a small C driver that loads it, run
 * the driver once and check exit code 0 and the "py_weight() =" line.
 * pycore.c is also checked alone with -fsyntax-only, to say whether the
 * 'Parsing failed' report is a real syntax error or a gap of the tool
 * that made it.
 * The commands, their exit codes and the first 40 lines of their output are
 * in the test log; the verdict names H4.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t10_build_c"

#include "te_config.h"

#include "t10_build.h"

static const t10_step steps[] = {
    { "pycore.c", "python/src/pycore.c",
      "gcc -D_GNU_SOURCE -Wall -Wextra -shared -fPIC -O2 "
      "$(python3-config --includes) "
      "\"-DRING_PY_DIR=\\\"$PWD/python\\\"\" python/src/pycore.c "
      "-o " H3_OUT "/libpycore.so $(python3-config --ldflags --embed)" },
    { "c-demo.c", H3_OUT "/c-demo.c",
      "printf '%s' \"$C_DRIVER_SRC\" > " H3_OUT "/c-demo.c && "
      "gcc -Wall -O2 " H3_OUT "/c-demo.c -o " H3_OUT "/c-demo -ldl -lm" },
};

static const t10_lang lang = {
    "c", { "gcc", "python3-config" }, steps, TE_ARRAY_LEN(steps), "c-demo",
    "LD_LIBRARY_PATH=$PWD/dist/lib " H3_OUT "/c-demo",
    NULL, 0, "py_weight() =", NULL,
};

int
main(int argc, char **argv)
{
    res_t res = { .kind = R_PASS };

    TEST_START;

    t10_run(&res, &lang);
    if (res.kind != R_SKIP)
        t10_parse_alone("python/src/pycore.c", "gcc -D_GNU_SOURCE "
                        "-fsyntax-only $(python3-config --includes) "
                        "\"-DRING_PY_DIR=\\\"$PWD/python\\\"\" "
                        "python/src/pycore.c");

    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}

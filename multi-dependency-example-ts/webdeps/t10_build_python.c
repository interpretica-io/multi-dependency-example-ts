/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t10_build_python, the Python example byte-compiles and runs (settles H4)
 *
 * Byte-compile ring_stage.py and demo.py with python3, run demo.py once and
 * check exit code 0 and the "py-demo: result =" line.
 * The commands, their exit codes and the first 40 lines of their output are
 * in the test log; the verdict names H4.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t10_build_python"

#include "te_config.h"

#include "t10_build.h"

static const t10_step steps[] = {
    { "python", "python/*.py",
      "python3 -m py_compile python/ring_stage.py python/demo.py" },
};

static const t10_lang lang = {
    "python", { "python3" }, steps, TE_ARRAY_LEN(steps), "python3 demo.py 1 1",
    "python3 python/demo.py 1 1", NULL, 0, "py-demo: result =", NULL,
};

int
main(int argc, char **argv)
{
    res_t res = { .kind = R_PASS };

    TEST_START;

    t10_run(&res, &lang);

    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}

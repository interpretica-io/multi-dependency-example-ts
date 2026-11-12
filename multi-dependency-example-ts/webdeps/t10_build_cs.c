/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t10_build_cs, the C# examples build and run (settles H4)
 *
 * Build cscore and service-cs with dotnet (the build.sh lines), start
 * service-cs once, ask it once and check exit code 0 and "value=" in the
 * answer. Hardcoded endpoints of Program.cs:24, :34 and :78 go to the
 * report.
 * The commands, their exit codes and the first 40 lines of their output are
 * in the test log; the verdict names H4.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t10_build_cs"

#include "te_config.h"

#include "t10_build.h"

static const t10_step steps[] = {
    { "csharp", "csharp",
      "dotnet build csharp/cscore.csproj -c Release --nologo -v quiet "
      "-o " H3_OUT "/cscore" },
    { "service-cs", "web/service-cs",
      "dotnet build web/service-cs/webcs.csproj -c Release --nologo -v quiet "
      "-o " H3_OUT "/service-cs" },
};

static const t10_endpoints ep = { "web/service-cs/Program.cs",
                                  { 24, 34, 78 } };

static const t10_lang lang = {
    "csharp", { "dotnet" }, steps, TE_ARRAY_LEN(steps), "service-cs", NULL,
    H3_OUT "/service-cs/service-cs", CS, "value=", &ep,
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

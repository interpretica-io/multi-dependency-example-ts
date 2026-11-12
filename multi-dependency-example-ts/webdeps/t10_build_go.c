/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t10_build_go, the Go examples build and run (settles H4)
 *
 * Build libgocore and service-go with go build (the build.sh lines), start
 * service-go once, ask it once and check exit code 0 and "value=" in the
 * answer. Hardcoded endpoints of main.go:46, :51 and :87 go to the report.
 * The commands, their exit codes and the first 40 lines of their output are
 * in the test log; the verdict names H4.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t10_build_go"

#include "te_config.h"

#include "t10_build.h"

static const t10_step steps[] = {
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

static const t10_endpoints ep = { "web/service-go/main.go", { 46, 51, 87 } };

static const t10_lang lang = {
    "go", { "go" }, steps, TE_ARRAY_LEN(steps), "service-go", NULL,
    H3_OUT "/service-go", GO, "value=", &ep,
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

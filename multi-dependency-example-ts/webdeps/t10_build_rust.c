/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t10_build_rust, the Rust examples build and run (settles H4)
 *
 * Build rustcore, rust-demo and gateway-rs with cargo (the build.sh lines), run
 * rust-demo once and check exit code 0 and the "rust-demo: result =" line.
 * Hardcoded endpoints of main.rs:33, :34 and :36 go to the report.
 * The commands, their exit codes and the first 40 lines of their output are
 * in the test log; the verdict names H4.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t10_build_rust"

#include "te_config.h"

#include "t10_build.h"

static const t10_step steps[] = {
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

static const t10_endpoints ep = { "web/gateway-rs/src/main.rs",
                                  { 33, 34, 36 } };

static const t10_lang lang = {
    "rust", { "cargo", "rustc" }, steps, TE_ARRAY_LEN(steps),
    "rust-demo 1 1",
    "LD_LIBRARY_PATH=$PWD/dist/lib " H3_OUT "/rust-demo/release/rust-demo "
    "1 1",
    NULL, 0, "rust-demo: result =", &ep,
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

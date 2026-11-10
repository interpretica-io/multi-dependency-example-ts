# multi-dependency-example-ts

A [Test Environment](https://github.com/interpretica-io/test-environment)
suite for the **multi-dependency-example**: eight small projects in C++, Rust,
Go, C# and Python wired into two dependency cycles.

- A native **ring** (`cpp → rust → go → cs → py → cpp`). Each stage exports a C
  ABI and calls the next language, passing a value on until a hop counter runs
  out.
- An HTTP **web tier** (`gateway-rs → service-go → service-cs → gateway-rs`)
  that does the same over the network.

The suite tests the example and nothing else. It uses the `tsf-*` modules
that can say something about it: how it is built and linked, what it puts
on disk and in memory, what it exposes, how its services answer, how it
behaves under a fuzzer, inside other images and in a browser. It is written
for **maximum evidence**:

- **Charts.** Almost every test emits MI line graphs, over a thousand per
  run.
- **Report per test.** Each test fills one finding report, gated by a
  `min_severity` parameter.
- **Known-bad controls.** A control sits next to every audit. An audit that
  cannot find a planted defect fails on its own.
- **Deep checks.** Tests check exact values against a model, encode/decode
  round trips, and two independent views of the same fact. A test never just
  checks that something ran.

> The example ships as a corpus for review tools, with one always-true
> condition planted in every source file. Each one short-circuits a stage, so
> a value stops after the **first** stage of whichever cycle it enters. The
> tests are written against the *correct* behaviour. On the shipped example
> they fail with stable known-issue verdicts (recorded in `conf/trc.xml`) and
> pass once the defects are fixed.

## Groups

| Group | Modules | Tests |
|---|---|---|
| `ring` | suite model (`lib/tsapi_mde_ring`) | `propagation` (72 it.), `reference`, `sweep`, `determinism`, `entry_matrix`: every stage line checked against a reference model of the five formulas |
| `web` | suite (`lib/tsapi_mde_web`) | `cycle`, `latency`, `contract`, `robustness` |
| `webdeps` | tsf-cybersec (netexpose, egress, binscan) | `h1_gateway_bad_request` (H1), `h2_stalled_peer` (H2), `h3_csharp_bad_input` (H3), `h4_go_contract` (H4): standalone plain TCP/HTTP clients on `webdeps_lib.h`, each starting its service, waiting for the listen port and ending with `H<n> PASS` or `H<n> FAIL` plus the status code or time it measured (`service did not start: <service>` when the port stays closed); `sec_binscan_netexpose_egress` (`SEC` verdict, no hypothesis); plus `s_rust`, `s_go`, `s_cs`, `s_cpp`, `s_c`: one smoke test per language, settling no hypothesis |
| `graph` | binutils | `links`, `symbols`, `cycle_closure` (DOT graph artifact) |
| `binary` | tsf-cybersec (binscan, objdump) | `hardening`, `hardening_matrix`, `disasm_defect`, `linked_libs` |
| `devtool` | tsf-devtool | `rebuild_pycore`, `make_stub`, `reproducible` |
| `package` | tsf-package | `dut_runtime_deps` |
| `fs` | tsf-fs | `perm_audit`, `secrets`, `integrity` |
| `memmap` | tsf-memorymap | `elf`, `proc` |
| `exposure` | tsf-cybersec (netexpose, egress, sniffrules, frida) | `listeners`, `reachability`, `egress`, `sniff`, `frida`, `h3_endpoints` (hypothesis id SEC-H3, no longer the H3 of the web tests) |
| `http` | tsf-http | `headers`, `methods`, `redirects`, `load_curve` |
| `fuzz` | tsf-fuzz | `ring_abi` (libFuzzer + ASan on the ring's C ABI), `replay` |
| `container` | tsf-container | `ring_inside` (the ring walked inside images it was not built for) |
| `browser` | tsf-playwright | `walk_page` (screenshot, HAR, trace), `canary`, `network_shape`, `pw_project` |

The `exposure/sniff`, `exposure/frida`, `browser` and `container` tests need
prerequisites that the current agent lacks; they stay skipped and no
hypothesis is read from them.

What the container cannot do (capture on loopback, Frida) leads to a `SKIP`
with a concrete reason, never a failure.

## How it runs

The tests are engine-side orchestrators. Everything that touches the
example runs on the Test Agent `Agt_A` through job factories and RPC.

The example has to be native to the agent. `scripts/build-dut.sh` builds a
private Linux copy under `build/mde-<os>-<arch>` when the tree holds binaries
for another OS. The example itself is not modified; a thin `cc` wrapper makes
its macOS-only `build.sh` link on Linux.

```sh
git clone https://github.com/interpretica-io/test-environment ../test-environment
./scripts/run.sh docker guess --cfg=localhost     # the supported path
```

`TE_TS_MDE_SRC` points the suite at another example tree.

The build container (`scripts/docker/build/Dockerfile`) carries the example's
toolchains (cmake, cargo, go, .NET 9 NativeAOT, python3-dev, clang with
libFuzzer) and the tools the tests drive: binutils, tcpdump, Docker,
Playwright + Chromium.

Two platforms are built: the engine plus every TAPI on `default`, and the agent
on `linux_ta`. This keeps static agent copies of engine-only TAPIs out of the
build.

Optional environment: `TE_TS_MDE_BUILD=0` to skip the private build, and
`TE_TS_MDE_REPORTS=0` to skip reports.

## Reports

After the run, `scripts/reports.sh` writes everything into `reports/`.
Start with `reports/index.html`.

| File | What |
|---|---|
| `html/` | TE multi-page HTML log; RGT draws every MI chart |
| `log.txt`, `json/`, `mi.txt` | text, JSON and machine-interface logs |
| `bublik.json` | the run as Bublik imports it |
| `trc-full.html`, `trc-brief.html`, `trc-bad.html`, `trc.xml` | TRC reports against `conf/trc.xml` |
| `charts/*.svg` | every MI line graph rendered offline (`scripts/mde_reports.py`) |
| `measurements.csv/.json` | every MI measurement, flattened |
| `findings.csv` | every audit finding (severity, check, subject, detail) |
| `artifacts.csv` | every test artifact |
| `junit.xml` | per-iteration results for CI dashboards |
| `files/` | files fetched from the agent: Chromium screenshots, Playwright traces, HAR |
| `summary.md`, `index.html` | totals per group, known issues, skips, chart gallery |

## Known issues

`conf/known-issues.json` lists what is expected to fail and why.
`scripts/trc-known-issues.py reports/mi.txt conf/known-issues.json
conf/trc.xml` rebuilds the TRC database from a run. Anything that fails and
is not on the list stays an unexpected result.

The entries fall into two kinds.

**The example (DUT).**
- **Injected defect.** It shows up in ring, web, browser and HTTP body
  depth, inside other container images, in the machine code
  (`binary.dead-call`), and in the linkage (the dead calls let the linker
  drop `libcppcore → librustcore` and `librustcore → libgocore`).
- **Linux portability.** `build.sh` is macOS-only. On glibc,
  `ring_stage.py`'s `ctypes.CDLL(None)` cannot see `go_weight`, so the C++
  stage breaks its own formula. NativeAOT needs a runtime identifier.
- **Build posture.** `service-go` is not PIE, and there are relative
  RUNPATHs. The web tier answers TRACE and sends no security headers.

**Environment.** The amd64 container runs under Rosetta on Apple silicon, and
its code cache shows as W+X mappings in `memmap/proc`.

## Layout

```
conf/                       dispatcher configuration
  builder.conf              two platforms, the tsf-* repositories in use
  external.yml              the tsf-* repositories and their references
  known-issues.json         expected failures and why
  trc.xml                   expected results (generated from known-issues.json)
multi-dependency-example-ts/
  lib/                      session, DUT layout, ring model, web tier, MI charts,
                            the per-test report with known-bad controls
  <group>/                  one directory per group above
scripts/
  run.sh                    entry point (builds the DUT copy, runs, reports)
  build-dut.sh              native build of the example for the agent's host
  reports.sh, mde_reports.py, trc-known-issues.py
  docker/build/Dockerfile   toolchains and tools
```

# multi-dependency-example-ts

A [Test Environment](https://github.com/interpretica-io/test-environment)
suite for the **multi-dependency-example**: eight small projects in C++, Rust,
Go, C# and Python wired into two dependency cycles.

- A native **ring** (`cpp → rust → go → cs → py → cpp`). Each stage exports a C
  ABI and calls the next language, passing a value on until a hop counter runs
  out.
- An HTTP **web tier** (`gateway-rs → service-go → service-cs → gateway-rs`)
  that does the same over the network.

The suite drives the built example with **every `tsf-*` module of the TE
catalog** (31 of 32; see [Known issues](#known-issues)). It is written for
**maximum evidence**:

- **Charts.** Almost every test emits MI line graphs, in the order of 1 500
  graphs and 16 000 measurements per run.
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
| `graph` | binutils | `links`, `symbols`, `cycle_closure` (DOT graph artifact) |
| `package` | tsf-package | `inventory`, `ensure_rollback`, `dut_runtime_deps` |
| `devtool` | tsf-devtool | `compile_probe`, `rebuild_pycore`, `make_stub`, `reproducible` |
| `kernel` | tsf-kernel | `posture`, `kmsg_window`, `resources`, `modules`, `ktrace` |
| `fs` | tsf-fs | `perm_audit`, `secrets`, `integrity`, `mounts`, `health` |
| `memmap` | tsf-memorymap | `elf`, `proc`, `ram` |
| `binary` | tsf-cybersec (binscan, objdump) | `hardening`, `hardening_matrix`, `disasm_defect`, `linked_libs` |
| `exposure` | tsf-cybersec (netexpose, egress, sniffrules, frida) | `listeners`, `reachability`, `egress`, `sniff`, `frida` |
| `http` | tsf-http | `headers`, `methods`, `redirects`, `load_curve` |
| `tls` | tsf-tls | `front`, `client_check`, `cert_matrix` |
| `time` | tsf-time (+tls, http) | `shim_check`, `ring_under_time`, `cert_expiry_travel`, `web_under_time` |
| `mqtt` | tsf-mqtt | `ring_bus`, `broker_audit`, `retained` |
| `smb` | tsf-smb | `serve_dist`, `server_audit` (the group starts its own smbd) |
| `printing` | tsf-printing | `ring_report_job`, `print_audit`, `caps` (the group starts its own cupsd) |
| `cwmp` | tsf-cwmp | `inform_codec`, `acs_session`, `connection_request` |
| `container` | tsf-container | `ring_inside`, `posture`, `copy_roundtrip` |
| `emu` | tsf-emu | `qmp_lifecycle`, `snapshot`, `serial_console` (a 32-bit guest built on the agent) |
| `fuzz` | tsf-fuzz | `ring_abi` (libFuzzer + ASan on the ring's C ABI), `replay` |
| `iot` | tsf-802154, tsf-lorawan, tsf-sdr, tsf-can, tsf-bluetooth | `frames_802154`, `frames_lorawan`, `sdr`, `can_bus`, `bluetooth` |
| `net` | tsf-tunnel, tsf-wifi | `vpn_tree`, `wifi_tree`, `wg_tunnel`, `ipsec_builder` |
| `bench` | tsf-jtag, tsf-flash, tsf-power | `jtag_dummy`, `flash_emulated` (flashrom's emulated W25Q128FV), `power_window`, `power_switch` |
| `browser` | tsf-playwright | `walk_page` (screenshot, HAR, trace), `canary`, `network_shape`, `pw_project` |
| `mobile` | tsf-android, tsf-apple, tsf-appium | `stack_presence`, `devices`, `rpc_roundtrip` |
| `ai` | tsf-ai | `grade_trace`, `grade_screenshot`, `stream` (need `TSF_AI_KEY`) |
| `dummy` | tsf-dummy | `greeting` |

Hardware the container does not have (radios, CAN, JTAG targets, power
instruments, phones, KVM) and tools it cannot use (dmesg, tracefs) lead to a
`SKIP` with a concrete reason, never a failure.

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
toolchains (cmake, cargo, go, .NET 9 NativeAOT, python3-dev) and the tools the
modules drive: openssl, mosquitto, samba, cups, faketime, qemu, afl++/libFuzzer,
openocd, flashrom, rtl-433, can-utils, bluez, wireguard, Playwright + Chromium,
appium, and others.

Two platforms are built: the engine plus every TAPI on `default`, and the agent
on `linux_ta`. This keeps static agent copies of engine-only TAPIs out of the
build.

Optional environment: `TSF_AI_KEY`, `TSF_AI_PROVIDER` and `TSF_AI_MODEL` for
the `ai` group, `TE_TS_MDE_BUILD=0` to skip the private build, and
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

The entries fall into three kinds.

**The example (DUT).**
- **Injected defect.** It shows up in ring, web, browser, MQTT and HTTP body
  depth, in the machine code (`binary.dead-call`), and in the linkage (the
  dead calls let the linker drop `libcppcore → librustcore` and
  `librustcore → libgocore`).
- **Linux portability.** `build.sh` is macOS-only. On glibc,
  `ring_stage.py`'s `ctypes.CDLL(None)` cannot see `go_weight`, so the C++
  stage breaks its own formula. NativeAOT needs a runtime identifier.
- **Build posture.** `service-go` is not PIE, and there are relative
  RUNPATHs. The web tier answers TRACE and sends no security headers.

**Modules (upstream).** The deep checks found these defects in the modules
themselves:
- **tsf-802154:** at MIC-only levels the MIC is never verified, and the header
  is not authenticated.
- **tsf-sdr:** a missing capture reads as an empty one with rtl_433 22.11.
- **tsf-kernel:** `tapi_kmod_list` fails on a `-` use count.
- **tsf-tunnel:** `ta_vpn` cannot be linked into an agent, so the net VPN
  tests fail.
- **tsf-cwmp:** `tapi_cwmp_acs_session_fini()` frees completed transfers
  twice. The test works around it.
- **tsf-fuzz:** libFuzzer's "deadly signal" is not triaged. The harness uses
  ASan `handle_abort=1`.

The log formatter also rejects the `%0*` widths in
`tapi_802154_frame_log()` and `tapi_can_frame_log()`.

**Environment.** The amd64 container runs under Rosetta on Apple silicon, and
its code cache shows as W+X mappings in `memmap/proc`.

## Layout

```
conf/                       dispatcher configuration
  builder.conf              two platforms, all tsf-* repositories
  external.yml              the tsf-* catalog
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

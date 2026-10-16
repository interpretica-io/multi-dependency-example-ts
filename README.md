# multi-dependency-example-ts

A [Test Environment](https://github.com/interpretica-io/test-environment) suite
for the **multi-dependency-example** — eight small projects in C++, Rust, Go, C#
and Python wired into two dependency cycles:

- a native **ring** (`cpp → rust → go → cs → py → cpp`) where each stage exports
  a C ABI and calls the next language, passing a value on until a hop counter
  runs out;
- an HTTP **web tier** (`gateway-rs → service-go → service-cs → gateway-rs`)
  that does the same over the network.

A value that enters either cycle must come back having visited **every** stage.
That single invariant — *propagation depth equals `hops + 1`* — is what this
suite checks, and it is exactly what the example's injected defect breaks.

> The example ships as a corpus for review tools, with one trivial always-true
> condition (`if (5)`, `if true`, `if True`, `if (1)`) planted in every source
> file. Each one short-circuits a stage, so a value stops after the **first**
> stage of whichever cycle it enters. These tests are written against the
> *correct* behaviour, so on the as-shipped example they fail with stable
> known-issue verdicts (recorded in `conf/trc.xml`) and pass once the defects
> are fixed.

## What it checks

| Group | Test | Checks | On the shipped example |
|---|---|---|---|
| `ring`  | `propagation` | run `cpp-demo` / `rust-demo` / the Python demo; stages visited = `hops+1` | FAILED (stops at 1) |
| `ring`  | `reference`   | `cpp-demo 1 7` → `20.0735` (README oracle) | FAILED (returns ~2.6) |
| `web`   | `cycle`       | one `GET /ring` walks the HTTP cycle; node steps = `hops+1` | FAILED (stops at 1) |
| `graph` | `links`       | `otool -L` / `nm -u`: the ring's load-time edges and the undefined `cpp_weight` | PASSED (linkage is correct) |

The `graph` group tests properties of the *build*, not the arithmetic, so the
defect does not affect it.

## How it runs

The suite drives the already-built example as **programs on a Test Agent**
(`Agt_A`, started on the engine host for the `localhost` configuration):

- the demos and `curl` are short-lived — run them, read stdout, check it;
- the three web services are long-running — start them, wait for each to
  announce its URL, send one request, then stop them.

Nothing links the example into the test binaries: the device under test is the
built artifacts, located at run time.

### Where the example is

The tests read `TE_TS_MDE_SRC` (exported by `scripts/run.sh`, default: the
sibling `../multi-dependency-example`) and look under it for `dist/bin`,
`dist/lib` and `python/demo.py`. **Build the example first** with its own
`./build.sh`. When it is missing or unbuilt, every test **skips** rather than
fails — so a run on a host that cannot build it (e.g. the Linux build
container) is clean.

## Running

```sh
# clone TE as a sibling
git clone https://github.com/interpretica-io/test-environment ../test-environment

# build the example under test (its own toolchains: cmake, cargo, go, .NET, python3-embed)
( cd ../multi-dependency-example && ./build.sh )

# run the suite
./scripts/run.sh guess --cfg=localhost          # on the host
./scripts/run.sh docker guess --cfg=localhost   # in the TE build container
```

Point the suite at an example built elsewhere with
`TE_TS_MDE_SRC=/path/to/multi-dependency-example ./scripts/run.sh ...`.

Results:

```sh
cat build/log.txt         # plain-text log: PASSED/FAILED per iteration + verdicts
./scripts/html-log.sh     # HTML report
```

On the as-shipped example the `ring` and `web` tests report **known issues**
(matched by `conf/trc.xml`) rather than regressions, `graph` passes, and the
numbers in the verdicts spell out how far the value actually travelled.

## Layout

```
conf/                         dispatcher configuration
  builder.conf                TE + agent (ta_rpcprovider) to build
  rcf.conf                    one localhost agent, Agt_A
  tester.conf                 binds the suite to ${TE_TS_MULTIDEP}
  cs.conf.local               /local tree + Agt_A rpcprovider binding
  trc.xml                     expected results (known-issue verdicts)
multi-dependency-example-ts/  suite source (dir name == suite name)
  lib/tsapi_mde.{c,h}         agent session + "run a program, read it back"
  lib/tsapi_evo.{c,h}         charts + analysis hints
  ring/                       propagation + reference tests
  web/                        the HTTP cycle test
  graph/                      the build-time linkage test
scripts/run.sh                entry point (exports TE_TS_MDE_SRC, runs dispatcher)
```

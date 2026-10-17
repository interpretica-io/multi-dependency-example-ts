#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Maxim Menshikov
#
# Make sure the multi-dependency-example under test is built for the host
# the agent runs on, and print the root the suite should test.
#
# The example's own ./build.sh writes into its source tree, and the tree
# is shared between the developer's host (macOS: Mach-O) and the Linux
# build container (ELF). When the binaries in the tree cannot run here,
# a private copy is built under the suite's build directory instead, so
# neither side overwrites the other.
#
# Usage: build-dut.sh <example source> <private build root>
# Prints the path to use as TE_TS_MDE_SRC on stdout; everything else goes
# to stderr. Never fails the run: when the example cannot be built the
# source path is printed unchanged and the groups skip.
#
# TE_TS_MDE_BUILD=0 turns the private build off.

SRC="$1"
PRIV="$2"

log() { echo "build-dut: $*" >&2; }

if [ -z "${SRC}" ] || [ ! -d "${SRC}" ] ; then
    log "no example at '${SRC}'"
    echo "${SRC}"
    exit 0
fi

runnable() {
    # The demo exits 0 and prints its result line when the binary is
    # native here and every library it links can be found.
    local root="$1"
    [ -x "${root}/dist/bin/cpp-demo" ] || return 1
    "${root}/dist/bin/cpp-demo" 1 1 2>/dev/null | grep -q "result ="
}

if runnable "${SRC}" ; then
    log "using the example built in place: ${SRC}"
    echo "${SRC}"
    exit 0
fi

if [ "${TE_TS_MDE_BUILD:-1}" = "0" ] ; then
    log "TE_TS_MDE_BUILD=0: not building a private copy"
    echo "${SRC}"
    exit 0
fi

mkdir -p "${PRIV}"
LOG="${PRIV}.log"
log "building a private copy for $(uname -s)/$(uname -m) in ${PRIV}"
rsync -a --delete \
      --exclude dist --exclude target --exclude 'cpp/build' \
      --exclude bin --exclude obj --exclude out --exclude __pycache__ \
      "${SRC}/" "${PRIV}/" >&2

if runnable "${PRIV}" ; then
    log "private copy already built"
    echo "${PRIV}"
    exit 0
fi

# build.sh is written on macOS: its two plain "cc" stages pass
# -Wl,-install_name,@rpath/<lib>, which GNU ld does not know, and the C#
# stand-in uses RTLD_DEFAULT, which glibc defines only under _GNU_SOURCE.
# Everything else in it already branches on the OS. A "cc" first in PATH
# translates the one and adds the other, so the example itself is built
# unchanged. (That the example does not build on Linux as shipped is
# itself a finding; devtool and graph see the result.)
SHIM="${PRIV}.cc-shim"
mkdir -p "${SHIM}"
cat > "${SHIM}/cc" <<SHIM_EOF
#!/bin/sh
for a in "\$@" ; do
    shift
    case "\$a" in
        -Wl,-install_name,@rpath/*)
            set -- "\$@" "-Wl,-soname,\${a#-Wl,-install_name,@rpath/}" ;;
        *)  set -- "\$@" "\$a" ;;
    esac
done
exec $(command -v cc) -D_GNU_SOURCE "\$@"
SHIM_EOF
chmod +x "${SHIM}/cc"
case "$(uname -s)" in
    Darwin) BUILD_PATH="${PATH}" ;;
    *)      BUILD_PATH="${SHIM}:${PATH}"
            # build.sh passes -r to dotnet publish only on macOS; NativeAOT
            # needs a runtime identifier, and MSBuild takes properties from
            # the environment.
            case "$(uname -m)" in
                aarch64|arm64) export RuntimeIdentifier=linux-arm64 ;;
                *)             export RuntimeIdentifier=linux-x64 ;;
            esac ;;
esac

if ( cd "${PRIV}" && PATH="${BUILD_PATH}" ./build.sh ) > "${LOG}" 2>&1 ; then
    log "built (log: ${LOG})"
else
    # NativeAOT is the stage most likely to be missing on a build host;
    # the example has a C stand-in of the same ABI for exactly that case.
    log "full build failed, retrying with RING_SKIP_CSHARP=1 (log: ${LOG})"
    ( cd "${PRIV}" && PATH="${BUILD_PATH}" RING_SKIP_CSHARP=1 ./build.sh ) \
        >> "${LOG}" 2>&1 || log "build failed - the groups will skip"
fi

if runnable "${PRIV}" ; then
    echo "${PRIV}"
else
    echo "${SRC}"
fi

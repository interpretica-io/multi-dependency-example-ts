#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 midair <midair@localhost>
#
# One-time setup of the throwaway container, run as root before the suite is
# built. Installs everything the groups need so that no prologue has to:
# the C, C++, Go, Rust and .NET toolchains, node, npm and the TypeScript
# tools, the binary inspection tools and the network tools. Safe to run again.
#
# Environment: MIDAIR_SUITE_DIR (this suite), TE_BASE, MIDAIR_PROJECT_DIR
# (the checkout of the project under test, when there is one).
set -e

fail() { echo "midair-setup: FAILED: $*" >&2; exit 1; }

SUITE="${MIDAIR_SUITE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ENSURE="${SUITE}/scripts/ensure-web-deps.sh"
[ -f "${ENSURE}" ] || fail "${ENSURE} is missing"

if [ "$(id -u)" != 0 ] && ! command -v sudo >/dev/null 2>&1; then
    fail "not root and no sudo: cannot install packages"
fi

# node, npm and tsc come first and on their own: the TypeScript tests need
# them even when a later optional install (.NET, for instance) fails.
export DEBIAN_FRONTEND=noninteractive
SUDO=
[ "$(id -u)" = 0 ] || SUDO="sudo -n"
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    echo "midair-setup: installing nodejs and npm"
    ${SUDO} apt-get update >&2 || fail "apt-get update failed"
    ${SUDO} apt-get install -y nodejs npm >&2 ||
        fail "apt-get install nodejs npm failed"
fi
command -v node >/dev/null 2>&1 || fail "node is missing after the install"
command -v npm >/dev/null 2>&1 || fail "npm is missing after the install"
if ! command -v tsc >/dev/null 2>&1; then
    echo "midair-setup: installing typescript with npm"
    ${SUDO} npm install -g typescript >&2 ||
        fail "npm install -g typescript failed"
    hash -r
fi
command -v tsc >/dev/null 2>&1 || fail "tsc is missing after npm install -g typescript"
echo "midair-setup: node -v: $(node -v)"
echo "midair-setup: npm -v: $(npm -v)"
echo "midair-setup: tsc -v: $(tsc -v)"

# A directory the installer can use as the example root even when the
# project checkout is not there (it only reads it to decide on a build).
ROOT="${MIDAIR_PROJECT_DIR:-}"
if [ -z "${ROOT}" ] || [ ! -d "${ROOT}" ]; then
    ROOT="$(mktemp -d /tmp/midair-setup-root.XXXXXX)"
    trap 'rm -rf "${ROOT}"' EXIT
fi

echo "midair-setup: installing the toolchains and tools (base, exposure, ts)"
# 'soft' turns a failed optional install (.NET) into a warning: the tests
# that need it then report the cause themselves.
"${ENSURE}" "${ROOT}" base exposure ts soft ||
    fail "scripts/ensure-web-deps.sh base exposure ts failed (see above)"

# The probe of ensure-web-deps.sh stays as it is. Where ts-node cannot run a
# trivial file in the ts/ or web/service-ts directory of the project, install
# ts-node and typescript there and print the versions.
PROJ="${MIDAIR_PROJECT_DIR:-}"
for d in ts web/service-ts; do
    dir="${PROJ}/${d}"
    if [ -z "${PROJ}" ] || [ ! -d "${dir}" ]; then
        echo "midair-setup: ${d}: no such directory in the project, ts-node probe not run"
        continue
    fi
    PT="$(mktemp -d /tmp/midair-tsprobe.XXXXXX)"
    echo 'const n: number = 41; console.log(n + 1);' > "${PT}/t.ts"
    if [ "$(cd "${dir}" && npx --no-install ts-node "${PT}/t.ts" 2>&1)" != 42 ]; then
        echo "midair-setup: ${d}: ts-node probe failed on node $(node -v), installing ts-node and typescript there"
        (cd "${dir}" && npm install --no-save ts-node typescript @types/node) >&2 ||
            echo "midair-setup: WARNING: npm install of ts-node and typescript in ${d} failed" >&2
    else
        echo "midair-setup: ${d}: ts-node probe passed"
    fi
    rm -rf "${PT}"
    echo "midair-setup: ${d}: ts-node $(cd "${dir}" && npx --no-install ts-node --version 2>&1 | head -n 1)"
    echo "midair-setup: ${d}: tsc $(cd "${dir}" && npx --no-install tsc --version 2>&1 | head -n 1)"
done

# The Go toolchain (go.mod wants 1.21 or newer) and the .NET 9 SDK build the
# go-demo and cs-demo references. Each is installed here and checked: a
# missing one fails the setup and is named, it is not left for a test to find.
go_ok() {
    local v
    command -v go >/dev/null 2>&1 || return 1
    v="$(go version 2>/dev/null | sed -n 's/.* go\([0-9]*\)\.\([0-9]*\).*/\1 \2/p')"
    [ -n "${v}" ] || return 1
    set -- ${v}
    [ "$1" -gt 1 ] || [ "$2" -ge 21 ]
}
if ! go_ok; then
    echo "midair-setup: installing the Go toolchain"
    ${SUDO} apt-get update >&2 || fail "apt-get update failed"
    ${SUDO} apt-get install -y golang-go >&2 || echo "midair-setup: apt-get install golang-go failed" >&2
    if ! go_ok; then
        case "$(uname -m)" in aarch64|arm64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac
        GOV="$(curl -fsSL 'https://go.dev/VERSION?m=text' 2>/dev/null | head -n 1)"
        [ -n "${GOV}" ] || GOV=go1.22.5
        curl -fsSL "https://go.dev/dl/${GOV}.linux-${GOARCH}.tar.gz" -o /tmp/go-dist.tgz &&
            ${SUDO} rm -rf /usr/local/go &&
            ${SUDO} tar -C /usr/local -xzf /tmp/go-dist.tgz &&
            ${SUDO} ln -sf /usr/local/go/bin/go /usr/local/bin/go &&
            ${SUDO} ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt ||
            echo "midair-setup: the download of ${GOV} for ${GOARCH} failed" >&2
        hash -r
    fi
fi
go_ok || fail "no Go toolchain 1.21 or newer (go version: $(go version 2>&1))"
echo "midair-setup: $(go version)"

have_dotnet9() {
    command -v dotnet >/dev/null 2>&1 &&
        dotnet --list-sdks 2>/dev/null | grep -q '^9\.'
}
if ! have_dotnet9; then
    echo "midair-setup: installing the .NET 9 SDK"
    ${SUDO} apt-get update >&2 || fail "apt-get update failed"
    if ! ${SUDO} apt-get install -y dotnet-sdk-9.0 >&2; then
        curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh &&
            ${SUDO} bash /tmp/dotnet-install.sh --channel 9.0 \
                --install-dir /usr/share/dotnet >&2 &&
            ${SUDO} ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet ||
            echo "midair-setup: dotnet-install.sh failed" >&2
        hash -r
    fi
fi
have_dotnet9 || fail "no .NET 9 SDK (dotnet --list-sdks: $(dotnet --list-sdks 2>&1 | tr '\n' ' '))"
echo "midair-setup: dotnet $(dotnet --version)"

# The 26 tools the suite prologue counts, each with its Debian package. Any
# that is still missing after the install is named and fails the setup.
declare -A TOOLPKG=(
    [python3]=python3 [python3-config]=python3-dev [curl]=curl
    [readelf]=binutils [nm]=binutils [objdump]=binutils [strings]=binutils
    [ldd]=libc-bin [dpkg]=dpkg [sha256sum]=coreutils [clang]=clang
    [gcc]=build-essential [tcc]=tcc [make]=build-essential
    [llvm-symbolizer]=llvm [docker]=docker.io [node]=nodejs [npx]=npm
    [lsof]=lsof [ss]=iproute2 [tcpdump]=tcpdump
    [file]=file [g++]=build-essential [timeout]=coreutils [cmp]=diffutils
)
TOOLPKGS=
for c in "${!TOOLPKG[@]}"; do
    command -v "$c" >/dev/null 2>&1 || TOOLPKGS="${TOOLPKGS} ${TOOLPKG[$c]}"
done
if [ -n "${TOOLPKGS}" ]; then
    echo "midair-setup: installing${TOOLPKGS}"
    ${SUDO} apt-get update >&2 || fail "apt-get update failed"
    for pk in $(echo ${TOOLPKGS} | tr ' ' '\n' | sort -u); do
        ${SUDO} apt-get install -y "${pk}" >&2 ||
            echo "midair-setup: apt-get install ${pk} failed" >&2
    done
fi
# llvm-symbolizer is often installed only with a version suffix.
if ! command -v llvm-symbolizer >/dev/null 2>&1; then
    LS="$(ls /usr/bin/llvm-symbolizer-* /usr/lib/llvm-*/bin/llvm-symbolizer 2>/dev/null | head -n 1)"
    [ -z "${LS}" ] || ${SUDO} ln -sf "${LS}" /usr/local/bin/llvm-symbolizer
fi
if ! command -v frida >/dev/null 2>&1; then
    echo "midair-setup: installing frida-tools with pip"
    ${SUDO} apt-get install -y python3-pip >&2 || true
    pip3 install frida-tools >&2 ||
        pip3 install --break-system-packages frida-tools >&2 ||
        echo "midair-setup: pip install frida-tools failed" >&2
    hash -r
fi
TOOLMISS=
for c in python3 python3-config curl readelf nm objdump strings ldd dpkg \
         sha256sum clang gcc tcc make llvm-symbolizer docker node npx lsof \
         ss tcpdump frida file g++ timeout cmp; do
    command -v "$c" >/dev/null 2>&1 || TOOLMISS="${TOOLMISS} $c"
done
[ -z "${TOOLMISS}" ] || fail "missing after the install:${TOOLMISS}"
echo "midair-setup: all 26 tools of the suite prologue are present"

# cmp, pkill and timeout are used by the ts_example tests.
for c in cmp pkill timeout; do
    if ! command -v "$c" >/dev/null 2>&1; then
        echo "midair-setup: installing diffutils, procps and coreutils"
        ${SUDO} apt-get update >&2 || fail "apt-get update failed"
        ${SUDO} apt-get install -y diffutils procps coreutils >&2 ||
            fail "apt-get install diffutils procps coreutils failed"
        break
    fi
done
for c in cmp pkill timeout; do
    command -v "$c" >/dev/null 2>&1 || fail "$c is missing after the install"
done

for c in node npm gcc g++ make go cargo python3 curl tar; do
    command -v "$c" >/dev/null 2>&1 || fail "$c is still missing after the install"
done
# Report the three tools again after the rest of the install, and fail when
# any of them has gone missing or does not run.
for c in node npm tsc; do
    command -v "$c" >/dev/null 2>&1 || fail "$c is missing at the end of the setup"
done
echo "midair-setup: node -v: $(node -v)" || fail "node -v failed"
echo "midair-setup: npm -v: $(npm -v)" || fail "npm -v failed"
echo "midair-setup: tsc -v: $(tsc -v)" || fail "tsc -v failed"
echo "midair-setup: $(go version 2>&1)"
# Leave a marker so that the ts_example prologue can tell whether this script
# ran on the machine where the tests run, before them.
{
    echo "node $(node --version)"
    echo "npm $(npm --version)"
    echo "tsc $(tsc --version)"
    date -u +%Y-%m-%dT%H:%M:%SZ
} > /var/tmp/midair-setup.done 2>/dev/null ||
    echo "midair-setup: WARNING: cannot write /var/tmp/midair-setup.done"
echo "midair-setup: done"

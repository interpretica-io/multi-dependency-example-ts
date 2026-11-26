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

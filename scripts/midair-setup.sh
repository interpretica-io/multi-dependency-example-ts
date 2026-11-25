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
echo "midair-setup: node $(node --version), npm $(npm --version), $(go version 2>&1)"
echo "midair-setup: done"

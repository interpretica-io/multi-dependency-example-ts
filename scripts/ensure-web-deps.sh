#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 midair <midair@localhost>
#
# Make sure the toolchains the example under test needs are installed on the
# agent and that the web tier and the C/C++ demos are built, building them in
# place when they are not. Run by the webdeps group prologue.
#
# Usage: ensure-web-deps.sh <example root>
# Exit status 0 when everything is in place; otherwise 1 and a line starting
# with "ensure-web-deps:" says what went wrong.

ROOT="$1"
FAILED=0

die() { echo "ensure-web-deps: $*" >&2; exit 1; }

[ -n "${ROOT}" ] && [ -d "${ROOT}" ] || die "no example at '${ROOT}'"

SUDO=
[ "$(id -u)" = "0" ] || SUDO="sudo -n"

# command -> Debian/Ubuntu package
declare -A PKG=(
    [gcc]=build-essential [g++]=build-essential [make]=build-essential
    [cmake]=cmake [go]=golang-go [cargo]=cargo [rustc]=rustc
    [python3-config]=python3-dev [clang]=clang [ss]=iproute2
    [readelf]=binutils [curl]=curl [rsync]=rsync
)

missing_pkgs() {
    local c
    for c in "${!PKG[@]}" ; do
        command -v "$c" >/dev/null 2>&1 || echo "${PKG[$c]}"
    done | sort -u
}

PKGS="$(missing_pkgs | tr '\n' ' ')"
if [ -n "${PKGS}" ] ; then
    echo "ensure-web-deps: installing ${PKGS}"
    export DEBIAN_FRONTEND=noninteractive
    ${SUDO} apt-get update >&2 &&
        ${SUDO} apt-get install -y ${PKGS} zlib1g-dev >&2 ||
        die "apt-get install ${PKGS} failed"
fi
for c in "${!PKG[@]}" ; do
    command -v "$c" >/dev/null 2>&1 || die "$c is still missing after the install"
done

if ! command -v dotnet >/dev/null 2>&1 ; then
    echo "ensure-web-deps: installing the .NET SDK"
    export DEBIAN_FRONTEND=noninteractive
    if ! ${SUDO} apt-get install -y dotnet-sdk-8.0 >&2 2>&1 ; then
        curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh &&
            ${SUDO} bash /tmp/dotnet-install.sh --channel 8.0 \
                --install-dir /usr/share/dotnet >&2 &&
            ${SUDO} ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet ||
            die "cannot install the .NET SDK (apt and dotnet-install.sh failed)"
    fi
    command -v dotnet >/dev/null 2>&1 || die "dotnet is still missing after the install"
fi

built() {
    [ -x "${ROOT}/dist/bin/$1" ]
}

if built cpp-demo && built gateway-rs && built service-go &&
   built service-cs ; then
    echo "ensure-web-deps: the example is built in ${ROOT}"
    exit 0
fi

# build.sh is written for macOS: translate its soname flag and define
# _GNU_SOURCE for the C stage, as scripts/build-dut.sh does.
SHIM="$(mktemp -d /tmp/mde-cc-shim.XXXXXX)"
trap 'rm -rf "${SHIM}"' EXIT
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
case "$(uname -m)" in
    aarch64|arm64) export RuntimeIdentifier=linux-arm64 ;;
    *)             export RuntimeIdentifier=linux-x64 ;;
esac

echo "ensure-web-deps: building the example in ${ROOT}"
if ! ( cd "${ROOT}" && PATH="${SHIM}:${PATH}" ./build.sh ) > /tmp/mde-ensure-build.log 2>&1 ; then
    tail -n 25 /tmp/mde-ensure-build.log >&2
    die "build.sh failed (full log /tmp/mde-ensure-build.log)"
fi
for b in cpp-demo gateway-rs service-go service-cs ; do
    built "$b" || die "dist/bin/$b was not produced by build.sh"
done
echo "ensure-web-deps: built"

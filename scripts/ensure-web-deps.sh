#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 midair <midair@localhost>
#
# Make sure the toolchains the example under test needs are installed on the
# agent and that the web tier and the C/C++ demos are built, building them in
# place when they are not. Run by the webdeps group prologue.
#
# Usage: ensure-web-deps.sh <example root> [component...]
# Components: base (toolchains and inspection tools, the default), build (the
# example itself), exposure (tcpdump, sudo, frida), fuzz (clang with the
# fuzzer runtime), browser (node, playwright, chromium), all.
# Exit status 0 when everything is in place; otherwise 1 and a line starting
# with "ensure-web-deps:" says what went wrong.

ROOT="$1"
shift
COMPONENTS="${*:-base build}"
case " ${COMPONENTS} " in *" all "*) COMPONENTS="base build exposure fuzz browser" ;; esac
want() { case " ${COMPONENTS} " in *" $1 "*) return 0 ;; esac; return 1; }

die() { echo "ensure-web-deps: $*" >&2; exit 1; }

[ -n "${ROOT}" ] && [ -d "${ROOT}" ] || die "no example at '${ROOT}'"

SUDO=
[ "$(id -u)" = "0" ] || SUDO="sudo -n"

# command -> Debian/Ubuntu package
declare -A PKG=(
    [gcc]=build-essential [g++]=build-essential [make]=build-essential
    [cmake]=cmake [go]=golang-go [cargo]=cargo [rustc]=rustc
    [python3-config]=python3-dev [clang]=clang [ss]=iproute2
    [readelf]=binutils [objdump]=binutils [nm]=binutils [strings]=binutils
    [curl]=curl [rsync]=rsync [python3]=python3 [lsof]=lsof [ldd]=libc-bin
    [sha256sum]=coreutils [dpkg]=dpkg
)

UPDATED=
apt_update() {
    [ -n "${UPDATED}" ] || { ${SUDO} apt-get update >&2 || die "apt-get update failed"; UPDATED=1; }
}

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
    apt_update
    ${SUDO} apt-get install -y ${PKGS} zlib1g-dev >&2 ||
        die "apt-get install ${PKGS} failed"
fi
for c in "${!PKG[@]}" ; do
    command -v "$c" >/dev/null 2>&1 || die "$c is still missing after the install"
done

# The Cargo.lock files are lock file version 4: cargo older than 1.78 (the
# one apt ships on older Ubuntu) cannot read them, so install a current one.
cargo_ok() {
    local v
    v="$(cargo --version 2>/dev/null | sed -n 's/^cargo \([0-9]*\)\.\([0-9]*\).*/\1 \2/p')"
    [ -n "${v}" ] || return 1
    set -- ${v}
    [ "$1" -gt 1 ] || [ "$2" -ge 78 ]
}
if ! cargo_ok ; then
    echo "ensure-web-deps: installing a current Rust toolchain with rustup (cargo $(cargo --version 2>&1) is too old for Cargo.lock version 4)"
    curl -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh &&
        ${SUDO} env RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo \
            sh /tmp/rustup-init.sh -y --profile minimal --no-modify-path >&2 ||
        die "cannot install Rust with rustup (needed for Cargo.lock version 4)"
    # Link the real toolchain binaries, not the rustup proxies, which need
    # RUSTUP_HOME in the environment of every caller.
    TC="$(ls -d /usr/local/rustup/toolchains/*/bin 2>/dev/null | head -n 1)"
    [ -n "${TC}" ] || die "rustup installed no toolchain under /usr/local/rustup"
    for t in cargo rustc rustdoc ; do
        ${SUDO} ln -sf "${TC}/$t" /usr/local/bin/$t
    done
    hash -r
    cargo_ok || die "cargo is still too old after rustup ($(cargo --version 2>&1)); need 1.78 or newer"
fi

# The projects target net9.0: an older SDK cannot build them.
have_dotnet9() {
    command -v dotnet >/dev/null 2>&1 &&
        dotnet --list-sdks 2>/dev/null | grep -q '^9\.'
}
if ! have_dotnet9 ; then
    echo "ensure-web-deps: installing the .NET 9 SDK"
    export DEBIAN_FRONTEND=noninteractive
    apt_update
    if ! ${SUDO} apt-get install -y dotnet-sdk-9.0 >&2 ; then
        curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh &&
            ${SUDO} bash /tmp/dotnet-install.sh --channel 9.0 \
                --install-dir /usr/share/dotnet >&2 &&
            ${SUDO} ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet ||
            die "cannot install the .NET 9 SDK (apt-get install dotnet-sdk-9.0 and dotnet-install.sh both failed)"
    fi
    have_dotnet9 || die "no .NET 9 SDK after the install (dotnet --list-sdks: $(dotnet --list-sdks 2>&1 | tr '\n' ' '))"
fi

export DEBIAN_FRONTEND=noninteractive

if want exposure ; then
    PK=
    command -v tcpdump >/dev/null 2>&1 || PK="${PK} tcpdump"
    command -v sudo >/dev/null 2>&1 || PK="${PK} sudo"
    command -v pip3 >/dev/null 2>&1 || PK="${PK} python3-pip"
    if [ -n "${PK}" ] ; then
        echo "ensure-web-deps: installing${PK}"
        apt_update
        ${SUDO} apt-get install -y ${PK} >&2 || die "apt-get install${PK} failed"
    fi
    command -v tcpdump >/dev/null 2>&1 || die "tcpdump is still missing after the install"
    command -v sudo >/dev/null 2>&1 || die "sudo is still missing after the install"
    if ! command -v frida >/dev/null 2>&1 ; then
        pip3 install frida-tools >&2 ||
            pip3 install --break-system-packages frida-tools >&2 ||
            die "pip install frida-tools failed"
    fi
    command -v frida >/dev/null 2>&1 || die "frida is still missing after pip install"
fi

if want fuzz ; then
    if ! command -v clang >/dev/null 2>&1 || ! command -v llvm-symbolizer >/dev/null 2>&1 ; then
        echo "ensure-web-deps: installing clang and the fuzzer runtime"
        apt_update
        ${SUDO} apt-get install -y clang llvm libclang-rt-dev libfuzzer-dev >&2 ||
            ${SUDO} apt-get install -y clang llvm >&2 ||
            die "apt-get install clang llvm failed"
    fi
    command -v clang >/dev/null 2>&1 || die "clang is still missing after the install"
    T="$(mktemp -d /tmp/mde-fz.XXXXXX)"
    printf 'int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){return 0;}\n' > "${T}/f.c"
    clang -fsanitize=fuzzer,address "${T}/f.c" -o "${T}/f" >&2 2>&1 ||
        { rm -rf "${T}"; die "clang cannot build with -fsanitize=fuzzer,address (fuzzer runtime missing)"; }
    rm -rf "${T}"
fi

if want browser ; then
    command -v node >/dev/null 2>&1 && command -v npx >/dev/null 2>&1 || {
        echo "ensure-web-deps: installing nodejs and npm"
        apt_update
        ${SUDO} apt-get install -y nodejs npm >&2 || die "apt-get install nodejs npm failed"
    }
    command -v node >/dev/null 2>&1 || die "node is still missing after the install"
    command -v npx >/dev/null 2>&1 || die "npx is still missing after the install"
    PW=/opt/playwright
    ${SUDO} mkdir -p "${PW}" && ${SUDO} chmod 0777 "${PW}" || die "cannot create ${PW}"
    if [ ! -d "${PW}/node_modules/playwright" ] || [ ! -d "${PW}/node_modules/@playwright/test" ] ; then
        ( cd "${PW}" && { [ -f package.json ] || npm init -y >/dev/null; } &&
          npm install playwright @playwright/test ) >&2 ||
            die "npm install playwright in ${PW} failed"
    fi
    if ! ls "${PW}/browsers"/chromium* >/dev/null 2>&1 ; then
        ( cd "${PW}" && PLAYWRIGHT_BROWSERS_PATH="${PW}/browsers" \
              ${SUDO} env PLAYWRIGHT_BROWSERS_PATH="${PW}/browsers" \
              npx playwright install --with-deps chromium ) >&2 ||
            die "npx playwright install --with-deps chromium failed"
    fi
    ls "${PW}/browsers"/chromium* >/dev/null 2>&1 ||
        die "no chromium under ${PW}/browsers after the install"
fi

want build || { echo "ensure-web-deps: ${COMPONENTS} ready"; exit 0; }

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

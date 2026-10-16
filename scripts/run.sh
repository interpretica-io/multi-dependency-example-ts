#!/bin/bash
RUNDIR="$(pwd -P)"
export TS_TOPDIR="$(cd "$(dirname "$(which "$0")")"/.. ; pwd -P)"
export TE_TS_MULTIDEP=${TS_TOPDIR}/multi-dependency-example-ts

# Where the multi-dependency-example under test lives. By default a
# sibling checkout; override to point the suite at another build. The
# tests read it, locate dist/bin and dist/lib under it, and skip when
# it is absent or was not built yet (run ./build.sh in that tree).
export TE_TS_MDE_SRC=${TE_TS_MDE_SRC:-${TS_TOPDIR}/../multi-dependency-example}

function show_usage() {
    echo "Usage:"
    echo "    $0 [parameters] ..."
    echo
    echo "For the ease of use, you can use:"
    echo "    $0 guess [parameters] ..."
    echo "This variant expect the following folder structure:"
    echo " - multi-dependency-example-ts"
    echo " - test-environment"
    echo
}

function run_fail() {
    echo "Error:" $@ >&2
    exit 1
}

if [ -f /tmp/te.dhcpd.leases ] ; then
    sudo rm /tmp/te.dhcpd*.leases
fi

is_docker="0"
if [ "$1" == "docker" ] ; then
    is_docker="1"
    shift 1
fi

if [ "$1" == "guess" ] ; then
    . ${TS_TOPDIR}/scripts/env.sh
    shift 1
fi

if [ "$is_docker" == "1" ] ; then
    export TE_DOCKER_FILE_DIR="${TS_TOPDIR}/scripts/docker/build"
    export TE_DOCKER_TAG="multi-dependency-example-ts-build"
    export TE_DOCKER_MOUNT_PATHS="${TS_TOPDIR}:${TE_BASE}"
    # Mount the example under test at the same path inside the container, so
    # the absolute paths the tests build resolve there too. TE_DOCKER_MOUNT_PATHS
    # is a colon-separated list of paths, each self-mounted. Only add it when it
    # exists and is not already under a mounted path.
    if [ -d "${TE_TS_MDE_SRC}" ] ; then
        MDE_ABS="$(cd "${TE_TS_MDE_SRC}" ; pwd -P)"
        case "${MDE_ABS}" in
            "${TS_TOPDIR}"/*) ;;
            *) export TE_DOCKER_MOUNT_PATHS="${TE_DOCKER_MOUNT_PATHS}:${MDE_ABS}"
               export TE_TS_MDE_SRC="${MDE_ABS}" ;;
        esac
    fi
    export TE_DOCKER_WORK_DIR="$(pwd)"
    export TE_DOCKER_ENV="TE_BASE:TS_TOPDIR:TE_TS_MDE_SRC"
    ${TS_TOPDIR}/scripts/docker_env.sh ${TS_TOPDIR}/scripts/run.sh $@
    exit $?
fi

if [ -d "${TS_TOPDIR}/../test-environment" ] ; then
    export TE_BASE="${TS_TOPDIR}/../test-environment"
fi

if test -z "${TE_BASE}" ; then
    if test -e dispatcher.sh ; then
        export TE_BASE="${RUNDIR}"
    elif test -e "${TS_TOPDIR}/dispatcher.sh" ; then
        export TE_BASE="${TS_TOPDIR}"
    else
        show_usage
        run_fail "Path to TE sources MUST be specified in TE_BASE"
    fi
fi

usage() {
    cat <<EOF
USAGE: run.sh [run.sh options] [dispatcher.sh options]
Options:
    --cfg=<CFG>             Configuration to be used
EOF
${TE_BASE}/dispatcher.sh --help
exit 1
}

TS_OPTS=""
TS_CFG="localhost"
while test -n "$1" ; do
    case $1 in
        --help)
            usage
            ;;
        --cfg=*)
            TS_CFG=${1#--cfg=}
            ;;
        *)
            TS_OPTS+="$1 "
            ;;
    esac
    shift 1
done

source "${TE_BASE}/scripts/lib.meta"

te_meta_test_suite multi-dependency-example-ts ATS
te_meta_add "CFG" "$TS_CFG"

test -z "${TS_CFG}" || TS_OPTS+="--opts=run.conf.${TS_CFG} "

echo "Config is ${TS_CFG}"

if test -z "${TE_BUILD}" ; then
    if test "${TS_TOPDIR}" = "${RUNDIR}" ; then
        TE_BUILD="${TS_TOPDIR}/build"
        mkdir -p build
    else
        TE_BUILD="${RUNDIR}"
    fi
    export TE_BUILD
fi

if [ "${TE_WORKSPACE_DIR}" == "" ] ; then
    export TE_WORKSPACE_DIR="${TE_BUILD}/workspace"
fi

TS_CONF_DIRS=
TS_CONF_DIRS+="\"${TS_TOPDIR}\"/conf:"

TS_DEFAULT_OPTS=

TS_DEFAULT_OPTS+="--conf-dirs=${TS_CONF_DIRS} "
TS_DEFAULT_OPTS+="--export=TE_TS_MDE_SRC=${TE_TS_MDE_SRC} "
TS_DEFAULT_OPTS+="--build-parallel "
TS_DEFAULT_OPTS+="--trc-db=\"${TS_TOPDIR}\"/conf/trc.xml "
TS_DEFAULT_OPTS+="--trc-tag=trc_test1 --trc-tag=trc_test2 "

export TE_TMP="${TS_TOPDIR}/tmp"
mkdir -p "${TE_TMP}"

export TE_TS_SRC="${TS_TOPDIR}/multi-dependency-example-ts"

eval "${TE_BASE}/dispatcher.sh ${TS_DEFAULT_OPTS} ${TS_OPTS} " \
    "--script=scripts/ta-def"
if [ "$?" == "0" ] ; then
    echo OK
else
    echo FAIL
fi

mkdir -p ${TS_TOPDIR}/meson-logs
rm -rf ${TS_TOPDIR}/meson-logs/*
cp -R /tmp/te_ws*/build/meson-logs/* ${TS_TOPDIR}/meson-logs/

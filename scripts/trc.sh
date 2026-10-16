#!/bin/bash
export TS_TOPDIR="$(cd "$(dirname "$(which "$0")")"/.. ; pwd -P)"

if test -z "${TE_BASE}" ; then
    . ${TS_TOPDIR}/scripts/env.sh
    if test -z "${TE_BASE}" ; then
        echo "Path to Test Environment sources must be set"
        exit 1
    fi
fi

. ${TE_BASE}/scripts/guess.sh

${TE_BASE}/scripts/trc.sh \
    --db=${CONFDIR}/trc.xml \
    --key2html=${CONFDIR}/trc.key2html \
    "$@"

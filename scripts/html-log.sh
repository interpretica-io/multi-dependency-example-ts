#!/bin/bash
export TS_TOPDIR="$(cd "$(dirname "$(which "$0")")"/.. ; pwd -P)"

[ -e "./scripts/env.sh" ] && source "./scripts/env.sh"

if test -z "${TE_BASE}" ; then
	echo "Path to Test Environment sources must be set"
	exit 1
fi

. $TE_BASE/scripts/guess.sh

$TE_BASE/scripts/html-log.sh $@

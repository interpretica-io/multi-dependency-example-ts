#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Maxim Menshikov
#
# Turn the raw log of a run into every report the suite can produce.
#
# Usage: reports.sh [<raw log dir>]   (default: the run's TE_BUILD / cwd)
#
# Output goes to <raw log dir>/reports/:
#   log.txt                 plain-text log
#   html/                   multi-page HTML log (MI charts drawn by RGT)
#   json/                   JSON log
#   mi.txt                  the stream of machine-interface messages
#   bublik.json             the run as Bublik imports it
#   trc-full.html, trc-brief.html, trc-bad.html, trc.xml
#                           TRC reports against conf/trc.xml
#   measurements.json/.csv  every MI measurement of every test
#   charts/*.svg            every MI line-graph, rendered offline
#   findings.csv            every finding the audits reported
#   artifacts.csv           every TEST_ARTIFACT line
#   junit.xml               per-iteration results for CI dashboards
#   files/                  files the tests fetched from the agent
#                           (screenshots, Playwright traces, HAR)
#   summary.md, index.html  what happened, with links to all of the above
#
# Never fails the run: a report that cannot be produced is noted in
# summary.md and skipped.

export TS_TOPDIR="$(cd "$(dirname "$(which "$0")")"/.. ; pwd -P)"

LOGDIR="$(cd "${1:-${TE_BUILD:-$(pwd)}}" ; pwd -P)"
OUT="${LOGDIR}/reports"

[ -z "${TE_BASE}" ] && [ -d "${TS_TOPDIR}/../test-environment" ] && \
    export TE_BASE="$(cd "${TS_TOPDIR}/../test-environment" ; pwd -P)"

if [ ! -f "${LOGDIR}/tmp_raw_log" ] ; then
    echo "reports: no tmp_raw_log in ${LOGDIR}" >&2
    exit 0
fi

mkdir -p "${OUT}"
# The dispatcher removes its TE_TMP when the run ends; the renderers need
# one of their own.
export TE_TMP="${OUT}/.tmp"
mkdir -p "${TE_TMP}"
NOTES="${OUT}/.notes"
: > "${NOTES}"

step() {
    local name="$1" ; shift
    echo "reports: ${name}"
    if ! ( cd "${LOGDIR}" && "$@" ) > "${OUT}/.${name}.log" 2>&1 ; then
        echo "${name}: failed, see .${name}.log" >> "${NOTES}"
    fi
}

# TE's own renderers, from the installation the run used.
export PATH="${LOGDIR}/inst/default/bin:${PATH}"
TE_LOG="${TE_BASE}/scripts/log.sh"

RAW="${LOGDIR}/tmp_raw_log"
step log-txt  "${TE_LOG}" --output-to="${OUT}/log.txt" "${RAW}"
step log-html "${TE_LOG}" --html --output-to="${OUT}/html" "${RAW}"
step log-json "${TE_LOG}" --json --output-to="${OUT}/json" "${RAW}"
step log-mi   "${TE_LOG}" --mi --output-to="${OUT}/mi.txt" "${RAW}"

if [ -f "${OUT}/mi.txt" ] ; then
    # rgt-bublik-json reads "timestamp line, JSON line" pairs; log.sh --mi
    # of this TE writes one JSON per line, so give it the pairs.
    awk '/^\{/ { print "0"; print; next } { print }' "${OUT}/mi.txt" \
        > "${TE_TMP}/mi-ts.txt"
    step bublik python3 "${TE_BASE}/tools/rgt/rgt-bublik-json" \
                        -m "${TE_TMP}/mi-ts.txt" -o "${OUT}/bublik.json"
fi

TRC="${TE_BASE}/scripts/trc.sh"
TRC_COMMON=(--db="${TS_TOPDIR}/conf/trc.xml"
            --key2html="${TS_TOPDIR}/conf/trc.key2html"
            --html-logs=html)
step trc-full  "${TRC}" "${TRC_COMMON[@]}" --full  --html="${OUT}/trc-full.html"
step trc-brief "${TRC}" "${TRC_COMMON[@]}" --brief --html="${OUT}/trc-brief.html"
step trc-bad   "${TRC}" "${TRC_COMMON[@]}" --bad   --html="${OUT}/trc-bad.html"
step trc-xml   "${TRC}" "${TRC_COMMON[@]}" --xml="${OUT}/trc.xml"

# Files the tests fetched from the agent land in the run directory as
# te_tmp_<time>_<pid>_<n>_<name>: move them next to the reports.
rm -rf "${OUT}/files"
mkdir -p "${OUT}/files"
find "${LOGDIR}" -maxdepth 1 -type f -name 'te_tmp_*' \
     -exec mv {} "${OUT}/files/" \;

# Everything else comes out of the MI stream and the text log.
step derived python3 -I "${TS_TOPDIR}/scripts/mde_reports.py" \
                     --mi "${OUT}/mi.txt" --log "${OUT}/log.txt" \
                     --out "${OUT}" --notes "${NOTES}"

rm -rf "${TE_TMP}"
echo "reports: ${OUT}/index.html"

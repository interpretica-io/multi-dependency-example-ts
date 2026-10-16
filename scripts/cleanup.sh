#!/bin/bash
export TS_TOPDIR="$(cd "$(dirname "$(which "$0")")"/.. ; pwd -P)"
cd "$TS_TOPDIR"
sudo killall ta ta_rpcs te_tester te_logger dispatcher.sh
rm ta.*


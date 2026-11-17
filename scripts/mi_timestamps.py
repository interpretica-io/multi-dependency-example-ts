#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 midair <midair@localhost>
#
# Give every MI message of a run its real time, in the "timestamp line,
# JSON line" form rgt-bublik-json reads. log.sh --mi writes the JSON
# without times; the plain-text log has one "MI <entity> <user> HH:MM:SS.mmm"
# header per message, in the same order. The date comes from the raw log's
# modification time (the end of the run), walked back over midnight.
#
# Usage: mi_timestamps.py <mi.txt> <log.txt> <raw log> <out>
# Exit status 1, with the reason on stderr, when the two files do not hold
# the same number of messages: the caller then has no times to give Bublik.

import datetime
import os
import re
import sys


def main():
    mi_path, log_path, raw_path, out_path = sys.argv[1:5]
    head = re.compile(r'^MI  .*  (\d\d):(\d\d):(\d\d)\.(\d+)\s*$')

    with open(mi_path) as f:
        msgs = [l.rstrip('\n') for l in f if l.startswith('{')]
    secs = []
    with open(log_path, errors='replace') as f:
        for line in f:
            m = head.match(line)
            if m:
                h, mi, s, frac = m.groups()
                secs.append(int(h) * 3600 + int(mi) * 60 + int(s) +
                            float('0.' + frac))
    if len(msgs) != len(secs):
        sys.stderr.write('mi_timestamps: %d MI messages in %s but %d MI '
                         'headers in %s\n' % (len(msgs), mi_path,
                                              len(secs), log_path))
        return 1

    end = datetime.datetime.fromtimestamp(os.path.getmtime(raw_path))
    day = datetime.datetime(end.year, end.month, end.day)
    stamps = [0.0] * len(secs)
    prev = None
    for i in range(len(secs) - 1, -1, -1):
        if prev is not None and secs[i] > prev:
            day -= datetime.timedelta(days=1)
        stamps[i] = day.timestamp() + secs[i]
        prev = secs[i]

    with open(out_path, 'w') as out:
        for ts, msg in zip(stamps, msgs):
            out.write('%.3f\n%s\n' % (ts, msg))
    return 0


sys.exit(main())

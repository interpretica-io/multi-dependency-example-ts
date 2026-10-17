#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Maxim Menshikov
"""Rebuild conf/trc.xml from a run and a list of known issues.

Every iteration of the run is expected to pass, except those whose
obtained verdicts match a known issue listed in conf/known-issues.json:

    [
      {"test": "ring/propagation",          # path under the suite
       "verdict": "^Ring propagated through", # regexp on any verdict
       "note": "why this is a known issue"}
    ]

Those iterations go into the TRC database as FAILED with the verdicts the
run obtained, so the next run reports them as known issues rather than
regressions. Anything that fails and matches no entry is left out (and so
stays an unexpected result) and is printed, so it gets looked at.

Usage: trc-known-issues.py <mi.txt> <known-issues.json> <out trc.xml>
"""

import json
import re
import sys
import xml.etree.ElementTree as ET
from xml.dom import minidom


def read_mi(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if line.startswith('{'):
                try:
                    yield json.loads(line)
                except ValueError:
                    pass


class Node:
    def __init__(self, name, ntype, params, parent):
        self.name, self.type, self.params = name, ntype, params
        self.parent, self.children = parent, []
        self.status, self.verdicts = None, []

    def path(self):
        parts, n = [], self
        while n is not None and n.parent is not None:
            if n.type != 'session':
                parts.append(n.name)
            n = n.parent
        return '/'.join(reversed(parts))


def build(mi_path):
    root = Node('', 'root', [], None)
    stack = [root]
    for mi in read_mi(mi_path):
        if mi.get('type') == 'test_start':
            msg = mi['msg']
            node = Node(msg['name'], msg.get('node_type'),
                        [tuple(p) for p in (msg.get('params') or [])],
                        stack[-1])
            stack[-1].children.append(node)
            stack.append(node)
        elif mi.get('type') == 'test_end' and len(stack) > 1:
            node = stack.pop()
            obtained = (mi['msg'].get('obtained') or {})
            node.status = obtained.get('status')
            node.verdicts = obtained.get('verdicts') or []
    return root


def main():
    mi_path, known_path, out_path = sys.argv[1:4]
    known = json.load(open(known_path))
    root = build(mi_path)

    db = ET.Element('trc_db', unknown_exp_status='passed_ok')
    unexpected = []

    def emit(node, parent_xml):
        """Mirror packages; add an iteration only for a known issue."""
        if node.type == 'session':
            for c in node.children:
                emit(c, parent_xml)
            return
        is_pkg = node.type == 'pkg'
        test_xml = None
        for t in parent_xml.findall('test'):
            if t.get('name') == node.name:
                test_xml = t
        if test_xml is None:
            test_xml = ET.SubElement(parent_xml, 'test', name=node.name,
                                     type='package' if is_pkg else 'script')
            ET.SubElement(test_xml, 'objective')
            ET.SubElement(test_xml, 'notes')
        if is_pkg:
            it = test_xml.find('iter')
            if it is None:
                it = ET.SubElement(test_xml, 'iter', result='PASSED')
                ET.SubElement(it, 'notes')
            for c in node.children:
                emit(c, it)
            return

        if node.status in (None, 'PASSED', 'SKIPPED'):
            return
        path = node.path().split('/', 1)[-1]
        match = None
        for k in known:
            if k['test'] == path and any(re.search(k['verdict'], v)
                                         for v in node.verdicts):
                match = k
                break
        if match is None:
            unexpected.append((path, node.params, node.status,
                               node.verdicts))
            return
        it = ET.SubElement(test_xml, 'iter', result='FAILED')
        for name, value in node.params:
            ET.SubElement(it, 'arg', name=name).text = value
        notes = ET.SubElement(it, 'notes')
        notes.text = match.get('note', '')
        results = ET.SubElement(it, 'results')
        res = ET.SubElement(results, 'result', value='FAILED')
        for v in node.verdicts:
            ET.SubElement(res, 'verdict').text = v

    for c in root.children:
        emit(c, db)

    text = minidom.parseString(ET.tostring(db)).toprettyxml(indent='  ')
    with open(out_path, 'w') as f:
        f.write(text)

    for path, params, status, verdicts in unexpected:
        args = ' '.join(f'{k}={v}' for k, v in params)
        print(f'UNEXPECTED {path} {args}: {status} {verdicts}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

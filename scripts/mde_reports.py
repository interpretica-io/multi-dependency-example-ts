#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Maxim Menshikov
"""Derived reports of a multi-dependency-example-ts run.

Reads the MI stream TE produces (``log.sh --mi``: a timestamp line, then a
JSON line, per message) and writes what TE's own renderers do not:

- measurements.json / measurements.csv: every MI measurement, flattened;
- charts/<n>.svg: every line-graph view, drawn without any dependency;
- findings.csv: the audit findings the suite logs as artifacts
  ("[severity] check: subject - detail");
- artifacts.csv: every test artifact;
- junit.xml: one testcase per iteration;
- summary.md and index.html: the run at a glance, linking everything.

Standard library only, so it runs wherever the run ran.
"""

import argparse
import csv
import html
import json
import math
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

FINDING_RE = re.compile(
    r'^\[(info|low|medium|high|critical|issue)\]\s+([^:\s]+):\s+(.*?)\s+-\s+(.*)$',
    re.IGNORECASE)
SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'issue']
PALETTE = ['#2f6fdf', '#e0702a', '#2a9d5b', '#c2398a', '#8a5cd6', '#c9a227',
           '#1aa3b8', '#d64545']


def multiplier(text):
    """MI multipliers are numeric literals, decimal or hex-float."""
    if text is None:
        return 1.0
    try:
        return float(text)
    except ValueError:
        try:
            return float.fromhex(text)
        except ValueError:
            return 1.0


def read_mi(path):
    """Yield (timestamp, message) pairs.

    Two layouts exist: a timestamp line before each JSON line, and one
    JSON line per message (the timestamp, if any, inside it).
    """
    ts = 0.0
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if not line.startswith('{'):
                try:
                    ts = float(line)
                except ValueError:
                    pass
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            for key in ('ts', 'timestamp'):
                if isinstance(msg.get(key), (int, float)):
                    ts = float(msg[key])
            yield ts, msg


class Node:
    """A package, session or test iteration of the run."""

    def __init__(self, msg, parent, ts):
        self.name = msg.get('name', '')
        self.type = msg.get('node_type', '')
        self.params = {p[0]: p[1] for p in (msg.get('params') or [])}
        self.parent = parent
        self.children = []
        self.start = ts
        self.end = ts
        self.status = 'INCOMPLETE'
        self.verdicts = []
        self.artifacts = []
        self.expected = True
        self.measurements = []
        self.error = ''
        if parent is not None:
            parent.children.append(self)

    def path(self):
        parts = []
        node = self
        while node is not None and node.parent is not None:
            if node.type != 'session' and node.name:
                parts.append(node.name)
            node = node.parent
        return '/'.join(reversed(parts))

    def label(self):
        args = ' '.join(f'{k}={v}' for k, v in self.params.items())
        return f'{self.path()} {args}'.strip()

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()


def build_tree(mi_path):
    root = Node({'name': ''}, None, 0.0)
    stack = [root]
    for ts, mi in read_mi(mi_path):
        kind = mi.get('type')
        if kind == 'test_start':
            node = Node(mi.get('msg', {}), stack[-1], ts)
            stack.append(node)
        elif kind == 'test_end' and len(stack) > 1:
            node = stack.pop()
            node.end = ts
            msg = mi.get('msg', {})
            obtained = msg.get('obtained') or {}
            node.status = obtained.get('status', 'INCOMPLETE')
            node.verdicts = [v if isinstance(v, str) else v.get('verdict', '')
                             for v in obtained.get('verdicts') or []]
            node.artifacts = [a if isinstance(a, str) else a.get('artifact', '')
                              for a in obtained.get('artifacts') or []]
            node.expected = not msg.get('expected')
            node.error = msg.get('error') or ''
        elif kind == 'measurement':
            stack[-1].measurements.append(mi)
    return root


def flatten_measurements(root):
    rows = []
    for node in root.walk():
        for m_idx, meas in enumerate(node.measurements):
            for res in meas.get('results', []):
                for e_idx, entry in enumerate(res.get('entries', [])):
                    value = entry.get('value')
                    if not isinstance(value, (int, float)):
                        continue
                    rows.append({
                        'test': node.path(),
                        'params': ' '.join(f'{k}={v}'
                                           for k, v in node.params.items()),
                        'artifact': m_idx,
                        'tool': meas.get('tool', ''),
                        'type': res.get('type', ''),
                        'name': res.get('name', ''),
                        'index': e_idx,
                        'aggr': entry.get('aggr', ''),
                        'value': value * multiplier(entry.get('multiplier')),
                        'base_units': entry.get('base_units', ''),
                    })
    return rows


def series_of(meas, axis):
    """Values of the metric an axis names, scaled; None when absent."""
    name = axis.get('name') if isinstance(axis, dict) else axis
    mtype = axis.get('type') if isinstance(axis, dict) else None
    for res in meas.get('results', []):
        if res.get('name') == name and (mtype in (None, '', res.get('type'))
                                        or name):
            return [e.get('value', 0) * multiplier(e.get('multiplier'))
                    for e in res.get('entries', [])
                    if isinstance(e.get('value'), (int, float))]
    if mtype:
        for res in meas.get('results', []):
            if res.get('type') == mtype:
                return [e.get('value', 0) * multiplier(e.get('multiplier'))
                        for e in res.get('entries', [])
                        if isinstance(e.get('value'), (int, float))]
    return None


def nice_ticks(lo, hi, n=5):
    if not math.isfinite(lo) or not math.isfinite(hi):
        return [0, 1]
    if hi == lo:
        hi = lo + 1
    span = hi - lo
    step = 10 ** math.floor(math.log10(span / n))
    for mult in (1, 2, 5, 10):
        if span / (step * mult) <= n:
            step *= mult
            break
    start = math.floor(lo / step) * step
    ticks = []
    t = start
    while t <= hi + step * 0.5:
        ticks.append(round(t, 12))
        t += step
    return ticks


def fmt(v):
    if v == 0:
        return '0'
    if abs(v) >= 1e4 or abs(v) < 1e-2:
        return f'{v:.2g}'
    return f'{v:.4g}'


def render_svg(title, subtitle, xs, ys_named, keys):
    """A line chart; ys_named is [(name, values)]."""
    w, h = 640, 360
    ml, mr, mt, mb = 64, 16, 48, 72
    pw, ph = w - ml - mr, h - mt - mb
    all_y = [v for _, vals in ys_named for v in vals if math.isfinite(v)]
    if not xs or not all_y:
        return None
    x_lo, x_hi = min(xs), max(xs)
    y_lo, y_hi = min(all_y + [0]), max(all_y)
    xt = nice_ticks(x_lo, x_hi)
    yt = nice_ticks(y_lo, y_hi)
    x_lo, x_hi = min(xt[0], x_lo), max(xt[-1], x_hi)
    y_lo, y_hi = min(yt[0], y_lo), max(yt[-1], y_hi)

    def px(x):
        return ml + (x - x_lo) / ((x_hi - x_lo) or 1) * pw

    def py(y):
        return mt + ph - (y - y_lo) / ((y_hi - y_lo) or 1) * ph

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
           f'width="{w}" height="{h}" font-family="system-ui,sans-serif" '
           f'font-size="11">',
           '<style>.g{stroke:#d8dce3}.t{fill:#5b6170}.ti{fill:#1d2230;'
           'font-size:13px;font-weight:600}</style>',
           f'<rect width="{w}" height="{h}" fill="#ffffff"/>',
           f'<text class="ti" x="{ml}" y="20">{html.escape(title)}</text>',
           f'<text class="t" x="{ml}" y="36">{html.escape(subtitle)}</text>']
    for t in yt:
        y = py(t)
        out.append(f'<line class="g" x1="{ml}" x2="{ml + pw}" y1="{y:.1f}" '
                   f'y2="{y:.1f}"/>')
        out.append(f'<text class="t" x="{ml - 6}" y="{y + 4:.1f}" '
                   f'text-anchor="end">{fmt(t)}</text>')
    for t in xt:
        x = px(t)
        label = keys.get(f'x{int(t)}') if float(t).is_integer() else None
        out.append(f'<text class="t" x="{x:.1f}" y="{mt + ph + 16}" '
                   f'text-anchor="middle">{html.escape(label or fmt(t))}'
                   f'</text>')
    out.append(f'<line stroke="#9aa1ad" x1="{ml}" x2="{ml + pw}" '
               f'y1="{mt + ph}" y2="{mt + ph}"/>')
    for i, (name, vals) in enumerate(ys_named):
        color = PALETTE[i % len(PALETTE)]
        pts = [(px(x), py(y)) for x, y in zip(xs, vals) if math.isfinite(y)]
        if not pts:
            continue
        d = ' '.join(f'{x:.1f},{y:.1f}' for x, y in pts)
        out.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" '
                   f'points="{d}"/>')
        for x, y in pts:
            out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" '
                       f'fill="{color}"/>')
        lx = ml + i * 150
        out.append(f'<rect x="{lx}" y="{h - 22}" width="10" height="10" '
                   f'fill="{color}"/>')
        out.append(f'<text class="t" x="{lx + 14}" y="{h - 13}">'
                   f'{html.escape(name[:22])}</text>')
    out.append('</svg>')
    return '\n'.join(out)


def render_charts(root, out_dir):
    charts = []
    os.makedirs(os.path.join(out_dir, 'charts'), exist_ok=True)
    n = 0
    for node in root.walk():
        for meas in node.measurements:
            keys = meas.get('keys') or {}
            for view in meas.get('views', []):
                if view.get('type') != 'line-graph':
                    continue
                y_axes = view.get('axis_y') or []
                ax_x = view.get('axis_x') or {}
                x_name = ax_x.get('name') if isinstance(ax_x, dict) else ax_x
                named = []
                if not y_axes:
                    for res in meas.get('results', []):
                        if res.get('name') != x_name:
                            named.append((res.get('name') or res.get('type'),
                                          series_of(meas, res)))
                else:
                    for ax in y_axes:
                        named.append(((ax.get('name') if isinstance(ax, dict)
                                       else ax) or str(ax),
                                      series_of(meas, ax)))
                named = [(nm, v) for nm, v in named if v]
                if not named:
                    continue
                length = max(len(v) for _, v in named)
                if x_name in (None, '', 'auto-seqno'):
                    xs = list(range(length))
                else:
                    xs = series_of(meas, ax_x) or list(range(length))
                svg = render_svg(view.get('title') or view.get('name', ''),
                                 f'{node.label()} [{meas.get("tool", "")}]',
                                 xs, named, keys)
                if svg is None:
                    continue
                n += 1
                fname = f'charts/{n:04d}.svg'
                with open(os.path.join(out_dir, fname), 'w') as f:
                    f.write(svg)
                charts.append({'file': fname, 'test': node.path(),
                               'label': node.label(),
                               'title': view.get('title', '')})
    return charts


def write_csv(path, rows, fields):
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def leaves(root):
    return [n for n in root.walk()
            if n.parent is not None and n.type in ('test', 'script')]


def group_of(node):
    parts = node.path().split('/')
    return parts[1] if len(parts) > 2 else (parts[0] if parts else '')


def write_junit(path, tests):
    suites = defaultdict(list)
    for t in tests:
        suites[group_of(t)].append(t)
    top = ET.Element('testsuites', name='multi-dependency-example-ts')
    for name, cases in sorted(suites.items()):
        suite = ET.SubElement(top, 'testsuite', name=name,
                              tests=str(len(cases)))
        fails = skips = 0
        for t in cases:
            case = ET.SubElement(suite, 'testcase', classname=name,
                                 name=t.label(),
                                 time=f'{max(t.end - t.start, 0):.3f}')
            if t.status == 'SKIPPED':
                ET.SubElement(case, 'skipped')
                skips += 1
            elif t.status != 'PASSED' and not t.expected:
                fail = ET.SubElement(case, 'failure', message=t.status)
                fail.text = '\n'.join(t.verdicts) or t.error
                fails += 1
            elif t.status != 'PASSED':
                # A known issue: matched by TRC, reported but not a failure.
                prop = ET.SubElement(case, 'system-out')
                prop.text = 'known issue: ' + '\n'.join(t.verdicts)
        suite.set('failures', str(fails))
        suite.set('skipped', str(skips))
    ET.ElementTree(top).write(path, encoding='utf-8', xml_declaration=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mi', required=True)
    parser.add_argument('--log')
    parser.add_argument('--out', required=True)
    parser.add_argument('--notes')
    args = parser.parse_args()

    if not os.path.exists(args.mi):
        print(f'no MI stream at {args.mi}', file=sys.stderr)
        return 1

    root = build_tree(args.mi)
    tests = leaves(root)

    rows = flatten_measurements(root)
    with open(os.path.join(args.out, 'measurements.json'), 'w') as f:
        json.dump(rows, f, indent=1)
    write_csv(os.path.join(args.out, 'measurements.csv'), rows,
              ['test', 'params', 'artifact', 'tool', 'type', 'name', 'index',
               'aggr', 'value', 'base_units'])

    charts = render_charts(root, args.out)

    findings, artifacts = [], []
    for t in tests:
        for a in t.artifacts:
            artifacts.append({'test': t.path(), 'params': t.label(),
                              'artifact': a})
            m = FINDING_RE.match(a.strip())
            if m:
                findings.append({'test': t.path(), 'params': t.label(),
                                 'severity': m.group(1).lower(),
                                 'check': m.group(2), 'subject': m.group(3),
                                 'detail': m.group(4)})
    write_csv(os.path.join(args.out, 'findings.csv'), findings,
              ['test', 'params', 'severity', 'check', 'subject', 'detail'])
    write_csv(os.path.join(args.out, 'artifacts.csv'), artifacts,
              ['test', 'params', 'artifact'])
    write_junit(os.path.join(args.out, 'junit.xml'), tests)

    # Summary.
    by_group = defaultdict(Counter)
    for t in tests:
        key = t.status if t.status in ('PASSED', 'SKIPPED') else (
            'KNOWN' if t.expected else 'UNEXPECTED')
        by_group[group_of(t)][key] += 1
    sev = Counter(f['severity'] for f in findings)
    families = Counter(f['check'].split('.')[0] for f in findings)
    charts_by_group = Counter(c['test'].split('/')[1] if c['test'].count('/')
                              else c['test'] for c in charts)
    notes = []
    if args.notes and os.path.exists(args.notes):
        notes = [line.strip() for line in open(args.notes) if line.strip()]

    total = Counter()
    for c in by_group.values():
        total.update(c)

    md = ['# multi-dependency-example-ts — run summary', '',
          f'Iterations: **{len(tests)}** — passed {total["PASSED"]}, '
          f'known issues {total["KNOWN"]}, unexpected {total["UNEXPECTED"]}, '
          f'skipped {total["SKIPPED"]}.', '',
          f'MI measurements: **{len(rows)}** values in '
          f'{sum(len(n.measurements) for n in root.walk())} artifacts; '
          f'**{len(charts)}** line graphs rendered.', '',
          f'Findings logged: **{len(findings)}** '
          + ', '.join(f'{s} {sev[s]}' for s in SEVERITIES if sev[s]) + '.', '',
          '## Per group', '',
          '| group | passed | known issue | unexpected | skipped | charts |',
          '|---|---|---|---|---|---|']
    for g in sorted(by_group):
        c = by_group[g]
        md.append(f'| {g} | {c["PASSED"]} | {c["KNOWN"]} | {c["UNEXPECTED"]} '
                  f'| {c["SKIPPED"]} | {charts_by_group.get(g, 0)} |')
    md += ['', '## Findings by check family', '',
           '| family | findings |', '|---|---|']
    md += [f'| {k} | {v} |' for k, v in families.most_common()]
    unexpected = [t for t in tests
                  if t.status not in ('PASSED', 'SKIPPED') and not t.expected]
    if unexpected:
        md += ['', '## Unexpected results', '']
        md += [f'- `{t.label()}` — {t.status}: '
               f'{"; ".join(t.verdicts) or t.error}' for t in unexpected]
    known = [t for t in tests
             if t.status not in ('PASSED', 'SKIPPED') and t.expected]
    if known:
        md += ['', '## Known issues (matched by TRC)', '']
        md += [f'- `{t.label()}` — {"; ".join(t.verdicts)}' for t in known]
    skipped = [t for t in tests if t.status == 'SKIPPED']
    if skipped:
        md += ['', '## Skipped', '']
        md += [f'- `{t.label()}` — {"; ".join(t.verdicts) or t.error}'
               for t in skipped]
    if notes:
        md += ['', '## Reports that could not be produced', '']
        md += [f'- {n}' for n in notes]
    with open(os.path.join(args.out, 'summary.md'), 'w') as f:
        f.write('\n'.join(md) + '\n')

    links = [('HTML log', 'html/index.html'), ('Text log', 'log.txt'),
             ('JSON log', 'json/'), ('MI stream', 'mi.txt'),
             ('Bublik JSON', 'bublik.json'),
             ('TRC full', 'trc-full.html'), ('TRC brief', 'trc-brief.html'),
             ('TRC unexpected', 'trc-bad.html'), ('TRC XML', 'trc.xml'),
             ('Measurements CSV', 'measurements.csv'),
             ('Measurements JSON', 'measurements.json'),
             ('Findings CSV', 'findings.csv'),
             ('Artifacts CSV', 'artifacts.csv'), ('JUnit XML', 'junit.xml'),
             ('Summary (Markdown)', 'summary.md'),
             ('Files fetched from the agent', 'files/')]
    page = ['<!doctype html><meta charset="utf-8">',
            '<title>MDE run reports</title>',
            '<style>body{font-family:system-ui,sans-serif;margin:24px;'
            'color:#1d2230;background:#f6f7f9}a{color:#2f6fdf}'
            'table{border-collapse:collapse}td,th{padding:4px 10px;'
            'border-bottom:1px solid #dde}.g{display:flex;flex-wrap:wrap;'
            'gap:12px}.g figure{margin:0;background:#fff;padding:6px;'
            'border:1px solid #e3e6eb}figcaption{font-size:12px;max-width:'
            '640px}</style>',
            '<h1>multi-dependency-example-ts</h1>',
            f'<p>{len(tests)} iterations, {len(rows)} measurements, '
            f'{len(charts)} charts, {len(findings)} findings.</p>',
            '<h2>Reports</h2><ul>']
    for name, href in links:
        if os.path.exists(os.path.join(args.out, href.rstrip('/'))):
            page.append(f'<li><a href="{href}">{name}</a></li>')
    page.append('</ul><h2>Per group</h2><table><tr><th>group</th>'
                '<th>passed</th><th>known</th><th>unexpected</th>'
                '<th>skipped</th><th>charts</th></tr>')
    for g in sorted(by_group):
        c = by_group[g]
        page.append(f'<tr><td>{html.escape(g)}</td><td>{c["PASSED"]}</td>'
                    f'<td>{c["KNOWN"]}</td><td>{c["UNEXPECTED"]}</td>'
                    f'<td>{c["SKIPPED"]}</td>'
                    f'<td>{charts_by_group.get(g, 0)}</td></tr>')
    page.append('</table><h2>Charts</h2><div class="g">')
    for c in charts:
        page.append(f'<figure><img src="{c["file"]}" loading="lazy" '
                    f'width="640" height="360"><figcaption>'
                    f'{html.escape(c["label"])}</figcaption></figure>')
    page.append('</div>')
    files_dir = os.path.join(args.out, 'files')
    files = sorted(os.listdir(files_dir)) if os.path.isdir(files_dir) else []
    if files:
        page.append('<h2>Files fetched from the agent</h2><div class="g">')
        for name in files:
            href = 'files/' + html.escape(name, quote=True)
            if name.endswith('.png'):
                page.append(f'<figure><a href="{href}"><img src="{href}" '
                            f'loading="lazy" width="320"></a><figcaption>'
                            f'{html.escape(name)}</figcaption></figure>')
            else:
                page.append(f'<figure><a href="{href}">{html.escape(name)}'
                            f'</a></figure>')
        page.append('</div>')
    with open(os.path.join(args.out, 'index.html'), 'w') as f:
        f.write('\n'.join(page))

    print(f'{len(tests)} iterations, {len(rows)} measurements, '
          f'{len(charts)} charts, {len(findings)} findings')
    return 0


if __name__ == '__main__':
    sys.exit(main())

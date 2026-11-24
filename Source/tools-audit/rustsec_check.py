#!/usr/bin/env python3
"""Checks locked packages against the RustSec advisory database the way
cargo-audit does: a version is affected unless it matches one of the
advisory's `patched` or `unaffected` requirements (Cargo semver rules)."""
import json, os, re, sys, tomllib
DB, LOCKS = sys.argv[1], sys.argv[2]

def parse(v):
    m = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$', v.strip())
    if not m: raise ValueError(v)
    return (int(m[1]), None if m[2] is None else int(m[2]), None if m[3] is None else int(m[3]), m[4])

def pre_key(p):
    if p is None: return (1,)
    out = []
    for part in p.split('.'):
        out.append((0, int(part), '') if part.isdigit() else (1, 0, part))
    return (0, tuple(out))

def key(v):
    return (v[0], v[1] or 0, v[2] or 0, pre_key(v[3]))

def comparator(c, v):
    c = c.strip()
    m = re.match(r'^(>=|<=|>|<|=|\^|~)?\s*(.+)$', c)
    op, rest = m[1] or '^', m[2].strip()
    rest = rest.replace('.*', '').replace('*', '')
    if rest == '': return True
    r = parse(rest)
    full = (r[0], r[1] or 0, r[2] or 0, r[3])
    kv, kr = key(v), key(full)
    # a pre-release only matches a comparator that names a pre-release of the same x.y.z
    if v[3] is not None and not (r[3] is not None and (v[0], v[1], v[2]) == (full[0], full[1], full[2])):
        return False
    if op == '>=': return kv >= kr
    if op == '>':
        # a partial version stands for the whole range: >1.0 is >=1.1.0
        if r[1] is None: return v[0] > r[0]
        if r[2] is None: return (v[0], v[1]) > (r[0], r[1])
        return kv > kr
    if op == '<=':
        if r[1] is None: return v[0] <= r[0]
        if r[2] is None: return (v[0], v[1]) <= (r[0], r[1])
        return kv <= kr
    if op == '<': return kv < kr
    if op == '=':
        if r[1] is None: return v[0] == r[0]
        if r[2] is None: return (v[0], v[1]) == (r[0], r[1])
        return kv == kr
    if op == '~':
        if r[1] is None: return v[0] == r[0]
        return kv >= kr and (v[0], v[1]) == (r[0], r[1])
    # caret
    if kv < kr: return False
    if r[0] > 0 or r[1] is None: return v[0] == r[0]
    if r[1] > 0 or r[2] is None: return (v[0], v[1]) == (0, r[1])
    return (v[0], v[1], v[2]) == (0, 0, r[2])

def matches(req, v):
    return all(comparator(c, v) for c in req.split(','))

adv = {}
for root, _, files in os.walk(os.path.join(DB, 'crates')):
    for f in files:
        if not f.endswith('.md'): continue
        text = open(os.path.join(root, f), encoding='utf-8').read()
        m = re.search(r'```toml\n(.*?)\n```', text, re.S)
        if not m: continue
        t = tomllib.loads(m[1])
        a = t['advisory']
        if a.get('withdrawn'): continue
        title = re.search(r'^# (.+)$', text[m.end():], re.M)
        adv.setdefault(a['package'], []).append({
            'id': a['id'], 'date': str(a.get('date')), 'kind': a.get('informational'), 'title': title[1] if title else '',
            'patched': t.get('versions', {}).get('patched', []), 'unaffected': t.get('versions', {}).get('unaffected', []),
            'cvss': a.get('cvss'), 'url': a.get('url')})
data = json.load(open(LOCKS))
hits = []
for p in data['packages']:
    for a in adv.get(p['name'], []):
        v = parse(p['version'])
        if any(matches(r, v) for r in a['patched'] + a['unaffected']): continue
        hits.append((a['kind'] or 'vulnerability', p, a))
print(f"advisories loaded for {len(adv)} crates; packages checked: {len(data['packages'])}; lock files: {len(data['locks'])}")
order = {'vulnerability': 0, 'unsound': 1, 'unmaintained': 2, 'notice': 3}
hits.sort(key=lambda h: (order.get(h[0], 9), h[1]['name'], h[2]['id']))
for kind, p, a in hits:
    where = sorted({l.split('/')[1] + '/' + l.split('/')[2] for l in p['locks']})
    src = 'crates.io' if p['source'].startswith('registry') else ('local' if not p['source'] else p['source'][:30])
    print(f"{kind.upper():13} {a['id']} {p['name']} {p['version']} [{src}] patched: {a['patched'] or 'none'} — {a['title'][:90]}\n              in: {', '.join(where)}")
json.dump([{'kind': k, 'package': p, 'advisory': a} for k, p, a in hits], open('hits.json', 'w'), ensure_ascii=False, indent=1)
from collections import Counter
print(Counter(h[0] for h in hits))

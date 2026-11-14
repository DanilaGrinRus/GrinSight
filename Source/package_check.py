"""Supply check for GrinSight: what is shipped, with which dependencies, and that
no user data or secret goes with it.

  python package_check.py pack [--out dist\\grinsight-src.zip] [--with-vendor]
      build the source package from an ALLOW-list (nothing else can get in),
      scan it, write a manifest (SHA-256 of every file + package id) next to it.
      Refuses to write the package if the scan finds anything.
  python package_check.py scan PATH
      scan a folder or a .zip someone wants to ship (exit 1 on findings).
  python package_check.py deps [--out FILE]
      inventory of every Cargo.lock: packages, versions, sources, checksums;
      flags git / unknown-registry sources and missing checksums (exit 1).

No network. Findings are reported by file and line, never with the secret.
"""
import argparse, hashlib, io, json, os, pathlib, re, sys, time, zipfile

ROOT = pathlib.Path(__file__).resolve().parent

# What a source package may contain (relative to ROOT). Directories are taken
# recursively, but EXCLUDE_DIRS below is applied inside them too.
ALLOW = [
    'README.md', 'run_user.ps1', 'make_release.ps1', 'make_app.ps1', 'recheck_checkpoint.ps1', 'installer', 'broadcast_saved_tx.ps1',
    'run_acceptance_tests.ps1', 'package_check.py', 'checkpoint_crosscheck.py',
    'test_package_check.py',
    'docs/CHECKPOINT_TRUST_RU.md', 'docs/ACCEPTANCE_RU.md', 'deps-accepted.txt', 'docs/PLAN_VERIFIED_LIGHT_MODE_RU.md', 'docs/HEADER_MMR_PROOFS_PROPOSAL_RU.md',
    'header-sync/Cargo.toml', 'header-sync/Cargo.lock', 'header-sync/src', 'header-sync/tests', 'header-sync/patches', 'header-sync/release-keys.txt',
    'make_service.ps1', 'make_android.ps1', 'make_github_release.ps1', 'make_full_release.ps1', 'mark_release_buggy.ps1', 'publish_github.ps1', 'make_deb.sh', 'UI/backend', 'GrinSight/release-docs',
    'grinsight-state/Cargo.toml', 'grinsight-state/Cargo.lock', 'grinsight-state/src', 'grinsight-state/fuzz-corpus', 'grinsight-state/release-keys.txt',
    'grinsight-ffi/Cargo.toml', 'grinsight-ffi/Cargo.lock', 'grinsight-ffi/src', 'grinsight-ffi/include', 'grinsight-ffi/tests', 'grinsight-ffi/README.md',
    'state-verify/Cargo.toml', 'state-verify/Cargo.lock', 'state-verify/src',
    'tor/Cargo.toml', 'tor/Cargo.lock', 'tor/README.md', 'tor/vendor.toml', 'tor/grinsight-tor', 'tor/grinmessenger', 'tor/patches', 'tor/build_android_wsl.sh',
    'release',
    'web-core/Cargo.toml', 'web-core/Cargo.lock', 'web-core/src', 'web-core/README.md',
    'web-core/build_wasm.ps1', 'web-core/test/harness.c', 'web/README_RU.md',
    'web-core/build_browser.ps1', 'web-core/browser/grinsight_api.mjs',
    'web-core/test/pibd_fixture.bin',
    'web/pwa/index.html', 'web/pwa/manifest.webmanifest', 'web/pwa/sw.js',
    'web/pwa/worker.mjs', 'web/pwa/worker-selftest.mjs', 'web/pwa/build_pwa.ps1', 'web/pwa/README.md',
    'web/pwa/transport.mjs', 'web/pwa/transport-selftest.mjs', 'web/pwa/gateway-mock.mjs',
    'web/pwa/gateway-live-selftest.mjs', 'web/pwa/gateway-pool-selftest.mjs', 'web/pwa/gateway-verify-selftest.mjs', 'web/pwa/gateway-chain-selftest.mjs', 'web/pwa/wss-selftest.mjs', 'web/pwa/mainnet-chain-selftest.mjs', 'web/pwa/gateway-auto-selftest.mjs',
    'web-gateway/tls_proxy.py', 'web-gateway/deploy/Caddyfile', 'docs/WEB_APP_STATUS_2026-11-12_RU.md',
    'web-gateway/Cargo.toml', 'web-gateway/Cargo.lock', 'web-gateway/src', 'web-gateway/README.md',
    'checkpoints/floonet/checkpoint.rwm', 'checkpoints/floonet/recent-headers.bin',
    'web-core/browser/package.json', 'web-core/browser/README.md', 'web-core/browser/selftest.mjs',
]
VENDOR = ['vendor']
EXCLUDE_DIRS = {'target', '.build', '.git', '__pycache__', '.pytest_cache', 'evidence', 'sessions', '.data', 'dev-data', '_archive',
                'data', 'messenger', 'arti', 'inbox', 'outbox', 'sends', 'replies'}

# Names that are user data or secrets wherever they appear.
BAD_NAMES = [
    (re.compile(r'.*\.local\.txt$', re.I), 'local secrets file'),
    (re.compile(r'.*seeds?(\.txt)?$', re.I), 'seed file'),
    (re.compile(r'.*\.seed$', re.I), 'release / seed key'),
    (re.compile(r'wallet-outputs\.jsonl$', re.I), 'wallet outputs (user data)'),
    (re.compile(r'pending-receives\.jsonl.*', re.I), 'pending journal (user data)'),
    (re.compile(r'.*context.*\.json$', re.I), 'signing context (secrets)'),
    (re.compile(r'address-book\.json$', re.I), 'address book (user data)'),
    (re.compile(r'confirmed-kernels\.txt$', re.I), 'payment history (user data)'),
    (re.compile(r'messenger-processed\.txt$', re.I), 'messenger state (user data)'),
    (re.compile(r'.*\.(ust|rwm|ugb)$', re.I), 'wallet / chain state (user data)'),
]
BAD_DIR_PARTS = {'evidence', 'sessions', '.data', 'dev-data', 'release-key', 'user-run'}
# Allowed by name although they match a pattern above (code, not data).
NAME_OK = {'release-keys.txt'}
# Public, non-secret checkpoints shipped for the browser core. They are not user data.
PUBLIC_ARTIFACTS = {
    'checkpoints/floonet/checkpoint.rwm',
    'checkpoints/floonet/recent-headers.bin',
}

SECRET_TEXT = [
    (re.compile(r'(ADDRESS_SECRET_HEX|MESSAGING_SEED_HEX)=[0-9a-fA-F]{32,}'), 'printed secret key'),
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'), 'private key'),
    (re.compile(r'"sec_(key|nonce)"\s*:\s*"?[0-9a-fA-F\[]'), 'signing context secret'),
    (re.compile(r'BEGINSLATEPACK\.\s*[1-9A-HJ-NP-Za-km-z\s]{120,}?ENDSLATEPACK'), 'slatepack (user payment data)'),
    (re.compile(r'"kind"\s*:\s*"(receive|invoice|change|payment|inputs)".{0,200}"slate_id"'), 'pending journal record (user data)'),
]
UPSTREAM_BIP39_VECTORS = '31ba2a50442ea7a0554e4fa3f9a17e5a03827071d8f0c05af997c16bcb961ad7'
SOURCE_EXT = {'.rs', '.py', '.ps1', '.sh', '.dart', '.c', '.h', '.cpp'}
TEXT_EXT = {'.rs', '.py', '.ps1', '.sh', '.md', '.txt', '.toml', '.lock', '.json', '.jsonl', '.c', '.h', '.cpp',
            '.patch', '.cfg', '.yml', '.yaml', '.log', ''}


def bip39_words():
    p = ROOT / 'vendor' / 'grin-5.5.2' / 'keychain' / 'src' / 'wordlists' / 'en.txt'
    try:
        return set(p.read_text().split())
    except OSError:
        return None


WORDS = bip39_words()


def mnemonic_lines(text):
    """Line numbers holding 12+ consecutive BIP39 words (a seed phrase)."""
    if not WORDS:
        return []
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        run = best = 0
        for tok in re.split(r'[^A-Za-z]+', line):
            if not tok:
                continue
            run = run + 1 if tok.lower() in WORDS else 0
            best = max(best, run)
        if best >= 12:
            hits.append(n)
    return hits


def scan_bytes(rel, data):
    out = []
    name = rel.rsplit('/', 1)[-1]
    parts = set(rel.split('/')[:-1])
    # release/ ships the SIGNED checkpoint (checkpoint.rwm + recent-headers.bin)
    # (at the top of the pack, or under Source/ in the GitHub repository tree)
    signed_release = rel.startswith('release/') or rel.startswith('Source/release/')
    if name not in NAME_OK:
        for rx, why in BAD_NAMES:
            bare = rel.removeprefix('Source/')
            # The app's copy of the shipped checkpoints (signed mainnet release,
            # pinned floonet), made by make_android.ps1: public, not user data.
            public = bare in PUBLIC_ARTIFACTS or bare.startswith('UI/flutter_app/assets/checkpoints/')
            if (signed_release or public) and why.startswith('wallet / chain state'):
                continue
            if rx.fullmatch(name):
                out.append((rel, 0, why))
    for part in parts:
        if part in BAD_DIR_PARTS or part.startswith('user-run-') or part.startswith('tor-wallet-'):
            out.append((rel, 0, f'user data folder ({part})'))
            break
    if pathlib.PurePosixPath(rel).suffix.lower() in TEXT_EXT and len(data) < 8 * 1024 * 1024:
        text = data.decode('utf-8', 'replace')
        suffix = pathlib.PurePosixPath(rel).suffix.lower()
        for rx, why in SECRET_TEXT:
            # A journal record is user DATA (.jsonl/.json/.txt/.log). In source code the
            # same shape is the code that writes it (json!(...)) or a synthetic test
            # fixture: not user data, so the rule applies to data files only.
            if why.startswith('pending journal record') and suffix in SOURCE_EXT:
                continue
            for m in rx.finditer(text):
                out.append((rel, text.count('\n', 0, m.start()) + 1, why))
        # Grin's own BIP39 unit-test vectors (public, from the BIP39 spec), pinned
        # by hash: any change to the file makes the rule apply again.
        upstream_vectors = (rel.removeprefix('Source/') == 'vendor/grin-5.5.2/keychain/src/mnemonic.rs'
                            and hashlib.sha256(data).hexdigest() == UPSTREAM_BIP39_VECTORS)
        for n in ([] if upstream_vectors else mnemonic_lines(text)):
            out.append((rel, n, 'seed phrase (12+ BIP39 words in a row)'))
    return out


def walk_allowed(with_vendor):
    for entry in ALLOW + (VENDOR if with_vendor else []):
        p = ROOT / entry
        if p.is_file():
            yield entry, p
        elif p.is_dir():
            for dirpath, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS)
                for f in sorted(files):
                    fp = pathlib.Path(dirpath) / f
                    yield fp.relative_to(ROOT).as_posix(), fp


def iter_target(path):
    path = pathlib.Path(path)
    if path.is_file() and path.suffix.lower() == '.zip':
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                if not i.is_dir():
                    yield i.filename, z.read(i)
    else:
        for dirpath, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in {'target', '.git', '__pycache__'})
            for f in sorted(files):
                fp = pathlib.Path(dirpath) / f
                yield fp.relative_to(path).as_posix(), fp.read_bytes()


def report(findings):
    for rel, line, why in findings:
        print(f'FINDING {rel}' + (f':{line}' if line else '') + f' {why}')


def cmd_scan(a):
    findings = []
    n = 0
    for rel, data in iter_target(a.path):
        n += 1
        findings += scan_bytes(rel, data)
    report(findings)
    print(f'SCAN_FILES={n}\nSCAN_FINDINGS={len(findings)}\nSCAN={"PASS" if not findings else "FAIL"}')
    return 0 if not findings else 1


def cmd_pack(a):
    files = list(walk_allowed(a.with_vendor))
    findings, manifest = [], []
    for rel, p in files:
        data = p.read_bytes()
        findings += scan_bytes(rel, data)
        manifest.append(f'{hashlib.sha256(data).hexdigest()}  {len(data):>10}  {rel}')
    if findings:
        report(findings)
        print(f'PACK=REFUSED ({len(findings)} findings; nothing written)')
        return 1
    body = '\n'.join(manifest) + '\n'
    pkg_id = hashlib.sha256(body.encode()).hexdigest()
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for rel, p in files:
            # fixed timestamp: the same sources give the same zip content list
            zi = zipfile.ZipInfo(rel, date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, p.read_bytes())
        z.writestr(zipfile.ZipInfo('MANIFEST.sha256', date_time=(2026, 1, 1, 0, 0, 0)), f'# package id {pkg_id}\n' + body)
    out.with_suffix('.manifest.txt').write_text(f'# package id {pkg_id}\n# files {len(files)}\n' + body)
    # the finished zip is scanned once more as a whole
    rc = cmd_scan(argparse.Namespace(path=str(out)))
    print(f'PACK_FILES={len(files)}\nPACK_ID={pkg_id}\nPACK_OUT={out}\nPACK={"OK" if rc == 0 else "FAIL"}')
    return rc


LOCKS = ['header-sync/Cargo.lock', 'grinsight-state/Cargo.lock', 'grinsight-ffi/Cargo.lock', 'state-verify/Cargo.lock', 'tor/Cargo.lock']
MAX_DB_AGE_DAYS = 30
CRATES_IO = 'registry+https://github.com/rust-lang/crates.io-index'


def parse_lock(text):
    pkgs, cur = [], None
    for line in text.splitlines():
        line = line.strip()
        if line == '[[package]]':
            cur = {}
            pkgs.append(cur)
        elif cur is not None and ' = ' in line and not line.startswith('dependencies'):
            k, v = line.split(' = ', 1)
            if v.startswith('"'):
                cur[k] = v.strip('"')
    return pkgs


# ---- RustSec advisories (offline, from a local clone of rustsec/advisory-db) ----

def _ver(v):
    """'1.2.3-beta+x' -> (1, 2, 3, is_prerelease)"""
    core = v.strip().split('+')[0]
    pre = '-' in core
    nums = [int(x) if x.isdigit() else 0 for x in core.split('-')[0].split('.')]
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2], pre)


def _cmp_one(ver, comp):
    comp = comp.strip()
    m = re.match(r'^(>=|<=|>|<|=|\^|~)?\s*([0-9][0-9A-Za-z.\-+]*)$', comp)
    if not m:
        raise ValueError(comp)
    op, req = m.group(1) or '^', m.group(2)
    parts = req.split('-')[0].split('.')
    r = _ver(req)[:3]
    v = ver[:3]
    if op == '>=': return v >= r
    if op == '<=': return v <= r
    if op == '>': return v > r
    if op == '<': return v < r
    if op == '=': return v[:len(parts)] == r[:len(parts)]
    if op == '~':
        upper = (r[0] + 1, 0, 0) if len(parts) == 1 else (r[0], r[1] + 1, 0)
        return r <= v < upper
    # caret
    if r[0] > 0 or len(parts) == 1:
        upper = (r[0] + 1, 0, 0)
    elif r[1] > 0 or len(parts) == 2:
        upper = (0, r[1] + 1, 0)
    else:
        upper = (0, 0, r[2] + 1)
    return r <= v < upper


def version_matches(version, req):
    """Cargo-style requirement, comma = AND (as RustSec uses it)."""
    ver = _ver(version)
    return all(_cmp_one(ver, c) for c in req.split(',') if c.strip())


def load_advisories(db):
    out = {}
    for f in pathlib.Path(db, 'crates').glob('*/*.md'):
        t = f.read_text(encoding='utf-8', errors='replace')
        m = re.search(r'```toml\n(.*?)```', t, re.S)
        if not m:
            continue
        toml = m.group(1)
        get = lambda k: (re.search(rf'^{k}\s*=\s*"([^"]*)"', toml, re.M) or [None, None])[1]
        lst = lambda k: re.findall(r'"([^"]*)"', (re.search(rf'^{k}\s*=\s*\[(.*?)\]', toml, re.M | re.S) or [None, ''])[1])
        if re.search(r'^withdrawn\s*=', toml, re.M):
            continue
        adv = {'id': get('id'), 'package': get('package'), 'informational': get('informational'),
               'patched': lst('patched'), 'unaffected': lst('unaffected'), 'title': (re.search(r'^# (.+)$', t, re.M) or [None, ''])[1]}
        if adv['package']:
            out.setdefault(adv['package'], []).append(adv)
    return out


def load_accepted(path):
    """Reviewed advisories: `RUSTSEC-ID crate version | reason` per line. An
    entry covers exactly that crate VERSION: any other version, any new
    advisory, fails the check until it is reviewed too."""
    out = {}
    if not path or not pathlib.Path(path).exists():
        return out
    for n, line in enumerate(pathlib.Path(path).read_text(encoding='utf-8').splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        head, _, reason = line.partition('|')
        parts = head.split()
        if len(parts) != 3 or not reason.strip():
            raise SystemExit(f'{path} line {n}: expected  RUSTSEC-ID crate version | reason')
        out[tuple(parts)] = reason.strip()
    return out


def affected(adv, version):
    if any(version_matches(version, r) for r in adv['patched'] + adv['unaffected']):
        return False
    return True


def cmd_deps(a):
    problems, lines = [], []
    allp = {}
    for lock in LOCKS:
        p = ROOT / lock
        if not p.exists():
            problems.append(f'{lock}: missing (builds would not be reproducible)')
            continue
        pkgs = parse_lock(p.read_text())
        lines.append(f'## {lock}  sha256={hashlib.sha256(p.read_bytes()).hexdigest()}  packages={len(pkgs)}')
        for k in pkgs:
            src = k.get('source', 'local')
            lines.append(f"{k.get('name')} {k.get('version')} {src} {k.get('checksum', '-')}")
            if src.startswith('git+'):
                problems.append(f"{lock}: {k.get('name')} {k.get('version')} comes from git ({src})")
            elif src != 'local' and src != CRATES_IO:
                problems.append(f"{lock}: {k.get('name')} {k.get('version')} from an unknown registry ({src})")
            elif src == CRATES_IO and not k.get('checksum'):
                problems.append(f"{lock}: {k.get('name')} {k.get('version')} has no checksum")
            if src != 'local':
                allp.setdefault(k.get('name'), set()).add(k.get('version'))
    dups = {n: sorted(v) for n, v in allp.items() if len(v) > 1}
    lines.append(f'## crates with more than one version across the locks: {len(dups)}')
    lines += [f'{n} {" ".join(v)}' for n, v in sorted(dups.items())]
    text = '\n'.join(lines) + '\n'
    if a.out:
        pathlib.Path(a.out).write_text(text)
    print(f'DEPS_LOCKFILES={sum(1 for l in LOCKS if (ROOT / l).exists())}\nDEPS_CRATES={len(allp)}\nDEPS_MULTI_VERSION={len(dups)}')
    warnings = []
    accepted, acc_used, accepted_hits = load_accepted(a.accepted), set(), []
    if a.advisory_db:
        try:
            import subprocess
            ts = int(subprocess.run(['git', '-C', a.advisory_db, 'log', '-1', '--format=%ct'], capture_output=True, text=True, check=True).stdout.strip())
            age = (time.time() - ts) / 86400
            print(f'DEPS_ADVISORY_DB_AGE_DAYS={age:.1f}')
            if age > MAX_DB_AGE_DAYS:
                problems.append(f'advisory database older than {MAX_DB_AGE_DAYS} days: git -C {a.advisory_db} pull')
        except (OSError, ValueError, subprocess.CalledProcessError):
            warnings.append(f'age of {a.advisory_db} unknown (not a git checkout): make sure it is current')
        db = load_advisories(a.advisory_db)
        seen = set()
        for lock in LOCKS:
            p = ROOT / lock
            if not p.exists():
                continue
            for k in parse_lock(p.read_text()):
                if k.get('source', 'local') != CRATES_IO:
                    continue
                key = (k['name'], k['version'])
                if key in seen:
                    continue
                seen.add(key)
                for adv in db.get(k['name'], []):
                    try:
                        hit = affected(adv, k['version'])
                    except ValueError as e:
                        warnings.append(f"{adv['id']} {k['name']}: unparsed requirement {e}")
                        continue
                    if not hit:
                        continue
                    line = f"{adv['id']} {k['name']} {k['version']}: {adv['title']} (fixed: {', '.join(adv['patched']) or 'none'})"
                    if adv['informational']:
                        warnings.append(f"{adv['informational'].upper()} {line}")
                    elif (adv['id'], k['name'], k['version']) in accepted:
                        acc_used.add((adv['id'], k['name'], k['version']))
                        accepted_hits.append(f"{line} | {accepted[(adv['id'], k['name'], k['version'])]}")
                    else:
                        problems.append(f"VULNERABLE {line}")
        n = sum(len(v) for v in db.values())
        lines.append(f'## advisories checked: {n} from {a.advisory_db}')
        lines += [f'PROBLEM {x}' for x in problems] + [f'WARNING {w}' for w in warnings]
        if a.out:
            pathlib.Path(a.out).write_text('\n'.join(lines) + '\n')
        for key in sorted(set(accepted) - acc_used):
            warnings.append(f'accepted entry no longer needed (remove it from {a.accepted}): {" ".join(key)}')
        lines += [f'ACCEPTED {x}' for x in accepted_hits]
        if a.out:
            pathlib.Path(a.out).write_text('\n'.join(lines) + '\n')
        for x in accepted_hits:
            print(f'DEPS_ACCEPTED {x}')
        for w in warnings:
            print(f'DEPS_WARNING {w}')
        print(f'DEPS_ADVISORIES=CHECKED {n} advisories, {len(seen)} crate versions')
    else:
        print('DEPS_ADVISORIES=NOT_CHECKED (give --advisory-db PATH: a clone of https://github.com/rustsec/advisory-db)')
    for pr in problems:
        print(f'DEPS_PROBLEM {pr}')
    print(f'DEPS={"PASS" if not problems else "FAIL"}')
    return 0 if not problems else 1


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='mode', required=True)
    s = sub.add_parser('scan'); s.add_argument('path')
    k = sub.add_parser('pack'); k.add_argument('--out', default=str(ROOT / 'dist' / 'grinsight-src.zip')); k.add_argument('--with-vendor', action='store_true')
    d = sub.add_parser('deps'); d.add_argument('--out'); d.add_argument('--advisory-db'); d.add_argument('--accepted', default=str(ROOT / 'deps-accepted.txt'))
    a = p.parse_args()
    return {'scan': cmd_scan, 'pack': cmd_pack, 'deps': cmd_deps}[a.mode](a)


if __name__ == '__main__':
    sys.exit(main())





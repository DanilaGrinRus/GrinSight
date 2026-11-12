"""Cross-check a checkpoint header against independent sources (RESEARCH).

The checkpoint file is first validated by the Rust binary (header bytes, hash,
PoW, MMR peaks) and its header fields are printed. Each source is then asked
for the header at the same height and every field it provides is compared.

Sources (each optional, configurable):
  * node API v2 foreign `get_header` (JSON-RPC): local node and public nodes
  * block explorer JSON APIs (--json): the full header, every field compared
    (e.g. scan=https://scan.grin.money/api/block/{height}); counts like a node
  * block explorer pages: only the block hash is compared (HASH_ONLY)

PASS needs at least --min-full full-field matches (default 2), at least one of
them from a source not on this machine, and no mismatch anywhere. A source
that cannot be reached is reported and does not count either way.

This is a defence against a grossly substituted checkpoint, not a proof: if
every source is controlled by the same party, they can all agree on a lie.
"""
import argparse, base64, datetime, json, os, re, subprocess, sys, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN = Path(os.environ.get('GRINSIGHT_BIN_DIR', ROOT / '.build' / 'target' / 'release'))
EXE = BIN / ('reverse-wtema-header-sync' + ('.exe' if os.name == 'nt' else ''))

FIELDS = ['hash', 'version', 'previous', 'prev_root', 'timestamp_unix', 'output_root', 'output_mmr_size',
          'range_proof_root', 'kernel_root', 'kernel_mmr_size', 'total_kernel_offset', 'total_difficulty',
          'secondary_scaling', 'nonce', 'edge_bits', 'cuckoo_solution']


def describe(path, mainnet):
    cmd = [str(EXE), '--describe-checkpoint', str(path)] + (['--mainnet'] if mainnet else [])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or 'CHECKPOINT_FILE_VALID=true' not in r.stdout:
        raise SystemExit(f'checkpoint invalid: {r.stdout} {r.stderr}')
    return dict(l.split('=', 1) for l in r.stdout.splitlines() if '=' in l)


def norm(field, value):
    if value is None:
        return None
    if field == 'cuckoo_solution':
        return ','.join(str(int(x)) for x in (value if isinstance(value, list) else str(value).split(',')))
    if field == 'timestamp_unix':
        if isinstance(value, (int, float)) or str(value).isdigit():
            return str(int(value))
        return str(int(datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()))
    if isinstance(value, str):
        return value.lower()
    return str(value)


def api_header(url, height, secret_file):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'get_header', 'params': [height, None, None]}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    if secret_file and Path(secret_file).is_file():
        token = base64.b64encode(b'grin:' + Path(secret_file).read_text().strip().encode()).decode()
        req.add_header('Authorization', 'Basic ' + token)
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read(2_000_000))
    res = data.get('result', {})
    h = res.get('Ok') if isinstance(res, dict) else None
    if not isinstance(h, dict):
        raise ValueError(f'no header in response: {str(data)[:200]}')
    h = dict(h)
    h['timestamp_unix'] = h.get('timestamp')
    return {f: norm(f, h.get(f)) for f in FIELDS if h.get(f) is not None}


def json_header(url_template, height):
    """Header from an explorer JSON API: {"header": {...}} or the header itself,
    with the same field names as the node API (hash, previous, output_root ...)."""
    url = url_template.format(height=height)
    req = urllib.request.Request(url, headers={'User-Agent': 'grinsight-checkpoint-crosscheck', 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read(5_000_000))
    h = data.get('header', data) if isinstance(data, dict) else None
    if not isinstance(h, dict) or int(h.get('height', -1)) != int(height):
        raise ValueError(f'no header for height {height} in response')
    h = dict(h)
    h['timestamp_unix'] = h.get('timestamp')
    return {f: norm(f, h.get(f)) for f in FIELDS if h.get(f) is not None}


def explorer_hash(url_template, height):
    url = url_template.format(height=height)
    req = urllib.request.Request(url, headers={'User-Agent': 'grinsight-checkpoint-crosscheck'})
    with urllib.request.urlopen(req, timeout=20) as r:
        text = r.read(2_000_000).decode('utf-8', 'replace')
    hashes = set(re.findall(r'\b[0-9a-f]{64}\b', text))
    return hashes


def list_peers(url, secret):
    """Peers the node is connected to. Inbound peers report an ephemeral source
    port, so their IP is paired with the standard mainnet P2P port 3414.
    PIBD support is decided later by a real handshake (--probe-peer)."""
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'get_connected_peers', 'params': []}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    if secret and Path(secret).is_file():
        req.add_header('Authorization', 'Basic ' + base64.b64encode(b'grin:' + Path(secret).read_text().strip().encode()).decode())
    with urllib.request.urlopen(req, timeout=20) as r:
        peers = json.loads(r.read(5_000_000))['result']['Ok']
    seen = set()
    for x in sorted(peers, key=lambda x: -int(x.get('height') or 0)):
        caps = x.get('capabilities')
        bits = caps.get('bits', 0) if isinstance(caps, dict) else int(caps or 0)
        addr = str(x.get('addr') or '')
        ip, _, port = addr.rpartition(':')
        if not ip or ip.startswith(('127.', '[::1]', '10.', '192.168.')):
            continue
        if str(x.get('direction')) != 'Outbound':
            port = '3414'
        target = f'{ip}:{port}'
        if target in seen:
            continue
        seen.add(target)
        agent = str(x.get('user_agent') or '')
        kind = 'RUST_PEER' if agent.startswith('MW/Grin') and bits & 0x10 else 'OTHER_PEER'
        print(f'{kind}={target} agent={agent!r} caps=0x{bits:x} height={x.get("height")} dir={x.get("direction")}')
    # A public node refuses a second connection from an IP it is already
    # connected to (grin check_undesirable): the peers above are connected to
    # this machine's node, so they reject us. Healthy peers the node knows but
    # is NOT connected to can be used.
    connected_ips = {t.rpartition(':')[0] for t in seen}
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'get_peers', 'params': [None]}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    if secret and Path(secret).is_file():
        req.add_header('Authorization', 'Basic ' + base64.b64encode(b'grin:' + Path(secret).read_text().strip().encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            known = json.loads(r.read(50_000_000))['result']['Ok']
    except Exception as e:
        print(f'KNOWN_PEERS=UNAVAILABLE {type(e).__name__}: {str(e)[:120]}')
        return 0
    shown = 0
    for x in sorted(known, key=lambda x: -int(x.get('last_connected') or 0)):
        caps = x.get('capabilities')
        bits = caps.get('bits', 0) if isinstance(caps, dict) else int(caps or 0)
        addr = str(x.get('addr') or '')
        ip = addr.rpartition(':')[0]
        agent = str(x.get('user_agent') or '')
        if (str(x.get('flags')) != 'Healthy' or not agent.startswith('MW/Grin') or not bits & 0x10
                or not ip or ip in connected_ips or ip.startswith(('127.', '[', '10.', '192.168.'))):
            continue
        print(f'KNOWN_PEER={addr} agent={agent!r} caps=0x{bits:x} last_connected={x.get("last_connected")}')
        shown += 1
        if shown >= 30:
            break
    return 0


# Grin 5.5.2 servers/src/grin/seed.rs MAINNET_DNS_SEEDS
MAINNET_DNS_SEEDS = ['mainnet-seed.grinnode.live', 'grincoin.org', 'main.gri.mw',
                     'mainnet.grinffindor.org', 'main-seed.grin.money',
                     'mainnet.fountainoffairfortune.it']


def dns_seed_peers(port=3414, limit=40):
    """Public peers for a run without a local node. Which of them really serve
    PIBD is decided later by a real handshake (--probe-peer)."""
    import socket
    seen = []
    for host in MAINNET_DNS_SEEDS:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as e:
            print(f'DNS_SEED={host} FAIL {e}')
            continue
        n = 0
        for family, _, _, _, addr in infos:
            ip = addr[0]
            target = f'[{ip}]:{port}' if family == socket.AF_INET6 else f'{ip}:{port}'
            if target not in seen:
                seen.append(target)
                n += 1
        print(f'DNS_SEED={host} OK {n}')
    # interleave seeds a little: IPv4 first (most peers), then IPv6
    v4 = [t for t in seen if not t.startswith('[')]
    v6 = [t for t in seen if t.startswith('[')]
    for t in (v4 + v6)[:limit]:
        print(f'KNOWN_PEER={t}')
    return 0 if seen else 3


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--checkpoint')
    p.add_argument('--print-tip', help='URL of a node foreign API v2: print TIP=height and exit')
    p.add_argument('--tip-secret', help='PATH of the .foreign_api_secret for --print-tip')
    p.add_argument('--mainnet', action='store_true')
    p.add_argument('--list-peers', help='URL of a node OWNER API v2: print its connected peers (RUST_PEER=/OTHER_PEER=) and exit')
    p.add_argument('--peers-secret', help='PATH of the .api_secret (owner API) for --list-peers')
    p.add_argument('--dns-seeds', action='store_true', help='resolve the Grin mainnet DNS seeds: print KNOWN_PEER=ip:3414 and exit')
    p.add_argument('--api', action='append', default=[],
                   help='NAME=URL of a node foreign API v2, e.g. local=http://127.0.0.1:3413/v2/foreign')
    p.add_argument('--secret', action='append', default=[],
                   help='NAME=PATH of a .foreign_api_secret file for API NAME (read locally, never printed)')
    p.add_argument('--json', action='append', default=[],
                   help='NAME=URL template with {height} of an explorer JSON API, e.g. scan=https://scan.grin.money/api/block/{height}')
    p.add_argument('--explorer', action='append', default=[],
                   help='NAME=URL template with {height}, e.g. scan=https://scan.grin.money/block/{height}')
    p.add_argument('--min-full', type=int, default=2)
    a = p.parse_args()
    if a.dns_seeds:
        return dns_seed_peers()
    if a.list_peers:
        return list_peers(a.list_peers, a.peers_secret)
    if a.print_tip:
        url, secret = a.print_tip, a.tip_secret
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'get_tip', 'params': []}).encode()
        req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
        if secret and Path(secret).is_file():
            req.add_header('Authorization', 'Basic ' + base64.b64encode(b'grin:' + Path(secret).read_text().strip().encode()).decode())
        with urllib.request.urlopen(req, timeout=20) as r:
            tip = json.loads(r.read(100_000))['result']['Ok']
        print(f"TIP={tip['height']}")
        return 0
    if not a.checkpoint:
        p.error('--checkpoint is required')

    cp = describe(a.checkpoint, a.mainnet)
    height = int(cp['height'])
    mine = {f: norm(f, cp.get(f)) for f in FIELDS}
    print(f'CHECKPOINT_HEIGHT={height}\nCHECKPOINT_HASH={mine["hash"]}')

    full_ok, remote_ok, mismatch = 0, 0, False
    secrets = dict(x.partition('=')[::2] for x in a.secret)
    sources = [(s, 'api') for s in a.api] + [(s, 'json') for s in a.json]
    for spec, kind in sources:
        name, _, url = spec.partition('=')
        secret = secrets.get(name)
        local = any(x in url for x in ('127.0.0.1', 'localhost', '[::1]'))
        try:
            theirs = api_header(url, height, secret or None) if kind == 'api' else json_header(url, height)
        except Exception as e:
            print(f'SOURCE={name} UNREACHABLE {type(e).__name__}: {str(e)[:150]}')
            continue
        diff = [f for f in FIELDS if f in theirs and theirs[f] != mine[f]]
        compared = [f for f in FIELDS if f in theirs]
        if diff:
            mismatch = True
            print(f'SOURCE={name} MISMATCH fields={",".join(diff)}')
            for f in diff:
                print(f'  {f}: checkpoint={mine[f]} source={theirs[f]}')
        elif len(compared) < 10:
            print(f'SOURCE={name} PARTIAL compared={len(compared)} fields (not counted as full)')
        else:
            full_ok += 1
            remote_ok += 0 if local else 1
            print(f'SOURCE={name} MATCH fields={len(compared)}{" (local)" if local else ""}')
    for spec in a.explorer:
        name, _, tmpl = spec.partition('=')
        try:
            hashes = explorer_hash(tmpl, height)
        except Exception as e:
            print(f'SOURCE={name} UNREACHABLE {type(e).__name__}: {str(e)[:150]}')
            continue
        if mine['hash'] in hashes:
            print(f'SOURCE={name} HASH_ONLY_MATCH')
        elif hashes:
            mismatch = True
            print(f'SOURCE={name} HASH_NOT_FOUND (page lists {len(hashes)} other 64-hex values)')
        else:
            print(f'SOURCE={name} NO_HASH_ON_PAGE (not counted)')

    ok = not mismatch and full_ok >= a.min_full and remote_ok >= 1
    print(f'FULL_FIELD_MATCHES={full_ok}\nREMOTE_FULL_MATCHES={remote_ok}\nCROSSCHECK={"PASS" if ok else "FAIL"}')
    print('NOTE=agreement of sources is not proof; it guards against a grossly substituted checkpoint')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())

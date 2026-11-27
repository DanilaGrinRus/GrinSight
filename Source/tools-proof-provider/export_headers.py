"""Export public headers using the local Grin node's standard Foreign API.

Only loopback is reachable. Optional node credentials are taken from the explicit
file, never looked up in a wallet, included in an artifact or sent to another host.
The binary encoding follows the existing GrinSight research dump_headers.py.
"""
import argparse
import base64
import calendar
import hashlib
import http.client
import json
import os
from pathlib import Path
import struct
import tempfile
import time

REPLY_LIMIT = 65536
MAX_HEIGHT = 16_000_000


def seconds(stamp):
    from datetime import datetime, timezone
    dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("expected timestamp with timezone")
    return calendar.timegm(dt.astimezone(timezone.utc).timetuple())


def fixed(text):
    raw = bytes.fromhex(text)
    if len(raw) != 32:
        raise ValueError("expected a 32-byte field")
    return raw


def binary(h):
    bits = int(h["edge_bits"])
    nonces = h["cuckoo_solution"]
    if not 1 <= bits <= 63 or len(nonces) != 42:
        raise ValueError("unexpected Grin PoW dimensions")
    packed = 0
    for i, nonce in enumerate(nonces):
        n = int(nonce)
        if not 0 <= n < 1 << bits:
            raise ValueError("nonce outside declared width")
        packed |= n << (i * bits)
    solution = packed.to_bytes((bits * 42 + 7) // 8, "little")
    raw = struct.pack(">HQq", int(h["version"]), int(h["height"]), seconds(h["timestamp"]))
    for field in ("previous", "prev_root", "output_root", "range_proof_root", "kernel_root", "total_kernel_offset"):
        raw += fixed(h[field])
    raw += struct.pack(">QQQIQB", int(h["output_mmr_size"]), int(h["kernel_mmr_size"]),
                       int(h["total_difficulty"]), int(h["secondary_scaling"]), int(h["nonce"]), bits)
    return raw + solution, hashlib.blake2b(solution, digest_size=32).digest()


class LocalNode:
    def __init__(self, port, secret):
        self.port = port
        self.headers = {"Content-Type": "application/json"}
        if secret:
            self.headers["Authorization"] = "Basic " + base64.b64encode(b"grin:" + secret).decode("ascii")
        self.conn = None

    def call(self, method, params):
        request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        for attempt in range(3):
            try:
                if self.conn is None:
                    self.conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
                self.conn.request("POST", "/v2/foreign", request, self.headers)
                response = self.conn.getresponse()
                data = response.read(REPLY_LIMIT + 1)
                if response.status != 200 or len(data) > REPLY_LIMIT:
                    raise ValueError(f"node rejected request or exceeded bounds (HTTP {response.status})")
                payload = json.loads(data)
                if payload.get("id") != 1 or "Ok" not in payload.get("result", {}):
                    raise ValueError("invalid Foreign API response")
                return payload["result"]["Ok"]
            except (OSError, http.client.HTTPException):
                self.conn.close()
                self.conn = None
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)


def export(node, out, stop=None):
    tip = node.call("get_tip", [])
    height = int(tip["height"]) if stop is None else stop
    if not 0 <= height <= min(int(tip["height"]), MAX_HEIGHT):
        raise ValueError("export height outside range")
    # One completed snapshot, atomically replaced. An interruption leaves the old snapshot readable.
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(dir=out.parent, prefix=".headers-", delete=False) as stream:
            tmp = Path(stream.name)
            prev = None
            for h in range(height + 1):
                record = node.call("get_header", [h, None, None])
                raw, digest = binary(record)
                if int(record["height"]) != h or fixed(record["hash"]) != digest:
                    raise ValueError(f"inconsistent header at {h}")
                if prev is not None and fixed(record["previous"]) != prev:
                    raise ValueError(f"chain changed during export at {h}")
                stream.write(struct.pack(">H", len(raw)))
                stream.write(raw)
                prev = digest
            # Pin the end even if a reorganisation happens during an earlier request.
            if fixed(node.call("get_header", [height, None, None])["hash"]) != prev:
                raise ValueError("chain changed before export commit")
        os.replace(tmp, out)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("out", type=Path)
    p.add_argument("--port", type=int, default=3413)
    p.add_argument("--to", type=int)
    p.add_argument("--secret-file", type=Path, help="optional local node Foreign API credential")
    arg = p.parse_args()
    if not 1 <= arg.port <= 65535:
        p.error("invalid port")
    secret = None
    if arg.secret_file is not None:
        with arg.secret_file.open("rb") as f:
            secret = f.read(4097)
        if len(secret) > 4096:
            p.error("credential file too large")
        secret = secret.strip()
    export(LocalNode(arg.port, secret), arg.out, arg.to)

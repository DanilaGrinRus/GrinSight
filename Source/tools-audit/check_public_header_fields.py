"""Inspect public, read-only Grin Foreign responses at one common height."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import re
import urllib.request


def query(host, method, params):
    body = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode()
    request = urllib.request.Request("https://" + host + "/v2/foreign", data=body,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "GrinFlySight/0.4.7A"})
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.load(response)
    return result["result"]["Ok"]


def inspect(host, height):
    row = dict(host=host, height=height)
    for method, params in [("get_version", []), ("get_tip", []), ("get_header", [height, None, None])]:
        try:
            result = query(host, method, params)
            fields = dict(keys=sorted(result))
            if method == "get_version":
                fields["version"] = result.get("node_version")
            if method == "get_header":
                fields.update(height=result.get("height"), hash=result.get("hash"),
                              prev_root=result.get("prev_root"), previous=result.get("previous"))
                fields["valid_root_field"] = bool(re.fullmatch("[0-9a-fA-F]{64}", result.get("prev_root") or ""))
            row[method] = fields
        except Exception as error:
            row[method] = dict(error=str(error)[:200])
    return row


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("height", type=int)
    parser.add_argument("hosts", nargs="+")
    args = parser.parse_args()
    with ThreadPoolExecutor(max_workers=5) as pool:
        for record in pool.map(lambda host: inspect(host, args.height), args.hosts):
            print(json.dumps(record), flush=True)

#!/usr/bin/env python3
"""Minimal TLS reverse proxy for the GrinSight gateway prototype.

Terminates TLS and forwards raw bytes to the plain-WS gateway. In production
use Caddy/nginx with a real certificate; this script exists to test the WSS
client path end-to-end with a self-signed test certificate.

Example:
  python tls_proxy.py --listen 127.0.0.1:9443 \
    --cert <dummy-cert.pem> --key <dummy-key.pem> \
    --upstream 127.0.0.1:8787
"""
import argparse
import socket
import ssl
import threading


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--listen', default='127.0.0.1:9443')
    ap.add_argument('--cert', required=True)
    ap.add_argument('--key', required=True)
    ap.add_argument('--upstream', default='127.0.0.1:8787')
    args = ap.parse_args()
    host, port = args.listen.rsplit(':', 1)
    uhost, uport = args.upstream.rsplit(':', 1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, int(port)))
    srv.listen(16)
    print(f'TLS_PROXY_READY listen={args.listen} upstream={args.upstream}', flush=True)
    while True:
        try:
            raw, addr = srv.accept()
            tls = ctx.wrap_socket(raw, server_side=True)
            up = socket.create_connection((uhost, int(uport)), timeout=10)
            up.settimeout(None)
            tls.settimeout(None)
            t1 = threading.Thread(target=pump, args=(tls, up), daemon=True)
            t2 = threading.Thread(target=pump, args=(up, tls), daemon=True)
            t1.start(); t2.start()
        except Exception as e:
            print(f'TLS_PROXY_ERROR {e}', flush=True)


if __name__ == '__main__':
    main()

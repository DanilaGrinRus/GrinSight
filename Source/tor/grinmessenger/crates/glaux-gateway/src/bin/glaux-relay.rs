// SPDX-License-Identifier: MIT OR Apache-2.0
//! Standalone store-and-forward relay.
//!
//! It has no wallet at all: only opaque messenger envelopes, quotas, TTL and
//! signed recipient acks. Bind it to loopback and publish it through a Tor
//! hidden service (with an onion service pointing at this local port), or put a
//! TLS reverse proxy in front of it. Never expose this plaintext listener to the
//! public internet.

use std::path::PathBuf;

use glaux_gateway::{wait_ready, Gateway, GatewayConfig};

fn usage() -> &'static str {
    "glaux-relay [options]

  --listen <addr>       bind address (default 127.0.0.1:8080)
  --store <dir>         message directory (default glaux-relay-store)
  --ttl <seconds>       maximum message lifetime (default 93600)
  --max-per <n>         messages per recipient (default 100)
  --max-total <n>       messages on this relay (default 10000)
  --allow-unsigned-fetch
                        legacy/dev only: disable signed mailbox fetch proofs
  --help

Messages are opaque signed+encrypted envelopes. The relay cannot decrypt the
payload or the sender address. Recipient acks must be signed, envelopes must
carry a valid proof of work, and mailbox reads require a signed fetch proof from
the address key (otherwise anyone knowing an address could enumerate metadata)."
}

fn main() {
    let mut listen = "127.0.0.1:8080".to_string();
    let mut store = PathBuf::from("glaux-relay-store");
    let mut ttl = 26 * 60 * 60u64;
    let mut max_per = 100usize;
    let mut max_total = 10_000usize;
    let mut require_fetch_proof = true;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .unwrap_or_else(|| fatal(&format!("{arg}: нужно значение")))
        };
        match arg.as_str() {
            "--listen" => listen = value(),
            "--store" => store = PathBuf::from(value()),
            "--ttl" => ttl = value().parse().unwrap_or_else(|_| fatal("--ttl: число")),
            "--max-per" => {
                max_per = value()
                    .parse()
                    .unwrap_or_else(|_| fatal("--max-per: число"))
            }
            "--max-total" => {
                max_total = value()
                    .parse()
                    .unwrap_or_else(|_| fatal("--max-total: число"))
            }
            "--allow-unsigned-fetch" => require_fetch_proof = false,
            "--help" | "-h" => {
                println!("{}", usage());
                return;
            }
            other => fatal(&format!("неизвестный аргумент: {other}")),
        }
    }

    let bind = listen
        .parse()
        .unwrap_or_else(|_| fatal("--listen: ожидался host:port"));
    std::fs::create_dir_all(&store).unwrap_or_else(|e| fatal(&format!("store: {e}")));

    let gateway = Gateway::start(GatewayConfig {
        bind,
        require_signed_ack: true,
        require_pow: true,
        require_fetch_proof,
        store_dir: Some(store.clone()),
        ttl_secs: ttl,
        max_per_recipient: max_per,
        max_total,
        ..GatewayConfig::default()
    })
    .unwrap_or_else(|e| fatal(&format!("relay start: {e}")));
    if !wait_ready(&gateway, std::time::Duration::from_secs(5)) {
        fatal("relay не ответил на health-check");
    }

    println!("glaux-relay listening on {}", gateway.url());
    println!("store: {}", store.display());
    println!("ttl: {ttl}s, per-recipient: {max_per}, total: {max_total}");
    println!("signed acks: required, proof of work: required");
    if require_fetch_proof {
        println!("mailbox fetch: signed address proof required");
    } else {
        println!("WARNING: mailbox fetch proofs disabled (--allow-unsigned-fetch)");
    }
    println!("Publish this listener through Tor; do not expose it as plain HTTP.");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

fn fatal(message: &str) -> ! {
    eprintln!("glaux-relay: {message}");
    std::process::exit(1);
}

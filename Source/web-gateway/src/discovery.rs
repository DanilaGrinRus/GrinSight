//! Peer discovery for the gateway: DNS seeds -> short PIBD probe -> /16 pool.
//! The gateway does not verify chain data; this module only decides who to talk to.

use grin_p2p::types::Capabilities;
use grinsight_state::headers::net_group;
use grinsight_state::session::{
    dns_resolve, seed_peers, FLOONET_DNS_SEEDS, MAINNET_DNS_SEEDS,
};
use std::time::Duration;

pub const MAINNET_PORT: u16 = 3414;
pub const FLOONET_PORT: u16 = 13414;
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Clone, Debug)]
pub struct Probe {
    pub addr: String,
    pub caps: Capabilities,
}

impl Probe {
    pub fn pibd(&self) -> bool {
        self.caps.contains(Capabilities::PIBD_HIST)
    }
    pub fn group(&self) -> String {
        net_group(&self.addr)
    }
}

/// Resolve the seed list to candidate `ip:port` strings. DNS errors are
/// non-fatal: one broken seed must not stop discovery.
pub fn seed_candidates(mainnet: bool) -> Vec<String> {
    let (seeds, port) = if mainnet {
        (MAINNET_DNS_SEEDS, MAINNET_PORT)
    } else {
        (FLOONET_DNS_SEEDS, FLOONET_PORT)
    };
    let answers: Vec<Vec<std::net::IpAddr>> = seeds
        .iter()
        .map(|s| dns_resolve(s, port).unwrap_or_default())
        .collect();
    seed_peers(&answers, port, 64)
}

/// Probe all candidates in parallel with a short timeout; failures are skipped.
fn probe_round(candidates: &[String]) -> Vec<Probe> {
    let mut out = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for addr in candidates {
            let addr = addr.clone();
            handles.push(scope.spawn(move || {
                crate::peer::probe(&addr, PROBE_TIMEOUT)
                    .map(|caps| Probe { addr, caps })
                    .ok()
            }));
        }
        for h in handles {
            if let Ok(Some(p)) = h.join() {
                out.push(p);
            }
        }
    });
    out
}

/// Probe, then retry failed candidates once after a short pause (public peers
/// often drop the first handshake while forgetting a previous connection).
pub fn probe_candidates(candidates: &[String], want: usize) -> Vec<Probe> {
    let mut out = probe_round(candidates);
    if out.len() < want {
        let tried: Vec<String> = out.iter().map(|p| p.addr.clone()).collect();
        let retry: Vec<String> = candidates.iter().filter(|c| !tried.contains(c)).cloned().collect();
        if !retry.is_empty() {
            eprintln!("DISCOVERY_RETRY={}", retry.len());
            std::thread::sleep(Duration::from_secs(3));
            out.extend(probe_round(&retry));
        }
    }
    out
}

/// Keep PIBD-capable peers, at most one per /16, up to `max`.
pub fn select_pool(probes: &[Probe], max: usize) -> Vec<String> {
    let mut groups: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for p in probes {
        if !p.pibd() || out.len() >= max {
            continue;
        }
        let g = p.group();
        if groups.contains(&g) {
            continue;
        }
        groups.push(g);
        out.push(p.addr.clone());
    }
    out
}

/// Full discovery: seeds -> candidates -> PIBD probes -> distinct /16 pool.
pub fn discover(mainnet: bool, max: usize) -> Vec<String> {
    let candidates = seed_candidates(mainnet);
    eprintln!("DISCOVERY_CANDIDATES={}", candidates.len());
    let probes = probe_candidates(&candidates, max);
    let pibd = probes.iter().filter(|p| p.pibd()).count();
    eprintln!("DISCOVERY_PIBD={pibd}");
    let pool = select_pool(&probes, max);
    eprintln!("DISCOVERY_POOL={pool:?}");
    pool
}

#[cfg(test)]
mod tests {
    use super::*;
    use grin_p2p::types::Capabilities;

    fn probe(addr: &str, pibd: bool) -> Probe {
        let mut caps = Capabilities::empty();
        if pibd {
            caps = caps | Capabilities::PIBD_HIST;
        }
        Probe { addr: addr.into(), caps }
    }

    #[test]
    fn seed_list_has_known_entries() {
        assert!(!MAINNET_DNS_SEEDS.is_empty());
        assert!(!FLOONET_DNS_SEEDS.is_empty());
        assert_eq!(MAINNET_PORT, 3414);
        assert_eq!(FLOONET_PORT, 13414);
    }

    #[test]
    fn pool_filters_non_pibd_and_duplicate_16() {
        let probes = vec![
            probe("10.1.2.3:3414", true),
            probe("10.1.9.9:3414", true),  // same /16
            probe("10.2.4.5:3414", false), // not PIBD
            probe("10.3.4.5:3414", true),
            probe("10.4.4.5:3414", true),
        ];
        assert_eq!(
            select_pool(&probes, 3),
            vec!["10.1.2.3:3414", "10.3.4.5:3414", "10.4.4.5:3414"]
        );
    }

    #[test]
    fn pool_respects_max() {
        let probes: Vec<Probe> = (1..=8)
            .map(|i| probe(&format!("10.{}.1.1:3414", i), true))
            .collect();
        assert_eq!(select_pool(&probes, 3).len(), 3);
    }

    #[test]
    fn seed_peers_dedup_and_limit() {
        use std::net::IpAddr;
        let a: IpAddr = "10.1.1.1".parse().unwrap();
        let b: IpAddr = "10.2.2.2".parse().unwrap();
        let peers = seed_peers(&[vec![a, b], vec![a]], 3414, 1);
        assert_eq!(peers, vec!["10.1.1.1:3414"]);
    }
}

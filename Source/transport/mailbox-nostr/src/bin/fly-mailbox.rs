//! The transport process of GrinSight Fly.
//!
//! Started by the wallet's process with nothing on the command line. It
//! reads one start-up message from its standard input (the profile's
//! transport identity, contacts, relay and data directory), brings up Tor,
//! and then answers the six calls of the `Mailbox` port until its input is
//! closed. It holds no wallet key and takes no part in deciding payments.
//!
//! Standard output carries the protocol and nothing else; nothing is logged.
#![forbid(unsafe_code)]

use fly_mailbox_nostr::{from_config, TorConnector};
use fly_paycore_mailbox_pipe::{serve, Config};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let outcome = serve(&mut stdin.lock(), &mut stdout.lock(), |config: Config| {
        let start = Duration::from_secs(u64::from(config.start_timeout_secs));
        let publish = Duration::from_millis(u64::from(config.publish_timeout_ms));
        let relay = config.relay.clone();
        let tor_root = Path::new(&config.data_dir).to_path_buf();
        let bridges = config.tor_bridges.clone();
        from_config(&config, move |rt| {
            let tor = rt.block_on(fly_tor::SharedTor::bootstrap_through(&tor_root, start, &bridges)).map_err(|e| match e {
                fly_tor::TorError::Bridges => "the Tor bridges cannot be used".to_string(),
                _ => "Tor did not come up".to_string(),
            })?;
            Ok(TorConnector {
                tor,
                relay,
                timeout: publish,
            })
        })
    });
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(2),
    }
}

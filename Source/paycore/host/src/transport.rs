//! The transport process, as the payment core sees it.
//!
//! The core gets a `Mailbox` at once; the process behind it may still be
//! bringing up its network, may have failed to, or may have died. Until it
//! is ready nothing is published, nothing arrives and nothing can be sealed;
//! the answers are the cautious ones of the pipe ("busy", "nothing", never
//! "there is no stored reply"). A transport that is down is started again
//! after a pause, with the same identity, and only after the previous
//! process is gone.
use fly_paycore_bridge::pipe::{Config, PipeMailbox, Starting};
use fly_paycore_bridge::ports::{Envelope, Incoming, Mailbox, Published, TransportSpec};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a sealed message may wait at relays, in seconds.
const DELIVERY_WINDOW_SECS: u32 = 15 * 60;
/// Longest wait for a relay to acknowledge, in milliseconds.
const PUBLISH_TIMEOUT_MS: u32 = 20_000;
/// How long one contact is polled for a message, in milliseconds.
const POLL_MS: u32 = 100;
/// Longest wait for the transport's network to come up, in seconds.
const START_TIMEOUT_SECS: u32 = 180;
/// Longest wait for the answer to one call.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the transport program is and what it is told that is not secret.
#[derive(Clone)]
pub struct Launcher {
    /// The transport program.
    pub program: PathBuf,
    /// Address of the relay.
    pub relay: String,
    /// Directory for the transport's own files.
    pub data_dir: String,
    /// Pause before a transport that is down is started again.
    pub retry: Duration,
}

/// What the transport is doing, for the interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Phase {
    /// There is none: the profile is locked or has no transport identity.
    #[default]
    None,
    /// Its process runs and has not reported ready yet.
    Starting,
    /// It answers.
    Ready,
    /// It failed or stopped; it will be started again.
    Down,
}

/// The state of the transport as last seen by the worker.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// What it is doing.
    pub phase: Phase,
    /// Why it is down, if it is.
    pub error: Option<String>,
    /// How many times a process has been started for this profile session.
    pub starts: u32,
    /// What the running transport says is in its way (the relay cannot be
    /// reached, the relay refused and why), if anything. Words to show.
    pub problem: Option<String>,
}

/// Shared between the worker, which writes it, and the interface's thread.
pub type SharedReport = Arc<Mutex<Report>>;

fn update(report: &SharedReport, change: impl FnOnce(&mut Report)) {
    let mut slot = match report.lock() {
        Ok(slot) => slot,
        Err(poisoned) => poisoned.into_inner(),
    };
    change(&mut slot);
}

enum Stage {
    Starting(Starting),
    Ready(PipeMailbox),
    Down(Instant),
}

/// The `Mailbox` the host gives the bridge.
pub struct HostMailbox {
    launcher: Launcher,
    config: Config,
    stage: Stage,
    report: SharedReport,
}

impl HostMailbox {
    /// Start the transport for `spec` without waiting for it.
    pub fn start(launcher: &Launcher, spec: &TransportSpec, report: SharedReport) -> HostMailbox {
        let config = Config {
            identity_secret: *spec.identity_secret,
            identity_public: spec.identity_public,
            store_key: *spec.store_key,
            relay: launcher.relay.clone(),
            data_dir: launcher.data_dir.clone(),
            contacts: spec.contacts.clone(),
            delivery_window_secs: DELIVERY_WINDOW_SECS,
            publish_timeout_ms: PUBLISH_TIMEOUT_MS,
            poll_ms: POLL_MS,
            start_timeout_secs: START_TIMEOUT_SECS,
            tor_bridges: crate::tor_bridges::text(),
        };
        update(&report, |r| *r = Report::default());
        let mut mailbox = HostMailbox {
            launcher: launcher.clone(),
            config,
            stage: Stage::Down(Instant::now()),
            report,
        };
        mailbox.launch();
        mailbox
    }

    fn launch(&mut self) {
        match PipeMailbox::spawn_begin(&self.launcher.program, &self.config, CALL_TIMEOUT) {
            Ok(starting) => {
                self.stage = Stage::Starting(starting);
                update(&self.report, |r| {
                    r.phase = Phase::Starting;
                    r.error = None;
                    r.problem = None;
                    r.starts = r.starts.saturating_add(1);
                });
            }
            Err(why) => self.down(why),
        }
    }

    fn down(&mut self, why: String) {
        // whatever was there is dropped here, and its process with it
        self.stage = Stage::Down(Instant::now());
        update(&self.report, |r| {
            r.phase = Phase::Down;
            r.error = Some(why.chars().take(200).collect());
            r.problem = None;
        });
    }

    /// Move the state on and return the transport if it can be asked.
    fn live(&mut self) -> Option<&mut PipeMailbox> {
        match &mut self.stage {
            Stage::Starting(starting) => match starting.poll() {
                None => {}
                Some(Ok(mailbox)) => {
                    self.stage = Stage::Ready(mailbox);
                    update(&self.report, |r| r.phase = Phase::Ready);
                }
                Some(Err(why)) => self.down(why),
            },
            Stage::Ready(mailbox) => {
                if !mailbox.alive() {
                    self.down("the transport stopped".to_string());
                }
            }
            Stage::Down(since) => {
                if since.elapsed() >= self.launcher.retry {
                    self.launch();
                }
            }
        }
        match &mut self.stage {
            Stage::Ready(mailbox) => Some(mailbox),
            _ => None,
        }
    }
}

impl Drop for HostMailbox {
    fn drop(&mut self) {
        update(&self.report, |r| *r = Report::default());
    }
}

impl HostMailbox {
    fn tell(&mut self, problem: Option<String>) {
        update(&self.report, |r| r.problem = problem);
    }
}

impl Mailbox for HostMailbox {
    fn seal(&mut self, to: &[u8; 32], text: &str) -> Result<Envelope, String> {
        match self.live() {
            Some(mailbox) => mailbox.seal(to, text),
            None => Err("the transport is not ready".to_string()),
        }
    }
    fn publish(&mut self, envelope: &Envelope) -> Published {
        let Some(mailbox) = self.live() else {
            return Published::Busy;
        };
        let outcome = mailbox.publish(envelope);
        let problem = mailbox.problem();
        self.tell(problem);
        outcome
    }
    fn next_incoming(&mut self) -> Option<Incoming> {
        let mailbox = self.live()?;
        let incoming = mailbox.next_incoming();
        if incoming.is_none() {
            // the end of a round: a good moment to ask how it is going
            let problem = mailbox.problem();
            self.tell(problem);
        }
        incoming
    }
    fn resend_reply(&mut self, incoming: &[u8; 32]) -> Option<Published> {
        // without a transport to ask, "no stored reply" is not ours to say
        match self.live() {
            Some(mailbox) => mailbox.resend_reply(incoming),
            None => Some(Published::Busy),
        }
    }
    fn reply(&mut self, incoming: &[u8; 32], text: &str) -> Published {
        let Some(mailbox) = self.live() else {
            return Published::Busy;
        };
        let outcome = mailbox.reply(incoming, text);
        let problem = mailbox.problem();
        self.tell(problem);
        outcome
    }
    fn done(&mut self, incoming: &[u8; 32]) {
        if let Some(mailbox) = self.live() {
            mailbox.done(incoming);
        }
    }
    fn problem(&mut self) -> Option<String> {
        self.live()?.problem()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    /// With no transport to ask, every answer is the cautious one. Above
    /// all "there is no stored reply" is never said: the core would build
    /// a second reply to a payment it may have answered already.
    #[test]
    fn a_transport_that_is_not_there_is_never_spoken_for() {
        let report = SharedReport::default();
        let launcher = Launcher {
            program: std::env::temp_dir().join("no-such-transport-program"),
            relay: "wss://relay.example".into(),
            data_dir: String::new(),
            retry: Duration::from_secs(3600),
        };
        let spec = TransportSpec {
            identity_secret: Zeroizing::new([1; 32]),
            identity_public: [2; 32],
            store_key: Zeroizing::new([3; 32]),
            contacts: vec![[4; 32]],
        };
        let mut mailbox = HostMailbox::start(&launcher, &spec, report.clone());
        let seen = |r: &SharedReport| r.lock().unwrap().clone();
        assert_eq!((seen(&report).phase, seen(&report).starts), (Phase::Down, 0));
        assert_eq!(seen(&report).error.as_deref(), Some("the transport process could not be started"));
        let envelope = Envelope {
            event_id: [5; 32],
            bytes: vec![6; 10],
            expires_at: u64::MAX,
        };
        assert_eq!(mailbox.seal(&[4; 32], "text").err().as_deref(), Some("the transport is not ready"));
        assert_eq!(mailbox.publish(&envelope), Published::Busy);
        assert!(mailbox.next_incoming().is_none());
        assert_eq!(mailbox.resend_reply(&[7; 32]), Some(Published::Busy));
        assert_eq!(mailbox.reply(&[7; 32], "text"), Published::Busy);
        mailbox.done(&[7; 32]);
        // not started again before its pause is over
        assert_eq!(seen(&report).starts, 0);
        drop(mailbox);
        assert_eq!(seen(&report).phase, Phase::None);
        assert!(seen(&report).error.is_none());
    }
}

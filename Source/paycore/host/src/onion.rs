//! The Tor process for payments to and from the wallet's address, as the
//! payment core sees it.
//!
//! The core gets an `Onion` at once; the process behind it may still be
//! starting, may have failed or may have died. Until it answers nothing is
//! posted and nothing arrives. A process that is down, or whose Tor gave
//! up, is started again after a pause, and only after the previous process
//! is gone: two processes never announce one address.
use fly_paycore_bridge::onion_pipe::{Config, Event, Onion, Phase, PipeOnion, Starting, State};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Longest wait for the answer to one call. The process answers from
/// memory; it never waits for the network inside a call.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the Tor program is and what it is told that is not secret.
#[derive(Clone)]
pub struct OnionProgram {
    /// The program.
    pub program: PathBuf,
    /// Directory for Tor's own files: one per wallet, used by one process.
    pub data_dir: String,
    /// Pause before a process that is down is started again.
    pub retry: Duration,
}

enum Stage {
    Starting(Starting),
    Ready(PipeOnion),
    Down(Instant, String),
}

/// The `Onion` the host gives the bridge.
pub struct HostOnion {
    given: OnionProgram,
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
    stage: Stage,
    /// Since when the process says its Tor has failed.
    failed_since: Option<Instant>,
}

impl HostOnion {
    /// Start the process without waiting for it.
    pub fn start(given: &OnionProgram, secret: &Zeroizing<[u8; 32]>, public: &[u8; 32]) -> HostOnion {
        let mut onion = HostOnion {
            given: given.clone(),
            secret: secret.clone(),
            public: *public,
            stage: Stage::Down(Instant::now(), String::new()),
            failed_since: None,
        };
        onion.launch();
        onion
    }

    fn launch(&mut self) {
        let config = Config {
            secret: *self.secret,
            public: self.public,
            data_dir: self.given.data_dir.clone(),
            listen: true,
            // read at every start: a change is taken up when the process is next started
            tor_bridges: crate::tor_bridges::text(),
        };
        self.failed_since = None;
        self.stage = match PipeOnion::spawn_begin(&self.given.program, &config, CALL_TIMEOUT) {
            Ok(starting) => Stage::Starting(starting),
            Err(why) => Stage::Down(Instant::now(), why.chars().take(200).collect()),
        };
    }

    fn down(&mut self, why: &str) {
        // whatever was there is dropped here, and its process with it
        self.stage = Stage::Down(Instant::now(), why.chars().take(200).collect());
    }

    /// Move the state on and return the process if it can be asked.
    fn live(&mut self) -> Option<&mut PipeOnion> {
        match &mut self.stage {
            Stage::Starting(starting) => match starting.poll() {
                None => {}
                Some(Ok(onion)) => self.stage = Stage::Ready(onion),
                Some(Err(why)) => self.down(&why),
            },
            Stage::Ready(onion) => {
                if !onion.alive() {
                    self.down("the Tor process stopped");
                }
            }
            Stage::Down(since, _) => {
                if since.elapsed() >= self.given.retry {
                    self.launch();
                }
            }
        }
        match &mut self.stage {
            Stage::Ready(onion) => Some(onion),
            _ => None,
        }
    }
}

impl Onion for HostOnion {
    fn post(&mut self, ticket: &[u8; 16], to: &[u8; 32], body: &str) -> bool {
        self.live().is_some_and(|onion| onion.post(ticket, to, body))
    }
    fn next(&mut self) -> Option<Event> {
        self.live()?.next()
    }
    fn answer(&mut self, id: u64, body: &str) {
        if let Some(onion) = self.live() {
            onion.answer(id, body);
        }
    }
    fn state(&mut self) -> State {
        let Some(onion) = self.live() else {
            return match &self.stage {
                Stage::Down(_, why) => State { phase: Phase::Failed, problem: why.clone() },
                _ => State { phase: Phase::Starting, problem: String::new() },
            };
        };
        let state = onion.state();
        // a process whose Tor gave up is replaced by a new one
        if state.phase == Phase::Failed {
            let since = *self.failed_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= self.given.retry {
                let why = state.problem.clone();
                self.down(&why);
            }
        } else {
            self.failed_since = None;
        }
        state
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// With no process to ask, nothing is taken and nothing is made up.
    #[test]
    fn a_tor_process_that_is_not_there_is_never_spoken_for() {
        let given = OnionProgram {
            program: std::env::temp_dir().join("no-such-tor-program"),
            data_dir: String::new(),
            retry: Duration::from_secs(3600),
        };
        let mut onion = HostOnion::start(&given, &Zeroizing::new([1; 32]), &[2; 32]);
        assert!(!onion.post(&[2; 16], &[3; 32], "{}"));
        assert!(onion.next().is_none());
        onion.answer(1, "{}");
        let state = onion.state();
        assert_eq!(state.phase, Phase::Failed);
        assert_eq!(state.problem, "the Tor process could not be started");
    }
}

//! The chain process, as the payment core sees it.
//!
//! Like the transport, the chain layer is a process of its own, started
//! without being waited for and started again when it dies. Until it is
//! ready the core is told the truth: nothing is known about the chain, no
//! time is confirmed, the next step is unknown, a broadcast is unknown.
//! "Nothing new" is said only by a chain process that said it.
use crate::transport::Phase;
use fly_paycore_bridge::chain_pipe::{Config, PipeChain, Starting};
use fly_paycore_bridge::chain_port::{ChainFeed, Level, OldOutputs, Posted, Status, Step, Tip, Unknown};
use fly_paycore_bridge::ports::{Broadcaster, ChainView, Clock, PaymentBasis};
use fly_paycore_wallet::{Broadcast, ChainState};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Longest wait for the chain process to report ready, in seconds.
const START_TIMEOUT_SECS: u32 = 180;
/// Longest wait for the answer to one call.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Confirmations asked for while the chain layer cannot name its own number.
const DEFAULT_K_CONF: u64 = 10;

/// The chain program as the host was started with it.
#[derive(Clone)]
pub struct ChainProgram {
    /// The chain program.
    pub program: PathBuf,
    /// Peers or nodes the user named.
    pub peers: Vec<String>,
    /// Pause before a chain process that is down is started again.
    pub retry: Duration,
    /// The user agreed to send a transaction directly when Tor fails.
    pub direct_post: bool,
}

/// The chain program together with what the open profile adds.
#[derive(Clone)]
pub struct ChainLauncher {
    /// The chain program.
    pub program: PathBuf,
    /// Peers or nodes the user named.
    pub peers: Vec<String>,
    /// Directory for the chain process's own files.
    pub data_dir: String,
    /// The chain: 1 main, 2 test, 3 automated tests.
    pub network: u8,
    /// Hash of the genesis block the journal is bound to.
    pub genesis: [u8; 32],
    /// Pause before a chain process that is down is started again.
    pub retry: Duration,
    /// The user agreed to send a transaction directly when Tor fails.
    pub direct_post: bool,
}

/// The state of the chain process as last seen by the worker.
#[derive(Clone, Debug, Default)]
pub struct ChainReport {
    /// What the process is doing.
    pub phase: Phase,
    /// Why it is down, if it is.
    pub error: Option<String>,
    /// What the running chain layer says is in its way, if anything.
    pub problem: Option<String>,
    /// How many times a process has been started for this profile session.
    pub starts: u32,
}

/// Shared between the worker, which writes it, and the interface's thread.
pub type SharedChainReport = Arc<Mutex<ChainReport>>;

fn update(report: &SharedChainReport, change: impl FnOnce(&mut ChainReport)) {
    let mut slot = match report.lock() {
        Ok(slot) => slot,
        Err(poisoned) => poisoned.into_inner(),
    };
    change(&mut slot);
}

enum Stage {
    Starting(Starting),
    Ready(PipeChain),
    Down(Instant),
}

/// The chain process of one unlocked profile.
pub struct HostChain {
    launcher: ChainLauncher,
    stage: Stage,
    report: SharedChainReport,
}

impl HostChain {
    /// Start the chain process without waiting for it.
    pub fn start(launcher: ChainLauncher, report: SharedChainReport) -> HostChain {
        update(&report, |r| *r = ChainReport::default());
        let mut chain = HostChain {
            launcher,
            stage: Stage::Down(Instant::now()),
            report,
        };
        chain.launch();
        chain
    }

    fn launch(&mut self) {
        let config = Config {
            network: self.launcher.network,
            genesis: self.launcher.genesis,
            data_dir: self.launcher.data_dir.clone(),
            peers: self.launcher.peers.clone(),
            start_timeout_secs: START_TIMEOUT_SECS,
            direct_post: self.launcher.direct_post,
            // read at every start: a change is taken up when the process is next started
            tor_bridges: crate::tor_bridges::text(),
        };
        match PipeChain::spawn_begin(&self.launcher.program, &config, CALL_TIMEOUT) {
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

    /// Move the state on and return the chain process if it can be asked.
    fn live(&mut self) -> Option<&mut PipeChain> {
        match &mut self.stage {
            Stage::Starting(starting) => match starting.poll() {
                None => {}
                Some(Ok(chain)) => {
                    self.stage = Stage::Ready(chain);
                    update(&self.report, |r| r.phase = Phase::Ready);
                }
                Some(Err(why)) => self.down(why),
            },
            Stage::Ready(chain) => {
                if !chain.alive() {
                    self.down("the chain process stopped".to_string());
                }
            }
            Stage::Down(since) => {
                if since.elapsed() >= self.launcher.retry {
                    self.launch();
                }
            }
        }
        match &mut self.stage {
            Stage::Ready(chain) => Some(chain),
            _ => None,
        }
    }
}

impl Drop for HostChain {
    fn drop(&mut self) {
        update(&self.report, |r| *r = ChainReport::default());
    }
}

impl ChainFeed for HostChain {
    fn status(&mut self) -> Option<Status> {
        self.live()?.status()
    }
    fn next(&mut self, at: Option<Tip>) -> Result<Step, Unknown> {
        let Some(chain) = self.live() else {
            return Err(Unknown);
        };
        let step = chain.next(at);
        // once a round, when there is nothing more to take: how is it going
        if !matches!(step, Ok(Step::Block(_))) {
            let problem = chain.problem();
            update(&self.report, |r| r.problem = problem);
        }
        step
    }
    fn post(&mut self, tx: &[u8]) -> Posted {
        match self.live() {
            Some(chain) => chain.post(tx),
            None => Posted::Unknown,
        }
    }
    fn problem(&mut self) -> Option<String> {
        self.live()?.problem()
    }
    fn old_outputs(&mut self, piece: u64) -> Result<OldOutputs, Unknown> {
        self.live().ok_or(Unknown)?.old_outputs(piece)
    }
    fn old_outputs_since(&mut self, piece: u64, since: Tip) -> Result<OldOutputs, Unknown> {
        self.live().ok_or(Unknown)?.old_outputs_since(piece, since)
    }
}

/// One chain process behind the four ports the bridge has for the chain.
/// Every answer is asked for when it is needed; nothing is remembered from
/// an earlier answer, so a chain layer that has lowered its verdict is
/// believed at once.
#[derive(Clone)]
pub struct Link(Rc<RefCell<HostChain>>);

impl Link {
    /// Start the chain process for a profile.
    pub fn start(launcher: ChainLauncher, report: SharedChainReport) -> Link {
        Link(Rc::new(RefCell::new(HostChain::start(launcher, report))))
    }
    fn now(&self) -> Option<Status> {
        self.0.try_borrow_mut().ok()?.status()
    }
}

impl ChainFeed for Link {
    fn status(&mut self) -> Option<Status> {
        self.now()
    }
    fn next(&mut self, at: Option<Tip>) -> Result<Step, Unknown> {
        self.0.try_borrow_mut().map_err(|_| Unknown)?.next(at)
    }
    fn post(&mut self, tx: &[u8]) -> Posted {
        match self.0.try_borrow_mut() {
            Ok(mut chain) => chain.post(tx),
            Err(_) => Posted::Unknown,
        }
    }
    fn problem(&mut self) -> Option<String> {
        self.0.try_borrow_mut().ok()?.problem()
    }
    fn old_outputs(&mut self, piece: u64) -> Result<OldOutputs, Unknown> {
        self.0.try_borrow_mut().map_err(|_| Unknown)?.old_outputs(piece)
    }
    fn old_outputs_since(&mut self, piece: u64, since: Tip) -> Result<OldOutputs, Unknown> {
        self.0.try_borrow_mut().map_err(|_| Unknown)?.old_outputs_since(piece, since)
    }
}

impl Broadcaster for Link {
    fn post_tx(&mut self, tx: &[u8]) -> Broadcast {
        match self.post(tx) {
            Posted::Accepted => Broadcast::Accepted,
            Posted::Rejected => Broadcast::Rejected,
            Posted::Unknown => Broadcast::Unknown,
        }
    }
}

impl Clock for Link {
    fn confirmed_time(&self) -> Option<u64> {
        self.now()?.confirmed_time
    }
}

fn payment_state(status: &Status) -> ChainState {
    match status.level {
        // "at the tip" counts only for a layer that has selected a tip
        // by its acceptance rules and vouches for what the tip stands
        // on; one that merely follows a source, or follows from a
        // point nobody vouches for, keeps every status preliminary
        Level::AtTip if status.selected.is_some() && !status.provisional => ChainState::AtTip,
        Level::AtTip | Level::Behind => ChainState::Behind,
        Level::Unknown => ChainState::Unknown,
    }
}

impl ChainView for Link {
    fn payment_basis(&self) -> PaymentBasis {
        match self.now() {
            Some(status) => PaymentBasis {
                state: payment_state(&status),
                selected: status.selected.map(|tip| (tip.height, tip.hash)),
                k_conf: if status.k_conf > 0 { status.k_conf } else { DEFAULT_K_CONF },
            },
            None => PaymentBasis { state: ChainState::Unknown, selected: None, k_conf: DEFAULT_K_CONF },
        }
    }
    fn chain_state(&self) -> ChainState {
        self.now().as_ref().map(payment_state).unwrap_or(ChainState::Unknown)
    }
    fn k_conf(&self) -> u64 {
        // never fewer than the layer asks for, and never none
        self.now().map(|s| s.k_conf).filter(|k| *k > 0).unwrap_or(DEFAULT_K_CONF)
    }
    fn rangeproofs_authenticated(&self) -> bool {
        self.now().is_some_and(|s| s.rangeproofs_authenticated)
    }
    fn selected_tip(&self) -> Option<(u64, [u8; 32])> {
        self.now()?.selected.map(|t| (t.height, t.hash))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// With no chain process to ask, every answer is the cautious one:
    /// the state is unknown, no time is confirmed, no tip is selected, the
    /// next step is unknown and so is the fate of a broadcast. "Nothing
    /// new" and "accepted" are never said for a process that did not say
    /// them.
    #[test]
    fn a_chain_that_is_not_there_is_never_spoken_for() {
        let report = SharedChainReport::default();
        let launcher = ChainLauncher {
            program: std::env::temp_dir().join("no-such-chain-program"),
            peers: Vec::new(),
            data_dir: String::new(),
            network: 3,
            genesis: [7; 32],
            retry: Duration::from_secs(3600),
            direct_post: false,
        };
        let mut link = Link::start(launcher, report.clone());
        let seen = |r: &SharedChainReport| r.lock().unwrap().clone();
        assert_eq!((seen(&report).phase, seen(&report).starts), (Phase::Down, 0));
        assert_eq!(seen(&report).error.as_deref(), Some("the chain process could not be started"));
        assert!(link.status().is_none());
        assert!(matches!(link.next(None), Err(Unknown)));
        let at = Tip { height: 5, hash: [5; 32] };
        assert!(matches!(link.next(Some(at)), Err(Unknown)));
        assert!(matches!(link.post(b"tx"), Posted::Unknown));
        assert!(matches!(link.post_tx(b"tx"), Broadcast::Unknown));
        assert!(link.problem().is_none());
        assert!(matches!(link.old_outputs(0), Err(Unknown)), "no chain process, no \"there are none\"");
        assert!(matches!(link.chain_state(), ChainState::Unknown));
        assert_eq!((link.confirmed_time(), link.selected_tip()), (None, None));
        assert!(!link.rangeproofs_authenticated());
        assert_eq!(link.k_conf(), DEFAULT_K_CONF);
        // not started again before its pause is over
        assert_eq!(seen(&report).starts, 0);
        drop(link);
        assert_eq!(seen(&report).phase, Phase::None);
        assert!(seen(&report).error.is_none());
    }
}

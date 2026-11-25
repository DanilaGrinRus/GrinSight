//! The one worker of an unlocked profile.
//!
//! While a profile is unlocked exactly one thread owns its [`Bridge`]: every
//! request from the interface and every round of delivery runs on it, one at
//! a time. Locking or switching the profile is [`Runner::stop`]: it returns
//! only after that thread has finished and dropped the bridge with
//! everything in it, so nothing of the profile is published, received or
//! signed afterwards.
use crate::Bridge;
use fly_paycore_store::{Dir, Guard};
use grin_keychain::Keychain;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Shortest pause between two rounds of delivery.
pub const MIN_TICK: Duration = Duration::from_millis(200);
/// Requests waiting for the worker; more are refused instead of queued.
pub const MAX_WAITING: usize = 64;

/// Why a request got no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerError {
    /// The worker is not running: the profile is locked.
    Stopped,
    /// Too many requests are waiting.
    Busy,
}

enum Job {
    Call(String, mpsc::Sender<String>),
    Stop,
}

/// Handle of the running worker. Dropping it stops the worker.
pub struct Runner {
    jobs: mpsc::SyncSender<Job>,
    stopping: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// One round: follow the chain, publish what waits, take what arrived,
/// close the receive drafts whose time has run out. Returns the
/// notifications worth showing, as JSON-RPC notification texts, and whether
/// the chain layer has more for the wallet than one round takes.
pub fn round<D: Dir, G: Guard, K: Keychain>(bridge: &mut Bridge<D, G, K>) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    let mut more = false;
    for (method, list) in [
        // the chain first: what is published and answered below is judged
        // against the newest verified state
        ("paycore.chain.sync", "chain"),
        // then the wallet's own transactions that are not in the chain yet
        ("paycore.send.pump", "broadcast"),
        ("paycore.delivery.pump", "published"),
        ("paycore.delivery.receive", "events"),
        // payments to and from the address through Tor
        ("paycore.onion.pump", "onion"),
        // receive drafts nobody completed in seven days of confirmed time
        // are closed (7.2): nobody else would ask for it
        ("paycore.receive.expire", ""),
    ] {
        let request = json!({"jsonrpc": "2.0", "id": 0, "method": method}).to_string();
        let Ok(reply) = serde_json::from_str::<Value>(&bridge.call(&request)) else {
            continue;
        };
        if list == "chain" {
            more = reply.get("result").and_then(|r| r.get("more")).and_then(Value::as_bool) == Some(true);
        }
        let Some(items) = reply
            .get("result")
            .and_then(|r| r.get(list))
            .and_then(Value::as_array)
        else {
            // no mailbox, or the storage refused: nothing to report here;
            // the next request of the interface will see the same error
            continue;
        };
        for item in items {
            out.push(
                json!({"jsonrpc": "2.0", "method": "paycore.event",
                       "params": {"source": list, "event": item}})
                .to_string(),
            );
        }
    }
    (out, more)
}

impl Runner {
    /// Start the worker. `open` runs on the worker thread and builds the
    /// bridge there: the keychain, the journal keys and the transport never
    /// exist on any other thread. `on_event` receives delivery notifications
    /// (`paycore.event`) and also runs on the worker thread; it must not
    /// block. Fails with the text `open` returned.
    pub fn start<D, G, K, F>(
        open: F,
        tick: Duration,
        mut on_event: Box<dyn FnMut(&str) + Send>,
    ) -> Result<Runner, String>
    where
        D: Dir + 'static,
        G: Guard + 'static,
        K: Keychain + 'static,
        F: FnOnce() -> Result<Bridge<D, G, K>, String> + Send + 'static,
    {
        let tick = tick.max(MIN_TICK);
        let (jobs, inbox) = mpsc::sync_channel::<Job>(MAX_WAITING);
        let (ready, started) = mpsc::channel::<Result<(), String>>();
        let stopping = Arc::new(AtomicBool::new(false));
        let stop_seen = stopping.clone();
        let thread = thread::Builder::new()
            .name("paycore-profile".into())
            .spawn(move || {
                let mut bridge = match open() {
                    Ok(b) => {
                        let _ = ready.send(Ok(()));
                        b
                    }
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                let mut next_round = Instant::now();
                loop {
                    let wait = next_round.saturating_duration_since(Instant::now());
                    let job = inbox.recv_timeout(wait);
                    // once the profile is being locked nothing more is
                    // started: a waiting request loses its answer channel
                    // and its caller is told the worker has stopped
                    if stop_seen.load(Ordering::SeqCst) {
                        break;
                    }
                    match job {
                        Ok(Job::Call(request, answer)) => {
                            let _ = answer.send(bridge.call(&request));
                        }
                        Ok(Job::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {}
                    }
                    if Instant::now() >= next_round {
                        let (notes, more) = round(&mut bridge);
                        for note in notes {
                            on_event(&note);
                        }
                        // A wallet that has blocks or old outputs still to
                        // take does not sit out the pause between rounds;
                        // requests of the interface get their turn in
                        // between all the same.
                        let pause = if more { MIN_TICK.min(tick) } else { tick };
                        next_round = Instant::now().checked_add(pause).unwrap_or(next_round);
                    }
                }
                // the bridge, the core, its keys and the transport end here
                drop(bridge);
            })
            .map_err(|_| "the worker thread could not be started".to_string())?;
        match started.recv() {
            Ok(Ok(())) => Ok(Runner {
                jobs,
                stopping,
                thread: Mutex::new(Some(thread)),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err("the profile could not be opened".to_string())
            }
        }
    }

    /// Handle one JSON-RPC request on the worker, after whatever it is
    /// doing now. May be called from any thread.
    pub fn call(&self, request: &str) -> Result<String, RunnerError> {
        if self.stopping.load(Ordering::SeqCst) {
            return Err(RunnerError::Stopped);
        }
        let (answer, reply) = mpsc::channel();
        match self.jobs.try_send(Job::Call(request.to_string(), answer)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => return Err(RunnerError::Busy),
            Err(mpsc::TrySendError::Disconnected(_)) => return Err(RunnerError::Stopped),
        }
        reply.recv().map_err(|_| RunnerError::Stopped)
    }

    /// Lock the profile: let the request in progress finish, then end the
    /// worker. Returns when the worker thread is gone. Requests that were
    /// still waiting are not started and get [`RunnerError::Stopped`].
    pub fn stop(self) {
        self.lock_now();
    }

    /// The same as [`Runner::stop`] through a shared handle: other threads
    /// may still hold it and get [`RunnerError::Stopped`] from now on.
    pub fn lock_now(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        // wake the worker if it is waiting; with a full queue it wakes on
        // the next job and sees the flag
        let _ = self.jobs.try_send(Job::Stop);
        // the handle stays locked while the worker is joined, so every
        // caller of this function returns only once the worker is gone
        let mut slot = match self.thread.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(thread) = slot.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.lock_now();
    }
}

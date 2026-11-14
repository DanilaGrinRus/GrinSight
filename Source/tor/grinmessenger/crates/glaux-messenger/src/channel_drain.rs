//! In-process drain barrier for a payment daemon. This module does not itself
//! stop listeners or gate operations; all entry points must hold a Permit.
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct State { draining: bool, active: usize }
#[derive(Default)]
struct Inner { state: Mutex<State>, changed: Condvar }
#[derive(Clone, Default)]
pub struct ChannelDrain { inner: Arc<Inner> }
pub struct Permit { inner: Arc<Inner> }
pub struct Drained { inner: Arc<Inner> }

impl Permit {
    /// Hand work already admitted to a spawned child without a gap in which
    /// the drain could claim all work is done.
    pub fn child(&self) -> Result<Permit, &'static str> {
        let mut state = self.inner.state.lock().map_err(|_| "drain state poisoned")?;
        state.active = state.active.checked_add(1).ok_or("too many active tasks")?;
        Ok(Permit { inner: self.inner.clone() })
    }
}

impl ChannelDrain {
    /// Returns None after drain has begun; callers must not start work then.
    pub fn enter(&self) -> Option<Permit> {
        let mut state = self.inner.state.lock().ok()?;
        if state.draining { return None; }
        state.active = state.active.checked_add(1)?;
        Some(Permit { inner: self.inner.clone() })
    }

    /// Take admission before spawning: otherwise a drain can finish while a
    /// newly-created worker has not yet started. The permit is released on
    /// completion, panic, or spawn failure.
    pub fn spawn<F>(&self, f: F) -> Result<std::thread::JoinHandle<()>, &'static str>
    where F: FnOnce() + Send + 'static {
        let permit = self.enter().ok_or("channel is draining")?;
        std::thread::Builder::new().spawn(move || { let _permit = permit; f(); })
            .map_err(|_| "worker spawn failed")
    }

    /// Atomically close admission and wait for all previously admitted work.
    /// Timeout reopens admission and never signals that stopping is safe.
    pub fn drain(&self, timeout: Duration) -> Result<Drained, &'static str> {
        let deadline = Instant::now().checked_add(timeout).ok_or("invalid timeout")?;
        let mut state = self.inner.state.lock().map_err(|_| "drain state poisoned")?;
        if state.draining { return Err("already draining"); }
        state.draining = true;
        while state.active != 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.draining = false;
                self.inner.changed.notify_all();
                return Err("active work did not drain");
            }
            let (next, _) = self.inner.changed.wait_timeout(state, remaining).map_err(|_| "drain state poisoned")?;
            state = next;
        }
        drop(state);
        Ok(Drained { inner: self.inner.clone() })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.active = state.active.saturating_sub(1);
            self.inner.changed.notify_all();
        }
    }
}
impl Drop for Drained {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.draining = false;
            self.inner.changed.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn drains_in_flight_and_rejects_new_work() {
        let gate = ChannelDrain::default();
        let permit = gate.enter().unwrap();
        let other = gate.clone();
        let (tx, rx) = mpsc::channel();
        let join = thread::spawn(move || { let drained = other.drain(Duration::from_secs(2)).unwrap(); tx.send(()).unwrap(); drained });
        // Wait until admission is actually closed, without guessing timings.
        while gate.enter().is_some() { thread::yield_now(); }
        assert!(rx.try_recv().is_err());
        drop(permit);
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let drained = join.join().unwrap();
        assert!(gate.enter().is_none());
        drop(drained);
        assert!(gate.enter().is_some());
    }

    #[test]
    fn timeout_does_not_claim_safe_stop_and_reopens() {
        let gate = ChannelDrain::default();
        let _permit = gate.enter().unwrap();
        assert!(gate.drain(Duration::from_millis(5)).is_err());
        assert!(gate.enter().is_some());
    }

    #[test]
    fn concurrent_drains_are_rejected() {
        let gate = ChannelDrain::default();
        let drained = gate.drain(Duration::from_secs(1)).unwrap();
        assert!(gate.drain(Duration::from_secs(1)).is_err());
        drop(drained);
        assert!(gate.drain(Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn worker_is_admitted_before_it_starts() {
        let gate = ChannelDrain::default();
        let (tx, rx) = mpsc::channel();
        let worker = gate.spawn(move || { rx.recv().unwrap(); }).unwrap();
        assert!(gate.drain(Duration::from_millis(5)).is_err());
        tx.send(()).unwrap(); worker.join().unwrap();
        let drained = gate.drain(Duration::from_secs(1)).unwrap();
        assert!(gate.spawn(|| {}).is_err());
        drop(drained);
    }

    #[test]
    fn admitted_parent_can_handoff_while_drain_waits() {
        let gate = ChannelDrain::default();
        let parent = gate.enter().unwrap();
        let other = gate.clone();
        let (tx, rx) = mpsc::channel();
        let join = thread::spawn(move || { let drained = other.drain(Duration::from_secs(2)).unwrap(); tx.send(()).unwrap(); drained });
        while gate.enter().is_some() { thread::yield_now(); }
        let child = parent.child().unwrap();
        drop(parent);
        assert!(rx.try_recv().is_err());
        drop(child);
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(join.join().unwrap());
    }
}

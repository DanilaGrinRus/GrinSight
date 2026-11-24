//! Asking every source of a list at once.
//!
//! Each source is asked on a thread of its own, so that a slow one holds
//! nobody up and finding a name's address - which the system does in its
//! own time - is waited for no longer than the caller chooses. What comes
//! back is handed over as it comes, with the place of the source in the
//! list; what it means is for the caller to work out.

use crate::ask::{Answer, Asker, Failure};
use crate::source::Source;
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Duration;

/// One asking of a whole list.
pub struct Round {
    told: Receiver<(usize, Result<Answer, Failure>)>,
    waiting: usize,
}

impl Round {
    /// Starts asking every one of `sources`, each for no longer than
    /// `limit` once its address is known.
    pub fn start(asker: &Asker, sources: &[Source], limit: Duration) -> Round {
        let (tell, told) = channel();
        for (index, source) in sources.iter().cloned().enumerate() {
            let tell = tell.clone();
            let asker = asker.clone();
            thread::spawn(move || {
                let addresses = crate::ask::addresses(&source);
                let _ = tell.send((index, asker.ask_at(&source, &addresses, limit)));
            });
        }
        Round {
            told,
            waiting: sources.len(),
        }
    }

    /// How many sources have not been heard of yet.
    pub fn waiting(&self) -> usize {
        self.waiting
    }

    /// The next source to be heard of and what it gave, waiting no longer
    /// than `wait`. Nothing if none was heard of in that time or none is
    /// left.
    pub fn next(&mut self, wait: Duration) -> Option<(usize, Result<Answer, Failure>)> {
        if self.waiting == 0 {
            return None;
        }
        let heard = self.told.recv_timeout(wait).ok()?;
        self.waiting = self.waiting.saturating_sub(1);
        Some(heard)
    }
}

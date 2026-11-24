//! One generation from the first question to the last answer.
//!
//! The pieces put together: every source of the generation is asked at
//! once; each answer is placed next to the program's tip and recorded
//! with the moment it was read; the times written on the answers are kept
//! for confirming the time. The caller steps through it and can read the
//! verdict after every step - it does not have to wait for sources that
//! will never answer once the quorum is there, and it goes on listening,
//! because a later answer can still take a confirmation away.

use crate::ask::{Asker, Failure};
use crate::generation::{Generation, Recorded};
use crate::round::Round;
use crate::said::Said;
use crate::time::Stamp;
use crate::verdict::classify;
use std::time::{Duration, Instant};

/// How long after the deadline answers are usually still listened for.
/// They are not counted; they tell that the deadline was too short, and a
/// claim of more among them is not lost.
pub const GRACE: Duration = Duration::from_secs(15);

/// A generation being asked.
pub struct Survey {
    generation: Generation,
    round: Round,
    recent: Vec<Said>,
    stamps: Vec<Stamp>,
    failures: Vec<(usize, Failure)>,
    until: Instant,
}

impl Survey {
    /// Starts asking the sources of `generation`. `recent` are blocks of
    /// the program's verified chain below its tip: a source that names
    /// one of them is behind, and one that names a block further back
    /// than these has not answered. Answers are listened for until
    /// `grace` after the generation's deadline and no longer.
    pub fn start(asker: &Asker, generation: Generation, recent: Vec<Said>, grace: Duration) -> Survey {
        let now = Instant::now();
        let until = generation.deadline().checked_add(grace).unwrap_or(generation.deadline());
        let limit = until.saturating_duration_since(now);
        let round = Round::start(asker, generation.sources(), limit);
        Survey {
            generation,
            round,
            recent,
            stamps: Vec::new(),
            failures: Vec::new(),
            until,
        }
    }

    /// Waits no longer than `wait` for the next source and records what
    /// it gave. Returns whether anything more can come.
    pub fn step(&mut self, wait: Duration) -> bool {
        let left = self.until.saturating_duration_since(Instant::now());
        if self.round.waiting() == 0 || left.is_zero() {
            return false;
        }
        let Some((index, result)) = self.round.next(wait.min(left)) else {
            return Instant::now() < self.until;
        };
        match result {
            Ok(answer) => {
                let recent = &self.recent;
                let at = |height: u64| recent.iter().find(|block| block.height == height).copied();
                let class = classify(&answer.said, self.generation.tip(), at);
                let recorded = self.generation.record(index, Some((class, answer.said)), answer.got);
                if let (Recorded::Counted, Some(date)) = (recorded, answer.date) {
                    self.stamps.push(Stamp {
                        source: index,
                        date,
                        sent: answer.sent,
                        got: answer.got,
                    });
                }
            }
            Err(failure) => {
                self.generation.record(index, None, Instant::now());
                self.failures.push((index, failure));
            }
        }
        self.round.waiting() > 0
    }

    /// The generation as recorded so far.
    pub fn generation(&self) -> &Generation {
        &self.generation
    }

    /// The times written on the answers that were counted.
    pub fn stamps(&self) -> &[Stamp] {
        &self.stamps
    }

    /// The sources that gave no answer, and why.
    pub fn failures(&self) -> &[(usize, Failure)] {
        &self.failures
    }
}

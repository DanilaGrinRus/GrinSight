//! Whether public nodes name the same header at one height.
//!
//! A starting point for a release is a header well below the tip. Before
//! it is compiled in, the nodes of the named operators are each asked for
//! the header of their chain at that height. What they say is still only
//! their word - but a point that two operators on different networks name
//! and none contradicts is not one node's private history.
//!
//! This module asks and counts. It does not make a point and does not
//! decide what a build carries.
use crate::ask::{Asker, Failure};
use crate::said::Said;
use crate::source::Source;
use std::sync::mpsc::channel;
use std::thread;
use std::time::{Duration, Instant};

/// What one source said about the height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Voice {
    /// The same header: the hash and the total work asked about.
    Same,
    /// Another header at that height.
    Other(Said),
    /// No answer that could be read.
    Silent(Failure),
}

/// What the voices come to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Two operators on different networks named the header and nobody
    /// named another; these sources named it.
    Confirmed {
        /// Places in the list of those who named it.
        by: Vec<usize>,
    },
    /// Somebody named another header at that height. However many agree,
    /// the point is not taken.
    Differs {
        /// Places in the list of those who named another.
        who: Vec<usize>,
    },
    /// Nobody contradicts, and not enough agree.
    TooFew {
        /// How many named the header.
        same: usize,
    },
}

/// The header asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asked {
    /// Its height.
    pub height: u64,
    /// Its hash.
    pub hash: [u8; 32],
    /// The total work up to and including it.
    pub work: u64,
}

impl Asked {
    /// What an answer about this height is: the same header or another.
    pub fn hear(&self, answer: Result<Said, Failure>) -> Voice {
        match answer {
            Ok(said) if said.height == self.height && said.hash == self.hash && said.total_difficulty == self.work => Voice::Same,
            Ok(said) => Voice::Other(said),
            Err(failure) => Voice::Silent(failure),
        }
    }
}

/// Counts the voices; `voices` are in the order of `sources`. A source
/// without a voice has not been heard.
pub fn judge(sources: &[Source], voices: &[Voice]) -> Verdict {
    let heard = || sources.iter().zip(voices).enumerate();
    let who: Vec<usize> = heard().filter(|(_, (_, voice))| matches!(voice, Voice::Other(_))).map(|(index, _)| index).collect();
    if !who.is_empty() {
        return Verdict::Differs { who };
    }
    let same: Vec<(usize, &Source)> = heard().filter(|(_, (_, voice))| **voice == Voice::Same).map(|(index, (source, _))| (index, source)).collect();
    let independent = same.iter().any(|(_, a)| same.iter().any(|(_, b)| a.independent_of(b)));
    if independent {
        Verdict::Confirmed {
            by: same.iter().map(|(index, _)| *index).collect(),
        }
    } else {
        Verdict::TooFew { same: same.len() }
    }
}

/// Asks every one of `sources` for the header at the height of `asked`,
/// all at once, and waits for each no longer than `within`. The voices
/// are in the order of the sources.
pub fn ask_all(asker: &Asker, sources: &[Source], asked: Asked, within: Duration) -> Vec<Voice> {
    let (tell, told) = channel();
    for (index, source) in sources.iter().cloned().enumerate() {
        let tell = tell.clone();
        let asker = asker.clone();
        thread::spawn(move || {
            let addresses = crate::ask::addresses(&source);
            let _ = tell.send((index, asker.ask_header_at(&source, &addresses, asked.height, within)));
        });
    }
    drop(tell);
    // finding a name's address is not under the asker's limit: the wait
    // here is, with a little on top for the answers to arrive
    let until = Instant::now().checked_add(within.saturating_add(Duration::from_secs(2)));
    let mut voices = vec![Voice::Silent(Failure::Late); sources.len()];
    let mut waiting = sources.len();
    while waiting > 0 {
        let left = until.map_or(Duration::ZERO, |until| until.saturating_duration_since(Instant::now()));
        let Ok((index, answer)) = told.recv_timeout(left) else {
            break;
        };
        if let Some(slot) = voices.get_mut(index) {
            *slot = asked.hear(answer);
        }
        waiting = waiting.saturating_sub(1);
    }
    voices
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const ASKED: Asked = Asked {
        height: 4_114_380,
        hash: [7; 32],
        work: 900,
    };

    fn said(height: u64, mark: u8, work: u64) -> Said {
        Said {
            height,
            hash: [mark; 32],
            total_difficulty: work,
        }
    }

    #[test]
    fn the_same_header_or_another() {
        assert_eq!(ASKED.hear(Ok(said(4_114_380, 7, 900))), Voice::Same);
        for other in [said(4_114_380, 8, 900), said(4_114_380, 7, 901), said(4_114_380, 7, 899), said(4_114_381, 7, 900), said(4_114_379, 7, 900)] {
            assert_eq!(ASKED.hear(Ok(other)), Voice::Other(other));
        }
        assert_eq!(ASKED.hear(Err(Failure::Late)), Voice::Silent(Failure::Late));
    }

    fn list() -> Vec<Source> {
        vec![
            Source::listed("One", Some(1), "one.example"),
            Source::listed("Two", Some(2), "two.example"),
            Source::listed("Three", Some(2), "three.example"),
            Source::listed("One", Some(4), "one-more.example"),
            Source::listed("Five", None, "five.example"),
        ]
    }

    const SILENT: Voice = Voice::Silent(Failure::Connect);

    #[test]
    fn two_operators_on_two_networks_and_nobody_against() {
        let other = Voice::Other(said(4_114_380, 8, 900));
        let judged = |voices: [Voice; 5]| judge(&list(), &voices);
        assert_eq!(judged([Voice::Same, Voice::Same, SILENT, SILENT, SILENT]), Verdict::Confirmed { by: vec![0, 1] });
        assert_eq!(judged([Voice::Same; 5]), Verdict::Confirmed { by: vec![0, 1, 2, 3, 4] });
        assert_eq!(judged([SILENT, SILENT, Voice::Same, Voice::Same, SILENT]), Verdict::Confirmed { by: vec![2, 3] });
        // one network, one operator, a network nobody recorded
        assert_eq!(judged([SILENT, Voice::Same, Voice::Same, SILENT, SILENT]), Verdict::TooFew { same: 2 });
        assert_eq!(judged([Voice::Same, SILENT, SILENT, Voice::Same, SILENT]), Verdict::TooFew { same: 2 });
        assert_eq!(judged([Voice::Same, SILENT, SILENT, SILENT, Voice::Same]), Verdict::TooFew { same: 2 });
        assert_eq!(judged([Voice::Same, SILENT, SILENT, SILENT, SILENT]), Verdict::TooFew { same: 1 });
        assert_eq!(judged([SILENT; 5]), Verdict::TooFew { same: 0 });
        // one voice against outweighs all the others
        assert_eq!(judged([Voice::Same, Voice::Same, Voice::Same, Voice::Same, other]), Verdict::Differs { who: vec![4] });
        assert_eq!(judged([other, Voice::Same, Voice::Same, other, SILENT]), Verdict::Differs { who: vec![0, 3] });
        // a source nobody heard is not a voice
        assert_eq!(judge(&list(), &[Voice::Same]), Verdict::TooFew { same: 1 });
        assert_eq!(judge(&list()[..1], &[Voice::Same, Voice::Same]), Verdict::TooFew { same: 1 });
        assert_eq!(judge(&[], &[]), Verdict::TooFew { same: 0 });
    }
}

//! One round of asking every source of the list, and what it adds up to.
//!
//! A *generation* is opened for one tip of the program and one list, with
//! a number that is never used twice and a deadline fixed at the opening.
//! An answer counts only for the generation it was asked in and only if it
//! came strictly before that deadline. The count is plain: enough of the
//! list answered, two of the answers name exactly the program's tip and
//! come from sources independent of each other, and nobody claimed more
//! than the program has verified.
//!
//! The verdict is a function of what has been recorded so far. It can be
//! read at any moment and it can go down as well as up: a claim of more
//! work that comes after two confirmations takes the confirmation away.

use crate::said::Said;
use crate::source::Source;
use crate::verdict::Class;
use std::time::{Duration, Instant};

/// The deadlines of a generation, in seconds, from the first to the last
/// resort.
pub const STEPS: [u64; 4] = [45, 90, 180, 300];

/// How long the next generation is given. It grows when answers came but
/// came too late, and returns to the start after a success; silence does
/// not make it grow, for silence cannot be told from a lost answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pace {
    step: usize,
}

impl Pace {
    /// The deadline of the next generation.
    pub fn within(&self) -> Duration {
        let seconds = STEPS.get(self.step).copied().unwrap_or(300);
        Duration::from_secs(seconds)
    }

    /// Takes in how a generation ended: with the quorum or without, and
    /// whether any answer of it came after its deadline.
    pub fn after(&mut self, confirmed: bool, late: bool) {
        if confirmed {
            self.step = 0;
        } else if late {
            self.step = self.step.saturating_add(1).min(STEPS.len().saturating_sub(1));
        }
    }
}

/// What is known of one source in a generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// It answered before the deadline.
    InTime(Class, Said),
    /// It answered at the deadline or after it.
    Late(Class, Said),
    /// It gave no answer.
    Failed,
}

/// What became of something handed to [`Generation::record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    /// It is part of the generation's count.
    Counted,
    /// It came at the deadline or after it: kept as an observation, not
    /// counted.
    Late,
    /// The source is not of this generation or has been recorded already.
    Ignored,
}

/// What a generation adds up to at this moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Two independent sources named exactly the program's tip, enough of
    /// the list answered and nobody claimed more. `by` are the two.
    Confirmed {
        /// The two sources, by their place in the list.
        by: (usize, usize),
    },
    /// A source claimed more height or work than the program has verified.
    Ahead,
    /// The list has too few operators recorded with a network for any
    /// quorum.
    List,
    /// Not enough so far.
    NoQuorum {
        /// How many sources answered in time.
        answered: usize,
        /// How many have to.
        needed: usize,
        /// How many of the answers name exactly the program's tip.
        confirming: usize,
    },
}

/// One round of asking, for one tip and one list.
#[derive(Debug, Clone)]
pub struct Generation {
    id: u64,
    tip: Said,
    sources: Vec<Source>,
    deadline: Instant,
    seen: Vec<Option<Seen>>,
    least_groups: usize,
}

impl Generation {
    /// Opens the generation `id` for the program's `tip`, to end `within`
    /// from `now`. `least_groups` is how many operators the list has to
    /// record with a network for a quorum to be possible at all.
    pub fn open(
        id: u64,
        tip: Said,
        sources: Vec<Source>,
        now: Instant,
        within: Duration,
        least_groups: usize,
    ) -> Generation {
        let seen = sources.iter().map(|_| None).collect();
        Generation {
            id,
            tip,
            sources,
            // A deadline that cannot be told is one that has passed.
            deadline: now.checked_add(within).unwrap_or(now),
            seen,
            least_groups,
        }
    }

    /// The number of the generation.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The tip the generation was opened for.
    pub fn tip(&self) -> &Said {
        &self.tip
    }

    /// The sources asked, in the order answers are recorded by.
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    /// The moment answers stop counting.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Records what the source at `index` gave: its answer placed next to
    /// the tip, or nothing if it failed. `got` is the moment the answer
    /// was read to its end.
    pub fn record(&mut self, index: usize, answer: Option<(Class, Said)>, got: Instant) -> Recorded {
        let Some(slot) = self.seen.get_mut(index) else {
            return Recorded::Ignored;
        };
        if slot.is_some() {
            return Recorded::Ignored;
        }
        match answer {
            None => {
                *slot = Some(Seen::Failed);
                Recorded::Counted
            }
            Some((class, said)) if got < self.deadline => {
                *slot = Some(Seen::InTime(class, said));
                Recorded::Counted
            }
            Some((class, said)) => {
                *slot = Some(Seen::Late(class, said));
                Recorded::Late
            }
        }
    }

    /// Whether nothing more can be counted: every source is recorded or
    /// the deadline has come.
    pub fn over(&self, now: Instant) -> bool {
        now >= self.deadline || self.seen.iter().all(Option::is_some)
    }

    /// Whether any answer came at the deadline or after it.
    pub fn late(&self) -> bool {
        self.seen.iter().any(|seen| matches!(seen, Some(Seen::Late(..))))
    }

    /// Every claim of more than the program has verified, in time or
    /// late, with the place of its source in the list.
    pub fn claims(&self) -> Vec<(usize, Said)> {
        self.seen
            .iter()
            .enumerate()
            .filter_map(|(index, seen)| match seen {
                Some(Seen::InTime(Class::Ahead, said) | Seen::Late(Class::Ahead, said)) => {
                    Some((index, *said))
                }
                _ => None,
            })
            .collect()
    }

    /// What the generation adds up to at this moment.
    pub fn verdict(&self) -> Verdict {
        let mut groups: Vec<&str> = self
            .sources
            .iter()
            .filter(|source| source.asn.is_some() && !source.group.is_empty())
            .map(|source| source.group.as_str())
            .collect();
        groups.sort_unstable();
        groups.dedup();
        if groups.len() < self.least_groups || self.sources.is_empty() {
            return Verdict::List;
        }
        let mut answered = 0usize;
        let mut confirming: Vec<usize> = Vec::new();
        for (index, seen) in self.seen.iter().enumerate() {
            match seen {
                Some(Seen::InTime(Class::Ahead, _)) => return Verdict::Ahead,
                Some(Seen::InTime(Class::Confirms, _)) => {
                    answered = answered.saturating_add(1);
                    confirming.push(index);
                }
                Some(Seen::InTime(Class::Behind, _)) => answered = answered.saturating_add(1),
                Some(Seen::InTime(Class::Aside, _) | Seen::Late(..) | Seen::Failed) | None => {}
            }
        }
        let needed = self.sources.len().div_ceil(2);
        let mut pair = None;
        for (place, first) in confirming.iter().enumerate() {
            for second in confirming.iter().skip(place.saturating_add(1)) {
                let independent = match (self.sources.get(*first), self.sources.get(*second)) {
                    (Some(a), Some(b)) => a.independent_of(b),
                    _ => false,
                };
                if independent && pair.is_none() {
                    pair = Some((*first, *second));
                }
            }
        }
        match pair {
            Some(by) if answered >= needed => Verdict::Confirmed { by },
            _ => Verdict::NoQuorum {
                answered,
                needed,
                confirming: confirming.len(),
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn tip() -> Said {
        Said {
            height: 100,
            hash: [7; 32],
            total_difficulty: 1000,
        }
    }

    fn other(height: u64, work: u64) -> Said {
        Said {
            height,
            hash: [9; 32],
            total_difficulty: work,
        }
    }

    /// Five operators; the last two share a network, as on Mainnet.
    fn five() -> Vec<Source> {
        vec![
            Source::listed("A", Some(1), "a.example"),
            Source::listed("B", Some(2), "b.example"),
            Source::listed("C", Some(3), "c.example"),
            Source::listed("D", Some(4), "d.example"),
            Source::listed("E", Some(4), "e.example"),
        ]
    }

    const WITHIN: Duration = Duration::from_secs(45);

    fn open(sources: Vec<Source>) -> (Generation, Instant) {
        let now = Instant::now();
        (Generation::open(3, tip(), sources, now, WITHIN, 3), now)
    }

    fn confirms() -> Option<(Class, Said)> {
        Some((Class::Confirms, tip()))
    }

    fn behind() -> Option<(Class, Said)> {
        Some((Class::Behind, other(99, 990)))
    }

    fn ahead() -> Option<(Class, Said)> {
        Some((Class::Ahead, other(101, 1010)))
    }

    fn aside() -> Option<(Class, Said)> {
        Some((Class::Aside, other(100, 1000)))
    }

    fn no_quorum(answered: usize, confirming: usize) -> Verdict {
        Verdict::NoQuorum {
            answered,
            needed: 3,
            confirming,
        }
    }

    #[test]
    fn two_independent_confirmations_and_half_the_list() {
        let (mut g, now) = open(five());
        assert_eq!((g.id(), *g.tip(), g.sources().len()), (3, tip(), 5));
        assert_eq!(g.deadline(), now + WITHIN);
        assert_eq!(g.verdict(), no_quorum(0, 0));
        assert_eq!(g.record(0, confirms(), now), Recorded::Counted);
        assert_eq!(g.verdict(), no_quorum(1, 1));
        assert_eq!(g.record(1, confirms(), now), Recorded::Counted);
        // Two confirm, but two of five is not half the list.
        assert_eq!(g.verdict(), no_quorum(2, 2));
        // A third that is merely behind is an answer.
        assert_eq!(g.record(2, behind(), now), Recorded::Counted);
        assert_eq!(g.verdict(), Verdict::Confirmed { by: (0, 1) });
        assert!(!g.over(now));
        g.record(3, None, now);
        g.record(4, None, now);
        assert!(g.over(now));
        assert_eq!(g.verdict(), Verdict::Confirmed { by: (0, 1) });
    }

    #[test]
    fn confirmations_have_to_be_independent() {
        // The two that share a network, and a third answer.
        let (mut g, now) = open(five());
        g.record(3, confirms(), now);
        g.record(4, confirms(), now);
        g.record(0, behind(), now);
        assert_eq!(g.verdict(), no_quorum(3, 2));
        // A third confirmation from another network makes a pair.
        g.record(1, confirms(), now);
        assert_eq!(g.verdict(), Verdict::Confirmed { by: (1, 3) });

        // A node of the user answers and confirms, and is nobody's pair.
        let mut list = five();
        list.push(Source::own("https://mine.example").unwrap());
        let now = Instant::now();
        let mut g = Generation::open(1, tip(), list, now, WITHIN, 3);
        g.record(0, confirms(), now);
        g.record(5, confirms(), now);
        g.record(1, behind(), now);
        assert_eq!(g.verdict(), no_quorum(3, 2));
        g.record(2, confirms(), now);
        assert_eq!(g.verdict(), Verdict::Confirmed { by: (0, 2) });
    }

    #[test]
    fn what_is_not_an_answer_is_not_counted() {
        let (mut g, now) = open(five());
        g.record(0, confirms(), now);
        g.record(1, confirms(), now);
        g.record(2, aside(), now);
        g.record(3, None, now);
        assert_eq!(g.verdict(), no_quorum(2, 2));
        // The list does not shrink when sources are lost: three of five
        // are needed, whoever is left.
        g.record(4, None, now);
        assert!(g.over(now));
        assert_eq!(g.verdict(), no_quorum(2, 2));
    }

    #[test]
    fn a_claim_of_more_takes_the_confirmation_away() {
        let (mut g, now) = open(five());
        g.record(0, confirms(), now);
        g.record(1, confirms(), now);
        g.record(2, confirms(), now);
        assert_eq!(g.verdict(), Verdict::Confirmed { by: (0, 1) });
        assert!(g.claims().is_empty());
        g.record(3, ahead(), now);
        assert_eq!(g.verdict(), Verdict::Ahead);
        g.record(4, confirms(), now);
        assert_eq!(g.verdict(), Verdict::Ahead);
        assert_eq!(g.claims(), [(3, other(101, 1010))]);
    }

    #[test]
    fn only_before_the_deadline_and_only_once() {
        let (mut g, now) = open(five());
        let just_before = now + WITHIN - Duration::from_nanos(1);
        let at = now + WITHIN;
        assert_eq!(g.record(0, confirms(), just_before), Recorded::Counted);
        // The deadline itself is too late.
        assert_eq!(g.record(1, confirms(), at), Recorded::Late);
        assert_eq!(g.record(2, confirms(), at + WITHIN), Recorded::Late);
        assert_eq!(g.verdict(), no_quorum(1, 1));
        assert!(g.late());
        // A source is recorded once: a second word from it changes nothing.
        assert_eq!(g.record(1, confirms(), now), Recorded::Ignored);
        assert_eq!(g.record(0, ahead(), now), Recorded::Ignored);
        assert_eq!(g.record(5, confirms(), now), Recorded::Ignored);
        assert_eq!(g.verdict(), no_quorum(1, 1));
        // A late claim of more is not counted, but it is not lost.
        assert_eq!(g.record(3, ahead(), at), Recorded::Late);
        assert_eq!(g.verdict(), no_quorum(1, 1));
        assert_eq!(g.claims(), [(3, other(101, 1010))]);
        // A failure after the deadline is a failure, not a late answer.
        let (mut g, now) = open(five());
        assert_eq!(g.record(0, None, now + WITHIN), Recorded::Counted);
        assert!(!g.late());
        assert!(!g.over(now) && g.over(now + WITHIN));
    }

    #[test]
    fn a_list_too_small_for_any_quorum() {
        // Two operators where three are required.
        let two = vec![
            Source::listed("A", Some(1), "a.example"),
            Source::listed("B", Some(2), "b.example"),
        ];
        let (mut g, now) = open(two.clone());
        g.record(0, confirms(), now);
        g.record(1, confirms(), now);
        assert_eq!(g.verdict(), Verdict::List);
        // The same two where two are required: both have to confirm.
        let mut g = Generation::open(1, tip(), two, now, WITHIN, 2);
        g.record(0, confirms(), now);
        assert_eq!(
            g.verdict(),
            Verdict::NoQuorum {
                answered: 1,
                needed: 1,
                confirming: 1
            }
        );
        g.record(1, confirms(), now);
        assert_eq!(g.verdict(), Verdict::Confirmed { by: (0, 1) });
        // Operators without a recorded network, nodes of the user and two
        // nodes of one operator do not make the list larger.
        let mut mine = Source::own("https://mine.example").unwrap();
        mine.asn = Some(5);
        let thin = vec![
            Source::listed("A", Some(1), "a.example"),
            Source::listed("A", Some(2), "a2.example"),
            Source::listed("B", Some(3), "b.example"),
            Source::listed("C", None, "c.example"),
            Source::own("https://mine.example").unwrap(),
            mine,
        ];
        let (g, _) = open(thin);
        assert_eq!(g.verdict(), Verdict::List);
        let (g, _) = open(Vec::new());
        assert_eq!(g.verdict(), Verdict::List);
        let now = Instant::now();
        assert_eq!(Generation::open(1, tip(), Vec::new(), now, WITHIN, 0).verdict(), Verdict::List);
    }

    #[test]
    fn the_deadline_grows_only_when_answers_came_late() {
        let mut pace = Pace::default();
        assert_eq!(pace.within(), Duration::from_secs(45));
        // Silence does not make it grow.
        pace.after(false, false);
        assert_eq!(pace.within(), Duration::from_secs(45));
        pace.after(false, true);
        assert_eq!(pace.within(), Duration::from_secs(90));
        pace.after(false, true);
        pace.after(false, false);
        assert_eq!(pace.within(), Duration::from_secs(180));
        pace.after(false, true);
        assert_eq!(pace.within(), Duration::from_secs(300));
        pace.after(false, true);
        assert_eq!(pace.within(), Duration::from_secs(300));
        // A success returns it to the start, late answers or not.
        pace.after(true, true);
        assert_eq!(pace.within(), Duration::from_secs(45));
    }
}

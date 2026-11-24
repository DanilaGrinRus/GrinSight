//! Claims of more than the program has verified.
//!
//! When a source of the list names more height or work than the program's
//! verified chain has, either the program is behind - then the block
//! arrives, is verified and the claim is settled - or the program is kept
//! from the chain the source sees, or the source is wrong. From the claim
//! alone these cannot be told apart, so an open claim stands in the way of
//! any confirmation. Nothing but the block itself settles it: not silence,
//! not a timeout, not what other sources say.
//!
//! A claim nobody could settle does not stand for ever. After half an hour
//! it *expires*: it no longer blocks, but for another half hour it remains
//! as a caveat on whatever is confirmed. Both spans are measured on
//! confirmed time and in the direction that makes them longer; while the
//! time is not confirmed, neither runs.

use crate::said::Said;

/// How long an unsettled claim blocks, in milliseconds of confirmed time.
pub const TTL_MS: u64 = 30 * 60 * 1000;

/// How long an expired claim remains a caveat.
pub const CAVEAT_MS: u64 = 30 * 60 * 1000;

/// How many claims are kept. One more than this blocks until there is
/// room: a full list is not a reason to forget a claim.
pub const MAX_CLAIMS: usize = 64;

/// One claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The name of the source that made it.
    pub host: String,
    /// What the source named.
    pub said: Said,
    /// The latest the confirmed time can have been when the claim was
    /// first seen with the time confirmed; nothing until then.
    pub seen_ms: Option<u64>,
    /// The latest the confirmed time can have been when the claim
    /// expired; nothing while it is open.
    pub expired_ms: Option<u64>,
}

/// What became of a claim handed to [`Claims::note`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Noted {
    /// It is a new open claim.
    New,
    /// The same source already has this claim open.
    Known,
    /// There is no room; everything is blocked until there is.
    Full,
}

/// The claims that are open or still a caveat.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Claims {
    list: Vec<Claim>,
    full: bool,
}

impl Claims {
    /// The claims as kept, for writing them down again.
    pub fn parts(&self) -> (&[Claim], bool) {
        (&self.list, self.full)
    }

    /// Claims read back from where they were written down.
    pub fn from_parts(list: Vec<Claim>, full: bool) -> Claims {
        Claims { list, full }
    }

    /// Takes in that `host` named `said`, which is more than the program
    /// has verified. `now` is the confirmed time, if it is confirmed.
    pub fn note(&mut self, host: &str, said: Said, now: Option<(u64, u64)>) -> Noted {
        let open = |claim: &Claim| claim.expired_ms.is_none() && claim.host == host && claim.said == said;
        if self.list.iter().any(open) {
            return Noted::Known;
        }
        if self.list.len() >= MAX_CLAIMS {
            self.full = true;
            return Noted::Full;
        }
        self.list.push(Claim {
            host: host.to_string(),
            said,
            seen_ms: now.map(|(_, high)| high),
            expired_ms: None,
        });
        Noted::New
    }

    /// Settles every claim whose block the program now holds in its
    /// verified chain, open or expired. Returns how many.
    pub fn settle(&mut self, held: impl Fn(&Said) -> bool) -> usize {
        let before = self.list.len();
        self.list.retain(|claim| !held(&claim.said));
        self.room();
        before.saturating_sub(self.list.len())
    }

    /// Preserve only the age already established before a gap in confirmed
    /// time. A later clock reading starts a new period for each active timer.
    pub fn resume_at(&mut self, previous_low: u64, now_high: u64) {
        for claim in &mut self.list {
            let start = if claim.expired_ms.is_some() {
                &mut claim.expired_ms
            } else {
                &mut claim.seen_ms
            };
            let elapsed = start.map_or(0, |t| previous_low.saturating_sub(t));
            *start = Some(now_high.saturating_sub(elapsed));
        }
    }

    /// Lets confirmed time pass: `now` are its bounds at this moment.
    pub fn tick(&mut self, now: (u64, u64)) {
        let (low, high) = now;
        for claim in &mut self.list {
            match (claim.seen_ms, claim.expired_ms) {
                (None, _) => claim.seen_ms = Some(high),
                (Some(seen), None) if low.saturating_sub(seen) >= TTL_MS => {
                    claim.expired_ms = Some(high);
                }
                _ => {}
            }
        }
        self.list.retain(|claim| {
            claim
                .expired_ms
                .is_none_or(|expired| low.saturating_sub(expired) < CAVEAT_MS)
        });
        self.room();
    }

    /// Whether a claim stands in the way of any confirmation.
    pub fn blocks(&self) -> bool {
        self.full || self.list.iter().any(|claim| claim.expired_ms.is_none())
    }

    /// Whether what is confirmed is confirmed with a caveat: a claim
    /// expired unsettled not long ago.
    pub fn caveat(&self) -> bool {
        self.list.iter().any(|claim| claim.expired_ms.is_some())
    }

    fn room(&mut self) {
        if self.list.len() < MAX_CLAIMS {
            self.full = false;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn more(mark: u8) -> Said {
        Said {
            height: 101,
            hash: [mark; 32],
            total_difficulty: 1010,
        }
    }

    const T: u64 = 1_795_392_000_000;

    #[test]
    fn a_claim_blocks_until_its_block_is_held() {
        let mut claims = Claims::default();
        assert!(!claims.blocks() && !claims.caveat());
        assert_eq!(claims.note("a.example", more(1), Some((T, T + 500))), Noted::New);
        assert!(claims.blocks() && !claims.caveat());
        // The same word from the same source is the same claim; from
        // another source, or another block, it is another.
        assert_eq!(claims.note("a.example", more(1), Some((T, T + 500))), Noted::Known);
        assert_eq!(claims.note("b.example", more(1), Some((T, T + 500))), Noted::New);
        assert_eq!(claims.note("a.example", more(2), Some((T, T + 500))), Noted::New);
        assert_eq!(claims.parts().0.len(), 3);
        // Holding another block settles nothing.
        assert_eq!(claims.settle(|said| *said == more(3)), 0);
        assert!(claims.blocks());
        // The block of two of them arrives.
        assert_eq!(claims.settle(|said| *said == more(1)), 2);
        assert!(claims.blocks());
        assert_eq!(claims.settle(|said| *said == more(2)), 1);
        assert!(!claims.blocks() && !claims.caveat());
    }

    #[test]
    fn an_unsettled_claim_expires_and_stays_a_caveat() {
        let mut claims = Claims::default();
        claims.note("a.example", more(1), Some((T, T + 500)));
        // Half an hour is counted from the latest the claim can have
        // been seen to the earliest it can be now.
        claims.tick((T + 500 + TTL_MS - 1, T + 1000 + TTL_MS));
        assert!(claims.blocks() && !claims.caveat());
        claims.tick((T + 500 + TTL_MS, T + 1000 + TTL_MS));
        assert!(!claims.blocks() && claims.caveat());
        let expired = T + 1000 + TTL_MS;
        assert_eq!(claims.parts().0[0].expired_ms, Some(expired));
        // The caveat lasts half an hour of its own.
        claims.tick((expired + CAVEAT_MS - 1, expired + CAVEAT_MS + 500));
        assert!(!claims.blocks() && claims.caveat());
        claims.tick((expired + CAVEAT_MS, expired + CAVEAT_MS + 500));
        assert!(!claims.blocks() && !claims.caveat());
        assert!(claims.parts().0.is_empty());
    }

    #[test]
    fn expiry_settles_nothing() {
        let mut claims = Claims::default();
        claims.note("a.example", more(1), Some((T, T)));
        claims.tick((T + TTL_MS, T + TTL_MS));
        assert!(!claims.blocks() && claims.caveat());
        // The source says it again: an open claim again, beside the caveat.
        assert_eq!(claims.note("a.example", more(1), Some((T + TTL_MS, T + TTL_MS))), Noted::New);
        assert!(claims.blocks() && claims.caveat());
        // The block arrives after all: both are gone, caveat included.
        assert_eq!(claims.settle(|said| *said == more(1)), 2);
        assert!(!claims.blocks() && !claims.caveat());
    }

    #[test]
    fn no_time_no_expiry() {
        let mut claims = Claims::default();
        // Seen while the time was not confirmed: its half hour starts
        // when the time is first confirmed, however much later that is.
        assert_eq!(claims.note("a.example", more(1), None), Noted::New);
        assert_eq!(claims.parts().0[0].seen_ms, None);
        claims.tick((T + 10 * TTL_MS, T + 10 * TTL_MS + 7));
        assert!(claims.blocks());
        assert_eq!(claims.parts().0[0].seen_ms, Some(T + 10 * TTL_MS + 7));
        claims.tick((T + 11 * TTL_MS + 6, T + 11 * TTL_MS + 9));
        assert!(claims.blocks());
        claims.tick((T + 11 * TTL_MS + 7, T + 11 * TTL_MS + 9));
        assert!(!claims.blocks() && claims.caveat());
        // A time that seems to go back makes nothing expire sooner.
        let mut claims = Claims::default();
        claims.note("a.example", more(1), Some((T, T)));
        claims.tick((0, 0));
        assert!(claims.blocks() && !claims.caveat());
    }

    #[test]
    fn a_full_list_blocks_instead_of_forgetting() {
        let mut claims = Claims::default();
        for i in 0..MAX_CLAIMS {
            assert_eq!(claims.note(&format!("{i}.example"), more(1), Some((T, T))), Noted::New);
        }
        assert_eq!(claims.note("one-more.example", more(2), Some((T, T))), Noted::Full);
        assert_eq!(claims.parts(), (claims.clone().parts().0, true));
        assert_eq!(claims.parts().0.len(), MAX_CLAIMS);
        // All of them expire: none is open, and still everything is
        // blocked, because one claim could not be kept.
        claims.tick((T + TTL_MS, T + TTL_MS));
        assert!(claims.parts().0.iter().all(|claim| claim.expired_ms.is_some()));
        assert!(claims.blocks());
        // Room appears when the caveats end.
        claims.tick((T + TTL_MS + CAVEAT_MS, T + TTL_MS + CAVEAT_MS));
        assert!(!claims.blocks() && claims.parts().0.is_empty());
        // And when a block settles a claim.
        let mut claims = Claims::default();
        for i in 0..MAX_CLAIMS {
            claims.note(&format!("{i}.example"), more(u8::try_from(i).unwrap()), Some((T, T)));
        }
        assert_eq!(claims.note("one-more.example", more(200), Some((T, T))), Noted::Full);
        claims.settle(|said| said.hash != [0; 32]);
        assert_eq!(claims.parts(), (&[Claim {
            host: "0.example".to_string(),
            said: more(0),
            seen_ms: Some(T),
            expired_ms: None,
        }][..], false));
    }
}

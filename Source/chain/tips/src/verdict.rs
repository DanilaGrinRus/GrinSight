//! What a node's word means next to the program's own verified tip.
//!
//! The program has verified its chain header by header; a node of the list
//! has only said something. Four things it can have said: exactly the
//! program's tip; a block of the program's chain below the tip; more than
//! the program has verified; or something the program can place nowhere.
//! Nothing is guessed: a block the program does not have is not taken for
//! an ancestor or a rival, it is simply not an answer - unless it claims
//! more work or height, and then it is a claim that has to be met.

use crate::said::Said;

/// What one answer is, next to the program's tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Exactly the program's tip: its height, its hash and its work.
    Confirms,
    /// A block of the program's own chain below its tip. The node answered
    /// but does not vouch for the tip.
    Behind,
    /// More height or more work than the program has verified. A claim
    /// that stands until the program has that block in its verified chain.
    Ahead,
    /// A block the program cannot place and that claims no more than the
    /// program has. Not an answer.
    Aside,
}

/// Places `said` next to the program's verified `tip`. `at` gives the
/// block of the program's verified chain at a height below the tip.
pub fn classify(said: &Said, tip: &Said, at: impl Fn(u64) -> Option<Said>) -> Class {
    if said.height > tip.height || said.total_difficulty > tip.total_difficulty {
        return Class::Ahead;
    }
    if said == tip {
        return Class::Confirms;
    }
    if said.height < tip.height && at(said.height).is_some_and(|ours| ours == *said) {
        return Class::Behind;
    }
    Class::Aside
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn block(height: u64, mark: u8, work: u64) -> Said {
        Said {
            height,
            hash: [mark; 32],
            total_difficulty: work,
        }
    }

    /// The program's chain: block `h` has the mark `h` and the work `10 h`.
    fn ours(height: u64) -> Option<Said> {
        (height <= 50).then(|| block(height, u8::try_from(height).unwrap(), height * 10))
    }

    #[test]
    fn the_four_things_a_node_can_have_said() {
        let tip = ours(50).unwrap();
        let class = |said: Said| classify(&said, &tip, ours);
        assert_eq!(class(tip), Class::Confirms);
        assert_eq!(class(ours(49).unwrap()), Class::Behind);
        assert_eq!(class(ours(1).unwrap()), Class::Behind);
        // One block further, and the same height with more work.
        assert_eq!(class(block(51, 51, 510)), Class::Ahead);
        assert_eq!(class(block(50, 99, 501)), Class::Ahead);
        // Lower, yet claiming more work: the lower height takes nothing
        // from the claim.
        assert_eq!(class(block(40, 99, 501)), Class::Ahead);
        // Higher with less work is still more than was verified.
        assert_eq!(class(block(51, 99, 1)), Class::Ahead);
    }

    #[test]
    fn what_cannot_be_placed_is_not_an_answer() {
        let tip = ours(50).unwrap();
        let class = |said: Said| classify(&said, &tip, ours);
        // Another block at the tip's height with the same or less work.
        assert_eq!(class(block(50, 99, 500)), Class::Aside);
        assert_eq!(class(block(50, 99, 499)), Class::Aside);
        // Another block below the tip.
        assert_eq!(class(block(49, 99, 490)), Class::Aside);
        // The program's hash with another work, at the tip and below it.
        assert_eq!(class(block(50, 50, 499)), Class::Aside);
        assert_eq!(class(block(49, 49, 489)), Class::Aside);
        // The tip's hash at another height.
        assert_eq!(class(block(49, 50, 490)), Class::Aside);
        // A height the program has no block for.
        let nothing = |_| None;
        assert_eq!(classify(&ours(49).unwrap(), &tip, nothing), Class::Aside);
        // The tip is not looked up: it is what the program holds.
        assert_eq!(classify(&tip, &tip, nothing), Class::Confirms);
    }
}

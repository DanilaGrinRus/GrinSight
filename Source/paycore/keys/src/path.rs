//! Output key paths.
//!
//! A Grin identifier holds a depth and four 32-bit components; the identifier
//! of an output travels inside its range proof. Under the account `m/a/0`
//! the core uses three classes that cannot be confused with one another:
//!
//! | class          | path                              | depth | told apart by            |
//! |----------------|-----------------------------------|-------|--------------------------|
//! | instance branch| `m/a/0/branch/index`              | 4     | second component is 0    |
//! | stateless      | `m/a/(0x40000000 \| r0)/r1/r2`    | 4     | bit 30 of the second     |
//! | legacy         | `m/a/0/n`                         | 3     | depth                    |
use grin_keychain::{ChildNumber, ExtKeychain, Identifier, Keychain};

/// Marker bit in the second component of a stateless-receive path
/// (grin-wallet issue 844).
pub const STATELESS_MARKER: u32 = 0x4000_0000;
/// Random bits below the marker.
pub const STATELESS_R0_BITS: u32 = 27;
const R0_MASK: u32 = (1 << STATELESS_R0_BITS) - 1;
const NON_HARDENED: u32 = 0x7fff_ffff;

/// A key path of one of the known classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyPath {
    /// `m/account/0/branch/index`: handed out by the branch ledger.
    Branch {
        /// Account number.
        account: u32,
        /// Random identifier of the instance branch.
        branch: u32,
        /// Position in the branch.
        index: u32,
    },
    /// `m/account/(0x40000000 | r0)/r1/r2`: drawn at random per request.
    Stateless {
        /// Account number.
        account: u32,
        /// 27 random bits.
        r0: u32,
        /// 31 random bits.
        r1: u32,
        /// 31 random bits.
        r2: u32,
    },
    /// `m/account/0/n`: sequential keys of grin-wallet and of v0.1.
    Legacy {
        /// Account number.
        account: u32,
        /// Sequential index.
        index: u32,
    },
}

/// The random generator of the operating system failed.
#[derive(Debug, PartialEq, Eq)]
pub struct RngError;

impl KeyPath {
    /// A stateless path, if the components are within their ranges.
    pub fn stateless(account: u32, r0: u32, r1: u32, r2: u32) -> Option<KeyPath> {
        if r0 > R0_MASK || r1 > NON_HARDENED || r2 > NON_HARDENED {
            return None;
        }
        Some(KeyPath::Stateless {
            account,
            r0,
            r1,
            r2,
        })
    }

    /// A fresh stateless path: 89 bits from the operating system generator.
    pub fn stateless_random(account: u32) -> Result<KeyPath, RngError> {
        let mut b = [0u8; 12];
        getrandom::getrandom(&mut b).map_err(|_| RngError)?;
        let word = |i: usize| -> u32 {
            let mut w = [0u8; 4];
            for (dst, src) in w.iter_mut().zip(b.iter().skip(i.saturating_mul(4))) {
                *dst = *src;
            }
            u32::from_le_bytes(w)
        };
        Ok(KeyPath::Stateless {
            account,
            r0: word(0) & R0_MASK,
            r1: word(1) & NON_HARDENED,
            r2: word(2) & NON_HARDENED,
        })
    }

    /// Account the path belongs to.
    pub fn account(&self) -> u32 {
        match *self {
            KeyPath::Branch { account, .. }
            | KeyPath::Stateless { account, .. }
            | KeyPath::Legacy { account, .. } => account,
        }
    }

    /// The Grin identifier of this path.
    pub fn to_identifier(&self) -> Identifier {
        match *self {
            KeyPath::Branch {
                account,
                branch,
                index,
            } => ExtKeychain::derive_key_id(4, account, 0, branch, index),
            KeyPath::Stateless {
                account,
                r0,
                r1,
                r2,
            } => ExtKeychain::derive_key_id(4, account, STATELESS_MARKER | r0, r1, r2),
            KeyPath::Legacy { account, index } => {
                ExtKeychain::derive_key_id(3, account, 0, index, 0)
            }
        }
    }

    /// Identifier of the account path `m/account/0`.
    pub fn account_identifier(&self) -> Identifier {
        ExtKeychain::derive_key_id(2, self.account(), 0, 0, 0)
    }
}

/// Recognise an identifier recovered from a range proof. `None` for anything
/// that is not exactly one of the three classes, including non-canonical
/// encodings.
pub fn classify(id: &Identifier) -> Option<KeyPath> {
    let p = id.to_path();
    let c: [u32; 4] = [
        component(p.path.first()),
        component(p.path.get(1)),
        component(p.path.get(2)),
        component(p.path.get(3)),
    ];
    let [account, second, third, fourth] = c;
    let candidate = match p.depth {
        3 if second == 0 && fourth == 0 => KeyPath::Legacy {
            account,
            index: third,
        },
        4 if second == 0 => KeyPath::Branch {
            account,
            branch: third,
            index: fourth,
        },
        4 if second & !R0_MASK == STATELESS_MARKER => {
            KeyPath::stateless(account, second & R0_MASK, third, fourth)?
        }
        _ => return None,
    };
    // Only the canonical encoding counts.
    if candidate.to_identifier() == *id {
        Some(candidate)
    } else {
        None
    }
}

fn component(c: Option<&ChildNumber>) -> u32 {
    c.map(|n| u32::from(*n)).unwrap_or(0)
}

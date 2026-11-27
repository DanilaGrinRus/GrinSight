//! A deliberately narrow exact relation: the first Mainnet successor, C29, v1,
//! one new output and kernel, zero offset, timestamp in January 2019.
//! The witness contains no subsequent chain and the result confers no freshness.
use blake2::{Blake2b, Digest, digest::consts::U32};
#[allow(dead_code)]
#[path = "../../../vendor/grin/core/src/pow/siphash.rs"]
mod grin_siphash;

const GENESIS: &[u8; 400] = include_bytes!("mainnet-genesis.bin");
const PROOF_OFFSET: usize = 247;

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    for data in parts {
        hasher.update(data);
    }
    hasher.finalize().into()
}

fn uint(header: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(header[offset..offset + 8].try_into().unwrap())
}

// Match Grin Cuckaroo v1's bipartite cycle predicate. Each endpoint must
// have exactly one partner on the same side and all 42 edges form one cycle.
fn check_cycle(pre_pow: &[u8], packed: &[u8]) {
    const BITS: usize = 29;
    const EDGES: usize = 42;
    let mask = (1u64 << BITS) - 1;
    assert_eq!(packed.len(), (BITS * EDGES).div_ceil(8));
    assert_eq!(packed[152] >> 2, 0);
    let key_bytes = hash(&[pre_pow]);
    let keys = core::array::from_fn(|i| {
        u64::from_le_bytes(key_bytes[8*i..8*i+8].try_into().unwrap())
    });
    let mut endpoints = [[0u64; 2]; EDGES];
    let mut last = None;
    for (i, pair) in endpoints.iter_mut().enumerate() {
        let mut nonce = 0u64;
        for j in 0..BITS {
            let bit = i * BITS + j;
            nonce |= (((packed[bit / 8] >> (bit % 8)) & 1) as u64) << j;
        }
        assert!(last.is_none_or(|previous| nonce > previous));
        last = Some(nonce);
        let edge = grin_siphash::siphash_block(&keys, nonce, 21, false);
        *pair = [edge & mask, (edge >> 32) & mask];
    }
    let mut pos = 0usize;
    let mut side = 0usize;
    let mut visited = [false; EDGES];
    for _ in 0..EDGES {
        assert!(!visited[pos]);
        visited[pos] = true;
        let mut other = None;
        for (i, endpoint) in endpoints.iter().enumerate() {
            if i != pos && endpoint[side] == endpoints[pos][side] {
                assert!(other.replace(i).is_none());
            }
        }
        pos = other.expect("unpaired endpoint");
        side ^= 1;
    }
    assert_eq!((pos, side), (0, 0));
}

pub fn checkpoint(h: &[u8; 400]) -> Vec<u8> {
    let genesis_hash = hash(&[&GENESIS[PROOF_OFFSET..]]);
    let genesis_leaf = hash(&[&0u64.to_be_bytes(), &GENESIS[PROOF_OFFSET..]]);
    assert_eq!(h[..2], 1u16.to_be_bytes());
    assert_eq!(uint(h, 2), 1);
    assert_eq!(h[18..50], genesis_hash);
    assert_eq!(h[50..82], genesis_leaf);
    let time = uint(h, 10);
    assert!(time > uint(GENESIS, 10) && time < 1_548_979_200);
    assert_eq!(h[178..210], [0; 32]);
    // PMMR size 3 = 2 leaves. Genesis had one leaf of each kind.
    // Delta weight and chain-wide weight are then both within the HF1 limit.
    assert_eq!((uint(h, 210), uint(h, 218)), (3, 3));
    assert_eq!(h[246], 29);

    // The first DMA window uses 60 one-minute intervals, every work entry
    // at genesis difficulty, all 60 entries secondary at initial scaling.
    // next_dma_difficulty therefore returns the genesis difficulty as target.
    let target_work = uint(GENESIS, 226);
    assert_eq!(uint(h, 226), target_work.checked_mul(2).unwrap());
    let target_count = 60 * 90;
    let damped_count = (60 * 100 + 12 * target_count) / 13;
    let initial_scale = u32::from_be_bytes(GENESIS[234..238].try_into().unwrap());
    let scale = (60 * initial_scale * 90) / damped_count;
    assert_eq!(h[234..238], scale.to_be_bytes());
    let packed = &h[PROOF_OFFSET..];
    check_cycle(&h[..246], packed);
    let id = hash(&[packed]);
    let denominator = uint(&id, 0).max(1) as u128;
    assert!(((scale as u128) << 64) >= (target_work as u128) * denominator);

    let child_leaf = hash(&[&1u64.to_be_bytes(), packed]);
    let root = hash(&[&2u64.to_be_bytes(), &genesis_leaf, &child_leaf]);
    let mut point = Vec::with_capacity(520);
    point.extend_from_slice(b"GSZ1MH01");
    point.extend_from_slice(&1u64.to_be_bytes());
    point.extend_from_slice(&genesis_hash);
    point.extend_from_slice(h);
    point.extend_from_slice(&id);
    point.extend_from_slice(&h[226..234]);
    point.extend_from_slice(&root);
    point
}


//! A first-era C29 successor of the authenticated first-stage statement.
use blake2::{digest::consts::U32, Blake2b, Digest};

#[allow(dead_code)]
#[path = "../../../vendor/grin/core/src/pow/siphash.rs"]
mod grin_siphash;

const GENESIS: &[u8; 400] = include_bytes!("../../../research-genesis-receipt/guest/src/mainnet-genesis.bin");
const NONCES: usize = 247;

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn be64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn scale(header: &[u8]) -> u64 {
    u32::from_be_bytes(header[234..238].try_into().unwrap()).into()
}

// Direct specialization of difficulty_data_to_vector + next_dma_difficulty
// for height two. With two real entries, 59 synthetic ones precede genesis.
// The 60 values summed after dropping the earliest synthetic entry are h1,
// genesis and 58 synthetic entries. Timestamp padding uses the h1-genesis
// interval, the newest work delta, genesis scaling and is_secondary=true.
fn next_difficulty(h1: &[u8]) -> (u64, u32) {
    let genesis_ts = be64(GENESIS, 10);
    let h1_ts = be64(h1, 10);
    let interval = h1_ts.checked_sub(genesis_ts).unwrap();
    let oldest_ts = genesis_ts.saturating_sub(59 * interval);
    let damped_span = ((h1_ts - oldest_ts + 2 * 3600) / 3).clamp(1800, 7200);

    let genesis_work = be64(GENESIS, 226);
    let newest_work = be64(h1, 226).checked_sub(genesis_work).unwrap();
    let work_sum = genesis_work + 59 * newest_work;
    let target = (work_sum * 60 / damped_span).max(3);

    // Both real headers are C29, as are the synthetic pre-genesis entries.
    let target_count = 60 * 90;
    let count = ((6000 + 12 * target_count) / 13).clamp(target_count / 2, target_count * 2);
    let scale_sum = scale(h1) + 59 * scale(GENESIS);
    let secondary = ((scale_sum * 90) / count).max(13);
    (target, u32::try_from(secondary).unwrap())
}

// Same Cuckaroo v1 graph predicate as the first-stage guest. The pinned first
// program stays immutable; both derive all graph endpoints with Grin SipHash.
fn c29_cycle(pre_pow: &[u8], packed: &[u8]) {
    const EDGES: usize = 42;
    const BITS: usize = 29;
    assert_eq!(packed.len(), 153);
    assert_eq!(packed[152] >> 2, 0);
    let key_digest = digest(&[pre_pow]);
    let keys = core::array::from_fn(|i| {
        u64::from_le_bytes(key_digest[8 * i..8 * i + 8].try_into().unwrap())
    });
    let mask = (1u64 << BITS) - 1;
    let mut last = None;
    let mut graph = [[0u64; 2]; EDGES];
    for (i, ends) in graph.iter_mut().enumerate() {
        let mut nonce = 0u64;
        for j in 0..BITS {
            let bit = i * BITS + j;
            nonce |= u64::from((packed[bit / 8] >> (bit % 8)) & 1) << j;
        }
        assert!(last.is_none_or(|prev| prev < nonce));
        last = Some(nonce);
        let edge = grin_siphash::siphash_block(&keys, nonce, 21, false);
        *ends = [edge & mask, (edge >> 32) & mask];
    }
    let mut seen = [false; EDGES];
    let mut current = 0;
    for step in 0..EDGES {
        assert!(!seen[current]);
        seen[current] = true;
        let side = step % 2;
        let mut partner = None;
        for (j, end) in graph.iter().enumerate() {
            if j != current && end[side] == graph[current][side] {
                assert!(partner.replace(j).is_none());
            }
        }
        current = partner.expect("unpaired endpoint");
    }
    assert_eq!(current, 0);
}

pub fn successor(parent: &[u8; 520], h2: &[u8; 400]) -> Vec<u8> {
    assert_eq!(&parent[..8], b"GSZ1MH01");
    assert_eq!(be64(parent, 8), 1);
    assert_eq!(parent[16..48], digest(&[&GENESIS[NONCES..]]));
    let h1 = &parent[48..448];
    let parent_hash = &parent[448..480];
    let parent_root = &parent[488..520];
    assert_eq!(&h2[..2], &1u16.to_be_bytes());
    assert_eq!(be64(h2, 2), 2);
    assert_eq!(&h2[18..50], parent_hash);
    assert_eq!(&h2[50..82], parent_root);
    assert!(be64(h2, 10) > be64(h1, 10) && be64(h2, 10) < 1_548_979_200);
    assert_eq!(h2[178..210], [0; 32]);
    // Sizes 4 and 4 add exactly one output and one kernel to h1 (sizes 3).
    assert_eq!((be64(h2, 210), be64(h2, 218)), (4, 4));
    assert_eq!(h2[246], 29);
    let (work, scaling) = next_difficulty(h1);
    assert_eq!(be64(h2, 226), be64(parent, 480).checked_add(work).unwrap());
    assert_eq!(scale(h2), u64::from(scaling));

    let nonces = &h2[NONCES..];
    c29_cycle(&h2[..246], nonces);
    let id = digest(&[nonces]);
    let denominator = u128::from(be64(&id, 0).max(1));
    assert!((u128::from(scaling) << 64) >= u128::from(work) * denominator);

    let right = digest(&[&3u64.to_be_bytes(), nonces]);
    // Bag the two peaks at the *unpruned size* 4 per ReadonlyPMMR::root.
    let root = digest(&[&4u64.to_be_bytes(), parent_root, &right]);
    let mut point = Vec::with_capacity(1104);
    point.extend_from_slice(b"GSZ2MH02");
    point.extend_from_slice(&2u64.to_be_bytes());
    point.extend_from_slice(&parent[16..48]);
    point.extend_from_slice(h2);
    point.extend_from_slice(&id);
    point.extend_from_slice(&h2[226..234]);
    point.extend_from_slice(&root);
    point.extend_from_slice(parent_root);
    point.extend_from_slice(&right);
    point.extend_from_slice(parent);
    point
}


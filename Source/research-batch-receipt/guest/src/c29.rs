// Exact HF1 Cuckaroo graph predicate used by the linked h2 guest.
#[allow(dead_code)]
#[path = "../../../vendor/grin/core/src/pow/siphash.rs"]
mod grin_siphash;

pub(super) fn check(pre_pow: &[u8], packed: &[u8]) {
    const EDGES: usize = 42;
    const BITS: usize = 29;
    assert_eq!(packed.len(), 153);
    assert_eq!(packed[152] >> 2, 0);
    let key_digest = super::digest(&[pre_pow]);
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

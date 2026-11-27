#[cfg(test)]
#[path = "../../guest/src/state.rs"]
mod state;

#[cfg(test)]
mod tests {
    use super::state::State;
    use std::{io::{Cursor,Read}, panic::catch_unwind};
    const PARENT: &[u8] = include_bytes!("../../../research-linked-receipt/testdata/checkpoint.bin");
    const FRAMES: &[u8] = include_bytes!("../../../chain/headers/tests/mainnet/first-4100-headers.bin");
    const SELF: [u8; 32] = [0x17; 32]; // Native tests exercise the relation, not RISC Zero verification.

    fn headers(n: usize) -> Vec<[u8; 400]> {
        let mut data = Cursor::new(FRAMES);
        (0..n).map(|_| {
            let mut len = [0; 2];
            data.read_exact(&mut len).unwrap();
            assert_eq!(u16::from_be_bytes(len), 400);
            let mut h = [0; 400];
            data.read_exact(&mut h).unwrap();
            h
        }).collect()
    }

    #[test]
    fn rolls_frontier_and_window_across_61_and_resumes_at_every_height() {
        let mut state = State::from_h2(PARENT);
        let h = headers(92);
        for i in 3..=90 {
            state.advance(h[i]);
            let point = state.encode(&SELF);
            assert_eq!(&point[80..480], &h[i]);
            assert_eq!(&point[528..560], &h[i + 1][50..82]);
            let count = (i + 1).min(61);
            assert_eq!(point[560] as usize, count);
            for row in 0..count {
                let j = i - row;
                let at = 561 + 21 * row;
                let work = |idx: usize| u64::from_be_bytes(h[idx][226..234].try_into().unwrap());
                let delta = work(j) - if j == 0 { 0 } else { work(j - 1) };
                assert_eq!(&point[at..at + 8],&h[j][10..18]);
                assert_eq!(&point[at + 8..at + 16],&delta.to_be_bytes());
                assert_eq!(&point[at + 16..at + 20],&h[j][234..238]);
                assert_eq!(point[at + 20],1);
            }
            let peaks = (i+1).count_ones() as usize;
            assert_eq!(point.len(), 562 + 21*count + 32*peaks);
            state = State::from_batch(&point, &SELF);
            assert_eq!(state.encode(&SELF),point);
        }
    }

    #[test]
    fn refuses_wrong_self_id_forged_frontier_and_trailing_bytes() {
        let mut state = State::from_h2(PARENT);
        state.advance(headers(4)[3]);
        let point = state.encode(&SELF);
        assert!(catch_unwind(|| State::from_batch(&point, &[0;32])).is_err());
        for offset in [0, 47, 48, 480, 519, 527, 528, 560, 581, point.len()-1] {
            let mut wrong = point.clone();
            wrong[offset] ^= 1;
            assert!(catch_unwind(|| State::from_batch(&wrong, &SELF)).is_err(), "offset {offset}");
        }
        let mut trailing = point;
        trailing.push(0);
        assert!(catch_unwind(|| State::from_batch(&trailing, &SELF)).is_err());
    }

    #[test]
    fn refuses_tampered_fields_and_overflowing_window_in_release() {
        let h = headers(5);
        for offset in [1,9,18,50,210,218,233,237,246,247,399] {
            let mut bad = h[3];
            bad[offset] ^= if offset == 399 {128} else {1};
            assert!(catch_unwind(|| State::from_h2(PARENT).advance(bad)).is_err(), "offset {offset}");
        }
        let mut prev = State::from_h2(PARENT);
        prev.advance(h[3]);
        let mut overflow = prev.encode(&SELF);
        overflow[569..577].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(catch_unwind(|| State::from_batch(&overflow, &SELF).advance(h[4])).is_err());
    }
}


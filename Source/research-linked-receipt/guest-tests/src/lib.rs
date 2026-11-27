#[cfg(test)]
mod tests {
    use std::io::{Read, Cursor};

    fn fixture() -> ([u8; 520], [u8; 400]) {
        let parent = *include_bytes!("../../../research-genesis-receipt/testdata/checkpoint.bin");
        let archive = include_bytes!("../../../chain/headers/tests/mainnet/first-4100-headers.bin");
        let mut frames = Cursor::new(archive);
        let mut header = [0; 400];
        for _ in 0..3 {
            let mut len = [0; 2];
            frames.read_exact(&mut len).unwrap();
            assert_eq!(u16::from_be_bytes(len), 400);
            frames.read_exact(&mut header).unwrap();
        }
        (parent, header)
    }

    #[test]
    fn real_successor_matches_oracle_and_carries_authenticated_frontier() {
        let (parent, header) = fixture();
        let output = super::relation::successor(&parent, &header);
        let hex = |s: &[u8]| s.iter().map(|v| format!("{v:02x}")).collect::<String>();
        assert_eq!(output.len(), 1104);
        assert_eq!(&output[0..8], b"GSZ2MH02");
        assert_eq!(&output[8..16], &2u64.to_be_bytes());
        assert_eq!(&output[16..48], &parent[16..48]);
        assert_eq!(&output[48..448], &header);
        assert_eq!(hex(&output[448..480]), "000000563d23bdcc0301571feb1ebcef08aed18efe48d671493de1e227a616cb");
        assert_eq!(&output[480..488], &42949672960u64.to_be_bytes());
        assert_eq!(hex(&output[488..520]), "d2cc273a5ef57cb0a5f2a2e22683465503d644996a17b05e1813643c516fb2df");
        assert_eq!(&output[520..552], &parent[488..520]);
        assert_eq!(hex(&output[552..584]), "77859a5798cb4bde54cd81bb223a6eb658edffdda623b01a966d91a206014e9d");
        assert_eq!(&output[584..], &parent);
    }

    #[test]
    fn rejects_each_invalid_child_field() {
        let (parent, header) = fixture();
        for (name, offset) in [
            ("version", 1), ("height", 9), ("parent id", 18), ("parent root", 50),
            ("output PMMR size", 217), ("kernel PMMR size", 225), ("work", 233),
            ("secondary scaling", 237), ("graph size", 246), ("cycle", 247),
            ("noncanonical high proof bits", 399),
        ] {
            let mut bad = header;
            bad[offset] ^= if offset == 399 { 128 } else { 1 };
            let result = std::panic::catch_unwind(|| super::relation::successor(&parent, &bad));
            assert!(result.is_err(), "{name} accepted");
        }
    }
}

#[cfg(test)]
#[path = "../../guest/src/relation.rs"]
mod relation;


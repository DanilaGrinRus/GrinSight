use blake2::{digest::consts::U32, Blake2b, Digest};

#[path = "c29.rs"]
mod c29;

type Hash = [u8; 32];
type Header = [u8; 400];
const GENESIS: &Header = include_bytes!("../../../research-genesis-receipt/guest/src/mainnet-genesis.bin");
const MAX_HEIGHT: u64 = 1000;
const ROWS: usize = 61;

fn digest(parts: &[&[u8]]) -> Hash {
    let mut hash = Blake2b::<U32>::new();
    for part in parts { hash.update(part); }
    hash.finalize().into()
}
fn u64_at(data: &[u8], i: usize) -> u64 {
    u64::from_be_bytes(data[i..i + 8].try_into().unwrap())
}
fn u32_at(data: &[u8], i: usize) -> u32 {
    u32::from_be_bytes(data[i..i + 4].try_into().unwrap())
}
fn header_id(h: &Header) -> Hash { digest(&[&h[247..]]) }
fn nodes(leaves: u64) -> u64 { 2 * leaves - u64::from(leaves.count_ones()) }

// Only complete mmr sizes are in this bounded subset. The interval is
// independently bounded by the chain-wide weight limit at MAX_HEIGHT.
fn leaf_count(size: u64) -> u64 {
    let mut lo = 0;
    let mut hi = (MAX_HEIGHT + 1) * 40000;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if nodes(mid) < size { lo = mid + 1; } else { hi = mid; }
    }
    assert_eq!(nodes(lo), size);
    lo
}
fn bag(size: u64, peaks: &[Hash]) -> Hash {
    let mut rev = peaks.iter().rev();
    let first = *rev.next().unwrap();
    rev.fold(first, |right,left| digest(&[&size.to_be_bytes(), left, &right]))
}

#[derive(Clone, Copy)]
struct Row { timestamp: u64, work: u64, scale: u32 }
impl Row {
    fn from_header(header: &Header, previous_td: u64) -> Self {
        Self {
            timestamp: u64_at(header, 10),
            work: u64_at(header, 226).checked_sub(previous_td).unwrap(),
            scale: u32_at(header, 234),
        }
    }
}

// The last row (oldest of 61) is an anchor for time only. On startup,
// simulate missing rows using the exact padding in Grin global.rs.
fn next_difficulty(rows: &[Row]) -> (u64, u32) {
    assert!((2..=ROWS).contains(&rows.len()));
    let newest = rows[0];
    let interval = newest.timestamp.checked_sub(rows[1].timestamp).unwrap();
    let missing = (ROWS - rows.len()) as u64;
    let oldest_time = rows.last().unwrap().timestamp.saturating_sub(
        missing.checked_mul(interval).unwrap()
    );
    let elapsed = newest.timestamp.checked_sub(oldest_time).unwrap();
    let adjusted = (elapsed.checked_add(7200).unwrap() / 3).clamp(1800, 7200);
    let measured = rows.len().min(60);
    let pad = (60 - measured) as u64;
    let mut work_sum = pad.checked_mul(newest.work).unwrap();
    let mut scale_sum = pad * u64::from(u32_at(GENESIS, 234));
    for row in &rows[..measured] {
        work_sum = work_sum.checked_add(row.work).unwrap();
        scale_sum += u64::from(row.scale);
    }
    let work = (work_sum.checked_mul(60).unwrap() / adjusted).max(3);
    // Heights 0..1000 have a 90 percent target. The supported C29-only
    // history (including the pre-genesis padding) consists entirely of secondary rows.
    let target_count = 60 * 90;
    let count = ((6000 + 12 * target_count) / 13).clamp(target_count / 2, target_count * 2);
    let scaling = ((scale_sum * 90) / count).max(13);
    (work, u32::try_from(scaling).unwrap())
}

pub struct State { tip: Header, rows: Vec<Row>, peaks: Vec<Hash> }

impl State {
    pub fn from_h2(point: &[u8]) -> Self {
        assert_eq!(point.len(), 1104);
        assert_eq!(&point[..8], b"GSZ2MH02");
        assert_eq!(u64_at(point, 8), 2);
        assert_eq!(&point[16..48], &header_id(GENESIS));
        let h2: Header = point[48..448].try_into().unwrap();
        let parent = &point[584..];
        assert_eq!(&parent[..8], b"GSZ1MH01");
        let h1: Header = parent[48..448].try_into().unwrap();
        let rows = vec![Row::from_header(&h2, u64_at(&h1, 226)),
                        Row::from_header(&h1, u64_at(GENESIS, 226)),
                        Row::from_header(GENESIS, 0)];
        let peaks = vec![point[520..552].try_into().unwrap(), point[552..584].try_into().unwrap()];
        assert_eq!(&point[488..520], &bag(4, &peaks));
        Self {tip: h2, rows, peaks}
    }

    pub fn from_batch(point: &[u8], self_id: &Hash) -> Self {
        assert!(point.len() >= 562);
        assert_eq!(&point[..8], b"GSZBMH01");
        assert_eq!(&point[8..40], self_id);
        let height = u64_at(point, 40);
        assert!((3..=MAX_HEIGHT).contains(&height));
        assert_eq!(&point[48..80], &header_id(GENESIS));
        let tip: Header = point[80..480].try_into().unwrap();
        assert_eq!(u64_at(&tip, 2), height);
        assert_eq!(&point[480..512], &header_id(&tip));
        assert_eq!(u64_at(&tip, 226), u64_at(point, 512));
        let size = nodes(height + 1);
        assert_eq!(u64_at(point, 520), size);
        let count = usize::from(point[560]);
        assert_eq!(count, (height as usize + 1).min(ROWS));
        let index = 561 + count * 21;
        let peak_count = (height + 1).count_ones() as usize;
        assert_eq!(point.len(), index + 1 + peak_count * 32);
        assert_eq!(usize::from(point[index]), peak_count);
        let rows = point[561..index].chunks_exact(21).map(|r| {
            assert_eq!(r[20], 1);
            Row { timestamp: u64_at(r, 0), work: u64_at(r, 8), scale: u32_at(r, 16) }
        }).collect::<Vec<_>>();
        assert_eq!(rows[0].timestamp, u64_at(&tip, 10));
        assert_eq!(rows[0].scale, u32_at(&tip, 234));
        let peaks = point[index + 1..].chunks_exact(32).map(|v| v.try_into().unwrap()).collect::<Vec<_>>();
        assert_eq!(&point[528..560], &bag(size, &peaks));
        Self {tip,rows,peaks}
    }

    pub fn advance(&mut self, header: Header) {
        let height = u64_at(&header, 2);
        assert!((3..=MAX_HEIGHT).contains(&height));
        assert_eq!(u64_at(&self.tip, 2) + 1, height);
        assert_eq!(&header[..2], &1u16.to_be_bytes());
        assert_eq!(header[246], 29);
        assert_eq!(&header[18..50], &header_id(&self.tip));
        let mut position = nodes(height);
        assert_eq!(&header[50..82], &bag(position, &self.peaks));
        let ts = u64_at(&header, 10);
        assert!(ts > u64_at(&self.tip, 10) && ts < 1_548_979_200);

        let output = leaf_count(u64_at(&header, 210));
        let kernel = leaf_count(u64_at(&header, 218));
        let added_output = output.checked_sub(leaf_count(u64_at(&self.tip, 210))).unwrap();
        let added_kernel = kernel.checked_sub(leaf_count(u64_at(&self.tip, 218))).unwrap();
        assert!(added_output > 0 && added_kernel > 0);
        assert!(added_output * 21 + added_kernel * 3 <= 40000);
        assert!(output * 21 + kernel * 3 <= 40000 * (height + 1));

        let row = Row::from_header(&header, u64_at(&self.tip, 226));
        let (expected_work, expected_scale) = next_difficulty(&self.rows);
        assert_eq!((row.work, row.scale), (expected_work, expected_scale));
        c29::check(&header[..246], &header[247..]);
        let hash = header_id(&header);
        assert!((u128::from(row.scale) << 64) >= u128::from(row.work) * u128::from(u64_at(&hash, 0).max(1)));

        let mut peak = digest(&[&position.to_be_bytes(), &header[247..]]);
        for _ in 0..height.trailing_ones() {
            position += 1;
            let left = self.peaks.pop().unwrap();
            peak = digest(&[&position.to_be_bytes(), &left, &peak]);
        }
        self.peaks.push(peak);
        self.rows.truncate(ROWS - 1);
        self.rows.insert(0,row);
        self.tip = header;
    }

    pub fn encode(&self, self_id: &Hash) -> Vec<u8> {
        let height = u64_at(&self.tip,2);
        let size = nodes(height + 1);
        let mut point = Vec::new();
        point.extend_from_slice(b"GSZBMH01");
        point.extend_from_slice(self_id);
        point.extend_from_slice(&height.to_be_bytes());
        point.extend_from_slice(&header_id(GENESIS));
        point.extend_from_slice(&self.tip);
        point.extend_from_slice(&header_id(&self.tip));
        point.extend_from_slice(&self.tip[226..234]);
        point.extend_from_slice(&size.to_be_bytes());
        point.extend_from_slice(&bag(size,&self.peaks));
        point.push(self.rows.len() as u8);
        for row in &self.rows {
            point.extend_from_slice(&row.timestamp.to_be_bytes());
            point.extend_from_slice(&row.work.to_be_bytes());
            point.extend_from_slice(&row.scale.to_be_bytes());
            point.push(1);
        }
        point.push(self.peaks.len() as u8);
        for peak in &self.peaks { point.extend_from_slice(peak); }
        point
    }
}


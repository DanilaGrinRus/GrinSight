//! Historical header MMR inclusion proofs (HEADER_PROOF_HIST).
//!
//! This is the client-side verifier from the header-proof fork. It is kept
//! independent of `grin_p2p` message types: the wire codec can be added later
//! without weakening verification. Membership alone binds only the leaf
//! position/PoW nonces, so full PoW + WTEMA is checked here.

use grin_core::consensus;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::merkle_proof::MerkleProof;
use grin_core::core::pmmr;
use grin_core::core::{BlockHeader, HeaderVersion};
use grin_core::ser::{self, Readable, Reader, Writeable, Writer};

pub const MAX_HEADER_PROOF_ITEMS: u16 = 64;
pub const MAX_HEADER_PROOF_PATH: u16 = 64;

#[derive(Clone, Debug)]
pub struct HeaderProofItem {
    pub header: BlockHeader,
    pub path: Vec<Hash>,
}

#[derive(Clone, Debug)]
pub struct HeaderProofs {
    pub anchor: Hash,
    pub mmr_size: u64,
    pub items: Vec<HeaderProofItem>,
}


#[derive(Clone, Debug)]
pub struct GetHeaderProofs {
    pub anchor: Hash,
    pub heights: Vec<u64>,
}

impl Writeable for GetHeaderProofs {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        if self.heights.is_empty() || self.heights.len() > MAX_HEADER_PROOF_ITEMS as usize {
            return Err(ser::Error::TooLargeReadErr);
        }
        self.anchor.write(writer)?;
        writer.write_u16(self.heights.len() as u16)?;
        for h in &self.heights {
            writer.write_u64(*h)?;
        }
        Ok(())
    }
}

impl Readable for GetHeaderProofs {
    fn read<R: Reader>(reader: &mut R) -> Result<GetHeaderProofs, ser::Error> {
        let anchor = Hash::read(reader)?;
        let count = reader.read_u16()?;
        if count == 0 || count > MAX_HEADER_PROOF_ITEMS {
            return Err(ser::Error::CorruptedData);
        }
        let mut heights = Vec::with_capacity(count as usize);
        for _ in 0..count {
            heights.push(reader.read_u64()?);
        }
        Ok(GetHeaderProofs { anchor, heights })
    }
}

impl Writeable for HeaderProofItem {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        if self.path.len() > MAX_HEADER_PROOF_PATH as usize {
            return Err(ser::Error::TooLargeReadErr);
        }
        self.header.write(writer)?;
        writer.write_u8(self.path.len() as u8)?;
        for h in &self.path {
            h.write(writer)?;
        }
        Ok(())
    }
}

impl Readable for HeaderProofItem {
    fn read<R: Reader>(reader: &mut R) -> Result<HeaderProofItem, ser::Error> {
        let header = BlockHeader::read(reader)?;
        let n = reader.read_u8()?;
        if n > MAX_HEADER_PROOF_PATH as u8 {
            return Err(ser::Error::CorruptedData);
        }
        let mut path = Vec::with_capacity(n as usize);
        for _ in 0..n {
            path.push(Hash::read(reader)?);
        }
        Ok(HeaderProofItem { header, path })
    }
}

impl Writeable for HeaderProofs {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        if self.items.is_empty() || self.items.len() > MAX_HEADER_PROOF_ITEMS as usize {
            return Err(ser::Error::TooLargeReadErr);
        }
        self.anchor.write(writer)?;
        writer.write_u64(self.mmr_size)?;
        writer.write_u16(self.items.len() as u16)?;
        for item in &self.items {
            item.write(writer)?;
        }
        Ok(())
    }
}

impl Readable for HeaderProofs {
    fn read<R: Reader>(reader: &mut R) -> Result<HeaderProofs, ser::Error> {
        let anchor = Hash::read(reader)?;
        let mmr_size = reader.read_u64()?;
        let count = reader.read_u16()?;
        if count == 0 || count > MAX_HEADER_PROOF_ITEMS {
            return Err(ser::Error::CorruptedData);
        }
        let mut items = Vec::with_capacity(count as usize);
        for _ in 0..count {
            items.push(HeaderProofItem::read(reader)?);
        }
        Ok(HeaderProofs { anchor, mmr_size, items })
    }
}

pub fn header_mmr_size(height: u64) -> u64 {
    pmmr::insertion_to_pmmr_index(height)
}

pub fn header_leaf_pos(height: u64) -> u64 {
    pmmr::insertion_to_pmmr_index(height)
}

pub fn verify_header_proof_item(
    root: Hash,
    mmr_size: u64,
    height: u64,
    header: &BlockHeader,
    path: &[Hash],
) -> Result<(), String> {
    if header.height != height {
        return Err(format!(
            "header height {} does not match requested height {}",
            header.height, height
        ));
    }
    if path.len() > MAX_HEADER_PROOF_PATH as usize {
        return Err(format!("proof path length {} exceeds max {}", path.len(), MAX_HEADER_PROOF_PATH));
    }
    let pos = header_leaf_pos(height);
    if pos >= mmr_size {
        return Err(format!("header leaf position {} outside historical MMR size {}", pos, mmr_size));
    }
    if mmr_size != pmmr::insertion_to_pmmr_index(pmmr::n_leaves(mmr_size)) {
        return Err(format!("invalid historical MMR size {}", mmr_size));
    }
    let proof = MerkleProof { mmr_size, path: path.to_vec() };
    proof
        .verify(root, header, pos)
        .map_err(|_| format!("header proof root mismatch at height {}", height))
}

pub fn verify_memberships(anchor: &BlockHeader, proofs: &HeaderProofs) -> Result<(), String> {
    if anchor.hash() != proofs.anchor {
        return Err("header proofs anchor does not match the anchor header".into());
    }
    let expected_size = header_mmr_size(anchor.height);
    if proofs.mmr_size != expected_size {
        return Err(format!(
            "header proofs mmr_size {} does not match anchor height {} (expected {})",
            proofs.mmr_size, anchor.height, expected_size
        ));
    }
    if proofs.items.is_empty() || proofs.items.len() > MAX_HEADER_PROOF_ITEMS as usize {
        return Err(format!(
            "header proofs item count {} outside 1..={}",
            proofs.items.len(),
            MAX_HEADER_PROOF_ITEMS
        ));
    }
    let mut prev_height: Option<u64> = None;
    for item in &proofs.items {
        let height = item.header.height;
        if height >= anchor.height {
            return Err(format!("header proof height {} is not below anchor height {}", height, anchor.height));
        }
        if let Some(prev) = prev_height {
            if height <= prev {
                return Err(format!("header proof heights are not strictly increasing ({} after {})", height, prev));
            }
        }
        prev_height = Some(height);
        verify_header_proof_item(anchor.prev_root, proofs.mmr_size, height, &item.header, &item.path)?;
    }
    Ok(())
}

/// Full verification: MMR membership plus PoW and post-HF4 WTEMA on every
/// sampled header, using `trusted_tail` for the h-2/h-1 neighbours.
pub fn verify_header_proofs_with_pow(
    anchor: &BlockHeader,
    proofs: &HeaderProofs,
    trusted_tail: &[BlockHeader],
) -> Result<(), String> {
    verify_memberships(anchor, proofs)?;
    let mut by_height: std::collections::HashMap<u64, &BlockHeader> = std::collections::HashMap::new();
    for header in trusted_tail {
        by_height.insert(header.height, header);
    }
    for item in &proofs.items {
        by_height.insert(item.header.height, &item.header);
    }
    for item in &proofs.items {
        let header = &item.header;
        let height = header.height;
        if !consensus::valid_header_version(height, header.version) {
            return Err(format!("invalid header version {} at height {}", header.version.0, height));
        }
        if header.version < HeaderVersion(5) {
            return Err(format!(
                "pre-HF4 header at height {} (version {}): use the explicit trusted checkpoint/window policy",
                height, header.version.0
            ));
        }
        if height < 2 {
            return Err(format!("sampled height {} cannot provide h-2/h-1 headers", height));
        }
        let prev1 = by_height
            .get(&(height - 1))
            .ok_or_else(|| format!("sampled height {} requires header h-1={} in the proof set or trusted tail", height, height - 1))?;
        let prev2 = by_height
            .get(&(height - 2))
            .ok_or_else(|| format!("sampled height {} requires header h-2={} in the proof set or trusted tail", height, height - 2))?;
        if header.pow.is_secondary() {
            return Err(format!("post-HF4 header at height {} carries secondary PoW", height));
        }
        if !header.pow.is_primary() {
            return Err(format!("invalid PoW edge bits {} at height {}", header.pow.edge_bits(), height));
        }
        grin_core::pow::verify_size(header).map_err(|e| {
            format!(
                "header PoW does not verify at height {} (header fields are not bound by the membership proof): {:?}",
                height, e
            )
        })?;
        if header.timestamp <= prev1.timestamp || prev1.timestamp <= prev2.timestamp {
            return Err(format!("header timestamps are not strictly increasing for the h-2/h-1/h triple below height {}", height));
        }
        if header.total_difficulty() <= prev1.total_difficulty()
            || prev1.total_difficulty() <= prev2.total_difficulty()
        {
            return Err(format!("header total_difficulty is not strictly increasing for the h-2/h-1/h triple below height {}", height));
        }
        if header.prev_hash != prev1.hash() || prev1.prev_hash != prev2.hash() {
            return Err(format!("header prev_hash linkage mismatch at height {}", height));
        }
        if header.timestamp >= anchor.timestamp {
            return Err(format!("header timestamp at height {} is not before the anchor timestamp", height));
        }
        if header.total_difficulty() > anchor.total_difficulty() {
            return Err(format!("header total_difficulty at height {} exceeds the anchor total_difficulty", height));
        }
        let last_net_difficulty = prev1.total_difficulty() - prev2.total_difficulty();
        let last_info = consensus::HeaderDifficultyInfo::new(
            Some(prev1.hash()),
            prev1.timestamp.timestamp() as u64,
            last_net_difficulty,
            prev1.pow.secondary_scaling,
            prev1.pow.is_secondary(),
        );
        let prev_info = consensus::HeaderDifficultyInfo::new(
            Some(prev2.hash()),
            prev2.timestamp.timestamp() as u64,
            grin_core::pow::Difficulty::zero(),
            prev2.pow.secondary_scaling,
            prev2.pow.is_secondary(),
        );
        let expected = consensus::next_wtema_difficulty(height, vec![last_info, prev_info]);
        let claimed_difficulty = header.total_difficulty() - prev1.total_difficulty();
        if claimed_difficulty != expected.difficulty {
            return Err(format!(
                "claimed difficulty {} at height {} does not match expected WTEMA difficulty {}",
                claimed_difficulty, height, expected.difficulty
            ));
        }
        if header.pow.to_difficulty(height) < claimed_difficulty {
            return Err(format!("proof of work difficulty too low at height {}", height));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmr_size_for_genesis_is_zero() {
        assert_eq!(header_mmr_size(0), 0);
        assert_eq!(header_leaf_pos(0), 0);
    }

    #[test]
    fn get_header_proofs_roundtrip() {
        let g = GetHeaderProofs { anchor: Hash::default(), heights: vec![1, 2, 7] };
        let bytes = grin_core::ser::ser_vec(&g, grin_core::ser::ProtocolVersion::local()).unwrap();
        let back: GetHeaderProofs = grin_core::ser::deserialize(&mut &bytes[..], grin_core::ser::ProtocolVersion::local(), grin_core::ser::DeserializationMode::default()).unwrap();
        assert_eq!(back.heights, vec![1, 2, 7]);
    }

    #[test]
    fn rejects_empty_proofs() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Testnet);
        let h = BlockHeader::default();
        let p = HeaderProofs { anchor: Hash::default(), mmr_size: 0, items: vec![] };
        assert!(verify_memberships(&h, &p).is_err());
    }
}

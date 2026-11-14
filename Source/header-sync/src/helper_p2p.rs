//! Minimal local P2P seed for a verified HelperChain.
//!
//! It serves headers and recent blocks immediately; PIBD bitmap segments are
//! generated from the helper's bitmap accumulator. Output/rangeproof/kernel
//! segment serving is not implemented yet and fails closed (the client can fall
//! back to public nodes).

use grinsight_state::helper::HelperChain;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{self, pmmr, BlockHeader, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use grin_core::core::pmmr::{ReadablePMMR, ReadonlyPMMR};
use grin_core::ser::{self, PMMRIndexHashable, ProtocolVersion};
use grinsight_state::outputs::{leaf_idx, OutputState};
use grin_core::global;
use grin_core::pow::Difficulty;
use grin_chain::txhashset::BitmapChunk;
use grin_p2p::types::{ChainAdapter, PeerInfo, TxHashSetRead};
use grin_p2p::{Capabilities, P2PConfig, Server};
use grin_util::secp::pedersen::RangeProof;
use grin_util::StopState;
use std::fs::File;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use chrono::prelude::{DateTime, Utc};


struct OutputBackend<'a> {
    st: &'a OutputState,
    by_pos: std::collections::HashMap<u64, OutputIdentifier>,
}

impl<'a> OutputBackend<'a> {
    fn new(st: &'a OutputState, spent: &[(u64, OutputIdentifier)]) -> Self {
        let mut by_pos = st.data_by_pos();
        for (pos, id) in spent {
            by_pos.entry(*pos).or_insert(*id);
        }
        Self { st, by_pos }
    }
    fn hash_at(&self, pos: u64) -> Option<Hash> {
        let ht = pmmr::bintree_postorder_height(pos);
        if ht == 0 {
            if let Some(id) = self.by_pos.get(&pos) {
                return Some(id.hash_with_index(pos));
            }
            return self.st.pruned.get(&pos).copied();
        }
        if let Some(h) = self.st.pruned.get(&pos) {
            return Some(*h);
        }
        let l = self.hash_at(pos - (1 << ht))?;
        let r = self.hash_at(pos - 1)?;
        Some((l, r).hash_with_index(pos))
    }
}


impl<'a> pmmr::Backend<OutputIdentifier> for OutputBackend<'a> {
    fn append(&mut self, _data: &OutputIdentifier, _hashes: &[Hash]) -> Result<(), String> {
        Err("helper output backend is read-only".into())
    }
    fn append_pruned_subtree(&mut self, _hash: Hash, _pos0: u64) -> Result<(), String> {
        Err("helper output backend is read-only".into())
    }
    fn append_hash(&mut self, _hash: Hash) -> Result<(), String> {
        Err("helper output backend is read-only".into())
    }
    fn rewind(&mut self, _pos1: u64, _rewind_rm_pos: &croaring::Bitmap) -> Result<(), String> {
        Err("helper output backend is read-only".into())
    }
    fn get_hash(&self, pos0: u64) -> Option<Hash> {
        self.hash_at(pos0)
    }
    fn get_data(&self, pos0: u64) -> Option<OutputIdentifier> {
        self.by_pos.get(&pos0).copied()
    }
    fn get_from_file(&self, pos0: u64) -> Option<Hash> {
        self.hash_at(pos0)
    }
    fn get_peak_from_file(&self, pos0: u64) -> Option<Hash> {
        self.hash_at(pos0)
    }
    fn get_data_from_file(&self, pos0: u64) -> Option<OutputIdentifier> {
        self.by_pos.get(&pos0).copied()
    }
    fn leaf_pos_iter(&self) -> Box<dyn Iterator<Item = u64> + '_> {
        let v: Vec<u64> = self.st.leaves.iter().map(|i| pmmr::insertion_to_pmmr_index(i as u64)).collect();
        Box::new(v.into_iter())
    }
    fn n_unpruned_leaves(&self) -> u64 {
        self.st.leaves.cardinality() as u64
    }
    fn n_unpruned_leaves_to_index(&self, to_index: u64) -> u64 {
        self.st.leaves.iter().filter(|i| *i as u64 <= to_index).count() as u64
    }
    fn leaf_idx_iter(&self, from_idx: u64) -> Box<dyn Iterator<Item = u64> + '_> {
        let v: Vec<u64> = self.st.leaves.iter().filter(|i| *i as u64 >= from_idx).map(|i| i as u64).collect();
        Box::new(v.into_iter())
    }
    fn remove(&mut self, _position: u64) -> Result<(), String> {
        Err("helper output backend is read-only".into())
    }
    fn remove_from_leaf_set(&mut self, _pos0: u64) {}
    fn release_files(&mut self) {}
    fn reset_prune_list(&mut self) {}
    fn snapshot(&self, _header: &BlockHeader) -> Result<(), String> {
        Ok(())
    }
    fn dump_stats(&self) {}
}
impl<'a> ReadablePMMR for OutputBackend<'a> {
    type Item = OutputIdentifier;
    fn get_hash(&self, pos: u64) -> Option<Hash> {
        self.hash_at(pos)
    }
    fn get_data(&self, pos: u64) -> Option<Self::Item> {
        if self.st.leaves.contains(leaf_idx(pos) as u32) {
            self.by_pos.get(&pos).copied()
        } else {
            None
        }
    }
    fn get_from_file(&self, pos: u64) -> Option<Hash> {
        self.hash_at(pos)
    }
    fn get_peak_from_file(&self, pos: u64) -> Option<Hash> {
        self.hash_at(pos)
    }
    fn get_data_from_file(&self, pos: u64) -> Option<Self::Item> {
        self.get_data(pos)
    }
    fn unpruned_size(&self) -> u64 {
        self.st.size
    }
    fn leaf_pos_iter(&self) -> Box<dyn Iterator<Item = u64> + '_> {
        let v: Vec<u64> = self.st.leaves.iter().map(|i| pmmr::insertion_to_pmmr_index(i as u64)).collect();
        Box::new(v.into_iter())
    }
    fn leaf_idx_iter(&self, from_idx: u64) -> Box<dyn Iterator<Item = u64> + '_> {
        let v: Vec<u64> = self.st.leaves.iter().filter(|i| *i as u64 >= from_idx).map(|i| i as u64).collect();
        Box::new(v.into_iter())
    }
    fn n_unpruned_leaves(&self) -> u64 {
        self.st.leaves.cardinality() as u64
    }
    fn n_unpruned_leaves_to_index(&self, to_index: u64) -> u64 {
        self.st.leaves.iter().filter(|i| *i as u64 <= to_index).count() as u64
    }
}
pub struct HelperAdapter {
    pub chain: Arc<Mutex<HelperChain>>,
    pub tmp: PathBuf,
    pub blocks: Mutex<BlockStore>,
}

/// Append-only store of recent blocks for serving `GetBlock`/`GetBlocks`
/// independently of the in-memory reorg window. The last `window` blocks are
/// kept; older records are dropped on compaction.
pub struct BlockStore {
    path: PathBuf,
    blocks: Vec<core::Block>,
    window: usize,
}

impl BlockStore {
    pub fn open(path: PathBuf, window: usize) -> Self {
        let mut blocks = Vec::new();
        if let Ok(raw) = std::fs::read(&path) {
            if raw.len() >= 4 && &raw[..4] == b"UBLK" {
                let mut off = 4usize;
                while off + 4 <= raw.len() {
                    let len = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap()) as usize;
                    off += 4;
                    if off + len > raw.len() {
                        break;
                    }
                    if let Ok(b) = ser::deserialize_default::<core::Block, _>(&mut &raw[off..off + len]) {
                        blocks.push(b);
                    }
                    off += len;
                }
            }
        }
        Self { path, blocks, window }
    }

    pub fn recent(&self, hash: &Hash) -> Option<core::Block> {
        self.blocks.iter().find(|b| b.header.hash() == *hash).cloned()
    }

    pub fn append(&mut self, block: core::Block) -> Result<(), String> {
        self.blocks.push(block);
        if self.blocks.len() > self.window {
            let drop = self.blocks.len() - self.window;
            self.blocks.drain(0..drop);
            self.rewrite()
        } else {
            let mut raw = Vec::new();
            let bytes = ser::ser_vec(self.blocks.last().unwrap(), ProtocolVersion::local()).map_err(|e| e.to_string())?;
            raw.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            raw.extend_from_slice(&bytes);
            use std::io::Write;
            let fresh = std::fs::metadata(&self.path).map(|m| m.len() == 0).unwrap_or(true);
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path).map_err(|e| e.to_string())?;
            if fresh {
                f.write_all(b"UBLK").map_err(|e| e.to_string())?;
            }
            f.write_all(&raw).map_err(|e| e.to_string())?;
            Ok(())
        }
    }

    fn rewrite(&self) -> Result<(), String> {
        let mut raw = b"UBLK".to_vec();
        for b in &self.blocks {
            let bytes = ser::ser_vec(b, ProtocolVersion::local()).map_err(|e| e.to_string())?;
            raw.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            raw.extend_from_slice(&bytes);
        }
        let tmp = format!("{}.new", self.path.display());
        std::fs::write(&tmp, &raw).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn err(msg: impl Into<String>) -> grin_chain::Error {
    grin_chain::Error::Other(msg.into())
}

impl ChainAdapter for HelperAdapter {
    fn total_difficulty(&self) -> Result<Difficulty, grin_chain::Error> {
        Ok(self.chain.lock().unwrap().state.header.total_difficulty())
    }

    fn total_height(&self) -> Result<u64, grin_chain::Error> {
        Ok(self.chain.lock().unwrap().state.header.height)
    }

    fn transaction_received(&self, _tx: core::Transaction, _stem: bool) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }

    fn get_transaction(&self, _kernel_hash: Hash) -> Option<core::Transaction> {
        None
    }

    fn tx_kernel_received(&self, _kernel_hash: Hash, _peer_info: &PeerInfo) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }

    fn block_received(
        &self,
        b: core::Block,
        _peer_info: &PeerInfo,
        _opts: grin_chain::Options,
    ) -> Result<bool, grin_chain::Error> {
        let mut chain = self.chain.lock().unwrap();
        if b.header.height != chain.state.header.height + 1 {
            return Ok(false);
        }
        chain.apply(&b).map_err(|e| err(e))?;
        // Segments are tied to the snapshot header. After the tip advances they
        // must not be served under the new header hash; fail closed until the
        // helper rebuilds a snapshot.
        chain.state.output_segments.clear();
        chain.state.rangeproof_segments.clear();
        chain.state.kernel_last = None;
        let _ = self.blocks.lock().unwrap().append(b.clone());
        Ok(true)
    }

    fn compact_block_received(
        &self,
        _cb: core::CompactBlock,
        _peer_info: &PeerInfo,
    ) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }

    fn header_received(
        &self,
        _bh: core::BlockHeader,
        _peer_info: &PeerInfo,
    ) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }

    fn headers_received(
        &self,
        _bh: &[core::BlockHeader],
        _peer_info: &PeerInfo,
    ) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }

    fn locate_headers(&self, locator: &[Hash]) -> Result<Vec<BlockHeader>, grin_chain::Error> {
        Ok(self.chain.lock().unwrap().headers_from_locator(locator, 32))
    }

    fn get_block(&self, h: Hash, _peer_info: &PeerInfo) -> Option<core::Block> {
        if let Some(b) = self.chain.lock().unwrap().block_by_hash(&h) {
            return Some(b);
        }
        self.blocks.lock().unwrap().recent(&h)
    }

    fn txhashset_read(&self, _h: Hash) -> Option<TxHashSetRead> {
        None
    }

    fn txhashset_archive_header(&self) -> Result<BlockHeader, grin_chain::Error> {
        Ok(self.chain.lock().unwrap().state.header.clone())
    }

    fn txhashset_receive_ready(&self) -> bool {
        false
    }

    fn txhashset_download_update(
        &self,
        _start_time: DateTime<Utc>,
        _downloaded_size: u64,
        _total_size: u64,
    ) -> bool {
        false
    }

    fn txhashset_write(
        &self,
        _h: Hash,
        _txhashset_data: File,
        _peer_peer_info: &PeerInfo,
    ) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }

    fn get_tmp_dir(&self) -> PathBuf {
        let _ = std::fs::create_dir_all(&self.tmp);
        self.tmp.clone()
    }

    fn get_tmpfile_pathname(&self, tmpfile_name: String) -> PathBuf {
        self.get_tmp_dir().join(tmpfile_name)
    }

    fn get_kernel_segment(
        &self,
        hash: Hash,
        id: SegmentIdentifier,
    ) -> Result<Segment<TxKernel>, grin_chain::Error> {
        let chain = self.chain.lock().unwrap();
        if chain.state.header.hash() != hash {
            return Err(err("helper: kernel segment snapshot hash mismatch"));
        }
        chain.state.kernel_last.clone().filter(|s| s.id() == id).ok_or_else(|| err("helper: kernel segment not stored"))
    }

    fn get_bitmap_segment(
        &self,
        hash: Hash,
        id: SegmentIdentifier,
    ) -> Result<(Segment<BitmapChunk>, Hash), grin_chain::Error> {
        eprintln!("DBG helper get_bitmap hash={} h={} idx={}", hash, id.height, id.idx);
        let chain = self.chain.lock().unwrap();
        if chain.state.header.hash() != hash {
            return Err(err("helper: bitmap segment snapshot hash mismatch"));
        }
        let st = &chain.state.base;
        let ro = st.acc.readonly_pmmr();
        let seg = Segment::from_pmmr(id, &ro, false).map_err(|e| err(format!("bitmap segment: {e:?}")))?;
        Ok((seg, st.output_root()))
    }

    fn get_output_segment(
        &self,
        hash: Hash,
        id: SegmentIdentifier,
    ) -> Result<(Segment<OutputIdentifier>, Hash), grin_chain::Error> {
        eprintln!("DBG helper get_output hash={} h={} idx={}", hash, id.height, id.idx);
        let chain = self.chain.lock().unwrap();
        if chain.state.header.hash() != hash {
            return Err(err("helper: output segment snapshot hash mismatch"));
        }
        if let Some(s) = chain.state.output_segments.iter().find(|s| s.id() == id) {
            return Ok((s.clone(), chain.state.base.output_root()));
        }
        let st = &chain.state.base;
        let backend = OutputBackend::new(st, &chain.state.spent_outputs);
        let ro = ReadonlyPMMR::at(&backend, st.size);
        let seg = Segment::from_pmmr(id, &ro, true)
            .map_err(|e| err(format!("output segment: {e:?}")))?;
        Ok((seg, st.output_root()))
    }

    fn get_rangeproof_segment(
        &self,
        hash: Hash,
        id: SegmentIdentifier,
    ) -> Result<Segment<RangeProof>, grin_chain::Error> {
        let chain = self.chain.lock().unwrap();
        if chain.state.header.hash() != hash {
            return Err(err("helper: rangeproof segment snapshot hash mismatch"));
        }
        chain.state.rangeproof_segments.iter().find(|s| s.id() == id).cloned().ok_or_else(|| err("helper: rangeproof segment not stored"))
    }

    fn receive_bitmap_segment(&self, _block_hash: Hash, _output_root: Hash, _segment: Segment<BitmapChunk>) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }

    fn receive_output_segment(&self, _block_hash: Hash, _bitmap_root: Hash, _segment: Segment<OutputIdentifier>) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }

    fn receive_rangeproof_segment(&self, _block_hash: Hash, _segment: Segment<RangeProof>) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }

    fn receive_kernel_segment(&self, _block_hash: Hash, _segment: Segment<TxKernel>) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }
}

static HELPER_SERVER: std::sync::OnceLock<Arc<Server>> = std::sync::OnceLock::new();

/// Broadcasts a fully built transaction through the helper's connected peers.
/// The caller passes only a transaction; no seed or private key reaches the
/// helper.
pub fn relay_transaction(tx: &core::Transaction) -> Result<(), String> {
    let server = HELPER_SERVER.get().ok_or("helper P2P listener is not running")?;
    server.peers.broadcast_transaction(tx);
    Ok(())
}
/// Starts a blocking P2P listener. Intended to be called from a dedicated
/// thread while the helper service is running.
pub fn serve(chain: Arc<Mutex<HelperChain>>, data_dir: &Path, host: IpAddr, port: u16) -> Result<(), String> {
    std::fs::create_dir_all(data_dir).map_err(|e| format!("p2p data dir: {e}"))?;
    // Honest capabilities: PIBD is advertised only when this helper actually
    // has the archive segments loaded (compact UST2 without sidecar must not
    // claim PIBD).
    let has_pibd = {
        let c = chain.lock().unwrap();
        !c.state.rangeproof_segments.is_empty() && c.state.base.utxo_count() > 0
    };
    let adapter = Arc::new(HelperAdapter { chain, tmp: data_dir.join("p2p-tmp"), blocks: Mutex::new(BlockStore::open(data_dir.join("blocks.bin"), 10080)) });
    let config = P2PConfig {
        host,
        port,
        // Public helper: bounded inbound fan-out, no unsolicited outbound
        // connections. Protocol-level rate limits are still per connection.
        peer_max_inbound_count: Some(16),
        peer_max_outbound_count: Some(0),
        ..Default::default()
    };
    let genesis = global::get_genesis_block().header.hash();
    let mut caps = Capabilities::HEADER_HIST | Capabilities::PEER_LIST;
    if has_pibd {
        caps |= Capabilities::PIBD_HIST | Capabilities::PIBD_HIST_1;
    }
    let server = Arc::new(Server::new(
        data_dir.join("p2p-peers").to_str().ok_or("bad data dir")?,
        caps,
        config,
        adapter,
        genesis,
        Arc::new(StopState::new()),
    )
    .map_err(|e| format!("p2p server: {e:?}"))?);
    let _ = HELPER_SERVER.set(server.clone());
    std::thread::sleep(Duration::from_millis(1));
    server.listen().map_err(|e| format!("p2p listen: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use grin_core::ser::{self, ProtocolVersion};
    use grinsight_state::outputs::OutputState;
    use grinsight_state::testkit;
    use grinsight_state::helper::HelperState;

    #[test]
    fn block_store_rotates_to_window() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
        let path = std::env::temp_dir().join(format!("grinsight-blockstore-rot-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut s = BlockStore::open(path.clone(), 2);
        for height in 1..=3u64 {
            let mut b = core::Block::default();
            b.header.height = height;
            b.header.prev_hash = Hash::from_vec(&[height as u8; 32]);
            s.append(b).unwrap();
        }
        assert_eq!(s.blocks.len(), 2);
        assert_eq!(s.blocks[0].header.height, 2);
        drop(s);
        let s = BlockStore::open(path.clone(), 2);
        assert_eq!(s.blocks.len(), 2);
        assert_eq!(s.blocks[1].header.height, 3);
        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn block_store_roundtrips_and_serves_recent_block() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
        let path = std::env::temp_dir().join(format!("grinsight-blockstore-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let b = core::Block::default();
        let h = b.header.hash();
        {
            let mut s = BlockStore::open(path.clone(), 10);
            s.append(b.clone()).unwrap();
        }
        let s = BlockStore::open(path.clone(), 10);
        assert_eq!(s.recent(&h).map(|x| x.header.hash()), Some(h));
        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn serves_bitmap_and_output_segments_from_helper_state() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
        let r = testkit::reference(5000, 2);
        let h = r.header();
        let (bitmap, output) = r.segments(11);
        let state = OutputState::from_segments(&h, &bitmap, &output).unwrap();
        let spent_outputs: Vec<(u64, OutputIdentifier)> = output
            .iter()
            .flat_map(|s| s.leaf_iter())
            .filter(|(_, id)| !state.utxo.contains_key(&id.commit.0))
            .map(|(p, id)| (p, *id))
            .collect();
        let hs = HelperState {
            base: state.clone(),
            header: h.clone(),
            rangeproofs: vec![],
            coinbase_heights: vec![],
            excess_sum: vec![],
            offset_sum: vec![],
            header_window: vec![h.clone()],
            rangeproof_segments: vec![],
            kernel_last: None,
            output_segments: vec![],
            spent_outputs,
        };
        let adapter = HelperAdapter {
            chain: Arc::new(Mutex::new(HelperChain::new(hs, 2016))),
            tmp: std::env::temp_dir().join("grinsight-helper-p2p-test"),
            blocks: Mutex::new(BlockStore::open(std::env::temp_dir().join("grinsight-helper-blocks-test.bin"), 10080)),
        };
        for s in &output {
            let (got, _root) = adapter.get_output_segment(h.hash(), s.id()).unwrap();
            if format!("{:?}", got.proof()) != format!("{:?}", s.proof()) {
                panic!("segment {} proof diff:\n got {:?}\n want {:?}", s.id().idx, got.proof(), s.proof());
            }
        }
        for s in &bitmap {
            let (got, root) = adapter.get_bitmap_segment(h.hash(), s.id()).unwrap();
            assert_eq!(root, state.output_root());
            let bro = state.acc.readonly_pmmr();
            got.validate(bro.unpruned_size(), None, state.acc.root())
                .unwrap_or_else(|e| panic!("bitmap segment {} invalid: {e:?}", s.id().idx));
        }
    }
}
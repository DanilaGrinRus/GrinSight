//! Fetch two ordinary PIBD segments and validate them against a selected header.
use super::*;
use croaring::Bitmap;
use grin_core::ser::PMMRIndexHashable;
use grin_chain::txhashset::BitmapSegment;

fn serialize_bundle(bitmap:&Segment<BitmapChunk>,raw:Hash,output:&Segment<OutputIdentifier>,other:Hash)->Result<Vec<u8>,String>{
    let b=ser::ser_vec(&BitmapSegment::from(bitmap.clone()),ProtocolVersion::local()).map_err(|e|format!("bitmap serialize: {e:?}"))?;
    let o=ser::ser_vec(output,ProtocolVersion::local()).map_err(|e|format!("output serialize: {e:?}"))?;
    let mut data=b"UPB1".to_vec();data.extend_from_slice(raw.as_bytes());data.extend_from_slice(other.as_bytes());
    for x in [&b,&o] {let len=u32::try_from(x.len()).map_err(|_|"segment too large")?;data.extend_from_slice(&len.to_le_bytes());data.extend_from_slice(x);}
    Ok(data)
}

fn read_bundle(bytes:&[u8])->Result<(Segment<BitmapChunk>,Hash,Segment<OutputIdentifier>,Hash),String>{
    if bytes.len()<76 || bytes.len()>4*1024*1024 || &bytes[..4]!=b"UPB1" {return Err("invalid proof bundle".into())}
    let raw=Hash::from_vec(&bytes[4..36]);let other=Hash::from_vec(&bytes[36..68]);let mut offset=68usize;
    let mut take=||->Result<&[u8],String>{
        let end=offset.checked_add(4).filter(|&x|x<=bytes.len()).ok_or("truncated length")?;
        let n=u32::from_le_bytes(bytes[offset..end].try_into().unwrap()) as usize;offset=end;
        let end=offset.checked_add(n).filter(|&x|x<=bytes.len()).ok_or("truncated segment")?;
        let value=&bytes[offset..end];offset=end;Ok(value)
    };
    let b=take()?;let o=take()?;if offset!=bytes.len(){return Err("trailing bundle data".into())}
    let mut bi=b;let wire:BitmapSegment=ser::deserialize_default(&mut bi).map_err(|e|format!("bitmap decode: {e:?}"))?;
    if !bi.is_empty(){return Err("trailing bitmap data".into())}
    let bitmap=wire.into_segment().map_err(|e|format!("bitmap shape: {e:?}"))?;
    let mut oi=o;let output:Segment<OutputIdentifier>=ser::deserialize_default(&mut oi).map_err(|e|format!("output decode: {e:?}"))?;
    if !oi.is_empty(){return Err("trailing output data".into())}
    Ok((bitmap,raw,output,other))
}

fn load_header(header_path:&str)->Result<BlockHeader,String>{
    let bytes=std::fs::read(header_path).map_err(|e|e.to_string())?;
    if bytes.len()>4096{return Err("oversized header".into())}
    let mut input=&bytes[..];let header:BlockHeader=ser::deserialize_default(&mut input).map_err(|e|format!("header: {e:?}"))?;
    if !input.is_empty(){return Err("trailing header bytes".into())}Ok(header)
}
fn load_commitment(commitment:&str)->Result<Vec<u8>,String>{
    let wanted=grin_util::from_hex(commitment).map_err(|_|"invalid commitment")?;
    if wanted.len()!=33{return Err("commitment must be 33 bytes".into())}Ok(wanted)
}

pub(super) fn replay(header_path:&str,proof_path:&str,leaf:u64,commitment:&str)->Result<(),String>{
    let header=load_header(header_path)?;let wanted=load_commitment(commitment)?;
    let f=std::fs::File::open(proof_path).map_err(|e|e.to_string())?;
    use std::io::Read;let mut bytes=Vec::new();f.take(4*1024*1024+1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
    let (bitmap,raw,output,other)=read_bundle(&bytes)?;
    let verdict=validate_segments(&header,leaf,&wanted,bitmap,raw,output,other)?;
    println!("PIBD_VERDICT={verdict}\nPIBD_ARCHIVE_HEIGHT={}\nPIBD_SOURCE=OFFLINE_BUNDLE\nHEADER_AUTHENTICATION=CALLER_REQUIRED",header.height);
    if verdict.starts_with("UNKNOWN"){Err("output identity unavailable at this position".into())}else{Ok(())}
}

fn validate_segments(header:&BlockHeader, leaf:u64, wanted:&[u8], bitmap:Segment<BitmapChunk>, raw_output_root:Hash, output:Segment<OutputIdentifier>, bitmap_root:Hash)->Result<&'static str,String>{
    if header.version<HeaderVersion(3){return Err("header version <3 does not bind bitmap".into())}
    let count=pmmr::n_leaves(header.output_mmr_size);
    if count==0 || count>u32::MAX as u64 || leaf>=count {return Err("leaf outside supported bitmap range".into())}
    let bid=SegmentIdentifier{height:9,idx:leaf/(1024*512)};
    let oid=SegmentIdentifier{height:11,idx:leaf/2048};
    if bitmap.identifier()!=bid || output.identifier()!=oid {return Err("unexpected segment identifier".into())}
    if (raw_output_root,bitmap_root).hash_with_index(header.output_mmr_size)!=header.output_root{return Err("combined roots mismatch".into())}
    let bit_size=pmmr::insertion_to_pmmr_index(count.div_ceil(1024));
    bitmap.validate_with(bit_size,None,header.output_root,header.output_mmr_size,raw_output_root,true).map_err(|e|format!("bitmap segment: {e:?}"))?;
    let mut live=Bitmap::new();let mut bit_found=false;
    for (pos,chunk) in bitmap.leaf_iter(){
        let ci=pmmr::pmmr_leaf_to_insertion_index(pos).ok_or("invalid bitmap leaf position")?;
        let start=ci.checked_mul(1024).ok_or("bitmap index overflow")?;
        if start>u32::MAX as u64 {return Err("bitmap index exceeds u32".into())}
        let mut entries=Vec::new();
        for bit in chunk.set_iter(0) {
            let absolute=start.checked_add(bit as u64).ok_or("bitmap index overflow")?;
            if absolute<count {entries.push(u32::try_from(absolute).map_err(|_|"bitmap index exceeds u32")?);}
        }
        if leaf/1024==ci {bit_found=true;}
        live.add_many(&entries);
    }
    if !bit_found {return Err("requested bitmap chunk not present".into())}
    // A clear bit cannot bind an arbitrary requested commitment to this position.
    if !live.contains(leaf as u32) {return Ok("UNKNOWN_IDENTITY_UNBOUND")}
    output.validate_with(header.output_mmr_size,Some(&live),header.output_root,header.output_mmr_size,bitmap_root,false).map_err(|e|format!("output segment: {e:?}"))?;
    let pos=pmmr::insertion_to_pmmr_index(leaf);
    let (_,id)=output.leaf_iter().find(|(p,_)|*p==pos).ok_or("unspent output leaf missing")?;
    if id.commit.0.as_slice()!=wanted{return Err("requested commitment mismatch".into())}
    Ok("UNSPENT_AT_ARCHIVE_HEADER")
}

pub(super) fn run(header_path:&str,peer_arg:&str,leaf:u64,commitment:&str,out:Option<&str>)->Result<(),String>{
    let header=load_header(header_path)?;let wanted=load_commitment(commitment)?;
    if leaf>=pmmr::n_leaves(header.output_mmr_size){return Err("leaf out of range".into())}
    let bid=SegmentIdentifier{height:9,idx:leaf/(1024*512)};let oid=SegmentIdentifier{height:11,idx:leaf/2048};
    let conn=TcpStream::connect(peer_arg).map_err(|e|format!("connect: {e}"))?;
    let local=conn.local_addr().map_err(|e|e.to_string())?;
    let hs=Handshake::new(global::get_genesis_block().header.hash(),P2PConfig::default());
    let inbox=Arc::new(Mutex::new(SegmentInbox{wanted:Some((header.hash(),bid,oid)),..Default::default()}));
    let adapter=Arc::new(SyncAdapter{peer_claim:Arc::new(Mutex::new((0,0))),headers:Arc::new(Mutex::new(Vec::new())),blocks:Arc::new(Mutex::new(Vec::new())),wanted:Arc::new(Mutex::new(HashSet::new())),segments:inbox.clone(),outgoing_tx:Arc::new(Mutex::new(None))});
    let peer=Peer::connect(conn,Capabilities::default()|Capabilities::PIBD_HIST|Capabilities::PIBD_HIST_1,Difficulty::min_dma(),PeerAddr(local),&hs,adapter).map_err(|e|format!("handshake: {e:?}"))?;
    let result=(||{
        peer.send_bitmap_segment_request(header.hash(),bid).map_err(|e|format!("bitmap request: {e:?}"))?;
        peer.send_output_segment_request(header.hash(),oid).map_err(|e|format!("output request: {e:?}"))?;
        let start=Instant::now();loop{
            let mut x=inbox.lock().map_err(|_|"segment lock")?;
            if x.bitmap.is_some() && x.output.is_some(){
                let (_,raw,bitmap)=x.bitmap.take().unwrap();let (_,other,output)=x.output.take().unwrap();
                let bitmap_bytes=ser::ser_vec(&bitmap,ProtocolVersion::local()).map(|x|x.len()).unwrap_or(0);
                let output_bytes=ser::ser_vec(&output,ProtocolVersion::local()).map(|x|x.len()).unwrap_or(0);
                let bundle=if out.is_some(){Some(serialize_bundle(&bitmap,raw,&output,other)?)}else{None};
                let verdict=validate_segments(&header,leaf,&wanted,bitmap,raw,output,other)?;
                if verdict=="UNSPENT_AT_ARCHIVE_HEADER" {if let (Some(path),Some(bytes))=(out,bundle){std::fs::write(path,bytes).map_err(|e|format!("write bundle: {e}"))?;}}
                println!("PIBD_VERDICT={verdict}\nPIBD_ARCHIVE_HEIGHT={}\nPIBD_HEADER_HASH={}\nPIBD_BITMAP_INTERNAL_SERIALIZED_BYTES={}\nPIBD_OUTPUT_INTERNAL_SERIALIZED_BYTES={}\nPIBD_SOURCE=STANDARD_GRIN_P2P\nHEADER_AUTHENTICATION=CALLER_REQUIRED",header.height,header.hash(),bitmap_bytes,output_bytes);
                return if verdict.starts_with("UNKNOWN"){Err("output identity unavailable at this position".into())}else{Ok(())};
            }
            drop(x);if start.elapsed()>Duration::from_secs(20){return Err("segment timeout or archive not served".into())}std::thread::sleep(Duration::from_millis(50));
        }
    })();
    peer.stop();let _=peer.wait();result
}

#[cfg(test)]
mod tests {
    use super::*;
    use grin_chain::txhashset::BitmapAccumulator;
    use grin_core::core::{OutputFeatures, pmmr::{PMMR, ReadablePMMR,ReadonlyPMMR,VecBackend}};
    use grin_util::secp::pedersen::Commitment;
    fn sample()->(BlockHeader,Segment<BitmapChunk>,Hash,Segment<OutputIdentifier>,Hash,Vec<u8>){
        global::set_local_chain_type(ChainTypes::Testnet);
        let id=OutputIdentifier{features:OutputFeatures::Plain,commit:Commitment::from_vec(vec![1;33])};
        let mut out=VecBackend::<OutputIdentifier>::new();let mut tree=PMMR::at(&mut out,0);tree.push(&id).unwrap();
        let out_root=tree.root().unwrap();let size=tree.size;drop(tree);
        let output=Segment::from_pmmr(SegmentIdentifier{height:11,idx:0},&ReadonlyPMMR::at(&out,size),true).unwrap();
        let mut bits=BitmapAccumulator::new();bits.init([0u64],1).unwrap();let bit_root=bits.root();
        let bitmap=Segment::from_pmmr(SegmentIdentifier{height:9,idx:0},&bits.readonly_pmmr(),false).unwrap();
        let mut header=BlockHeader::default();header.version=HeaderVersion(5);header.output_mmr_size=size;header.output_root=(out_root,bit_root).hash_with_index(size);
        (header,bitmap,out_root,output,bit_root,id.commit.0.to_vec())
    }
    #[test]
    fn authenticates_both_segments_and_requested_output(){
        let(h,b,oroot,o,broot,c)=sample();
        assert_eq!(validate_segments(&h,0,&c,b.clone(),oroot,o.clone(),broot).unwrap(),"UNSPENT_AT_ARCHIVE_HEADER");
        let bundle=serialize_bundle(&b,oroot,&o,broot).unwrap();let (bb,orr,oo,brr)=read_bundle(&bundle).unwrap();
        assert_eq!(validate_segments(&h,0,&c,bb,orr,oo,brr).unwrap(),"UNSPENT_AT_ARCHIVE_HEADER");
        let mut broken=bundle.clone();broken[0]=0;assert!(read_bundle(&broken).is_err());
        let mut broken=bundle;broken.push(0);assert!(read_bundle(&broken).is_err());
        assert!(validate_segments(&h,0,&[2;33],b.clone(),oroot,o.clone(),broot).is_err());
        assert!(validate_segments(&h,0,&c,b.clone(),Hash::from_vec(&[9;32]),o.clone(),broot).is_err());
        assert!(validate_segments(&h,1,&c,b.clone(),oroot,o.clone(),broot).is_err());
        let mut other=h.clone();other.output_mmr_size+=1;assert!(validate_segments(&other,0,&c,b.clone(),oroot,o.clone(),broot).is_err());
        let (identifier,hp,hs,lp,mut data,proof)=b.clone().parts();data[0].set(0,false);
        let tampered=Segment::from_parts(identifier,hp,hs,lp,data,proof);
        assert!(validate_segments(&h,0,&c,tampered,oroot,o.clone(),broot).is_err());
        let (identifier,hp,hs,lp,mut data,proof)=o.clone().parts();data[0].commit=Commitment::from_vec(vec![2;33]);
        let tampered=Segment::from_parts(identifier,hp,hs,lp,data,proof);
        assert!(validate_segments(&h,0,&c,b,oroot,tampered,broot).is_err());
    }
}

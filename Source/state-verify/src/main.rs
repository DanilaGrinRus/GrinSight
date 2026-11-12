//! GrinSight: verify a sidecar state proof against an explicitly pinned full header.
//! This command does not establish that a header is canonical or fresh.
use grin_core::{core::{BlockHeader, OutputIdentifier, merkle_proof::MerkleProof, hash::{Hash, Hashed}, pmmr}, global::{self, ChainTypes}, ser};
use grin_util::from_hex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{env, fs, process};
mod wallet_state;
use wallet_state::{StateProof, OutputState};

fn read_limited(path: &str, max: u64) -> Result<Vec<u8>, String> {
    let f = fs::File::open(path).map_err(|e| e.to_string())?;
    if f.metadata().map_err(|e| e.to_string())?.len() > max { return Err("file too large".into()); }
    use std::io::Read;
    let mut v = Vec::new(); f.take(max + 1).read_to_end(&mut v).map_err(|e| e.to_string())?;
    if v.len() as u64 > max { return Err("file too large".into()); }
    Ok(v)
}
fn hex(s: &str, n: usize) -> Result<Vec<u8>, String> {
    let b = from_hex(s).map_err(|_| "invalid hex".to_string())?;
    if b.len()!=n { return Err(format!("expected {n} bytes")); } Ok(b)
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str,String> { v.get(key).and_then(Value::as_str).ok_or_else(||format!("missing {key}")) }
fn uint(v: &Value,key:&str)->Result<u64,String>{v.get(key).and_then(Value::as_u64).ok_or_else(||format!("missing {key}"))}
fn hash(v:&Value,key:&str)->Result<Hash,String>{Ok(Hash::from_vec(&hex(string(v,key)?,32)?))}
fn path(v:&Value)->Result<Vec<Hash>,String>{
    let a=v.as_array().ok_or("path must be array")?;
    if a.len()>64 { return Err("proof path too long".into()); }
    a.iter().map(|x| Ok(Hash::from_vec(&hex(x.as_str().ok_or("path hash")?,32)?))).collect()
}
fn verify_bundle(header:&BlockHeader, wanted:&[u8], v:&Value)->Result<&'static str,String>{
    let tip=&v["tip"];
    if uint(tip,"height")? != header.height || hash(tip,"hash")? != header.hash() || hash(tip,"output_root")? != header.output_root || uint(tip,"output_mmr_size")? != header.output_mmr_size { return Err("proof does not match pinned header".into()); }
    if v["output_identifier_hex"].is_null() || v["inclusion"].is_null() { return Ok("UNKNOWN_IDENTITY_UNBOUND"); }
    let id_bytes=hex(string(v,"output_identifier_hex")?,34)?;
    let mut input=&id_bytes[..];
    let output:OutputIdentifier=ser::deserialize_default(&mut input).map_err(|e|format!("output decode: {e}"))?;
    if !input.is_empty() || output.commit.0.as_slice()!=wanted {return Err("requested commitment mismatch".into());}
    let inc=&v["inclusion"];let bp=&v["bitmap"]["proof"];
    let pos=uint(inc,"pos")?; let size=uint(inc,"mmr_size")?;
    if size!=header.output_mmr_size || pos>=size {return Err("invalid output MMR size or position".into());}
    let index=pmmr::pmmr_leaf_to_insertion_index(pos).ok_or("output position is not leaf")?;
    let leaves=pmmr::n_leaves(size);
    if index>=leaves || uint(bp,"index")?!=index || uint(bp,"chunk_index")?!=index/1024 {return Err("bitmap position mismatch".into());}
    let bitmap_size=pmmr::insertion_to_pmmr_index(leaves.div_ceil(1024));
    if uint(bp,"mmr_size")? != bitmap_size { return Err("bitmap MMR size mismatch".into()); }
    let bits=hex(string(bp,"chunk_bits")?,128)?; let mut chunk=[0u8;128];chunk.copy_from_slice(&bits);
    let proof=StateProof { output_mmr_size:size,pmmr_root:hash(tip,"output_pmmr_root")?,bitmap_root:hash(tip,"bitmap_root")?,output,output_pos:pos,output_proof:MerkleProof{mmr_size:size,path:path(&inc["path"])?},bit_index:index,chunk_index:index/1024,chunk_bits:chunk,bitmap_mmr_size:bitmap_size,bitmap_path:path(&bp["path"])? };
    let s=wallet_state::verify(header,&proof).map_err(|e|format!("proof verification: {e:?}"))?;
    Ok(match s.state {OutputState::Unspent=>"UNSPENT_AT_PINNED_HEADER",OutputState::Spent=>"SPENT_AT_PINNED_HEADER"})
}
fn verdict_exit_code(verdict: &str) -> i32 {
    match verdict { "UNSPENT_AT_PINNED_HEADER" => 0, "SPENT_AT_PINNED_HEADER" => 5, _ => 3 }
}
fn run()->Result<(),String>{
    let a:Vec<String>=env::args().skip(1).collect();
    if a.len()!=8 {return Err("usage: grinsight-state --header FILE --header-sha256 HEX --commitment HEX --proof FILE".into());}
    let get=|k:&str|->Result<&str,String>{let i=a.iter().position(|x|x==k).ok_or_else(||format!("missing {k}"))?;a.get(i+1).map(String::as_str).ok_or_else(||format!("missing value for {k}"))};
    for k in ["--header","--header-sha256","--commitment","--proof"] {if a.iter().filter(|x|x.as_str()==k).count()!=1{return Err(format!("duplicate or missing {k}"));}}
    let raw=read_limited(get("--header")?,4096)?;
    let expected=hex(get("--header-sha256")?,32)?;
    if Sha256::digest(&raw).as_slice()!=expected {return Err("full header SHA256 pin mismatch".into());}
    let wanted=hex(get("--commitment")?,33)?;
    global::set_local_chain_type(ChainTypes::Testnet);
    let mut input=&raw[..];let header:BlockHeader=ser::deserialize_default(&mut input).map_err(|e|format!("header decode: {e}"))?;
    if !input.is_empty(){return Err("trailing header bytes".into());}
    let v:Value=serde_json::from_slice(&read_limited(get("--proof")?,4*1024*1024)?).map_err(|e|format!("proof JSON: {e}"))?;
    let verdict=verify_bundle(&header,&wanted,&v)?;
    println!("VERDICT={verdict}\nHEIGHT={}\nHEADER_HASH={}\nTRUST=EXTERNALLY_PINNED_FULL_HEADER\nCANONICAL_CHAIN=NOT_ESTABLISHED\nFRESHNESS=NOT_ESTABLISHED",header.height,header.hash());
    match verdict_exit_code(verdict) { 0 => {}, code => process::exit(code) }
    Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("VERDICT=INVALID\nreason={e}");process::exit(1)}}

#[cfg(test)]
mod tests {
    use super::*;
    use grin_chain::txhashset::{BitmapAccumulator, BitmapChunk};
    use grin_core::core::{HeaderVersion, OutputFeatures, pmmr::{PMMR, ReadablePMMR, VecBackend, insertion_to_pmmr_index}};
    use grin_core::ser::ProtocolVersion;
    use grin_util::{secp::pedersen::Commitment, ToHex};
    fn case_with_bit(unspent: bool)->(BlockHeader,Vec<u8>,Value) {
        global::set_local_chain_type(ChainTypes::Testnet);
        let output=OutputIdentifier{features:OutputFeatures::Plain,commit:Commitment::from_vec(vec![1;33])};
        let mut backend=VecBackend::<OutputIdentifier>::new();
        let mut tree=PMMR::at(&mut backend,0); let pos=tree.push(&output).unwrap();
        let root=tree.root().unwrap(); let op=tree.merkle_proof(pos).unwrap(); let size=tree.size;
        let mut bitmap=BitmapAccumulator::new();let mut chunk=BitmapChunk::new();chunk.set(0,unspent);bitmap.append_chunk(chunk).unwrap();
        let bitmap_root=bitmap.root();let bp=bitmap.readonly_pmmr().merkle_proof(insertion_to_pmmr_index(0)).unwrap();
        let mut h=BlockHeader::default();h.version=HeaderVersion(3);h.height=100;h.output_mmr_size=size;h.output_root=wallet_state::merged_output_root(size,root,bitmap_root);
        let mut bits=[0u8;128];bits[0]=u8::from(unspent);
        let bytes=ser::ser_vec(&output,ProtocolVersion::local()).unwrap();
        let v=serde_json::json!({"tip":{"height":h.height,"hash":h.hash().to_hex(),"output_root":h.output_root.to_hex(),"output_mmr_size":size,"output_pmmr_root":root.to_hex(),"bitmap_root":bitmap_root.to_hex()},"output_identifier_hex":bytes.to_hex(),"inclusion":{"pos":pos,"mmr_size":size,"path":op.path.iter().map(|x|x.to_hex()).collect::<Vec<_>>()},"bitmap":{"proof":{"index":0,"chunk_index":0,"chunk_bits":bits.to_vec().to_hex(),"mmr_size":bp.mmr_size,"path":bp.path.iter().map(|x|x.to_hex()).collect::<Vec<_>>()}}});
        (h,output.commit.0.to_vec(),v)
    }
    fn case()->(BlockHeader,Vec<u8>,Value) { case_with_bit(true) }
    #[test] fn spent_proof_has_distinct_exit_code(){
        let(h,c,v)=case_with_bit(false);
        let verdict=verify_bundle(&h,&c,&v).unwrap();
        assert_eq!(verdict,"SPENT_AT_PINNED_HEADER");
        assert_eq!(verdict_exit_code(verdict),5);
        assert_eq!(verdict_exit_code("UNSPENT_AT_PINNED_HEADER"),0);
        assert_eq!(verdict_exit_code("UNKNOWN_IDENTITY_UNBOUND"),3);
    }
    #[test] fn unspent_is_bound_to_all_parts(){
        let(h,c,v)=case();assert_eq!(verify_bundle(&h,&c,&v).unwrap(),"UNSPENT_AT_PINNED_HEADER");
        let mut x=v.clone();x["bitmap"]["proof"]["chunk_bits"]=Value::String("00".repeat(128));assert!(verify_bundle(&h,&c,&x).is_err());
        let mut x=v.clone();x["inclusion"]["pos"]=1.into();assert!(verify_bundle(&h,&c,&x).is_err());
        let mut x=v.clone();x["tip"]["height"]=101.into();assert!(verify_bundle(&h,&c,&x).is_err());
        let mut x=v.clone();x["bitmap"]["proof"]["mmr_size"]=3.into();assert!(verify_bundle(&h,&c,&x).is_err());
        assert!(verify_bundle(&h,&[2;33],&v).is_err());
    }
    #[test] fn missing_inclusion_never_proves_spent(){let(h,c,mut v)=case();v["output_identifier_hex"]=Value::Null;v["inclusion"]=Value::Null;assert_eq!(verify_bundle(&h,&c,&v).unwrap(),"UNKNOWN_IDENTITY_UNBOUND");}
}

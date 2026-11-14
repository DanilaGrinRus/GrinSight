use grin_core::core::hash::Hashed;
use grin_core::core::{Block, BlockHeader};
use grin_core::ser::{self, DeserializationMode, ProtocolVersion};
use std::fs;

fn main() -> Result<(), String> {
    grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
    let input = std::env::args().nth(1).ok_or("usage: extract_header <block.bin> <header.bin>")?;
    let output = std::env::args().nth(2).ok_or("missing output")?;
    let raw = fs::read(&input).map_err(|e| e.to_string())?;
    let block: Block = ser::deserialize(&mut &raw[..], ProtocolVersion::local(), DeserializationMode::default())
        .map_err(|e| format!("block: {e:?}"))?;
    let header: BlockHeader = block.header;
    let bytes = ser::ser_vec(&header, ProtocolVersion::local()).map_err(|e| e.to_string())?;
    fs::write(&output, bytes).map_err(|e| e.to_string())?;
    println!("HEADER_HEIGHT={} HASH={}", header.height, header.hash());
    Ok(())
}



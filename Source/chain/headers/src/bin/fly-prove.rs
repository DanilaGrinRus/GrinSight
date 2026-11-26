//! Makes the proof of history for a starting point from a file of every
//! header (as `dump_headers.py` writes it), checks it as the wallet would,
//! tries to pass spoiled copies of it, and writes it out.
//!
//!     fly-prove <file of headers> <height of the point> <points> <file for the proof>
#![forbid(unsafe_code)]
use fly_chain_headers::proof::{self, Proof};
use fly_chain_headers::{read_header, Net};
use std::process::ExitCode;
use std::time::Instant;

fn run(args: &[String]) -> Result<(), String> {
    let [file, height, points, out] = args else { return Err("usage: fly-prove <headers> <height> <points> <out>".into()) };
    let height: u64 = height.parse().map_err(|_| "the height is a number")?;
    let points: u32 = points.parse().map_err(|_| "the points are a number")?;
    Net::Main.enter();
    let began = Instant::now();
    let raw = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    // where each header begins
    let mut starts = Vec::new();
    let mut at = 0usize;
    while let Some(size) = raw.get(at..at.saturating_add(2)).and_then(|b| <[u8; 2]>::try_from(b).ok()) {
        let from = at.saturating_add(2);
        let to = from.saturating_add(usize::from(u16::from_be_bytes(size)));
        if to > raw.len() {
            return Err("the file ends inside a header".into());
        }
        starts.push((from, to));
        at = to;
    }
    eprintln!("{} headers in the file, read in {:.1} s", starts.len(), began.elapsed().as_secs_f64());
    let header_at = |h: u64| {
        let (from, to) = *starts.get(usize::try_from(h).ok()?)?;
        read_header(raw.get(from..to)?)
    };
    let began = Instant::now();
    let made: Proof = proof::build(&header_at, height, Net::Main, points).ok_or("the proof could not be made from this file")?;
    eprintln!("made in {:.1} s", began.elapsed().as_secs_f64());
    let bytes = proof::write(&made, Net::Main).ok_or("the proof could not be written")?;
    let began = Instant::now();
    let read = proof::read(&bytes, Net::Main).ok_or("the proof written is not read back")?;
    let passed = proof::check(&read, Net::Main, points).map_err(|e| format!("the proof made does not pass: {e:?}"))?;
    let took = began.elapsed().as_secs_f64();
    let headers: usize = made.answers.iter().map(|a| a.run.len()).sum();
    let work_steps: usize = made.answers.iter().map(|a| a.path.beside.len()).sum();
    let place_steps: usize = made.answers.iter().map(|a| a.place.path.len()).sum();
    println!("point: height {} hash {}", passed.height, passed.hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("work from the first block: {}", passed.work);
    println!("points: {} ({} before the fourth hard fork)", passed.points, passed.early);
    println!("proof: {} bytes; {} headers, {} steps in the tree of work, {} steps in the header tree", bytes.len(), headers, work_steps, place_steps);
    println!("read and checked in {took:.3} s");
    // spoiled copies must not pass: one byte changed at places spread over the whole proof
    let mut tried = 0u32;
    let mut passed_spoiled = 0u32;
    let step = bytes.len().checked_div(199).unwrap_or(1).max(1);
    let mut place = 7usize;
    while place < bytes.len() {
        let mut spoiled = bytes.clone();
        if let Some(byte) = spoiled.get_mut(place) {
            *byte ^= 0x20;
        }
        tried = tried.saturating_add(1);
        if proof::read(&spoiled, Net::Main).is_some_and(|p| proof::check(&p, Net::Main, points).is_ok()) {
            passed_spoiled = passed_spoiled.saturating_add(1);
            println!("a spoiled copy passed: byte {place}");
        }
        place = place.saturating_add(step);
    }
    println!("spoiled copies: {tried} tried, {passed_spoiled} passed");
    // another number of points draws other points: the same answers must not pass for it
    let other = proof::check(&read, Net::Main, points.saturating_sub(1)).is_ok();
    println!("the same proof taken for another number of points: {}", if other { "PASSED" } else { "refused" });
    if passed_spoiled > 0 || other {
        return Err("a spoiled proof passed".into());
    }
    std::fs::write(out, &bytes).map_err(|e| format!("{out}: {e}"))?;
    println!("written: {out}");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("fly-prove: {why}");
            ExitCode::from(1)
        }
    }
}

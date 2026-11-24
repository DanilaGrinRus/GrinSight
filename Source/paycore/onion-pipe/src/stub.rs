#![allow(clippy::arithmetic_side_effects, missing_docs)]
//! A stand-in Tor process: "onion services" are files in one directory
//! that all stand-ins of a test share, `tor-net` two levels above the data
//! directory each is given (beside the profiles). A post to an address is
//! a file named for it; the answer is a file named for the post.
use crate::{decode_answer, decode_post, encode_event, encode_state, Config, Event, Phase, State};
use crate::{ANSWER, ASK_STATE, EVENT, MAX_FRAME, NEXT, POST, STATE, TAKEN, VERSION};
use fly_paycore_pipe_link::{read_frame, read_hello, write_failed, write_frame, write_ready};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes: Option<Vec<u8>> = (0..text.len() / 2).map(|i| u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()).collect();
    <[u8; N]>::try_from(bytes?).ok()
}

/// Write a file so that whoever lists the directory sees it whole.
fn put(dir: &Path, name: &str, text: &str) {
    let tmp = dir.join(format!("tmp-{name}"));
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join(name));
    }
}

fn take(dir: &Path, prefix: &str) -> Option<(String, String)> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.starts_with(prefix))
        .collect();
    names.sort();
    let name = names.into_iter().next()?;
    let text = std::fs::read_to_string(dir.join(&name)).ok()?;
    std::fs::remove_file(dir.join(&name)).ok()?;
    Some((name, text))
}

/// Run the stand-in on standard input and output.
pub fn run() {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let Ok(hello) = read_hello(&mut input, MAX_FRAME) else { return };
    let Some(config) = Config::decode(&hello) else {
        let _ = write_failed(&mut output, "the configuration is not one", MAX_FRAME);
        return;
    };
    let net: Option<PathBuf> = Path::new(&config.data_dir).parent().and_then(Path::parent).map(|base| base.join("tor-net"));
    let Some(net) = net.filter(|net| std::fs::create_dir_all(net).is_ok()) else {
        let _ = write_failed(&mut output, "no place for the stand-in network", MAX_FRAME);
        return;
    };
    if write_ready(&mut output, VERSION, MAX_FRAME).is_err() {
        return;
    }
    // Tor bridges it was given: kept for the tests to look at. Like the real
    // process, it does not bring Tor up with lines it cannot use.
    if !config.tor_bridges.is_empty() {
        let _ = std::fs::create_dir_all(&config.data_dir);
        let _ = std::fs::write(Path::new(&config.data_dir).join("tor-bridges.seen"), &config.tor_bridges);
    }
    let bridges_unusable = config.tor_bridges.lines().any(|line| line.trim() == "unusable");
    let me = hex(&config.public);
    // request id -> name of the answer file
    let mut waiting: BTreeMap<u64, String> = BTreeMap::new();
    let mut next_id = 0u64;
    let mut posts = 0u64;
    while let Ok(Some((tag, body))) = read_frame(&mut input, MAX_FRAME) {
        let answer: Option<(u8, Vec<u8>)> = match tag {
            ASK_STATE => {
                let down = net.join("down").exists();
                let state = if bridges_unusable {
                    State { phase: Phase::Failed, problem: "the Tor bridges cannot be used".to_string() }
                } else {
                    State { phase: if down { Phase::Starting } else { Phase::Listening }, problem: String::new() }
                };
                Some((STATE, encode_state(&state)))
            }
            POST => decode_post(&body).map(|(ticket, to, text)| {
                let taken = !net.join("down").exists();
                if taken {
                    posts = posts.wrapping_add(1);
                    put(&net, &format!("req-{}-{me}-{}-{posts:08}", hex(&to), hex(&ticket)), &text);
                }
                (TAKEN, vec![u8::from(taken)])
            }),
            NEXT => {
                let event = if let Some((name, text)) = take(&net, &format!("ans-{me}-")) {
                    // ans-<me>-<ticket>
                    let ticket = name.rsplit('-').next().and_then(unhex::<16>).unwrap_or([0; 16]);
                    Some(Event::Posted { ticket, result: Ok(text) })
                } else if let Some((name, text)) = take(&net, &format!("req-{me}-")) {
                    // req-<me>-<from>-<ticket>-<n>
                    let mut parts = name.split('-').skip(2);
                    let (from, ticket) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
                    next_id = next_id.wrapping_add(1);
                    waiting.insert(next_id, format!("ans-{from}-{ticket}"));
                    Some(Event::Request { id: next_id, body: text })
                } else {
                    None
                };
                encode_event(event.as_ref()).map(|wire| (EVENT, wire))
            }
            ANSWER => decode_answer(&body).map(|(id, text)| {
                let known = waiting.remove(&id);
                if let Some(name) = &known {
                    put(&net, name, &text);
                }
                (TAKEN, vec![u8::from(known.is_some())])
            }),
            _ => None,
        };
        let Some((tag, answer)) = answer else { break };
        if write_frame(&mut output, tag, &answer, MAX_FRAME).is_err() {
            break;
        }
    }
}

//! What a node says its tip is.
//!
//! This is the body of a node's answer to `get_tip`. It is a statement and
//! nothing more: the height, the hash and the work are the operator's
//! word. What the program does with that word - compare it with the tip it
//! verified itself - is decided elsewhere.

/// A node's word about its tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Said {
    /// The height of the tip.
    pub height: u64,
    /// The hash of the block at the tip.
    pub hash: [u8; 32],
    /// The total work of the chain up to the tip.
    pub total_difficulty: u64,
}

/// Why a body is not a word about a tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotSaid {
    /// The node answered that it will not or cannot say.
    Refused,
    /// The body is not the answer a Grin node gives; the words say where.
    Format(&'static str),
}

/// Reads a node's answer to `get_tip`.
pub fn read(body: &[u8]) -> Result<Said, NotSaid> {
    read_as(body, "last_block_pushed")
}

/// Reads a node's answer to `get_header`: the header of its chain at one
/// height. The work is the total up to and including that header.
pub fn read_header(body: &[u8]) -> Result<Said, NotSaid> {
    read_as(body, "hash")
}

fn read_as(body: &[u8], hash_field: &str) -> Result<Said, NotSaid> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| NotSaid::Format("the body is not JSON"))?;
    if value.get("error").is_some_and(|e| !e.is_null()) {
        return Err(NotSaid::Refused);
    }
    let result = value
        .get("result")
        .ok_or(NotSaid::Format("no result in the body"))?;
    if result.get("Err").is_some() {
        return Err(NotSaid::Refused);
    }
    let tip = result
        .get("Ok")
        .ok_or(NotSaid::Format("a result that is neither Ok nor Err"))?;
    let height = tip
        .get("height")
        .and_then(serde_json::Value::as_u64)
        .ok_or(NotSaid::Format("the height"))?;
    let total_difficulty = tip
        .get("total_difficulty")
        .and_then(serde_json::Value::as_u64)
        .ok_or(NotSaid::Format("the total difficulty"))?;
    let text = tip
        .get(hash_field)
        .and_then(serde_json::Value::as_str)
        .ok_or(NotSaid::Format("the hash"))?;
    let hash = unhex(text).ok_or(NotSaid::Format("the hash"))?;
    Ok(Said {
        height,
        hash,
        total_difficulty,
    })
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        if !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const HASH: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F";

    fn body(tip: &str) -> Vec<u8> {
        format!(r#"{{"id":1,"jsonrpc":"2.0","result":{{"Ok":{tip}}}}}"#).into_bytes()
    }

    #[test]
    fn the_answer_of_a_node() {
        let tip = format!(
            r#"{{"height":4118377,"last_block_pushed":"{HASH}","prev_block_to_last":"{HASH}","total_difficulty":2599999999999999}}"#
        );
        let said = read(&body(&tip)).unwrap();
        assert_eq!(said.height, 4_118_377);
        assert_eq!(said.total_difficulty, 2_599_999_999_999_999);
        let want: Vec<u8> = (0u8..32).collect();
        assert_eq!(said.hash.to_vec(), want);
    }

    #[test]
    fn the_header_at_a_height() {
        // as a node writes it: the fields of the header, the hash among them
        let header = format!(
            r#"{{"cuckoo_solution":[1,2,3],"edge_bits":32,"hash":"{HASH}","height":4114380,"kernel_root":"{HASH}","previous":"{HASH}","timestamp":"2026-11-20T01:02:03+00:00","total_difficulty":2377999999999999,"version":5}}"#
        );
        let said = read_header(&body(&header)).unwrap();
        assert_eq!((said.height, said.total_difficulty), (4_114_380, 2_377_999_999_999_999));
        let want: Vec<u8> = (0u8..32).collect();
        assert_eq!(said.hash.to_vec(), want);
        // an answer about the tip names no header, and the other way round
        let tip = format!(r#"{{"height":7,"last_block_pushed":"{HASH}","prev_block_to_last":"{HASH}","total_difficulty":1}}"#);
        assert_eq!(read_header(&body(&tip)), Err(NotSaid::Format("the hash")));
        assert_eq!(read(&body(&header)), Err(NotSaid::Format("the hash")));
        // a node that has no such header says so
        let none = br#"{"id":1,"jsonrpc":"2.0","result":{"Err":"NotFound"}}"#;
        assert_eq!(read_header(none), Err(NotSaid::Refused));
        let short = format!(r#"{{"hash":"{}","height":7,"total_difficulty":1}}"#, &HASH[..62]);
        assert_eq!(read_header(&body(&short)), Err(NotSaid::Format("the hash")));
    }

    #[test]
    fn a_node_that_will_not_say() {
        let err = br#"{"id":1,"jsonrpc":"2.0","result":{"Err":{"Internal":"busy"}}}"#;
        assert_eq!(read(err), Err(NotSaid::Refused));
        let rpc = br#"{"id":1,"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"}}"#;
        assert_eq!(read(rpc), Err(NotSaid::Refused));
    }

    #[test]
    fn what_is_not_an_answer() {
        let short = &HASH[..62];
        let odd = HASH.replace('a', "g");
        let signed = format!("+{}", &HASH[1..]);
        for tip in [
            format!(r#"{{"last_block_pushed":"{HASH}","total_difficulty":1}}"#),
            format!(r#"{{"height":-1,"last_block_pushed":"{HASH}","total_difficulty":1}}"#),
            format!(r#"{{"height":"7","last_block_pushed":"{HASH}","total_difficulty":1}}"#),
            format!(r#"{{"height":1.5,"last_block_pushed":"{HASH}","total_difficulty":1}}"#),
            format!(r#"{{"height":1,"last_block_pushed":"{HASH}"}}"#),
            format!(r#"{{"height":1,"last_block_pushed":"{HASH}","total_difficulty":18446744073709551616}}"#),
            format!(r#"{{"height":1,"last_block_pushed":"{short}","total_difficulty":1}}"#),
            format!(r#"{{"height":1,"last_block_pushed":"{odd}","total_difficulty":1}}"#),
            format!(r#"{{"height":1,"last_block_pushed":"{signed}","total_difficulty":1}}"#),
            r#"{"height":1,"last_block_pushed":7,"total_difficulty":1}"#.to_string(),
        ] {
            assert!(matches!(read(&body(&tip)), Err(NotSaid::Format(_))), "{tip}");
        }
        for whole in [
            &b""[..],
            b"<html>busy</html>",
            b"{}",
            br#"{"result":{}}"#,
            br#"{"result":[]}"#,
            br#"{"result":{"Ok":null}}"#,
        ] {
            assert!(matches!(read(whole), Err(NotSaid::Format(_))));
        }
    }
}

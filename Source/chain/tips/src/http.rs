//! One request and one answer of HTTP/1.1, as bytes.
//!
//! Nothing here touches the network. The request is the same for everyone
//! who asks: it names no wallet, no installation and nothing about the
//! asker beyond the program's name. The answer is read strictly and within
//! a fixed size, because whoever writes it is a stranger.

use crate::date;

/// The longest header block that is read.
pub const MAX_HEAD: usize = 8 * 1024;

/// The longest body that is read. An answer about the tip is a few hundred
/// bytes.
pub const MAX_BODY: usize = 16 * 1024;

/// The call every Grin node answers: what its tip is.
pub const GET_TIP: &str = r#"{"jsonrpc":"2.0","method":"get_tip","params":[],"id":1}"#;

/// The call that asks a node for the header of its chain at `height`.
pub fn get_header(height: u64) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"get_header","params":[{height},null,null],"id":1}}"#)
}

/// The bytes of a `POST` of `body` to `path` at `host`.
pub fn request(host: &str, port: u16, path: &str, agent: &str, body: &str) -> Vec<u8> {
    let at = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {at}\r\n\
         User-Agent: {agent}\r\n\
         Accept: application/json\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
    .into_bytes()
}

/// An answer read to its end.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    /// The status the server gave.
    pub status: u16,
    /// The time the server wrote on the answer, in seconds since 1970, if
    /// it wrote exactly one, wrote it the required way and the answer
    /// does not say that it was kept by somebody on the way (`Age`).
    pub date: Option<u64>,
    /// The body.
    pub body: Vec<u8>,
}

/// Why bytes are not an answer.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Bad {
    /// More than is read from a stranger.
    TooLong,
    /// Not HTTP as it has to be written; the words say where.
    Format(&'static str),
}

/// Reads an answer from the bytes received so far. `ended` says the server
/// has closed the connection. `Ok(None)` means more bytes are needed.
pub fn parse(bytes: &[u8], ended: bool) -> Result<Option<Response>, Bad> {
    parse_with_wire_limit(bytes, ended, MAX_WIRE)
}

// Allow framing as well as payload, even when every body byte is a separate chunk.
const MAX_WIRE: usize = 2 * 1024 * 1024;

fn parse_with_wire_limit(bytes: &[u8], ended: bool, max_wire: usize) -> Result<Option<Response>, Bad> {
    if bytes.len() > max_wire {
        return Err(Bad::TooLong);
    }
    let Some(split) = find(bytes, b"\r\n\r\n") else {
        if bytes.len() > MAX_HEAD {
            return Err(Bad::TooLong);
        }
        if ended {
            return Err(Bad::Format("the header is cut short"));
        }
        return Ok(None);
    };
    if split > MAX_HEAD {
        return Err(Bad::TooLong);
    }
    let (head, rest) = bytes.split_at(split);
    let rest = rest.get(4..).unwrap_or_default();
    let head = std::str::from_utf8(head).map_err(|_| Bad::Format("the header is not text"))?;
    let mut lines = head.split("\r\n");
    let status = status(lines.next().unwrap_or_default())?;

    let mut length: Option<usize> = None;
    let mut chunked = false;
    let mut dates: Vec<&str> = Vec::new();
    let mut kept = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(Bad::Format("a header line without a colon"))?;
        if name.is_empty() || name.bytes().any(|b| b <= b' ' || b >= 0x7f) {
            return Err(Bad::Format("a header name"));
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-length") {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Bad::Format("a content length"));
            }
            let n: usize = value.parse().map_err(|_| Bad::TooLong)?;
            if length.is_some_and(|had| had != n) {
                return Err(Bad::Format("two content lengths"));
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(Bad::Format("a transfer encoding"));
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("date") {
            dates.push(value);
        } else if name.eq_ignore_ascii_case("age") {
            // somebody kept this answer and hands it out again: the time
            // on it is the time it was first written
            kept = true;
        }
    }
    let date = match dates.as_slice() {
        [one] if !kept => date::parse(one),
        _ => None,
    };

    let body = match (chunked, length) {
        (true, Some(_)) => return Err(Bad::Format("both a length and chunks")),
        (true, None) => match unchunk(rest)? {
            Some(body) => body,
            None if ended => return Err(Bad::Format("the chunks are cut short")),
            None => return Ok(None),
        },
        (false, Some(n)) => {
            if n > MAX_BODY {
                return Err(Bad::TooLong);
            }
            if rest.len() > n {
                return Err(Bad::Format("more than the length said"));
            }
            if rest.len() < n {
                if ended {
                    return Err(Bad::Format("the body is cut short"));
                }
                return Ok(None);
            }
            rest.to_vec()
        }
        (false, None) => {
            if rest.len() > MAX_BODY {
                return Err(Bad::TooLong);
            }
            if !ended {
                return Ok(None);
            }
            rest.to_vec()
        }
    };
    Ok(Some(Response { status, date, body }))
}

fn status(line: &str) -> Result<u16, Bad> {
    let bad = Bad::Format("the status line");
    let rest = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))
        .ok_or(bad)?;
    let code = rest.get(..3).ok_or(bad)?;
    if !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad);
    }
    if !matches!(rest.as_bytes().get(3), None | Some(b' ')) {
        return Err(bad);
    }
    code.parse().map_err(|_| bad)
}

/// The body out of its chunks, or nothing if the last chunk has not come.
fn unchunk(mut rest: &[u8]) -> Result<Option<Vec<u8>>, Bad> {
    let mut body = Vec::new();
    loop {
        let Some(end) = find(rest, b"\r\n") else {
            if rest.len() > 64 {
                return Err(Bad::Format("a chunk size"));
            }
            return Ok(None);
        };
        let (line, after) = rest.split_at(end);
        let after = after.get(2..).unwrap_or_default();
        let line = std::str::from_utf8(line).map_err(|_| Bad::Format("a chunk size"))?;
        let digits = line.split(';').next().unwrap_or_default().trim();
        if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Bad::Format("a chunk size"));
        }
        let size = usize::from_str_radix(digits, 16).map_err(|_| Bad::Format("a chunk size"))?;
        if size == 0 {
            // What follows the last chunk is not read: nothing of the
            // answer is in it.
            return Ok(if find(rest, b"\r\n\r\n").is_some() {
                Some(body)
            } else {
                None
            });
        }
        if size > MAX_BODY.saturating_sub(body.len()) {
            return Err(Bad::TooLong);
        }
        let Some(data) = after.get(..size) else {
            return Ok(None);
        };
        let tail = after.get(size..).unwrap_or_default();
        match tail.get(..2) {
            Some(b"\r\n") => {}
            Some(_) => return Err(Bad::Format("the end of a chunk")),
            None => return Ok(None),
        }
        body.extend_from_slice(data);
        rest = tail.get(2..).unwrap_or_default();
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn whole(text: &str) -> Result<Option<Response>, Bad> {
        parse(text.as_bytes(), true)
    }

    #[test]
    fn the_wire_budget_covers_the_entire_http_message() {
        let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert!(matches!(parse_with_wire_limit(reply, true, reply.len()), Ok(Some(_))));
        assert_eq!(parse_with_wire_limit(reply, true, reply.len() - 1), Err(Bad::TooLong));
        assert_eq!(parse_with_wire_limit(&reply[..16], false, 15), Err(Bad::TooLong));
    }

    #[test]
    fn the_request_names_only_the_program() {
        let bytes = request("node.example", 443, "/v2/foreign", "GrinSight-Fly/0.2", GET_TIP);
        let text = String::from_utf8(bytes).unwrap_or_default();
        assert_eq!(
            text,
            "POST /v2/foreign HTTP/1.1\r\nHost: node.example\r\nUser-Agent: GrinSight-Fly/0.2\r\n\
             Accept: application/json\r\nContent-Type: application/json\r\nContent-Length: 55\r\n\
             Connection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"get_tip\",\"params\":[],\"id\":1}"
        );
        let other = request("node.example", 3413, "/v2/foreign", "x", "");
        assert!(String::from_utf8(other)
            .unwrap_or_default()
            .contains("\r\nHost: node.example:3413\r\n"));
    }

    #[test]
    fn an_answer_with_a_length() {
        let text = "HTTP/1.1 200 OK\r\ndate: Mon, 23 Nov 2026 02:09:33 GMT\r\nContent-Length: 2\r\n\r\n{}";
        let want = Response {
            status: 200,
            date: Some(1_795_399_773),
            body: b"{}".to_vec(),
        };
        assert_eq!(whole(text), Ok(Some(want)));
        // It is whole as soon as the last byte is there, and not before.
        let bytes = text.as_bytes();
        assert!(matches!(parse(bytes, false), Ok(Some(_))));
        for cut in 0..bytes.len() {
            assert_eq!(parse(bytes.get(..cut).unwrap_or_default(), false), Ok(None), "{cut}");
            assert!(parse(bytes.get(..cut).unwrap_or_default(), true).is_err(), "{cut}");
        }
    }

    #[test]
    fn an_answer_in_chunks() {
        let text = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n4;x=y\r\n\":1}\r\n0\r\n\r\n";
        let got = whole(text).ok().flatten().map(|r| r.body);
        assert_eq!(got, Some(b"{\"a\":1}".to_vec()));
        let bytes = text.as_bytes();
        for cut in 0..bytes.len() {
            assert_eq!(parse(bytes.get(..cut).unwrap_or_default(), false), Ok(None), "{cut}");
        }
    }

    #[test]
    fn an_answer_that_ends_with_the_connection() {
        let text = "HTTP/1.0 503 Busy\r\n\r\nlater";
        assert_eq!(parse(text.as_bytes(), false), Ok(None));
        let got = whole(text).ok().flatten();
        assert_eq!(got.as_ref().map(|r| r.status), Some(503));
        assert_eq!(got.map(|r| r.body), Some(b"later".to_vec()));
    }

    #[test]
    fn the_time_is_one_or_none() {
        let two = "HTTP/1.1 200 OK\r\nDate: Mon, 23 Nov 2026 02:09:33 GMT\r\nDate: Mon, 23 Nov 2026 02:09:34 GMT\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(whole(two).ok().flatten().map(|r| r.date), Some(None));
        let odd = "HTTP/1.1 200 OK\r\nDate: yesterday\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(whole(odd).ok().flatten().map(|r| r.date), Some(None));
        // An answer somebody kept and hands out again carries the time
        // it was first written: no time at all, however fresh it claims
        // to be. The answer itself is still read.
        for age in ["Age: 7", "age: 0", "AGE:"] {
            let kept = format!("HTTP/1.1 200 OK\r\nDate: Mon, 23 Nov 2026 02:09:33 GMT\r\n{age}\r\nContent-Length: 2\r\n\r\n{{}}");
            let read = whole(&kept).ok().flatten().unwrap();
            assert_eq!((read.date, read.body), (None, b"{}".to_vec()), "{age}");
        }
    }

    #[test]
    fn what_is_not_an_answer() {
        for bad in [
            "HTTP/2 200\r\n\r\n",
            "HTTP/1.1 20 OK\r\n\r\n",
            "HTTP/1.1 2000 OK\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}xx0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nX: 1\r\n folded\r\n\r\n",
            "HTTP/1.1 200 OK\r\nX: 1\r\n\tfolded: 2\r\n\r\n",
            "HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
            "HTTP/1.1 200 OK\r\nbad name: 1\r\n\r\n",
        ] {
            assert!(matches!(whole(bad), Err(Bad::Format(_))), "{bad:?}");
        }
    }

    #[test]
    fn no_more_than_the_limits() {
        let long_head = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert_eq!(whole(&long_head), Err(Bad::TooLong));
        let endless = format!("HTTP/1.1 200 OK\r\nX: {}", "a".repeat(MAX_HEAD));
        assert_eq!(parse(endless.as_bytes(), false), Err(Bad::TooLong));
        let announced = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert_eq!(parse(announced.as_bytes(), false), Err(Bad::TooLong));
        let at_the_limit = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {MAX_BODY}\r\n\r\n{}",
            "a".repeat(MAX_BODY)
        );
        assert!(matches!(whole(&at_the_limit), Ok(Some(_))));
        let unending = format!("HTTP/1.1 200 OK\r\n\r\n{}", "a".repeat(MAX_BODY + 1));
        assert_eq!(parse(unending.as_bytes(), false), Err(Bad::TooLong));
        let chunks = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            MAX_BODY + 1
        );
        assert_eq!(parse(chunks.as_bytes(), false), Err(Bad::TooLong));
        let huge = "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999999\r\n\r\n";
        assert_eq!(parse(huge.as_bytes(), false), Err(Bad::TooLong));
    }
}

//! The little of HTTP that wallets speak to each other: one POST with a
//! body of known length, one answer, then the connection ends.
//!
//! Everything read here comes from whoever is at the other end. Every
//! length is bounded before anything is kept.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

/// Longest head of a request or an answer, in bytes.
pub const MAX_HEAD: usize = 8 * 1024;
// A separate wire budget for all chunk sizes, extensions, separators and trailers.
const CHUNK_FRAMING: usize = 32 * 1024;
/// The path wallets post to.
pub const PATH: &str = "/v2/foreign";

/// What is wrong with what was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bad {
    /// More is needed.
    Short,
    /// Not what a wallet sends.
    Form,
    /// Larger than is taken.
    Large,
    /// A request for something else than a wallet's post.
    Other,
}

// Limit the reader itself, including an unterminated line. Each byte is read once.
async fn line<R: AsyncBufRead + Unpin>(reader: &mut R, out: &mut Vec<u8>, budget: &mut usize) -> Result<usize, Bad> {
    let limit = u64::try_from(*budget).map_err(|_| Bad::Large)?.saturating_add(1);
    let size = reader.take(limit).read_until(b'\n', out).await.map_err(|_| Bad::Short)?;
    *budget = budget.checked_sub(size).ok_or(Bad::Large)?;
    if size == 0 || !out.ends_with(b"\n") { return Err(Bad::Short); }
    if size < 2 || !out.ends_with(b"\r\n") { return Err(Bad::Form); }
    Ok(size)
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then_some(value.trim())
    })
}

fn length(head: &str, max: usize) -> Result<Option<usize>, Bad> {
    match header(head, "content-length") {
        None => Ok(None),
        Some(text) => {
            let n: usize = text.parse().map_err(|_| Bad::Form)?;
            if n > max {
                Err(Bad::Large)
            } else {
                Ok(Some(n))
            }
        }
    }
}

/// Which HTTP start line and body framing are allowed on this side of the exchange.
#[derive(Clone, Copy)]
pub enum Message {
    /// A wallet request.
    Request,
    /// A wallet response.
    Response,
}

/// Read a single message, preserving buffered bytes of the next request. The caller
/// keeps the bounded header only to distinguish a silent connection or report a path.
pub async fn read<R: AsyncBufRead + Unpin>(
    reader: &mut R, message: Message, max: usize, head: &mut Vec<u8>,
) -> Result<String, Bad> {
    let mut head_room = MAX_HEAD;
    while line(reader, head, &mut head_room).await? != 2 {}
    let head = std::str::from_utf8(head).map_err(|_| Bad::Form)?;
    let mut first = head.lines().next().unwrap_or_default().split(' ');
    let (first, second) = (first.next().unwrap_or_default(), first.next().unwrap_or_default());
    match message {
        Message::Request if first != "POST" || !is_wallet_path(second) => return Err(Bad::Other),
        Message::Response if !first.starts_with("HTTP/1.") => return Err(Bad::Form),
        Message::Response if second != "200" => return Err(Bad::Other),
        _ => {}
    }
    let mut body = Vec::new();
    if let Some(coding) = header(head, "transfer-encoding") {
        if !coding.eq_ignore_ascii_case("chunked") || header(head, "content-length").is_some() { return Err(Bad::Form); }
        read_chunks(reader, max, &mut body).await?;
    } else if let Some(size) = length(head, max)? {
        read_bytes(reader, size, &mut body).await?;
    } else if matches!(message, Message::Response) {
        let limit = u64::try_from(max).map_err(|_| Bad::Large)?.saturating_add(1);
        reader.take(limit).read_to_end(&mut body).await.map_err(|_| Bad::Short)?;
        if body.len() > max { return Err(Bad::Large); }
    } else { return Err(Bad::Form); }
    String::from_utf8(body).map_err(|_| Bad::Form)
}

async fn read_bytes<R: AsyncBufRead + Unpin>(reader: &mut R, size: usize, body: &mut Vec<u8>) -> Result<(), Bad> {
    let limit = u64::try_from(size).map_err(|_| Bad::Large)?;
    let received = reader.take(limit).read_to_end(body).await.map_err(|_| Bad::Short)?;
    if received != size { return Err(Bad::Short); }
    Ok(())
}

/// Whether a request names the wallet's path. Senders write it in more
/// than one way: with the scheme and the host in front (as to a proxy),
/// with a doubled or a trailing slash, with a query after it.
fn is_wallet_path(target: &str) -> bool {
    let mut path = target;
    for scheme in ["http://", "https://"] {
        if let Some(rest) = path.strip_prefix(scheme) {
            // what follows the host
            path = rest.find('/').and_then(|at| rest.get(at..)).unwrap_or("/");
        }
    }
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    parts == ["v2", "foreign"]
}

/// The first line of what was sent, cut to a few plain characters: for
/// telling the owner what knocked. Nothing else of a request is kept.
pub fn first_line(data: &[u8]) -> String {
    let line = data.split(|b| *b == b'\r' || *b == b'\n').next().unwrap_or_default();
    line.iter().take(48).map(|b| if b.is_ascii_graphic() || *b == b' ' { char::from(*b) } else { '?' }).collect()
}

/// An answer with a JSON body.
pub fn answer(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// An answer that says no and nothing else.
pub fn refusal(bad: Bad) -> Vec<u8> {
    let line = match bad {
        Bad::Large => "413 Payload Too Large",
        Bad::Other => "404 Not Found",
        Bad::Short | Bad::Form => "400 Bad Request",
    };
    format!("HTTP/1.1 {line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

/// A wallet's post to the onion service `host`.
pub fn request(host: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {PATH} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

async fn read_chunks<R: AsyncBufRead + Unpin>(reader: &mut R, max: usize, body: &mut Vec<u8>) -> Result<(), Bad> {
    let mut room = CHUNK_FRAMING;
    let mut framing = Vec::new();
    loop {
        framing.clear();
        line(reader, &mut framing, &mut room).await?;
        let text = std::str::from_utf8(&framing).map_err(|_| Bad::Form)?;
        let digits = text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(digits, 16).map_err(|_| Bad::Form)?;
        if size > max.saturating_sub(body.len()) { return Err(Bad::Large); }
        if size == 0 {
            loop {
                framing.clear();
                if line(reader, &mut framing, &mut room).await? == 2 { return Ok(()); }
            }
        }
        read_bytes(reader, size, body).await?;
        room = room.checked_sub(2).ok_or(Bad::Large)?;
        let mut end = [0u8; 2];
        reader.read_exact(&mut end).await.map_err(|_| Bad::Short)?;
        if end != *b"\r\n" { return Err(Bad::Form); }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn message_body(data: &[u8], max: usize, side: Message) -> Result<String, Bad> {
        let mut reader = tokio::io::BufReader::with_capacity(3, data);
        futures::executor::block_on(read(&mut reader, side, max, &mut Vec::new()))
    }

    fn request_body(data: &[u8], max: usize) -> Result<String, Bad> {
        message_body(data, max, Message::Request)
    }

    fn answer_body(data: &[u8], max: usize) -> Result<String, Bad> {
        message_body(data, max, Message::Response)
    }

    #[test]
    fn both_directions_share_a_finite_framing_budget() {
        for (side, start) in [(Message::Request, "POST /v2/foreign HTTP/1.1"), (Message::Response, "HTTP/1.1 200 OK")] {
            let head = format!("{start}\r\nTransfer-Encoding: chunked\r\n\r\n");
            // A one-byte payload needs 10 framing bytes, excluding its extension.
            let extension = "x".repeat(CHUNK_FRAMING.saturating_sub(11));
            let wire = format!("{head}1;{extension}\r\na\r\n0\r\n\r\n");
            assert_eq!(message_body(wire.as_bytes(), 1, side).as_deref(), Ok("a"));
            let excess = wire.replacen("1;", "1;x", 1);
            assert_eq!(message_body(excess.as_bytes(), 1, side), Err(Bad::Large));
        }
    }

    #[test]
    fn a_wallets_post_is_read_whole_or_not_at_all() {
        let whole = request("abc.onion", "{\"a\":1}");
        assert_eq!(request_body(&whole, 100), Ok("{\"a\":1}".to_string()));
        // every shorter piece asks for more, none is taken for the whole
        for cut in 0..whole.len() {
            assert_eq!(request_body(whole.get(..cut).unwrap(), 100), Err(Bad::Short), "{cut}");
        }
        // what grin-wallet sends: other headers, any case
        let other = b"POST /v2/foreign HTTP/1.1\r\ncontent-type: application/json\r\nCONTENT-LENGTH: 2\r\nhost: x.onion\r\n\r\n{}";
        assert_eq!(request_body(other, 100), Ok("{}".to_string()));
        assert_eq!(request_body(b"POST /v2/foreign/ HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}", 100), Ok("{}".to_string()));
    }

    #[test]
    fn what_is_not_a_wallets_post_is_refused() {
        assert_eq!(request_body(b"GET /v2/foreign HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 100), Err(Bad::Other));
        assert_eq!(request_body(b"POST /v2/owner HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}", 100), Err(Bad::Other));
        assert_eq!(request_body(b"POST /v2/foreign HTTP/1.1\r\n\r\n{}", 100), Err(Bad::Form));
        assert_eq!(request_body(b"POST /v2/foreign HTTP/1.1\r\nContent-Length: x\r\n\r\n{}", 100), Err(Bad::Form));
        assert_eq!(request_body(b"POST /v2/foreign HTTP/1.1\r\nContent-Length: -1\r\n\r\n{}", 100), Err(Bad::Form));
        assert_eq!(request_body(b"POST /v2/foreign HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}", 100), Err(Bad::Form));
        assert_eq!(request_body(b"POST /v2/foreign HTTP/1.1\r\nContent-Length: 2\r\n\r\n\xff\xfe", 100), Err(Bad::Form));
        assert_eq!(request_body(b"POST /v2/foreign HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n{}", 100), Err(Bad::Form));
        // the wallet's path, however the sender writes it; and nothing that only looks like it
        for target in ["/v2/foreign", "/v2/foreign/", "//v2/foreign", "http://abc.onion/v2/foreign", "http://abc.onion:80//v2/foreign?x=1", "/v2/foreign?x"] {
            let request = format!("POST {target} HTTP/1.1\r\nContent-Length: 2\r\n\r\n{{}}");
            assert_eq!(request_body(request.as_bytes(), 100).as_deref(), Ok("{}"), "{target}");
        }
        for target in ["/", "/v2", "/v2/foreign/x", "/v3/foreign", "http://abc.onion/", "http://abc.onion", "/v2/owner", "v2foreign", "/x/v2/foreign"] {
            let request = format!("POST {target} HTTP/1.1\r\nContent-Length: 2\r\n\r\n{{}}");
            assert_eq!(request_body(request.as_bytes(), 100), Err(Bad::Other), "{target}");
        }
        assert_eq!(first_line(b"GET /some/long/path\x01\xff HTTP/1.1\r\nHost: x\r\n\r\n"), "GET /some/long/path?? HTTP/1.1");
        assert_eq!(first_line(&[b'a'; 100]).len(), 48);
        assert_eq!(first_line(b""), "");
        // a body given in chunks is read whole, waited for while it is not all here, and bounded
        let chunked = b"POST /v2/foreign HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{\"\r\n4\r\na\":1\r\n1\r\n}\r\n0\r\n\r\n";
        assert_eq!(request_body(chunked, 100).as_deref(), Ok("{\"a\":1}"));
        assert_eq!(request_body(chunked.get(..chunked.len().saturating_sub(9)).unwrap_or_default(), 100), Err(Bad::Short));
        assert_eq!(request_body(chunked, 5), Err(Bad::Large));
        // a body longer than is taken is refused by its announced length,
        // before any of it is kept
        assert_eq!(request_body(b"POST /v2/foreign HTTP/1.1\r\nContent-Length: 101\r\n\r\n", 100), Err(Bad::Large));
        assert_eq!(request_body(b"POST /v2/foreign HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n", 100), Err(Bad::Form));
        // a head that never ends
        let endless = vec![b'a'; MAX_HEAD.saturating_add(1)];
        assert_eq!(request_body(&endless, 100), Err(Bad::Large));
    }

    #[test]
    fn an_answer_is_read_in_the_forms_wallets_give_it() {
        let plain = answer("{\"ok\":1}");
        assert_eq!(answer_body(&plain, 100), Ok("{\"ok\":1}".to_string()));
        for cut in 0..plain.len() {
            assert_eq!(answer_body(plain.get(..cut).unwrap(), 100), Err(Bad::Short), "{cut}");
        }
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"ok\r\n4;x=1\r\n\":1}\r\n0\r\n\r\n";
        assert_eq!(answer_body(chunked, 100), Ok("{\"ok\":1}".to_string()));
        assert_eq!(answer_body(chunked.get(..chunked.len().saturating_sub(9)).unwrap(), 100), Err(Bad::Short));
        let to_the_end = b"HTTP/1.0 200 OK\r\n\r\n{}";
        assert_eq!(answer_body(to_the_end, 100), Ok("{}".to_string()));
    }

    #[test]
    fn an_answer_that_is_not_one_is_refused() {
        assert_eq!(answer_body(&refusal(Bad::Other), 100), Err(Bad::Other));
        assert_eq!(answer_body(b"HTTP/1.1 500 Oops\r\nContent-Length: 2\r\n\r\n{}", 100), Err(Bad::Other));
        assert_eq!(answer_body(b"SSH-2.0-x\r\n\r\n", 100), Err(Bad::Form));
        assert_eq!(answer_body(b"HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n", 100), Err(Bad::Large));
        assert_eq!(answer_body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n", 100), Err(Bad::Large));
        assert_eq!(answer_body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n40\r\n", 100), Err(Bad::Short));
        assert_eq!(answer_body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", 100), Err(Bad::Form));
        let mut long = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        long.extend(std::iter::repeat_n(b'a', 101));
        assert_eq!(answer_body(&long, 100), Err(Bad::Large));
    }

    /// An answer leaves the connection open for the sender's next request;
    /// a refusal ends it.
    #[test]
    fn an_answer_keeps_the_connection_and_a_refusal_ends_it() {
        let answer = String::from_utf8(answer("{}")).unwrap_or_default();
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n") && answer.ends_with("\r\n\r\n{}"));
        assert!(answer.contains("\r\nConnection: keep-alive\r\n") && answer.contains("\r\nContent-Length: 2\r\n"));
        for bad in [Bad::Large, Bad::Other, Bad::Short, Bad::Form] {
            let refusal = String::from_utf8(refusal(bad)).unwrap_or_default();
            assert!(refusal.contains("\r\nConnection: close\r\n") && !refusal.contains("keep-alive"), "{refusal}");
        }
    }

    #[test]
    fn refusals_say_no_and_nothing_else() {
        for bad in [Bad::Short, Bad::Form, Bad::Large, Bad::Other] {
            let text = String::from_utf8(refusal(bad)).unwrap();
            assert!(text.starts_with("HTTP/1.1 4") && text.ends_with("Connection: close\r\n\r\n"), "{text}");
        }
    }
}

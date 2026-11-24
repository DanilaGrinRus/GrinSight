//! The little of HTTP that wallets speak to each other: one POST with a
//! body of known length, one answer, then the connection ends.
//!
//! Everything read here comes from whoever is at the other end. Every
//! length is bounded before anything is kept.

/// Longest head of a request or an answer, in bytes.
pub const MAX_HEAD: usize = 8 * 1024;
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

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The head and what follows it, once the empty line has arrived.
fn split(data: &[u8]) -> Result<(&str, &[u8]), Bad> {
    let Some(at) = find(data, b"\r\n\r\n") else {
        return Err(if data.len() > MAX_HEAD { Bad::Large } else { Bad::Short });
    };
    if at > MAX_HEAD {
        return Err(Bad::Large);
    }
    let (head, rest) = data.split_at(at);
    let head = std::str::from_utf8(head).map_err(|_| Bad::Form)?;
    Ok((head, rest.get(4..).unwrap_or_default()))
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

/// The body of a wallet's post, once all of it has arrived.
pub fn request_body(data: &[u8], max: usize) -> Result<String, Bad> {
    let (head, rest) = split(data)?;
    let mut first = head.lines().next().unwrap_or_default().split(' ');
    let (method, path) = (first.next().unwrap_or_default(), first.next().unwrap_or_default());
    if method != "POST" || !is_wallet_path(path) {
        return Err(Bad::Other);
    }
    // some senders give the body in chunks instead of saying its length
    if let Some(coding) = header(head, "transfer-encoding") {
        // chunks and a length at once, or another coding, is not what a wallet sends
        if !coding.trim().eq_ignore_ascii_case("chunked") || header(head, "content-length").is_some() {
            return Err(Bad::Form);
        }
        return String::from_utf8(unchunk(rest, max, false)?).map_err(|_| Bad::Form);
    }
    let n = length(head, max)?.ok_or(Bad::Form)?;
    let body = rest.get(..n).ok_or(Bad::Short)?;
    String::from_utf8(body.to_vec()).map_err(|_| Bad::Form)
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

fn unchunk(mut rest: &[u8], max: usize, ended: bool) -> Result<Vec<u8>, Bad> {
    let mut out = Vec::new();
    loop {
        let Some(at) = find(rest, b"\r\n") else {
            return Err(if ended { Bad::Form } else { Bad::Short });
        };
        let (line, after) = rest.split_at(at);
        let size = std::str::from_utf8(line).map_err(|_| Bad::Form)?;
        let size = size.split(';').next().unwrap_or_default().trim();
        let n = usize::from_str_radix(size, 16).map_err(|_| Bad::Form)?;
        if n > max || out.len().saturating_add(n) > max {
            return Err(Bad::Large);
        }
        let after = after.get(2..).unwrap_or_default();
        if n == 0 {
            return Ok(out);
        }
        let Some(piece) = after.get(..n) else {
            return Err(if ended { Bad::Form } else { Bad::Short });
        };
        out.extend_from_slice(piece);
        rest = match after.get(n.saturating_add(2)..) {
            Some(more) => more,
            None => return Err(if ended { Bad::Form } else { Bad::Short }),
        };
    }
}

/// The body of the answer to a post. `ended`: the other side has closed,
/// nothing more will come.
pub fn answer_body(data: &[u8], max: usize, ended: bool) -> Result<String, Bad> {
    let (head, rest) = match split(data) {
        Err(Bad::Short) if ended => return Err(Bad::Form),
        other => other?,
    };
    let mut first = head.lines().next().unwrap_or_default().split(' ');
    let (version, code) = (first.next().unwrap_or_default(), first.next().unwrap_or_default());
    if !version.starts_with("HTTP/1.") {
        return Err(Bad::Form);
    }
    if code != "200" {
        return Err(Bad::Other);
    }
    let body = if header(head, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        unchunk(rest, max, ended)?
    } else {
        match length(head, max)? {
            Some(n) => match rest.get(..n) {
                Some(body) => body.to_vec(),
                None => return Err(if ended { Bad::Form } else { Bad::Short }),
            },
            // no length: the body is all there is until the end
            None if !ended => return Err(if rest.len() > max { Bad::Large } else { Bad::Short }),
            None if rest.len() > max => return Err(Bad::Large),
            None => rest.to_vec(),
        }
    };
    String::from_utf8(body).map_err(|_| Bad::Form)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
        assert_eq!(answer_body(&plain, 100, false), Ok("{\"ok\":1}".to_string()));
        for cut in 0..plain.len() {
            assert_eq!(answer_body(plain.get(..cut).unwrap(), 100, false), Err(Bad::Short), "{cut}");
            // the other side closed before the answer was whole: unknown
            assert_eq!(answer_body(plain.get(..cut).unwrap(), 100, true), Err(Bad::Form), "{cut}");
        }
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"ok\r\n4;x=1\r\n\":1}\r\n0\r\n\r\n";
        assert_eq!(answer_body(chunked, 100, false), Ok("{\"ok\":1}".to_string()));
        assert_eq!(answer_body(chunked.get(..chunked.len().saturating_sub(9)).unwrap(), 100, false), Err(Bad::Short));
        let to_the_end = b"HTTP/1.0 200 OK\r\n\r\n{}";
        assert_eq!(answer_body(to_the_end, 100, false), Err(Bad::Short));
        assert_eq!(answer_body(to_the_end, 100, true), Ok("{}".to_string()));
    }

    #[test]
    fn an_answer_that_is_not_one_is_refused() {
        assert_eq!(answer_body(&refusal(Bad::Other), 100, true), Err(Bad::Other));
        assert_eq!(answer_body(b"HTTP/1.1 500 Oops\r\nContent-Length: 2\r\n\r\n{}", 100, true), Err(Bad::Other));
        assert_eq!(answer_body(b"SSH-2.0-x\r\n\r\n", 100, true), Err(Bad::Form));
        assert_eq!(answer_body(b"HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n", 100, false), Err(Bad::Large));
        assert_eq!(answer_body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n", 100, false), Err(Bad::Large));
        assert_eq!(answer_body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n40\r\n", 100, false), Err(Bad::Short));
        assert_eq!(answer_body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", 100, false), Err(Bad::Form));
        let mut long = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        long.extend(std::iter::repeat_n(b'a', 101));
        assert_eq!(answer_body(&long, 100, false), Err(Bad::Large));
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

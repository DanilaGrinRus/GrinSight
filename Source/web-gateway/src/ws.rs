//! Minimal RFC 6455 server framing + SHA-1 for the GrinSight data gateway.
//! Production TLS/WSS termination is done by a reverse proxy in front of this
//! plain-WS listener; the gateway never holds keys or verifies chain data.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4*i], chunk[4*i+1], chunk[4*i+2], chunk[4*i+3]]);
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d; d = c; c = b.rotate_left(30); b = a; a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() { out[4*i..4*i+4].copy_from_slice(&v.to_be_bytes()); }
    out
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Limits for a slow or silent client (it must not hold a slot forever).
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// Longest wait for the next frame of an open connection.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// One frame (header + payload) must arrive within this time once started.
pub const FRAME_DEADLINE: Duration = Duration::from_secs(20);

/// A reader that fails once `until` has passed: with a socket read timeout
/// this bounds the whole read, not just each `read` call (no slow drip).
pub struct Deadline<'a, R: Read> {
    pub inner: &'a mut R,
    pub until: Instant,
}

impl<R: Read> Read for Deadline<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() > self.until {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "deadline passed"));
        }
        self.inner.read(buf)
    }
}

/// Read one client frame (masked text frames only enough for JSON requests).
/// `Ok(None)`: the client closed (EOF, close frame) or sent too much.
/// The 2-byte header may arrive in pieces: it is read in full.
pub fn read_text<R: Read>(stream: &mut R) -> std::io::Result<Option<String>> {
    let mut h = [0u8; 2];
    // First byte: plain read (0 = clean EOF between frames).
    if stream.read(&mut h[..1])? == 0 { return Ok(None); }
    match stream.read_exact(&mut h[1..]) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let opcode = h[0] & 0x0f;
    if opcode == 0x8 { return Ok(None); }
    let mut len = (h[1] & 0x7f) as u64;
    if len == 126 {
        let mut b = [0u8; 2]; stream.read_exact(&mut b)?; len = u16::from_be_bytes(b) as u64;
    } else if len == 127 {
        let mut b = [0u8; 8]; stream.read_exact(&mut b)?; len = u64::from_be_bytes(b);
    }
    if len > 1024 * 1024 { return Ok(None); }
    let mut mask = [0u8; 4];
    if h[1] & 0x80 != 0 { stream.read_exact(&mut mask)?; }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;
    if h[1] & 0x80 != 0 {
        for (i, b) in payload.iter_mut().enumerate() { *b ^= mask[i % 4]; }
    }
    if opcode != 0x1 { return Ok(Some(String::new())); }
    Ok(Some(String::from_utf8_lossy(&payload).into_owned()))
}

pub fn write_text(stream: &mut TcpStream, text: &str) -> std::io::Result<()> {
    let p = text.as_bytes();
    let mut head = Vec::with_capacity(10);
    head.push(0x81);
    if p.len() < 126 { head.push(p.len() as u8); }
    else if p.len() < 65536 { head.push(126); head.extend_from_slice(&(p.len() as u16).to_be_bytes()); }
    else { head.push(127); head.extend_from_slice(&(p.len() as u64).to_be_bytes()); }
    stream.write_all(&head)?;
    stream.write_all(p)?;
    stream.flush()
}

/// Perform the HTTP Upgrade handshake. Returns false if the request is not WS.
pub fn handshake(stream: &mut TcpStream) -> std::io::Result<bool> {
    let mut req = Vec::new();
    let mut buf = [0u8; 1024];
    // The whole request must come within HANDSHAKE_DEADLINE (each read is also
    // bounded by the socket read timeout set by the caller).
    let until = Instant::now() + HANDSHAKE_DEADLINE;
    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
        if Instant::now() > until { return Ok(false); }
        let n = stream.read(&mut buf)?;
        if n == 0 || req.len() > 16 * 1024 { return Ok(false); }
        req.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&req);
    let key = text.lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("sec-websocket-key") {
                Some(value.trim().to_string())
            } else {
                None
            }
        });
    let upgrade = text.to_ascii_lowercase().contains("upgrade: websocket");
    let Some(key) = key else { return Ok(false); };
    if !upgrade { return Ok(false); }
    let accept = base64(&sha1(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()));
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Gives at most one byte per read (like a slow TCP stream).
    struct OneByte(Vec<u8>, usize);
    impl Read for OneByte {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.1 >= self.0.len() || buf.is_empty() { return Ok(0); }
            buf[0] = self.0[self.1];
            self.1 += 1;
            Ok(1)
        }
    }

    fn masked_text(s: &str) -> Vec<u8> {
        let mask = [1u8, 2, 3, 4];
        let mut f = vec![0x81, 0x80 | s.len() as u8];
        f.extend_from_slice(&mask);
        f.extend(s.bytes().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        f
    }

    #[test]
    fn frame_read_one_byte_at_a_time() {
        let mut r = OneByte(masked_text("{\"method\":\"hello\"}"), 0);
        assert_eq!(read_text(&mut r).unwrap().as_deref(), Some("{\"method\":\"hello\"}"));
        assert_eq!(read_text(&mut r).unwrap(), None, "clean EOF after the frame");
    }

    #[test]
    fn frame_cut_after_first_byte_is_eof() {
        let mut r = OneByte(vec![0x81], 0);
        assert_eq!(read_text(&mut r).unwrap(), None);
    }

    #[test]
    fn deadline_stops_a_slow_reader() {
        let mut inner = OneByte(masked_text("hello"), 0);
        let mut r = Deadline { inner: &mut inner, until: Instant::now() - Duration::from_secs(1) };
        assert_eq!(read_text(&mut r).unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn silent_client_does_not_hold_a_slot() {
        // A client connects and sends nothing: with the read timeout the
        // handshake gives up, so the connection (and its slot) is released.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let t0 = Instant::now();
        assert!(!matches!(handshake(&mut s), Ok(true)));
        assert!(t0.elapsed() < Duration::from_secs(3), "released in {:?}", t0.elapsed());
    }

    #[test]
    fn rfc6455_accept_example() {
        // RFC 6455 example key / expected accept.
        let accept = base64(&sha1(b"dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}

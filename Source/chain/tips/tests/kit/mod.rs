//! A server that listens on this computer for the length of one test and
//! answers one question over TLS, the way the test tells it to.
#![allow(dead_code)]
use fly_chain_tips::{Asker, Source};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub const HASH: &str = "00000a1b2c3d4e5f00000a1b2c3d4e5f00000a1b2c3d4e5f00000a1b2c3d4e5f";

pub fn pem(name: &str) -> (&'static [u8], &'static [u8]) {
    match name {
        "localhost" => (include_bytes!("../certs/localhost.pem"), include_bytes!("../certs/localhost.key")),
        "elsewhere" => (include_bytes!("../certs/elsewhere.pem"), include_bytes!("../certs/elsewhere.key")),
        "stranger" => (include_bytes!("../certs/stranger.pem"), include_bytes!("../certs/stranger.key")),
        "past" => (include_bytes!("../certs/past.pem"), include_bytes!("../certs/past.key")),
        other => panic!("no test certificate {other}"),
    }
}

pub fn asker() -> Asker {
    let mut roots = RootCertStore::empty();
    let ca = CertificateDer::from_pem_slice(include_bytes!("../certs/ca.pem")).unwrap();
    roots.add(ca).unwrap();
    Asker::trusting(roots).unwrap()
}

pub fn tip_json(height: u64) -> String {
    format!(
        r#"{{"id":1,"jsonrpc":"2.0","result":{{"Ok":{{"height":{height},"last_block_pushed":"{HASH}","prev_block_to_last":"{HASH}","total_difficulty":900}}}}}}"#
    )
}

/// A node's answer to `get_header`: the header at `height` with the hash
/// made of `mark` and the total work `work`.
pub fn header_json(height: u64, mark: u8, work: u64) -> String {
    let hash: String = std::iter::repeat_n(format!("{mark:02x}"), 32).collect();
    format!(
        r#"{{"id":1,"jsonrpc":"2.0","result":{{"Ok":{{"cuckoo_solution":[1,2,3],"edge_bits":32,"hash":"{hash}","height":{height},"previous":"{HASH}","timestamp":"2026-11-20T01:02:03+00:00","total_difficulty":{work},"version":5}}}}}}"#
    )
}

pub fn ok(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nDate: Mon, 23 Nov 2026 02:09:33 GMT\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// What the server does once it has read the question.
pub enum Then {
    /// Writes the bytes and closes the secure channel properly.
    Write(Vec<u8>),
    /// Writes the bytes and hangs up without closing the channel.
    Vanish(Vec<u8>),
    /// Writes the bytes one at a time with a pause before each.
    Drip(Vec<u8>, Duration),
    /// Says nothing for this long.
    Silence(Duration),
    /// Names the block `height` with the hash made of `mark` and the work
    /// `work`, and writes on the answer the time it is at that moment,
    /// `ahead` seconds off.
    Tip {
        height: u64,
        mark: u8,
        work: u64,
        ahead: i64,
    },
}

pub struct Server {
    pub at: SocketAddr,
    /// The question as the server read it, if the channel came up.
    pub asked: Receiver<Option<Vec<u8>>>,
}

pub fn serve(cert: &str, then: Then) -> Server {
    serve_after(Duration::ZERO, cert, then)
}

/// A server that takes the connection and only after `wait` starts the
/// secure channel.
pub fn serve_after(wait: Duration, cert: &str, then: Then) -> Server {
    let (chain, key) = pem(cert);
    let chain = vec![CertificateDer::from_pem_slice(chain).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(key).unwrap();
    let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let (tell, asked) = channel();
    thread::spawn(move || {
        let Ok((socket, _)) = listener.accept() else { return };
        thread::sleep(wait);
        let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
        let Ok(connection) = ServerConnection::new(config) else { return };
        let mut tls = StreamOwned::new(connection, socket);
        let mut question = Vec::new();
        let mut chunk = [0u8; 1024];
        let whole = loop {
            match tls.read(&mut chunk) {
                Ok(0) | Err(_) => break false,
                Ok(n) => question.extend_from_slice(&chunk[..n]),
            }
            if question.ends_with(br#""id":1}"#) {
                break true;
            }
        };
        let _ = tell.send(whole.then_some(question));
        if !whole {
            return;
        }
        match then {
            Then::Write(bytes) => {
                let _ = tls.write_all(&bytes);
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
            Then::Vanish(bytes) => {
                let _ = tls.write_all(&bytes);
                let _ = tls.flush();
            }
            Then::Drip(bytes, pause) => {
                for byte in bytes {
                    thread::sleep(pause);
                    if tls.write_all(&[byte]).and_then(|()| tls.flush()).is_err() {
                        return;
                    }
                }
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
            Then::Silence(long) => thread::sleep(long),
            Then::Tip {
                height,
                mark,
                work,
                ahead,
            } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let date = now.checked_add_signed(ahead).unwrap();
                let _ = tls.write_all(&says(height, mark, work, date));
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        }
    });
    Server { at, asked }
}

pub fn local(port: u16) -> Source {
    let mut source = Source::own(&format!("https://localhost:{port}")).unwrap();
    source.group = "Test".to_string();
    source
}


/// A node's answer naming the block `height` with the hash made of
/// `mark` and the work `work`, written at `date` seconds since 1970.
pub fn says(height: u64, mark: u8, work: u64, date: u64) -> Vec<u8> {
    let hash: String = std::iter::repeat_n(format!("{mark:02x}"), 32).collect();
    let body = format!(
        r#"{{"id":1,"jsonrpc":"2.0","result":{{"Ok":{{"height":{height},"last_block_pushed":"{hash}","prev_block_to_last":"{hash}","total_difficulty":{work}}}}}}}"#
    );
    let date = fly_chain_tips::date::write(date).unwrap();
    format!(
        "HTTP/1.1 200 OK\r\nDate: {date}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A source that takes every connection and hangs up at once. Returns
/// its port; it stays there for the rest of the test run, so the port is
/// nobody else's.
pub fn gone() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for connection in listener.incoming() {
            drop(connection);
        }
    });
    port
}

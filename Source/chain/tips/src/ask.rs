//! One question to one source.
//!
//! A connection is made for the one question and closed after the one
//! answer. The node is authenticated under the name it is listed by,
//! against the certificate authorities compiled into the program; nothing
//! is remembered between two questions. Everything has to happen within
//! the time the caller allows - except finding the address of the name,
//! which the system does in its own time, so a caller that cannot wait
//! asks on a thread of its own.

use crate::http::{self, Bad};
use crate::said::{self, NotSaid, Said};
use crate::source::Source;
use rustls::client::Resumption;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{CertificateError, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How the program names itself to the nodes: its name and version, the
/// same for every installation.
pub const AGENT: &str = "GrinSight-Fly/0.2";

/// How many addresses of one name are tried.
const MAX_ADDRESSES: usize = 4;

/// What one source answered.
#[derive(Debug, Clone, Copy)]
pub struct Answer {
    /// The tip the node named.
    pub said: Said,
    /// The time the server wrote on the answer, in seconds since 1970.
    pub date: Option<u64>,
    /// The moment the question was written, after the secure channel was
    /// up. The server wrote its time after this.
    pub sent: Instant,
    /// The moment the answer was read to its end. The server wrote its
    /// time before this.
    pub got: Instant,
    /// The address that answered.
    pub peer: SocketAddr,
}

/// Why there is no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The name has no address.
    Name,
    /// No address of the name took the connection.
    Connect,
    /// The server's certificate does not hold; the words say how. A clock
    /// of this computer that is far off shows up here.
    Certificate(&'static str),
    /// The secure channel failed otherwise.
    Secure,
    /// The connection broke.
    Broken,
    /// The allowed time ran out.
    Late,
    /// The server answered with another status than success.
    Status(u16),
    /// The answer is longer than is read from a stranger.
    TooLong,
    /// The answer is not what a Grin node writes; the words say where.
    Format(&'static str),
    /// The node answered that it will not or cannot say.
    Refused,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Name => write!(f, "the name has no address"),
            Failure::Connect => write!(f, "no connection"),
            Failure::Certificate(how) => write!(f, "the certificate {how}"),
            Failure::Secure => write!(f, "the secure channel failed"),
            Failure::Broken => write!(f, "the connection broke"),
            Failure::Late => write!(f, "no answer in time"),
            Failure::Status(code) => write!(f, "status {code}"),
            Failure::TooLong => write!(f, "the answer is too long"),
            Failure::Format(what) => write!(f, "not a node's answer: {what}"),
            Failure::Refused => write!(f, "the node would not say"),
        }
    }
}

/// Asks sources, authenticating them against one set of certificate
/// authorities.
#[derive(Clone)]
pub struct Asker {
    config: Arc<ClientConfig>,
}

impl Asker {
    /// An asker that trusts the certificate authorities compiled into the
    /// program.
    pub fn new() -> Result<Asker, Failure> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Asker::trusting(roots)
    }

    /// An asker that trusts the authorities whose certificates are in
    /// `pem` and no others. Nothing if there is no certificate in it or
    /// something in it is not one.
    pub fn trusting_pem(pem: &[u8]) -> Option<Asker> {
        let mut roots = RootCertStore::empty();
        let mut any = false;
        for certificate in CertificateDer::pem_slice_iter(pem) {
            roots.add(certificate.ok()?).ok()?;
            any = true;
        }
        if !any {
            return None;
        }
        Asker::trusting(roots).ok()
    }

    /// An asker that trusts the given authorities and no others.
    pub fn trusting(roots: RootCertStore) -> Result<Asker, Failure> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| Failure::Secure)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Nothing of one question is carried into the next.
        config.resumption = Resumption::disabled();
        Ok(Asker {
            config: Arc::new(config),
        })
    }

    /// Asks `source` what its tip is and waits no longer than `within`
    /// once the address of the name is known.
    pub fn ask(&self, source: &Source, within: Duration) -> Result<Answer, Failure> {
        self.ask_at(source, &addresses(source), within)
    }

    /// Asks `source` at the given addresses of its name, in their order,
    /// and waits no longer than `within` in all. Whatever the address,
    /// the node has to prove the name.
    pub fn ask_at(
        &self,
        source: &Source,
        addresses: &[SocketAddr],
        within: Duration,
    ) -> Result<Answer, Failure> {
        let heard = self.exchange(source, addresses, within, http::GET_TIP)?;
        let said = said::read(&heard.response.body).map_err(not_said)?;
        Ok(Answer {
            said,
            date: heard.response.date,
            sent: heard.sent,
            got: heard.got,
            peer: heard.peer,
        })
    }

    /// Asks `source` for the header of its chain at `height`, at the
    /// given addresses of its name and within `within` in all. An answer
    /// about another height is no answer.
    pub fn ask_header_at(
        &self,
        source: &Source,
        addresses: &[SocketAddr],
        height: u64,
        within: Duration,
    ) -> Result<Said, Failure> {
        let heard = self.exchange(source, addresses, within, &http::get_header(height))?;
        let said = said::read_header(&heard.response.body).map_err(not_said)?;
        if said.height != height {
            return Err(Failure::Format("a header of another height than asked for"));
        }
        Ok(said)
    }

    /// Posts `body` to `source` at the given addresses of its name and
    /// returns the body of an answer with the status of success. For calls
    /// other than the two questions above; what the body says is the
    /// caller's to read.
    pub fn call_at(&self, source: &Source, addresses: &[SocketAddr], body: &str, within: Duration) -> Result<Vec<u8>, Failure> {
        Ok(self.exchange(source, addresses, within, body)?.response.body)
    }

    /// One question and one answer: `body` posted to the source, the
    /// answer read to its end.
    fn exchange(
        &self,
        source: &Source,
        addresses: &[SocketAddr],
        within: Duration,
        body: &str,
    ) -> Result<Heard, Failure> {
        let name = ServerName::try_from(source.host.clone()).map_err(|_| Failure::Name)?;
        if addresses.is_empty() {
            return Err(Failure::Name);
        }
        let deadline = Instant::now().checked_add(within).ok_or(Failure::Late)?;

        let mut connected = None;
        let tried = addresses.len().min(MAX_ADDRESSES);
        for (index, address) in addresses.iter().take(MAX_ADDRESSES).enumerate() {
            let wait = share(left(deadline)?, tried.saturating_sub(index));
            if wait.is_zero() {
                return Err(Failure::Late);
            }
            if let Ok(socket) = TcpStream::connect_timeout(address, wait) {
                connected = Some((socket, *address));
                break;
            }
        }
        let Some((socket, peer)) = connected else {
            left(deadline)?;
            return Err(Failure::Connect);
        };
        let _ = socket.set_nodelay(true);

        let connection =
            ClientConnection::new(self.config.clone(), name).map_err(|_| Failure::Secure)?;
        let mut tls = StreamOwned::new(connection, socket);
        while tls.conn.is_handshaking() {
            limit(&tls.sock, deadline)?;
            tls.conn.complete_io(&mut tls.sock).map_err(|e| failure(&e))?;
        }

        let request = http::request(&source.host, source.port, &source.path, AGENT, body);
        limit(&tls.sock, deadline)?;
        let sent = Instant::now();
        tls.write_all(&request).map_err(|e| failure(&e))?;
        tls.flush().map_err(|e| failure(&e))?;

        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        let response = loop {
            limit(&tls.sock, deadline)?;
            let ended = match tls.read(&mut chunk) {
                Ok(0) => true,
                Ok(n) => {
                    bytes.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    false
                }
                // A server that hangs up without saying so has still
                // ended its answer; a cut answer does not parse.
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => true,
                Err(e) => return Err(failure(&e)),
            };
            match http::parse(&bytes, ended) {
                Ok(Some(response)) => break response,
                Ok(None) if ended => return Err(Failure::Format("the answer is cut short")),
                Ok(None) => {}
                Err(Bad::TooLong) => return Err(Failure::TooLong),
                Err(Bad::Format(what)) => return Err(Failure::Format(what)),
            }
        };
        let got = Instant::now();
        if response.status != 200 {
            return Err(Failure::Status(response.status));
        }
        Ok(Heard {
            response,
            sent,
            got,
            peer,
        })
    }
}

/// An answer with a good status, not yet read for what it says.
struct Heard {
    response: http::Response,
    sent: Instant,
    got: Instant,
    peer: SocketAddr,
}

fn not_said(e: NotSaid) -> Failure {
    match e {
        NotSaid::Refused => Failure::Refused,
        NotSaid::Format(what) => Failure::Format(what),
    }
}

/// The addresses of a source's name as the system gives them, those of
/// IPv4 first: the networks in the list were recorded from them, and an
/// IPv6 route that leads nowhere is the commoner trouble. Nothing if the
/// name has no address. The system takes its own time over this.
pub fn addresses(source: &Source) -> Vec<SocketAddr> {
    let found = (source.host.as_str(), source.port)
        .to_socket_addrs()
        .map(Iterator::collect)
        .unwrap_or_default();
    v4_first(found)
}

/// The same addresses, those of IPv4 before those of IPv6, each kind in
/// the order it came in.
pub fn v4_first(mut addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addresses.sort_by_key(SocketAddr::is_ipv6);
    addresses
}

/// How long one address may be waited for when `left` is left for it and
/// the `remaining` addresses after it, itself included: an address that
/// does not answer must not take the time of the others.
pub fn share(left: Duration, remaining: usize) -> Duration {
    let parts = u32::try_from(remaining).unwrap_or(u32::MAX).max(1);
    left.checked_div(parts).unwrap_or(left)
}

/// The time left until `deadline`, or the failure of having none.
fn left(deadline: Instant) -> Result<Duration, Failure> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Failure::Late);
    }
    Ok(left)
}

/// Lets the next read or write on `socket` take no longer than until
/// `deadline`.
fn limit(socket: &TcpStream, deadline: Instant) -> Result<(), Failure> {
    let left = left(deadline)?;
    socket
        .set_read_timeout(Some(left))
        .and_then(|()| socket.set_write_timeout(Some(left)))
        .map_err(|_| Failure::Broken)
}

fn failure(error: &io::Error) -> Failure {
    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
        return Failure::Late;
    }
    let tls = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    match tls {
        Some(rustls::Error::InvalidCertificate(why)) => Failure::Certificate(match why {
            CertificateError::Expired
            | CertificateError::ExpiredContext { .. }
            | CertificateError::NotValidYet
            | CertificateError::NotValidYetContext { .. } => "is not valid at this computer's time",
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "is for another name"
            }
            CertificateError::UnknownIssuer => "is from an authority the program does not know",
            _ => "does not hold",
        }),
        Some(_) => Failure::Secure,
        None => Failure::Broken,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn addresses_of_ipv4_come_first() {
        let at = |text: &str| -> SocketAddr { text.parse().unwrap() };
        let mixed = vec![at("[::1]:443"), at("10.0.0.1:443"), at("[2a01::1]:443"), at("10.0.0.2:443")];
        assert_eq!(
            v4_first(mixed),
            [at("10.0.0.1:443"), at("10.0.0.2:443"), at("[::1]:443"), at("[2a01::1]:443")]
        );
        assert_eq!(v4_first(Vec::new()), []);
        assert_eq!(v4_first(vec![at("[::1]:1")]), [at("[::1]:1")]);
    }

    #[test]
    fn the_time_is_shared_among_the_addresses_left() {
        let minute = Duration::from_secs(60);
        assert_eq!(share(minute, 4), Duration::from_secs(15));
        assert_eq!(share(minute, 2), Duration::from_secs(30));
        // The last address has all that is left, and so has an only one.
        assert_eq!(share(minute, 1), minute);
        assert_eq!(share(minute, 0), minute);
        assert_eq!(share(Duration::ZERO, 3), Duration::ZERO);
    }
}

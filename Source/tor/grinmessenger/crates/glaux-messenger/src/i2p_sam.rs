//! Experimental local SAM 3.1 client. Not a complete Glaux transport.
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use zeroize::Zeroizing;

const LIMIT: usize = 8192;
const TIMEOUT: Duration = Duration::from_secs(10);

fn token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~=+".contains(&b))
}

fn line(stream: &mut TcpStream) -> io::Result<String> {
    let mut data = Vec::new();
    loop {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b)?;
        if b[0] == b'\n' { break; }
        if b[0] == b'\r' || data.len() >= LIMIT { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SAM response")); }
        data.push(b[0]);
    }
    String::from_utf8(data).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SAM response"))
}

fn command(stream: &mut TcpStream, cmd: &str, expected: &str) -> io::Result<String> {
    stream.write_all(cmd.as_bytes())?;
    stream.write_all(b"\n")?;
    let response = line(stream)?;
    let mut fields = response.split_ascii_whitespace();
    let a = fields.next(); let b = fields.next();
    let mut expected = expected.split_ascii_whitespace();
    if a != expected.next() || b != expected.next() || !fields.any(|f| f == "RESULT=OK") {
        return Err(io::Error::new(io::ErrorKind::Other, "SAM request rejected"));
    }
    Ok(response)
}

fn local(addr: SocketAddr) -> io::Result<TcpStream> {
    if !matches!(addr.ip(), IpAddr::V4(a) if a.is_loopback()) && !matches!(addr.ip(), IpAddr::V6(a) if a.is_loopback()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "SAM must be local"));
    }
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    command(&mut stream, "HELLO VERSION MIN=3.1 MAX=3.1", "HELLO REPLY")?;
    Ok(stream)
}

/// Holds the SAM control connection alive. `destination` is a private key; callers
/// must store it safely and must never log it. This prototype does not store it.
pub struct Session { _control: TcpStream, addr: SocketAddr, id: String }

impl Session {
    pub fn create(addr: SocketAddr, id: &str, destination: &str) -> io::Result<Self> {
        if !token(id) || !(destination == "TRANSIENT" || token(destination)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid SAM parameter"));
        }
        let mut control = local(addr)?;
        // Routers may need to establish tunnels before acknowledging a session.
        control.set_read_timeout(Some(Duration::from_secs(90)))?;
        let request = Zeroizing::new(format!("SESSION CREATE STYLE=STREAM ID={id} DESTINATION={destination} SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4,0"));
        command(&mut control, &request, "SESSION STATUS")?;
        control.set_read_timeout(Some(TIMEOUT))?;
        Ok(Self { _control: control, addr, id: id.to_owned() })
    }

    pub fn connect(&self, destination: &str) -> io::Result<TcpStream> {
        if !token(destination) { return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid I2P destination")); }
        let mut stream = local(self.addr)?;
        command(&mut stream, &format!("STREAM CONNECT ID={} DESTINATION={} SILENT=false", self.id, destination), "STREAM STATUS")?;
        Ok(stream)
    }

    /// Wait for an incoming stream. The returned peer destination is not a
    /// verified Glaux identity; callers must verify a signed binding.
    pub fn accept(&self) -> io::Result<(TcpStream, String)> {
        self.accept_timeout(Duration::from_secs(150))
    }

    /// Bounded accept allows the owner to stop the listener when a wallet locks.
    pub fn accept_timeout(&self, timeout: Duration) -> io::Result<(TcpStream, String)> {
        let mut stream = local(self.addr)?;
        stream.set_read_timeout(Some(timeout))?;
        command(&mut stream, &format!("STREAM ACCEPT ID={} SILENT=false", self.id), "STREAM STATUS")?;
        let peer = line(&mut stream)?;
        if !token(&peer) { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid peer destination")); }
        stream.set_read_timeout(Some(TIMEOUT))?;
        Ok((stream, peer))
    }
}

/// Opaque destination keypair. Intentionally implements neither Debug nor
/// Display so private keys are not accidentally printed with diagnostics.
pub struct Destination { public: String, private: Zeroizing<String> }
impl Destination {
    pub fn generate(addr: SocketAddr) -> io::Result<Self> {
        let mut stream = local(addr)?;
        stream.write_all(b"DEST GENERATE SIGNATURE_TYPE=7\n")?;
        let reply = Zeroizing::new(line(&mut stream)?);
        let mut fields = reply.split_ascii_whitespace();
        if fields.next() != Some("DEST") || fields.next() != Some("REPLY") {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SAM destination response"));
        }
        let mut public = None; let mut private = None;
        for field in fields {
            if let Some(value) = field.strip_prefix("PUB=") { public = Some(value); }
            if let Some(value) = field.strip_prefix("PRIV=") { private = Some(value); }
        }
        match (public, private) {
            (Some(a), Some(b)) if token(a) && token(b) => Ok(Self { public: a.into(), private: Zeroizing::new(b.into()) }),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SAM destination response")),
        }
    }
    pub fn public(&self) -> &str { &self.public }
    /// Import only from authenticated, encrypted storage belonging to the
    /// current profile. This function does not authenticate a peer binding.
    pub fn from_saved(public: &str, private: &str) -> io::Result<Self> {
        if !token(public) || !token(private) || private == "TRANSIENT" {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid saved I2P destination"));
        }
        Ok(Self { public: public.to_owned(), private: Zeroizing::new(private.to_owned()) })
    }
    /// Only expose this value to authenticated encrypted storage. Never log it.
    pub fn private_for_storage(&self) -> Zeroizing<String> { Zeroizing::new(self.private.to_string()) }
    pub fn open_session(&self, addr: SocketAddr, id: &str) -> io::Result<Session> { Session::create(addr, id, &self.private) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    fn read_line(s: &mut TcpStream) -> String { line(s).unwrap() }
    #[test]
    fn creates_session_and_connects_without_losing_first_payload_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            assert!(read_line(&mut c).starts_with("HELLO VERSION"));
            c.write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n").unwrap();
            assert!(read_line(&mut c).contains("SESSION CREATE STYLE=STREAM"));
            c.write_all(b"SESSION STATUS RESULT=OK\n").unwrap();
            let (mut d, _) = listener.accept().unwrap();
            assert!(read_line(&mut d).starts_with("HELLO VERSION"));
            d.write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n").unwrap();
            assert!(read_line(&mut d).contains("STREAM CONNECT"));
            d.write_all(b"STREAM STATUS RESULT=OK\nhello").unwrap();
        });
        let s = Session::create(addr, "alice", "TRANSIENT").unwrap();
        let mut d = s.connect("testdestination").unwrap();
        let mut payload = [0; 5]; d.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"hello"); worker.join().unwrap();
    }
    #[test]
    fn rejects_remote_and_injection_without_connecting() {
        let remote = "192.0.2.1:7656".parse().unwrap();
        assert!(Session::create(remote, "alice", "TRANSIENT").is_err());
        let local = "127.0.0.1:7656".parse().unwrap();
        assert!(Session::create(local, "bad\ncommand", "TRANSIENT").is_err());
    }
    #[test]
    fn incoming_stream_preserves_payload_and_requires_valid_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            read_line(&mut c); c.write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n").unwrap();
            read_line(&mut c); c.write_all(b"SESSION STATUS RESULT=OK\n").unwrap();
            let (mut d, _) = listener.accept().unwrap();
            read_line(&mut d); d.write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n").unwrap();
            assert!(read_line(&mut d).contains("STREAM ACCEPT"));
            d.write_all(b"STREAM STATUS RESULT=OK\npeer-destination\nhello").unwrap();
        });
        let s = Session::create(addr, "alice", "TRANSIENT").unwrap();
        let (mut d, peer) = s.accept().unwrap();
        let mut payload = [0; 5]; d.read_exact(&mut payload).unwrap();
        assert_eq!(peer, "peer-destination"); assert_eq!(&payload, b"hello"); worker.join().unwrap();
    }
}

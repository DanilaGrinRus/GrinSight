//! How this program reaches the network.
//!
//! On a computer: the system's own connections and names. In a page
//! (the web wallet) there is neither; both go through the gateway
//! (`fly-web-dial`), and what comes back is an ordinary stream, read and
//! checked by the same code.
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// The most addresses taken for one name.
const MAX_FOUND: usize = 8;

/// A connection to `to`, waited for no longer than `within`.
#[cfg(not(target_os = "emscripten"))]
pub fn connect(to: &SocketAddr, within: Duration) -> io::Result<TcpStream> {
    TcpStream::connect_timeout(to, within)
}

/// A connection to `to`, waited for no longer than `within`.
#[cfg(target_os = "emscripten")]
pub fn connect(to: &SocketAddr, within: Duration) -> io::Result<TcpStream> {
    fly_web_dial::connect(to, within)
}

/// Addresses of `text`, which is `host:port` or `host`; a name without a
/// port gets `default_port`. Nothing if there are none.
#[cfg(not(target_os = "emscripten"))]
pub fn lookup(text: &str, default_port: Option<u16>) -> Vec<SocketAddr> {
    use std::net::ToSocketAddrs;
    let found = match (text.to_socket_addrs(), default_port) {
        (Ok(addrs), _) => addrs.collect(),
        (Err(_), Some(port)) => (text, port).to_socket_addrs().map(Iterator::collect).unwrap_or_default(),
        (Err(_), None) => Vec::new(),
    };
    let mut found: Vec<SocketAddr> = found;
    found.truncate(MAX_FOUND);
    found
}

/// Addresses of `text`, which is `host:port` or `host`; a name without a
/// port gets `default_port`. Nothing if there are none. An address written
/// out is taken as it is; a name is looked up by the gateway.
#[cfg(target_os = "emscripten")]
pub fn lookup(text: &str, default_port: Option<u16>) -> Vec<SocketAddr> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return vec![addr];
    }
    let (host, port) = split(text, default_port);
    let Some(port) = port else {
        return Vec::new();
    };
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![SocketAddr::new(ip, port)];
    }
    let mut found: Vec<SocketAddr> = fly_web_dial::lookup(host)
        .unwrap_or_default()
        .into_iter()
        .map(|ip| SocketAddr::new(ip.into(), port))
        .collect();
    found.truncate(MAX_FOUND);
    found
}

/// `host:port` taken apart; a text without a usable port gets `default_port`.
#[cfg_attr(not(any(target_os = "emscripten", test)), allow(dead_code))]
fn split(text: &str, default_port: Option<u16>) -> (&str, Option<u16>) {
    match text.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => match port.parse::<u16>() {
            Ok(port) => (host, Some(port)),
            Err(_) => (text, None),
        },
        _ => (text, default_port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name with a port keeps it, a name without one gets the given one,
    /// and what is neither is not guessed at.
    #[test]
    fn a_name_and_its_port_are_taken_apart() {
        assert_eq!(split("seed.example:3414", Some(1)), ("seed.example", Some(3414)));
        assert_eq!(split("seed.example", Some(3414)), ("seed.example", Some(3414)));
        assert_eq!(split("seed.example", None), ("seed.example", None));
        assert_eq!(split("seed.example:port", Some(3414)), ("seed.example:port", None));
        assert_eq!(split("seed.example:70000", Some(3414)), ("seed.example:70000", None));
        assert_eq!(split(":3414", Some(1)), (":3414", Some(1)));
        // an IPv6 address written without brackets is not a name with a port
        assert_eq!(split("2001:db8::1", Some(3414)), ("2001:db8::1", Some(3414)));
    }

    /// On a computer an address written out comes back as it is.
    #[test]
    fn an_address_written_out_is_itself() {
        assert_eq!(lookup("127.0.0.1:3414", None), vec!["127.0.0.1:3414".parse::<SocketAddr>().unwrap_or_else(|_| unreachable!())]);
        assert_eq!(lookup("127.0.0.1", Some(13414)), vec!["127.0.0.1:13414".parse::<SocketAddr>().unwrap_or_else(|_| unreachable!())]);
        assert!(lookup("127.0.0.1", None).is_empty());
    }
}

//! Connections of the web wallet.
//!
//! A page has no TCP. The wallet's module keeps its connections at the
//! gateway and reaches them over one WebSocket (`bridge.c`, linked into the
//! module); here they become ordinary [`TcpStream`]s, so that the network
//! code of the node reads and writes them as it does on a computer.
//!
//! Three things differ from a computer and are done here instead of by the
//! standard library: making a connection (the standard library marks a new
//! socket in the module's own table of files, where a socket of the gateway
//! is not), holding one connection twice (the standard library has no such
//! thing for WebAssembly), and looking a name up (the gateway does it; the
//! module's own C library invents addresses).
//!
//! `unsafe` is confined to the calls into `bridge.c` and to handing a
//! descriptor to the standard library; each is marked.
#![cfg(target_os = "emscripten")]
#![deny(
    unsafe_op_in_unsafe_fn,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

use std::ffi::{c_char, c_int, CString};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Duration;

extern "C" {
    fn fly_bridge_open(url: *const c_char) -> c_int;
    fn fly_bridge_state() -> c_int;
    fn fly_dial(ip: *const u8, port: u16, wait_ms: u32) -> c_int;
    fn fly_dup(fd: c_int) -> c_int;
    fn fly_resolve(name: *const c_char, out: *mut u8, room: c_int) -> c_int;
}

/// The most addresses taken for one name.
pub const MAX_ADDRESSES: usize = 8;

/// How the module stands with the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// There is no connection to it.
    None,
    /// One is being made.
    Connecting,
    /// It answers.
    Open,
}

/// Begin connecting to the gateway at `url` (`ws://` or `wss://`). Does not
/// wait; does nothing while a connection is there or being made - unless the
/// making has gone unanswered for ten seconds: then it is given up and begun
/// anew. Whoever keeps the connection calls this again and again while
/// [`gate`] is not [`Gate::Open`].
pub fn open(url: &str) -> Result<(), String> {
    let url = CString::new(url).map_err(|_| "the gateway address is not text".to_string())?;
    // SAFETY: a text ending in a zero byte that lives through the call; the
    // callee copies nothing but what it reads before returning.
    if unsafe { fly_bridge_open(url.as_ptr()) } != 0 {
        return Err("no connection to the gateway could be begun".to_string());
    }
    Ok(())
}

/// How the module stands with the gateway now.
pub fn gate() -> Gate {
    // SAFETY: takes nothing, returns a number.
    match unsafe { fly_bridge_state() } {
        2 => Gate::Open,
        1 => Gate::Connecting,
        _ => Gate::None,
    }
}

/// A connection to `to` through the gateway, waited for no longer than
/// `within`. Only IPv4: the gateway carries nothing else.
pub fn connect(to: &SocketAddr, within: Duration) -> io::Result<TcpStream> {
    let SocketAddr::V4(to) = to else {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "only IPv4 goes through the gateway"));
    };
    let ip = to.ip().octets();
    let wait = u32::try_from(within.as_millis()).unwrap_or(u32::MAX).min(120_000);
    // SAFETY: `ip` is four readable bytes for the length of the call.
    let fd = unsafe { fly_dial(ip.as_ptr(), to.port(), wait) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor the bridge has just made for this caller alone;
    // the stream is its only holder and closes it when dropped.
    Ok(unsafe { TcpStream::from_raw_fd(fd) })
}

/// The same connection held once more, for a second thread. It is closed
/// when both holders have dropped it.
pub fn again(stream: &TcpStream) -> io::Result<TcpStream> {
    // SAFETY: a number in, a number out; a descriptor that is not the
    // bridge's is refused there.
    let fd = unsafe { fly_dup(stream.as_raw_fd()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the bridge counts this holder; its close gives the count back.
    Ok(unsafe { TcpStream::from_raw_fd(fd) })
}

/// The public IPv4 addresses the gateway finds for `name`.
pub fn lookup(name: &str) -> io::Result<Vec<Ipv4Addr>> {
    let name = CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a name"))?;
    let mut found = [0u8; MAX_ADDRESSES * 4];
    let room = c_int::try_from(MAX_ADDRESSES).unwrap_or(1);
    // SAFETY: `name` ends in a zero byte; `found` has room for `room`
    // addresses of four bytes and the callee writes no more.
    let count = unsafe { fly_resolve(name.as_ptr(), found.as_mut_ptr(), room) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let count = usize::try_from(count).unwrap_or(0).min(MAX_ADDRESSES);
    Ok(found
        .chunks_exact(4)
        .take(count)
        .filter_map(|b| <[u8; 4]>::try_from(b).ok())
        .map(Ipv4Addr::from)
        .collect())
}

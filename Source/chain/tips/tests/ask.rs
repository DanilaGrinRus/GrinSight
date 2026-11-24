//! Asking a node over TLS, against a server that listens on this computer
//! for the length of one test: what is sent, what is taken for an answer,
//! who can answer for a name, how long the asker waits and how much it
//! reads.
mod kit;

use fly_chain_tips::ask::AGENT;
use fly_chain_tips::http::{self, MAX_BODY};
use fly_chain_tips::{Asker, Failure};
use kit::{asker, local, ok, serve, serve_after, tip_json, Server, Then};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

fn ask(server: &Server, within: Duration) -> Result<fly_chain_tips::Answer, Failure> {
    asker().ask_at(&local(server.at.port()), &[server.at], within)
}

const SOON: Duration = Duration::from_secs(10);

#[test]
fn a_node_says_what_its_tip_is() {
    let server = serve("localhost", Then::Write(ok(&tip_json(4_118_377))));
    let before = Instant::now();
    let answer = ask(&server, SOON).unwrap();
    let after = Instant::now();
    assert_eq!(answer.said.height, 4_118_377);
    assert_eq!(answer.said.total_difficulty, 900);
    assert_eq!(answer.said.hash[..4], [0, 0, 0x0a, 0x1b]);
    assert_eq!(answer.date, Some(1_795_399_773));
    assert_eq!(answer.peer, server.at);
    // The server wrote its time between these two moments.
    assert!(before <= answer.sent && answer.sent <= answer.got && answer.got <= after);

    // What went out names the program and nothing else about the asker.
    let asked = server.asked.recv().unwrap().unwrap();
    let port = server.at.port();
    assert_eq!(
        asked,
        http::request("localhost", port, "/v2/foreign", AGENT, http::GET_TIP)
    );
    assert_eq!(AGENT, "GrinSight-Fly/0.2");
}

#[test]
fn the_time_of_an_answer_is_bracketed_without_the_handshake() {
    // The server is slow to start the channel and quick to answer. The
    // moment "sent" is taken when the channel is up, so the slowness is
    // not between the two moments the server's time is known to lie in.
    let slow = Duration::from_millis(1500);
    let server = serve_after(slow, "localhost", Then::Write(ok(&tip_json(5))));
    let started = Instant::now();
    let answer = ask(&server, SOON).unwrap();
    assert!(started.elapsed() >= slow);
    assert!(answer.got.duration_since(answer.sent) < Duration::from_millis(1000));
}

#[test]
fn the_name_is_found_by_the_system_too() {
    let server = serve("localhost", Then::Write(ok(&tip_json(7))));
    let answer = asker().ask(&local(server.at.port()), SOON).unwrap();
    assert_eq!(answer.said.height, 7);
}

#[test]
fn an_answer_in_chunks_and_a_server_that_just_hangs_up() {
    let body = tip_json(12);
    let (a, b) = body.split_at(40);
    let chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
        a.len(),
        b.len()
    );
    let server = serve("localhost", Then::Vanish(chunked.into_bytes()));
    let answer = ask(&server, SOON).unwrap();
    assert_eq!((answer.said.height, answer.date), (12, None));

    // Without a length the answer ends where the connection does.
    let open = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
    let server = serve("localhost", Then::Vanish(open.into_bytes()));
    assert_eq!(ask(&server, SOON).unwrap().said.height, 12);

    // Cut anywhere, it is no answer.
    let cut = format!("HTTP/1.1 200 OK\r\n\r\n{}", &body[..body.len() - 9]);
    let server = serve("localhost", Then::Vanish(cut.into_bytes()));
    assert!(matches!(ask(&server, SOON), Err(Failure::Format(_))));
    let cut = ok(&body);
    let server = serve("localhost", Then::Vanish(cut[..cut.len() - 9].to_vec()));
    assert!(matches!(ask(&server, SOON), Err(Failure::Format(_))));
}

#[test]
fn nobody_else_answers_for_a_name() {
    // The right name from an authority the asker does not trust.
    let server = serve("stranger", Then::Write(ok(&tip_json(1))));
    assert_eq!(
        ask(&server, SOON).err(),
        Some(Failure::Certificate("is from an authority the program does not know"))
    );
    assert_eq!(server.asked.recv().ok().flatten(), None);

    // A trusted authority's certificate for another name.
    let server = serve("elsewhere", Then::Write(ok(&tip_json(1))));
    assert_eq!(
        ask(&server, SOON).err(),
        Some(Failure::Certificate("is for another name"))
    );
    assert_eq!(server.asked.recv().ok().flatten(), None);

    // The right name and authority, but the certificate has ended.
    let server = serve("past", Then::Write(ok(&tip_json(1))));
    assert_eq!(
        ask(&server, SOON).err(),
        Some(Failure::Certificate("is not valid at this computer's time"))
    );
    assert_eq!(server.asked.recv().ok().flatten(), None);

    // An asker with the compiled-in authorities does not know the tests'.
    let server = serve("localhost", Then::Write(ok(&tip_json(1))));
    let public = Asker::new().unwrap();
    assert!(matches!(
        public.ask_at(&local(server.at.port()), &[server.at], SOON),
        Err(Failure::Certificate(_))
    ));
}

#[test]
fn authorities_from_a_file() {
    // The tests' own authority, read from its file, is trusted like the
    // one handed over in memory - and nothing else is.
    let from_file = Asker::trusting_pem(include_bytes!("certs/ca.pem")).unwrap();
    let server = serve("localhost", Then::Write(ok(&tip_json(9))));
    assert_eq!(from_file.ask_at(&local(server.at.port()), &[server.at], SOON).unwrap().said.height, 9);
    let server = serve("stranger", Then::Write(ok(&tip_json(9))));
    assert!(matches!(
        from_file.ask_at(&local(server.at.port()), &[server.at], SOON),
        Err(Failure::Certificate(_))
    ));
    // A file without a certificate, or with something that is not one.
    assert!(Asker::trusting_pem(b"").is_none());
    assert!(Asker::trusting_pem(include_bytes!("certs/localhost.key")).is_none());
    let broken = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    assert!(Asker::trusting_pem(broken).is_none());
}

#[test]
fn a_server_that_does_not_speak_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else { return };
        let mut some = [0u8; 64];
        let _ = socket.read(&mut some);
        let _ = socket.write_all(&ok(&tip_json(1)));
        thread::sleep(Duration::from_millis(300));
    });
    assert_eq!(
        asker().ask_at(&local(at.port()), &[at], SOON).err(),
        Some(Failure::Secure)
    );
}

#[test]
fn no_longer_than_allowed() {
    let within = Duration::from_millis(700);
    let slack = Duration::from_secs(3);

    // A server that takes the connection and never starts the channel.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let held = thread::spawn(move || {
        let socket = listener.accept().map(|(socket, _)| socket);
        thread::sleep(Duration::from_secs(4));
        drop(socket);
    });
    let started = Instant::now();
    assert_eq!(asker().ask_at(&local(at.port()), &[at], within).err(), Some(Failure::Late));
    assert!(started.elapsed() >= within && started.elapsed() < slack);

    // One that reads the question and says nothing.
    let server = serve("localhost", Then::Silence(Duration::from_secs(4)));
    let started = Instant::now();
    assert_eq!(ask(&server, within).err(), Some(Failure::Late));
    assert!(started.elapsed() >= within && started.elapsed() < slack);

    // One that keeps writing, a byte now and then: every read succeeds
    // in time, the answer as a whole does not.
    let server = serve(
        "localhost",
        Then::Drip(ok(&tip_json(1)), Duration::from_millis(50)),
    );
    let started = Instant::now();
    assert_eq!(ask(&server, within).err(), Some(Failure::Late));
    assert!(started.elapsed() >= within && started.elapsed() < slack);

    // No time at all is no question at all.
    let server = serve("localhost", Then::Write(ok(&tip_json(1))));
    assert_eq!(ask(&server, Duration::ZERO).err(), Some(Failure::Late));
    drop(held);
}

#[test]
fn no_more_than_is_read_from_a_stranger() {
    let endless = format!("HTTP/1.1 200 OK\r\n\r\n{}", "a".repeat(MAX_BODY * 4));
    let server = serve("localhost", Then::Write(endless.into_bytes()));
    assert_eq!(ask(&server, SOON).err(), Some(Failure::TooLong));

    let announced = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
    let server = serve("localhost", Then::Write(announced.into_bytes()));
    assert_eq!(ask(&server, SOON).err(), Some(Failure::TooLong));

    let header = format!("HTTP/1.1 200 OK\r\nX-Filler: {}\r\n\r\n", "a".repeat(64 * 1024));
    let server = serve("localhost", Then::Write(header.into_bytes()));
    assert_eq!(ask(&server, SOON).err(), Some(Failure::TooLong));
}

#[test]
fn answers_that_are_not_a_tip() {
    let busy = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy".to_vec();
    let server = serve("localhost", Then::Write(busy));
    assert_eq!(ask(&server, SOON).err(), Some(Failure::Status(503)));

    // A success that carries a tip is still not taken under another status.
    let moved = String::from_utf8(ok(&tip_json(1))).unwrap().replace("200 OK", "203 Other");
    let server = serve("localhost", Then::Write(moved.into_bytes()));
    assert_eq!(ask(&server, SOON).err(), Some(Failure::Status(203)));

    let refused = ok(r#"{"id":1,"jsonrpc":"2.0","result":{"Err":{"Internal":"syncing"}}}"#);
    let server = serve("localhost", Then::Write(refused));
    assert_eq!(ask(&server, SOON).err(), Some(Failure::Refused));

    let page = ok("<html>welcome</html>");
    let server = serve("localhost", Then::Write(page));
    assert_eq!(ask(&server, SOON).err(), Some(Failure::Format("the body is not JSON")));

    let noise = b"SSH-2.0-OpenSSH\r\n".to_vec();
    let server = serve("localhost", Then::Write(noise));
    assert!(matches!(ask(&server, SOON), Err(Failure::Format(_))));
}

#[test]
fn nobody_there() {
    // A port nobody listens on.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    drop(listener);
    assert_eq!(asker().ask_at(&local(at.port()), &[at], SOON).err(), Some(Failure::Connect));
    // The second address is tried when the first refuses.
    let server = serve("localhost", Then::Write(ok(&tip_json(3))));
    let answer = asker()
        .ask_at(&local(server.at.port()), &[at, server.at], SOON)
        .unwrap();
    assert_eq!((answer.said.height, answer.peer), (3, server.at));
    // No address, and a name that is not one.
    assert_eq!(asker().ask_at(&local(at.port()), &[], SOON).err(), Some(Failure::Name));
    let mut odd = local(at.port());
    odd.host = "not a name".to_string();
    assert_eq!(asker().ask_at(&odd, &[at], SOON).err(), Some(Failure::Name));
    assert_eq!(asker().ask(&odd, SOON).err(), Some(Failure::Name));
    let _ = TcpStream::connect_timeout(&at, Duration::from_millis(10));
}

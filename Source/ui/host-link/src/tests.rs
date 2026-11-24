#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use super::*;
use std::io::{pipe, BufRead, BufReader, Write};
use std::sync::mpsc;

/// A fake host on the other end of two pipes: it hands each request line to
/// `answer`, which writes whatever it wants back.
fn fake(answer: impl Fn(Value, &mut dyn Write) + Send + 'static) -> (Arc<Client>, mpsc::Receiver<Value>, mpsc::Receiver<Vec<u8>>) {
    let (to_host_r, to_host_w) = pipe().unwrap();
    let (from_host_r, mut from_host_w) = pipe().unwrap();
    let (raw_tx, raw_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut lines = BufReader::new(to_host_r);
        let mut line = Vec::new();
        while lines.read_until(b'\n', &mut line).unwrap_or(0) > 0 {
            let _ = raw_tx.send(line.clone());
            if let Ok(v) = serde_json::from_slice::<Value>(&line) {
                answer(v, &mut from_host_w);
                let _ = from_host_w.flush();
            }
            line.clear();
        }
    });
    let (note_tx, note_rx) = mpsc::channel();
    let client = Client::start(Box::new(from_host_r), Box::new(to_host_w), Box::new(move |n| {
        let _ = note_tx.send(n);
    }));
    (client, note_rx, raw_rx)
}

fn reply(w: &mut dyn Write, id: &Value, result: Value) {
    writeln!(w, "{}", json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap();
}

const WAIT: Duration = Duration::from_secs(5);

#[test]
fn an_answer_reaches_its_call_and_a_note_goes_to_the_callback() {
    let (client, notes, _) = fake(|req, w| {
        writeln!(w, "{}", json!({"jsonrpc":"2.0","method":"paycore.event","params":{"source":"chain"}})).unwrap();
        reply(w, &req["id"], json!({"method": req["method"]}));
    });
    let got = client.call("host.status", json!({}), WAIT).unwrap();
    assert_eq!(got["method"], "host.status");
    let note = notes.recv_timeout(WAIT).unwrap();
    assert_eq!(note["method"], "paycore.event");
}

#[test]
fn answers_out_of_order_find_their_calls() {
    // The host holds the first answer until the second request comes.
    let held = Arc::new(Mutex::new(None::<Value>));
    let (client, _, _) = fake(move |req, w| {
        let mut h = held.lock().unwrap();
        match h.take() {
            None => *h = Some(req["id"].clone()),
            Some(first) => {
                reply(w, &req["id"], json!("second"));
                reply(w, &first, json!("first"));
            }
        }
    });
    let c = client.clone();
    let a = std::thread::spawn(move || c.call("a", json!({}), WAIT));
    std::thread::sleep(Duration::from_millis(100));
    let b = client.call("b", json!({}), WAIT);
    assert_eq!(b.unwrap(), json!("second"));
    assert_eq!(a.join().unwrap().unwrap(), json!("first"));
}

#[test]
fn an_error_is_named() {
    let (client, _, _) = fake(|req, w| {
        writeln!(w, "{}", json!({"jsonrpc":"2.0","id":req["id"],"error":{"code":-32043,"message":"wrong password"}})).unwrap();
    });
    let err = client.call("host.unlock", json!({}), WAIT).unwrap_err();
    assert_eq!(err, CallError::Rpc { code: -32043, name: "wrong_password".into(), message: "wrong password".into() });
}

/// The wallet's own reason for a refusal reaches the window, so that it
/// can say what to do; an empty reason leaves the message.
#[test]
fn the_reason_of_a_refusal_is_kept() {
    let (client, _, _) = fake(|req, w| {
        let reason = if req["method"] == "with" { "Tor is not ready yet" } else { "" };
        writeln!(w, "{}", json!({"jsonrpc":"2.0","id":req["id"],"error":{"code":-32011,"message":"refused","data":{"kind":"refused","reason":reason}}})).unwrap();
    });
    let err = client.call("with", json!({}), WAIT).unwrap_err();
    assert_eq!(err, CallError::Rpc { code: -32011, name: "refused".into(), message: "Tor is not ready yet".into() });
    let err = client.call("without", json!({}), WAIT).unwrap_err();
    assert_eq!(err, CallError::Rpc { code: -32011, name: "refused".into(), message: "refused".into() });
}

#[test]
fn no_answer_is_a_timeout_and_a_late_answer_is_dropped() {
    let (client, _, _) = fake(|req, w| {
        std::thread::sleep(Duration::from_millis(300));
        reply(w, &req["id"], json!("late"));
    });
    assert_eq!(client.call("slow", json!({}), Duration::from_millis(50)), Err(CallError::Timeout));
    // The next call gets its own answer, not the late one.
    assert_eq!(client.call("next", json!({}), WAIT).unwrap(), json!("late"));
    assert!(client.pending.lock().unwrap().is_empty());
}

#[test]
fn when_the_host_goes_every_waiting_call_ends() {
    let (to_host_r, to_host_w) = pipe().unwrap();
    let (from_host_r, from_host_w) = pipe().unwrap();
    let client = Client::start(Box::new(from_host_r), Box::new(to_host_w), Box::new(|_| {}));
    let c = client.clone();
    let waiting = std::thread::spawn(move || c.call("x", json!({}), WAIT));
    std::thread::sleep(Duration::from_millis(100));
    drop(from_host_w); // the host's output ends
    assert_eq!(waiting.join().unwrap(), Err(CallError::Gone));
    drop(to_host_r);
    assert_eq!(client.call("y", json!({}), WAIT), Err(CallError::Gone));
}

#[test]
fn a_line_too_long_is_skipped_and_reading_goes_on() {
    let (client, _, _) = fake(|req, w| {
        let junk = "x".repeat(MAX_LINE + 10);
        writeln!(w, "{{\"id\":{},\"result\":\"{junk}\"}}", req["id"]).unwrap();
        reply(w, &req["id"], json!("ok"));
    });
    assert_eq!(client.call("big", json!({}), WAIT).unwrap(), json!("ok"));
}

#[test]
fn several_secrets_go_in_one_proper_line() {
    let (client, _, raw) = fake(|req, w| {
        reply(w, &req["id"], req["params"].clone());
    });
    let words = "abandon \"ability\" able\u{0}";
    let pass = "p,a:s}s";
    let got = client
        .call_secrets("host.profile.restore", json!({"network": "main", "mnemonic": "not this"}), &[("password", pass), ("mnemonic", words)], WAIT)
        .unwrap();
    assert_eq!(got, json!({"network": "main", "password": pass, "mnemonic": words}));
    let got = client.call_secrets("x", json!(null), &[("a", "1"), ("b", "2")], WAIT).unwrap();
    assert_eq!(got, json!({"a": "1", "b": "2"}));
    let got = client.call_secrets("x", json!({}), &[], WAIT).unwrap();
    assert_eq!(got, json!({}));
    for _ in 0..3 {
        let line = raw.recv_timeout(WAIT).unwrap();
        let _: Value = serde_json::from_slice(&line).unwrap();
        assert!(line.ends_with(b"\n") && !line[..line.len() - 1].contains(&b'\n'), "one line");
    }
}

#[test]
fn a_password_goes_as_a_proper_json_string() {
    let (client, _, raw) = fake(|req, w| {
        reply(w, &req["id"], req["params"].clone());
    });
    let tricky = "pa\"ss\\word\n€";
    let got = client.call_secret("host.unlock", json!(null), "password", tricky, WAIT).unwrap();
    assert_eq!(got, json!({"password": tricky}));
    let got = client.call_secret("host.profile.create", json!({"network": "test", "password": "not this"}), "password", tricky, WAIT).unwrap();
    assert_eq!(got, json!({"network": "test", "password": tricky}));
    let line = raw.recv_timeout(WAIT).unwrap();
    let _second = raw.recv_timeout(WAIT).unwrap();
    let parsed: Value = serde_json::from_slice(&line).unwrap();
    assert_eq!(parsed["method"], "host.unlock");
    assert_eq!(parsed["jsonrpc"], "2.0");
    assert!(line.ends_with(b"\n") && !line[..line.len() - 1].contains(&b'\n'), "one line");
}

#[test]
fn host_error_names_follow_the_readme() {
    for (code, name) in [(-32040, "locked"), (-32041, "no_profile"), (-32043, "wrong_password"), (-32050, "busy")] {
        assert_eq!(host_error_name(code), name);
    }
    assert_eq!(host_error_name(-1), "");
}


/// A host kept by another process: the window talks over a connected stream,
/// and letting go of it closes the connection, not the host.
#[cfg(unix)]
#[test]
fn a_host_kept_elsewhere_is_attached_and_left_running() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;
    let (ours, theirs) = UnixStream::pair().unwrap();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut w = theirs.try_clone().unwrap();
        let mut lines = BufReader::new(theirs).lines();
        while let Some(Ok(line)) = lines.next() {
            let req: Value = serde_json::from_str(&line).unwrap();
            writeln!(w, "{}", json!({"jsonrpc": "2.0", "id": req["id"], "result": {"profile": "unlocked"}})).unwrap();
        }
        // the window let go: the stream ends, and the host is still here
        closed_tx.send(()).unwrap();
    });
    let host = Host::attach(ours, Box::new(|_| {})).unwrap();
    let client = host.client();
    assert_eq!(client.call("host.status", json!({}), WAIT).unwrap()["profile"], "unlocked");
    drop(client);
    drop(host);
    closed_rx.recv_timeout(WAIT).expect("the connection was not closed");
}

#[test]
fn service_identity_is_checked_before_creating_the_rpc_client() {
    use std::io::{Error, ErrorKind};
    let mut attached = 0;
    for peer in [Ok(200), Err(Error::from(ErrorKind::NotConnected))] {
        let result = with_service_peer(peer, 100, || { attached += 1; Ok(()) });
        assert!(result.is_err());
    }
    assert_eq!(attached, 0);
    assert!(with_service_peer(Ok(100), 100, || { attached += 1; Ok(()) }).is_ok());
    assert_eq!(attached, 1);
}

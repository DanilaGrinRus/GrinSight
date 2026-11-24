//! Asking public nodes for the header at one height, against servers that
//! listen on this computer for the length of one test.
mod kit;

use fly_chain_tips::ask::AGENT;
use fly_chain_tips::http;
use fly_chain_tips::point::{ask_all, judge, Asked, Verdict, Voice};
use fly_chain_tips::{Failure, Said, Source};
use kit::{asker, gone, header_json, local, ok, serve, tip_json, Server, Then};
use std::time::{Duration, Instant};

const SOON: Duration = Duration::from_secs(10);

fn ask(server: &Server, height: u64) -> Result<Said, Failure> {
    asker().ask_header_at(&local(server.at.port()), &[server.at], height, SOON)
}

#[test]
fn a_node_names_the_header_at_a_height() {
    let server = serve("localhost", Then::Write(ok(&header_json(4_114_380, 0x5a, 901))));
    let said = ask(&server, 4_114_380).unwrap();
    assert_eq!((said.height, said.hash, said.total_difficulty), (4_114_380, [0x5a; 32], 901));
    // the question names the height and nothing about the asker
    let asked = server.asked.recv().unwrap().unwrap();
    let body = r#"{"jsonrpc":"2.0","method":"get_header","params":[4114380,null,null],"id":1}"#;
    assert_eq!(http::get_header(4_114_380), body);
    assert_eq!(asked, http::request("localhost", server.at.port(), "/v2/foreign", AGENT, body));
}

#[test]
fn what_is_not_an_answer_about_the_height() {
    // the header of another height, even the next one
    for other in [4_114_381u64, 4_114_379, 0] {
        let server = serve("localhost", Then::Write(ok(&header_json(other, 1, 900))));
        assert_eq!(ask(&server, 4_114_380), Err(Failure::Format("a header of another height than asked for")));
    }
    // an answer about the tip
    let server = serve("localhost", Then::Write(ok(&tip_json(4_114_380))));
    assert_eq!(ask(&server, 4_114_380), Err(Failure::Format("the hash")));
    // a node that does not have the header
    let none = r#"{"id":1,"jsonrpc":"2.0","result":{"Err":"NotFound"}}"#;
    let server = serve("localhost", Then::Write(ok(none)));
    assert_eq!(ask(&server, 4_114_380), Err(Failure::Refused));
    // a server that is not the one named
    let server = serve("elsewhere", Then::Write(ok(&header_json(4_114_380, 1, 900))));
    assert!(matches!(ask(&server, 4_114_380), Err(Failure::Certificate(_))));
}

fn listed(port: u16, group: &str, asn: u32) -> Source {
    let mut source = local(port);
    source.group = group.to_string();
    source.asn = Some(asn);
    source
}

const ASKED: Asked = Asked {
    height: 4_114_380,
    hash: [0x5a; 32],
    work: 901,
};

#[test]
fn a_list_is_asked_and_counted() {
    let same = || serve("localhost", Then::Write(ok(&header_json(4_114_380, 0x5a, 901))));
    let (one, two, three) = (same(), same(), serve("localhost", Then::Silence(Duration::from_secs(3))));
    let sources = vec![
        listed(one.at.port(), "One", 1),
        listed(two.at.port(), "Two", 2),
        listed(three.at.port(), "Three", 3),
        listed(gone(), "Four", 4),
    ];
    let started = Instant::now();
    let voices = ask_all(&asker(), &sources, ASKED, Duration::from_millis(1500));
    // the silent one is waited for no longer than the limit and a little
    assert!(started.elapsed() < Duration::from_millis(3400), "{:?}", started.elapsed());
    assert_eq!(voices[..2], [Voice::Same, Voice::Same]);
    assert_eq!(voices[2], Voice::Silent(Failure::Late));
    assert!(matches!(voices[3], Voice::Silent(Failure::Broken | Failure::Secure | Failure::Connect)), "{:?}", voices[3]);
    assert_eq!(judge(&sources, &voices), Verdict::Confirmed { by: vec![0, 1] });
}

#[test]
fn one_node_on_another_chain_stops_it() {
    let same = || serve("localhost", Then::Write(ok(&header_json(4_114_380, 0x5a, 901))));
    let (one, two) = (same(), same());
    // the same height and work, another block
    let three = serve("localhost", Then::Write(ok(&header_json(4_114_380, 0x5b, 901))));
    let sources = vec![listed(one.at.port(), "One", 1), listed(two.at.port(), "Two", 2), listed(three.at.port(), "Three", 3)];
    let voices = ask_all(&asker(), &sources, ASKED, SOON);
    let other = Said {
        height: 4_114_380,
        hash: [0x5b; 32],
        total_difficulty: 901,
    };
    assert_eq!(voices, vec![Voice::Same, Voice::Same, Voice::Other(other)]);
    assert_eq!(judge(&sources, &voices), Verdict::Differs { who: vec![2] });
}

#[test]
fn two_nodes_of_one_network_are_not_enough() {
    let same = || serve("localhost", Then::Write(ok(&header_json(4_114_380, 0x5a, 901))));
    let (one, two) = (same(), same());
    let sources = vec![listed(one.at.port(), "One", 7), listed(two.at.port(), "Two", 7), listed(gone(), "Three", 3)];
    let voices = ask_all(&asker(), &sources, ASKED, SOON);
    assert_eq!(voices[..2], [Voice::Same, Voice::Same]);
    assert_eq!(judge(&sources, &voices), Verdict::TooFew { same: 2 });
    // nobody to ask
    assert!(ask_all(&asker(), &[], ASKED, SOON).is_empty());
}

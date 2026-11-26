//! What the wallet process is told.
//!
//! Until the state is collected and blocks have been applied to it, the
//! chain process has no fact about any block to hand over, and it says so
//! in the terms of the port: no verified state, the next step unknown.
//! After that it answers from the blocks it has applied: the block after
//! the wallet's position, how far to go back, or where to start over. It
//! answers "nothing new" only when it stands at the tip of the verified
//! header chain and no connected node claims more.
//!
//! The tip is called *selected* only when the blocks stand at the tip of
//! the verified headers and the asking of public nodes allows it
//! (`accept`); the confirmed time is the one taken from their answers.
//! Whatever is selected is marked provisional while the starting point is
//! one nobody vouches for (a development point), or while a claim of more
//! work went unsettled not long ago. A release point and a point the user
//! gave are vouched for by the maker of the release and by the user.
use crate::adapter::Event;
use crate::node::{SharedView, View};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::time::Duration;
use fly_paycore_chain_port::{plain_problem, ChainFeed, Level, OldOutputs, Posted, Status, Step, Tip, Unknown};

/// Confirmations asked for; the norm of the project.
const K_CONF: u64 = 10;

/// How long an answer about the next step is waited for.
const ANSWER_WITHIN: Duration = Duration::from_secs(5);

/// The chain process as the wallet's side of the pipe sees it.
pub struct Feed {
    view: SharedView,
    events: SyncSender<Event>,
}

impl Feed {
    /// A feed that reads the node's view and asks the node's thread.
    pub fn new(view: SharedView, events: SyncSender<Event>) -> Feed {
        Feed { view, events }
    }
    fn view(&self) -> View {
        match self.view.lock() {
            Ok(view) => view.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// The node's state in words.
pub fn describe(view: &View) -> String {
    if let Some(failed) = &view.failed {
        return failed.clone();
    }
    if !view.ready {
        return "verifying the stored headers".to_string();
    }
    // what the user has to know first: the text is cut short
    let mut text = view.unsent.as_ref().map(|unsent| format!("{unsent}; ")).unwrap_or_default();
    text.push_str(&format!("headers verified to {} from a {} ({})", view.height, view.point.note(), view.start));
    match &view.state {
        // once blocks are applied, the state they were applied to goes
        // without saying: the text has to stay short
        Some(state) if state.complete && view.blocks.is_some() => {}
        Some(state) if state.complete => {
            text.push_str(&format!("; the state at {} is collected and checked", state.height));
        }
        Some(state) => {
            text.push_str(&format!("; collecting the state at {}: {} of {} pieces", state.height, state.done, state.segments));
        }
        None => {}
    }
    match &view.blocks {
        Some(blocks) if blocks.at_tip => text.push_str(&format!("; blocks applied to the tip, {}", blocks.height)),
        Some(blocks) => text.push_str(&format!("; blocks applied to {}", blocks.height)),
        None => text.push_str("; no block has been applied yet"),
    }
    if view.selection().0 {
        text.push_str("; the tip is confirmed by public nodes");
        if view.caveat {
            text.push_str(", with a caveat: a claim of more work went unsettled not long ago");
        }
    } else if let Some(why) = &view.unselected {
        text.push_str("; ");
        text.push_str(why);
    }
    match (&view.problem, view.caught_up) {
        (Some(problem), _) => {
            text.push_str("; ");
            text.push_str(problem);
        }
        (None, false) if view.best_seen > view.height => {
            text.push_str(&format!("; nodes are at about {}", view.best_seen));
        }
        _ => {}
    }
    if let Some(signs) = &view.signs {
        text.push_str("; signs: ");
        text.push_str(signs);
    }
    // K202: the history before the point goes last, in short words: the
    // text is cut at 240 characters, and what is cut must never be the
    // tip or a transaction that is not sent
    if let Some(history) = view.history {
        text.push_str("; ");
        text.push_str(history);
    }
    text
}

impl Feed {
    /// A finished transaction to the node's thread; `direct`: with the
    /// owner's agreement to the direct way for this one (K192).
    fn hand_over(&mut self, tx: &[u8], direct: bool) -> Posted {
        // no answer in time is "unknown", never "refused"
        let (reply, answer) = sync_channel(1);
        if self.events.try_send(Event::Post { tx: tx.to_vec(), direct, reply }).is_err() {
            return Posted::Unknown;
        }
        answer.recv_timeout(ANSWER_WITHIN).unwrap_or(Posted::Unknown)
    }
    fn ask_old(&mut self, piece: u64, since: Option<Tip>) -> Result<OldOutputs, Unknown> {
        let (reply, answer) = sync_channel(1);
        self.events.try_send(Event::AskOld { piece, since, reply }).map_err(|_| Unknown)?;
        answer.recv_timeout(ANSWER_WITHIN).map_err(|_| Unknown)?
    }
}

impl ChainFeed for Feed {
    fn status(&mut self) -> Option<Status> {
        let view = self.view();
        let blocks = view.blocks.clone();
        let (selected, confirmed_time) = view.selection();
        Some(Status {
            level: match &blocks {
                Some(blocks) if blocks.at_tip => Level::AtTip,
                Some(_) => Level::Behind,
                None => Level::Unknown,
            },
            tip: blocks.as_ref().map(|blocks| Tip {
                height: blocks.height,
                hash: blocks.hash,
            }),
            // the wallet stands on blocks: a tip is named selected only
            // when the blocks have reached the selected tip of the headers
            selected: blocks
                .as_ref()
                .filter(|blocks| blocks.at_tip && selected && blocks.height == view.height && blocks.hash == view.hash)
                .map(|blocks| Tip {
                    height: blocks.height,
                    hash: blocks.hash,
                }),
            confirmed_time,
            k_conf: K_CONF,
            // the range proofs handed over are those the headers commit to
            rangeproofs_authenticated: blocks.is_some(),
            // nobody vouches for a development point
            provisional: view.point.provisional() || view.caveat,
        })
    }
    fn next(&mut self, at: Option<Tip>) -> Result<Step, Unknown> {
        let (reply, answer) = sync_channel(1);
        self.events.try_send(Event::Ask { at, reply }).map_err(|_| Unknown)?;
        answer.recv_timeout(ANSWER_WITHIN).map_err(|_| Unknown)?
    }
    fn post(&mut self, tx: &[u8]) -> Posted {
        self.hand_over(tx, false)
    }
    fn post_direct(&mut self, tx: &[u8]) -> Posted {
        self.hand_over(tx, true)
    }
    fn problem(&mut self) -> Option<String> {
        Some(plain_problem(&describe(&self.view())))
    }
    fn old_outputs(&mut self, piece: u64) -> Result<OldOutputs, Unknown> {
        self.ask_old(piece, None)
    }
    fn old_outputs_since(&mut self, piece: u64, since: Tip) -> Result<OldOutputs, Unknown> {
        self.ask_old(piece, Some(since))
    }
    /// K188: a point is made only of a chain whose tip the wallet is told
    /// is selected, and not provisionally. What is asked of the node's
    /// thread is the record alone; the decision is made here, from the
    /// same view the wallet's status is made from.
    fn set_tor(&mut self, off: bool) -> bool {
        let (reply, answer) = sync_channel(1);
        if self.events.try_send(Event::Tor { off, reply }).is_err() {
            return false;
        }
        answer.recv_timeout(ANSWER_WITHIN).unwrap_or(false)
    }
    fn point(&mut self) -> Result<Vec<u8>, String> {
        let status = self.status();
        match status {
            Some(status) if status.selected.is_some() && !status.provisional => {}
            Some(status) if status.selected.is_some() => return Err(POINT_PROVISIONAL.to_string()),
            _ => return Err(POINT_UNSELECTED.to_string()),
        }
        let (reply, answer) = sync_channel(1);
        self.events.try_send(Event::Point { reply }).map_err(|_| POINT_BUSY.to_string())?;
        answer.recv_timeout(ANSWER_WITHIN).map_err(|_| POINT_BUSY.to_string())?
    }
}

/// Why no starting point is made while the tip is not selected.
pub const POINT_UNSELECTED: &str = "a starting point is made only when the tip is confirmed by public nodes; it is not yet";
/// Why none is made on top of what nobody vouches for.
pub const POINT_PROVISIONAL: &str = "a starting point is not made while what is confirmed is provisional: nobody vouches for the point this program started from, or a claim of more work went unsettled not long ago";
/// The node's thread did not take the question or did not answer in time.
pub const POINT_BUSY: &str = "the chain process is busy; ask again in a moment";

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// K202: what the build knows of the history before its starting
    /// point is said last, after everything else, and a build without the
    /// proof says what it always said; in the longest text the program
    /// makes, the tip is still within the 240 characters.
    #[test]
    fn the_history_before_the_start_is_said_last() {
        let plain = View { ready: true, height: 9, start: 4, ..View::default() };
        let said = describe(&plain);
        assert!(!said.contains("history:"), "{said}");
        for words in [crate::node::HISTORY_SAMPLED, crate::node::HISTORY_EXTENDED, crate::node::HISTORY_OTHER_POINT, crate::node::HISTORY_REFUSED] {
            let with = describe(&View { history: Some(words), ..plain.clone() });
            assert_eq!(with, format!("{said}; {words}"));
            assert!(words.starts_with("history: ") && words.len() <= 40);
        }
        // while the stored headers are still verified, nothing is said of it yet
        assert_eq!(describe(&View { history: Some(crate::node::HISTORY_SAMPLED), ..View::default() }), "verifying the stored headers");
    }
    use crate::node::BlocksView;
    use std::sync::{Arc, Mutex};

    fn status(view: View) -> Status {
        let (events, _inbox) = sync_channel(1);
        Feed::new(Arc::new(Mutex::new(view)), events).status().unwrap()
    }

    /// K100: arriving blocks alone cannot replace a confirmed clock.
    #[test]
    fn wallet_selection_requires_a_current_confirmed_clock() {
        let view = View {
            ready: true,
            selected: true,
            caught_up: true,
            height: 101,
            hash: [7; 32],
            blocks: Some(BlocksView {
                at_tip: true,
                height: 101,
                hash: [7; 32],
                ..BlocksView::default()
            }),
            ..View::default()
        };
        let told = status(view);
        assert_eq!(told.confirmed_time, None);
        assert_eq!(told.selected, None);
        assert_eq!(told.tip, Some(Tip { height: 101, hash: [7; 32] }));
    }

    /// The wallet stands on blocks. A header whose block cannot be applied
    /// (one that names sizes its block does not have, for instance: the
    /// header rules cannot see that, the state refuses the block) may
    /// become the tip of the verified headers and even be allowed by the
    /// asking of public nodes, as a tip built on a confirmed one. The
    /// wallet is not told of a selected tip then: neither the header's,
    /// which it has no block for, nor the last block's, which is not the
    /// tip.
    #[test]
    fn a_header_without_its_block_is_never_the_wallets_selected_tip() {
        let header = (101u64, [7u8; 32]);
        let below = BlocksView {
            height: 100,
            hash: [6; 32],
            at_tip: false,
            ..BlocksView::default()
        };
        let now_ms = crate::node::clock_ms();
        let view = View {
            clock: Some(fly_chain_tips::time::Time {
                at: std::time::Instant::now(), low_ms: now_ms, high_ms: now_ms,
            }),
            ready: true,
            height: header.0,
            hash: header.1,
            caught_up: true,
            selected: true,
            blocks: Some(below.clone()),
            ..View::default()
        };
        let told = status(view.clone());
        assert_eq!(told.selected, None);
        assert_eq!(told.level, Level::Behind);
        assert_eq!(told.tip, Some(Tip { height: 100, hash: [6; 32] }));

        // not even if the blocks were said to be at the tip: the block
        // named has to be the header selected
        let claimed = View {
            blocks: Some(BlocksView { at_tip: true, ..below }),
            ..view.clone()
        };
        assert_eq!(status(claimed).selected, None);

        // nor while a connected node names more work than is verified
        let more_named = View {
            blocks: Some(BlocksView {
                height: header.0,
                hash: header.1,
                at_tip: false,
                ..BlocksView::default()
            }),
            ..view.clone()
        };
        assert_eq!(status(more_named).selected, None);

        // the block of the selected header applied: selected
        let applied = View {
            blocks: Some(BlocksView {
                height: header.0,
                hash: header.1,
                at_tip: true,
                ..BlocksView::default()
            }),
            ..view.clone()
        };
        assert_eq!(status(applied).selected, Some(Tip { height: 101, hash: [7; 32] }));

        // the blocks at the tip of the headers, the asking not through
        let unasked = View {
            selected: false,
            blocks: Some(BlocksView {
                height: header.0,
                hash: header.1,
                at_tip: true,
                ..BlocksView::default()
            }),
            ..view
        };
        assert_eq!(status(unasked).selected, None);
    }

    /// K188: the node's thread is asked for the record of a starting
    /// point only while the wallet is told of a selected tip that is not
    /// provisional; otherwise the reason is given and nothing is asked.
    /// No answer from the thread is "busy", never a point.
    #[test]
    fn a_starting_point_is_made_only_of_a_selected_tip_that_is_vouched_for() {
        let now_ms = crate::node::clock_ms();
        let good = View {
            clock: Some(fly_chain_tips::time::Time {
                at: std::time::Instant::now(), low_ms: now_ms, high_ms: now_ms,
            }),
            ready: true,
            height: 101,
            hash: [7; 32],
            caught_up: true,
            selected: true,
            point: crate::PointKind::Release,
            blocks: Some(BlocksView {
                height: 101,
                hash: [7; 32],
                at_tip: true,
                ..BlocksView::default()
            }),
            ..View::default()
        };
        // what the thread is asked, and what comes of its answer
        let ask = |view: View, answers: bool| -> (Result<Vec<u8>, String>, bool) {
            let (events, inbox) = sync_channel(1);
            let mut feed = Feed::new(Arc::new(Mutex::new(view)), events);
            let node = std::thread::spawn(move || match inbox.recv_timeout(Duration::from_millis(300)) {
                Ok(Event::Point { reply }) => {
                    if answers {
                        let _ = reply.try_send(Ok(b"record".to_vec()));
                    } else {
                        std::thread::sleep(ANSWER_WITHIN + Duration::from_millis(300));
                    }
                    true
                }
                _ => false,
            });
            let got = feed.point();
            (got, node.join().unwrap())
        };
        assert_eq!(ask(good.clone(), true), (Ok(b"record".to_vec()), true));
        let own = View { point: crate::PointKind::Own, ..good.clone() };
        assert_eq!(ask(own, true), (Ok(b"record".to_vec()), true));

        let provisional = Err(POINT_PROVISIONAL.to_string());
        let development = View { point: crate::PointKind::Development, ..good.clone() };
        assert_eq!(ask(development, true), (provisional.clone(), false));
        let caveat = View { caveat: true, ..good.clone() };
        assert_eq!(ask(caveat, true), (provisional, false));

        let unselected = Err(POINT_UNSELECTED.to_string());
        let unasked = View { selected: false, ..good.clone() };
        assert_eq!(ask(unasked, true), (unselected.clone(), false));
        let no_time = View { clock: None, ..good.clone() };
        assert_eq!(ask(no_time, true), (unselected.clone(), false));
        let behind = View {
            blocks: Some(BlocksView { height: 100, hash: [6; 32], at_tip: false, ..BlocksView::default() }),
            ..good.clone()
        };
        assert_eq!(ask(behind, true), (unselected.clone(), false));
        let no_blocks = View { blocks: None, ..good.clone() };
        assert_eq!(ask(no_blocks, true), (unselected, false));

        // the thread took the question and said nothing
        assert_eq!(ask(good.clone(), false), (Err(POINT_BUSY.to_string()), true));
        // the thread has no room for the question
        let (events, _inbox) = sync_channel(1);
        events.try_send(Event::Heard { kernels: Vec::new() }).unwrap();
        let mut feed = Feed::new(Arc::new(Mutex::new(good)), events);
        assert_eq!(feed.point(), Err(POINT_BUSY.to_string()));
    }
}

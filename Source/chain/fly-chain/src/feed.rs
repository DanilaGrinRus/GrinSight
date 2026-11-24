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
    text
}

impl Feed {
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
        // no answer in time is "unknown", never "refused"
        let (reply, answer) = sync_channel(1);
        if self.events.try_send(Event::Post { tx: tx.to_vec(), reply }).is_err() {
            return Posted::Unknown;
        }
        answer.recv_timeout(ANSWER_WITHIN).unwrap_or(Posted::Unknown)
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
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
}

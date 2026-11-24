//! Stand-in transport process for the two-process test (feature "stub").
fn main() {
    fly_paycore_mailbox_pipe::stub::run();
}

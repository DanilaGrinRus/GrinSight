//! Stand-in chain process for the tests of the host (feature "test-chain").
fn main() {
    fly_paycore_bridge::chain_pipe::stub::run();
}

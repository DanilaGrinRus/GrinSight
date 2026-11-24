//! Stand-in Tor process for the tests of the host (feature "test-chain").
fn main() {
    fly_paycore_bridge::onion_pipe::stub::run();
}

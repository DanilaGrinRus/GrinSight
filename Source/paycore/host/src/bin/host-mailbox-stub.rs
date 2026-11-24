//! Stand-in transport process for the tests of the host (feature "test-chain").
fn main() {
    fly_paycore_bridge::pipe::stub::run();
}

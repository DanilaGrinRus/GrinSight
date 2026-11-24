//! The wallet process of GrinSight. See the crate documentation.
#![forbid(unsafe_code)]
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = fly_paycore_host::run(
        fly_paycore_host::Setup::product(),
        &args,
        std::io::stdin().lock(),
        std::io::stdout(),
    );
    ExitCode::from(code)
}

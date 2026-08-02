//! Adapter-enabled `rem-daemon` entrypoint.

use std::process::ExitCode;

fn main() -> ExitCode {
    match remanence_adaptors::registry() {
        Ok(registry) => remanence_daemon::main_entry_with_registry(registry),
        Err(error) => {
            eprintln!("error: assemble foreign-format registry: {error}");
            ExitCode::from(1)
        }
    }
}

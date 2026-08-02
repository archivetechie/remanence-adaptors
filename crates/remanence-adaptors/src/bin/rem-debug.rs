//! Adapter-enabled `rem-debug` entrypoint.

use std::process::ExitCode;

fn main() -> ExitCode {
    match remanence_adaptors::registry() {
        Ok(registry) => remanence_cli::debug_main_entry_with_registry(registry),
        Err(error) => {
            eprintln!("error: assemble foreign-format registry: {error}");
            ExitCode::from(1)
        }
    }
}

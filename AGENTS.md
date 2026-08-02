# Agent conventions

Read `CLAUDE.md` before changing this repository.

Every change must finish with:

1. `cargo test --workspace`
2. `cargo fmt --all --check`
3. `cargo clippy --workspace --all-targets -- -D warnings`
4. `cargo build --release`
5. a descriptive commit and a clean working tree

Tests must fail loudly when a required subject or fixture is unavailable; do
not turn a skip into a passing test. Concrete adapters remain read-only, and
the distribution registry must list every adapter explicitly.

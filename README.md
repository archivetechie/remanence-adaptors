# Remanence adaptors

Auxiliary, read-only foreign-format adapters and adapter-enabled binaries for
[Remanence](https://github.com/archivetechie/remanence).

This is a separate project with its own releases. It is not part of the
Remanence core distribution. Core Remanence defines the normalized reader and
registry contract but deliberately ships no concrete foreign-format parser.
This repository is where selected parsers and the binaries that link them are
assembled.

## Included adapter

`remanence-bru` reads BRU and BRU-PE archives created by our discontinued
legacy application. It was developed from surviving tapes and dump files after
the original software was no longer available. The adapter can probe, scan,
restore, and recover from seekable dumps or physical tape records. It does not
write BRU archives.

The stable catalog format ID is `remanence-bru`; the CLI alias is `bru`.

## Build

Rust 1.88+ and the Protocol Buffers compiler (`protoc`) on Linux:

```sh
cargo build --release
```

The build produces `target/release/{rem,rem-debug,rem-daemon}`. These are the
normal Remanence entrypoints with this repository's adapter registry linked in.
They are intended to replace, not run alongside, binaries of the same name
from a core-only build.

For example, against a dump file:

```sh
target/release/rem archive probe --format bru --dump archive.bru
target/release/rem archive scan --format bru --dump archive.bru
target/release/rem archive restore --format bru --dump archive.bru --dest restored
```

Direct physical-tape commands remain on the break-glass CLI and require the
same explicit library allowlist as core Remanence:

```sh
target/release/rem-debug --allow <LIBRARY> archive scan \
  --format bru --tape <LIBRARY> --bay <BAY> --rewind
```

## Repository layout

```text
crates/remanence-bru       BRU/BRU-PE parser and normalized reader
crates/remanence-adaptors  registry assembly and rem/rem-debug/rem-daemon binaries
```

Adding another format means adding its parser crate and one explicit registry
entry in the distribution crate. There is no runtime loading of arbitrary
native-code plugins.

## Verification

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

Adapter output should be treated as migration input: verify restored files and
retain the source media until the destination system's own integrity checks
have completed.

## License

Source code is licensed under Apache License 2.0. See
[LICENSE-APACHE-2.0](LICENSE-APACHE-2.0).

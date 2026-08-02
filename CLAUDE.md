# Repository model

This public repository is the auxiliary foreign-format side of Remanence. It
contains concrete read-only parsers and a small distribution crate that links
them into the generic registry owned by core Remanence.

Keep these boundaries intact:

- No foreign-format parser moves back into the Remanence core workspace.
- Adapters may probe and read; they do not write their foreign format.
- Stable format IDs are catalog contracts. Do not rename one casually.
- The registry is compile-time and explicit; do not add runtime native-code
  plugin loading.
- Core dependencies are pinned to a reviewed Remanence commit before release.

Work directly on `main`, run the gates in `AGENTS.md`, and commit every finished
change. GitHub actions and commits must use the `archivetechie` identity.

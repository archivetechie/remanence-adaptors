//! End-to-end checks for the adapter-enabled CLI distribution.

use std::collections::BTreeMap;
use std::process::{Command, Output};

use base64::Engine as _;

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().expect("create fixture directory");
    let path = temp.path().join("minimal.bru");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(include_str!("../../../fixtures/minimal.bru.b64").trim())
        .expect("decode checked-in BRU fixture");
    std::fs::write(&path, bytes).expect("write BRU fixture");
    (temp, path)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rem"))
        .args(args)
        .output()
        .expect("run adapter-enabled rem")
}

fn successful_stdout(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout).expect("command output is utf-8")
}

fn key_value_lines(output: &str) -> BTreeMap<&str, &str> {
    output
        .lines()
        .map(|line| line.split_once(": ").expect("key/value report line"))
        .collect()
}

#[test]
fn distribution_registers_stable_id_and_alias() {
    let registry = remanence_adaptors::registry().expect("assemble registry");

    assert_eq!(registry.len(), 1);
    assert_eq!(registry.get("bru").unwrap().id(), "remanence-bru");
    assert_eq!(registry.get("remanence-bru").unwrap().id(), "remanence-bru");
}

#[test]
fn adapter_enabled_cli_reports_the_exact_linked_registry() {
    let output = successful_stdout(run(&["archive", "formats"]));
    let value: serde_json::Value = serde_json::from_str(&output).expect("formats JSON");

    assert_eq!(
        value,
        serde_json::json!({
            "foreign_formats": [{
                "id": "remanence-bru",
                "version": "0.1",
                "aliases": ["bru"],
                "sources": ["physical-tape-records", "byte-stream-dump"]
            }]
        })
    );
}

#[test]
fn adapter_enabled_cli_probes_scans_and_restores_dump() {
    let (temp, dump) = fixture();
    let dump = dump.to_str().expect("fixture path is utf-8");

    let probe = run(&["archive", "probe", "--format", "bru", "--dump", dump]);
    let probe_out = successful_stdout(probe);
    assert_eq!(
        key_value_lines(&probe_out),
        BTreeMap::from([
            ("confidence", "certain"),
            ("format", "remanence-bru"),
            ("source", "byte-stream-dump"),
        ])
    );

    let scan = run(&["archive", "scan", "--format", "bru", "--dump", dump]);
    let scan_out = successful_stdout(scan);
    let scan_lines = scan_out.lines().collect::<Vec<_>>();
    assert_eq!(scan_lines.len(), 4);
    let scan_header = scan_lines[..3].join("\n");
    assert_eq!(
        key_value_lines(&scan_header),
        BTreeMap::from([
            ("archive-gaps", "0"),
            ("damage-events", "0"),
            ("entries", "1"),
        ])
    );
    assert_eq!(scan_lines[3], "bru:1\tregular\t3\tcamera/a.txt");

    let restore_dir = temp.path().join("restore");
    let restore = run(&[
        "archive",
        "restore",
        "--format",
        "bru",
        "--dump",
        dump,
        "--dest",
        restore_dir.to_str().expect("restore path is utf-8"),
    ]);
    let restore_out = successful_stdout(restore);
    assert_eq!(
        key_value_lines(&restore_out),
        BTreeMap::from([
            ("applied_privileged_xattrs", "{}"),
            ("archive-gaps", "0"),
            ("bytes-written", "3"),
            ("damage-events", "0"),
            ("directories-seen", "0"),
            ("entries", "1"),
            ("files-written", "1"),
            ("skipped_xattrs", "{}"),
        ])
    );
    assert_eq!(
        std::fs::read(restore_dir.join("camera/a.txt")).expect("read restored file"),
        b"abc"
    );
}

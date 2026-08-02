//! End-to-end checks for the adapter-enabled CLI distribution.

use std::process::Command;

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

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rem"))
        .args(args)
        .output()
        .expect("run adapter-enabled rem")
}

#[test]
fn distribution_registers_stable_id_and_alias() {
    let registry = remanence_adaptors::registry().expect("assemble registry");

    assert_eq!(registry.len(), 1);
    assert_eq!(registry.get("bru").unwrap().id(), "remanence-bru");
    assert_eq!(registry.get("remanence-bru").unwrap().id(), "remanence-bru");
}

#[test]
fn adapter_enabled_cli_probes_scans_and_restores_dump() {
    let (temp, dump) = fixture();
    let dump = dump.to_str().expect("fixture path is utf-8");

    let probe = run(&["archive", "probe", "--format", "bru", "--dump", dump]);
    assert!(
        probe.status.success(),
        "{}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let probe_out = String::from_utf8(probe.stdout).expect("probe output is utf-8");
    assert!(probe_out.contains("format: remanence-bru"));
    assert!(probe_out.contains("confidence: certain"));

    let scan = run(&["archive", "scan", "--format", "bru", "--dump", dump]);
    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let scan_out = String::from_utf8(scan.stdout).expect("scan output is utf-8");
    assert!(scan_out.contains("entries: 1"));
    assert!(scan_out.contains("bru:1"));
    assert!(scan_out.contains("camera/a.txt"));

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
    assert!(
        restore.status.success(),
        "{}",
        String::from_utf8_lossy(&restore.stderr)
    );
    assert_eq!(
        std::fs::read(restore_dir.join("camera/a.txt")).expect("read restored file"),
        b"abc"
    );
}

//! CLI subprocess smoke tests.

mod common;

use std::time::{Duration, SystemTime};

use assert_cmd::Command;
use pcap_slim::testutil::pcap_fixtures::write_minimal_pcap;
use predicates::prelude::*;

#[test]
fn check_only_json_reports_fixture_stats() {
    let fixture = common::fixtures_dir().join("synth-tls-443.pcap");

    Command::cargo_bin("pcap-slim")
        .unwrap()
        .args([
            "--single",
            fixture.to_str().unwrap(),
            "--check-only",
            "--output=json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""check_only":true"#))
        .stdout(predicate::str::contains(r#""truncated":5"#))
        .stdout(predicate::str::contains(r#""in_pkts":5"#));
}

#[test]
fn age_minutes_dry_run_lists_only_old_pcaps() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.pcap");
    let new = dir.path().join("new.pcap");
    write_minimal_pcap(&old, 1).unwrap();
    write_minimal_pcap(&new, 1).unwrap();
    let past = SystemTime::now() - Duration::from_secs(120);
    std::fs::File::open(&old)
        .unwrap()
        .set_modified(past)
        .unwrap();

    let assert = Command::cargo_bin("pcap-slim")
        .unwrap()
        .args([
            "--dir",
            dir.path().to_str().unwrap(),
            "--age-minutes",
            "1",
            "--dry-run",
        ])
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(out.contains("old.pcap"));
    assert!(!out.contains("new.pcap"));
}

#[test]
fn pcapng_input_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.pcapng");
    std::fs::write(
        &p,
        &[
            0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0x00, 0x00, 0x00, 0x4D, 0x3C, 0x2B, 0x1A, 0x01, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1C, 0x00, 0x00, 0x00,
        ],
    )
    .unwrap();

    Command::cargo_bin("pcap-slim")
        .unwrap()
        .args(["--single", p.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pcapng"));
}

//! Parity regression tests against the Python (scapy) reference implementation.

mod common;

use std::path::PathBuf;

use pcap_slim::pcap_io::{slim_pcap, validate_pcap_magic, PcapError};
use tempfile::tempdir;

#[test]
fn ipv4_options_matches_python_reference() {
    let fixture = common::fixtures_dir().join("synth-ipv4-options.pcap");
    assert!(
        fixture.exists(),
        "run: python3 scripts/gen_fixtures.py"
    );

    if !common::reference_slim_available() {
        eprintln!("skip ipv4_options_matches_python_reference: scapy/python reference unavailable");
        return;
    }

    let dir = tempdir().unwrap();
    let py_out = dir.path().join("py.pcap");
    let rs_out = dir.path().join("rs.pcap");

    let status = std::process::Command::new("python3")
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/golden_slim.py"),
        )
        .arg(&fixture)
        .arg(&py_out)
        .status()
        .unwrap();
    assert!(status.success(), "python reference slim failed");

    slim_pcap(&fixture, &rs_out, None).unwrap();

    let py = std::fs::read(&py_out).unwrap();
    let rs = std::fs::read(&rs_out).unwrap();
    assert_eq!(py, rs, "IPv4-options fixture must match Python byte-for-byte");
}

#[test]
fn rejects_pcapng_cleanly() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("test.pcapng");
    std::fs::write(
        &p,
        &[
            0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0x00, 0x00, 0x00, 0x4D, 0x3C, 0x2B, 0x1A, 0x01, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1C, 0x00, 0x00, 0x00,
        ],
    )
    .unwrap();

    let err = validate_pcap_magic(&p).unwrap_err();
    assert!(matches!(err, PcapError::Pcapng { .. }));

    let out = dir.path().join("out.pcap");
    let err = slim_pcap(&p, &out, None).unwrap_err();
    assert!(matches!(err, PcapError::Pcapng { .. }));
}

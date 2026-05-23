//! Golden tests: compare Rust output to Scapy reference when available.

mod common;

use pcap_slim::pcap_io::slim_pcap;
use pcap_slim::testutil::pcap_fixtures::write_minimal_pcap;
use tempfile::tempdir;

#[test]
fn rust_slim_truncates_tls_payload() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("in.pcap");
    let dst = dir.path().join("out.pcap");
    write_minimal_pcap(&src, 3).unwrap();
    let stats = slim_pcap(&src, &dst, None).unwrap();
    assert_eq!(stats.in_pkts, 3);
    assert!(stats.truncated >= 1);
    assert!(stats.out_bytes < stats.in_bytes);
}

#[test]
#[ignore = "requires python3 + scapy + PCAP_External_Cleaner/pcap_slim_lib.py"]
fn golden_matches_scapy_reference() {
    if !common::reference_slim_available() {
        panic!("scapy reference not available");
    }

    let dir = tempdir().unwrap();
    let src = dir.path().join("in.pcap");
    let rust_out = dir.path().join("rust.pcap");
    let py_out = dir.path().join("py.pcap");
    write_minimal_pcap(&src, 5).unwrap();

    slim_pcap(&src, &rust_out, None).unwrap();

    let script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/golden_slim.py");
    let status = std::process::Command::new("python3")
        .arg(&script)
        .arg(&src)
        .arg(&py_out)
        .status()
        .unwrap();
    assert!(status.success(), "python reference slim failed");

    let rust_bytes = common::normalize_snaplen_for_compare(&std::fs::read(&rust_out).unwrap());
    let py_bytes = common::normalize_snaplen_for_compare(&std::fs::read(&py_out).unwrap());
    assert_eq!(
        rust_bytes, py_bytes,
        "packet bodies must match (snaplen field in global header ignored per spec)"
    );
}

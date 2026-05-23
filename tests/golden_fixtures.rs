//! Byte parity vs Python reference for every committed fixture.

mod common;

use std::path::PathBuf;
use std::process::Command;

use pcap_slim::pcap_io::slim_pcap;
use tempfile::tempdir;

#[test]
#[ignore = "requires python3 + scapy + PCAP_External_Cleaner/pcap_slim_lib.py"]
fn all_fixtures_match_python_reference() {
    if !common::reference_slim_available() {
        panic!("scapy reference not available");
    }

    let dir = common::fixtures_dir();
    let work = tempdir().unwrap();
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/golden_slim.py");

    for src in common::fixture_pcaps(&dir) {
        let name = src.file_name().unwrap().to_str().unwrap();
        let py_out = work.path().join(format!("{name}.py.pcap"));
        let rs_out = work.path().join(format!("{name}.rs.pcap"));

        let status = Command::new("python3")
            .arg(&script)
            .arg(&src)
            .arg(&py_out)
            .status()
            .unwrap();
        assert!(status.success(), "python slim failed for {name}");

        slim_pcap(&src, &rs_out, None).unwrap();

        let py = common::normalize_snaplen_for_compare(&std::fs::read(&py_out).unwrap());
        let rs = common::normalize_snaplen_for_compare(&std::fs::read(&rs_out).unwrap());
        assert_eq!(py, rs, "fixture {name} must match Python byte-for-byte");
    }
}

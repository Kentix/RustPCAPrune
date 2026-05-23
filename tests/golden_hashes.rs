//! Golden SHA-256 hashes of Rust slim output (source of truth; not Python/scapy).

mod common;

use std::collections::HashMap;
use pcap_slim::coord::slim_file_in_place;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

fn load_expected_hashes() -> HashMap<String, String> {
    let path = common::fixtures_dir().join("expected_hashes.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("parse fixtures/expected_hashes.json")
}

#[test]
fn fixtures_match_committed_output_hashes() {
    let expected = load_expected_hashes();
    let dir = common::fixtures_dir();

    for src in common::fixture_pcaps(&dir) {
        let name = src.file_name().unwrap().to_str().unwrap().to_string();
        let exp = expected
            .get(&name)
            .unwrap_or_else(|| panic!("missing fixtures/expected_hashes.json entry for {name}"));

        let work = tempdir().unwrap();
        let copy = work.path().join(&name);
        std::fs::copy(&src, &copy).unwrap();
        slim_file_in_place(&copy, None, false).unwrap();
        let got = sha256_bytes(&std::fs::read(&copy).unwrap());
        assert_eq!(got, *exp, "output hash mismatch for {name}");
    }
}

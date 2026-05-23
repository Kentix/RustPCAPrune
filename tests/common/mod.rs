//! Shared integration-test helpers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use pcap_slim::pcap_io::SlimStats;
use serde::Deserialize;

pub fn fixtures_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    assert!(
        dir.is_dir(),
        "fixtures/ missing — run: python3 scripts/gen_fixtures.py"
    );
    dir
}

#[derive(Debug, Deserialize)]
struct ExpectedFile {
    in_pkts: u64,
    truncated: u64,
    kept: u64,
    in_bytes: u64,
    out_bytes: u64,
}

pub fn load_expected() -> HashMap<String, SlimStats> {
    let path = fixtures_dir().join("expected.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let table: HashMap<String, ExpectedFile> =
        serde_json::from_str(&raw).expect("parse fixtures/expected.json");
    table
        .into_iter()
        .map(|(name, e)| {
            (
                name,
                SlimStats {
                    in_pkts: e.in_pkts,
                    truncated: e.truncated,
                    kept: e.kept,
                    in_bytes: e.in_bytes,
                    out_bytes: e.out_bytes,
                },
            )
        })
        .collect()
}

/// Zero snaplen bytes (offset 16..20); Python/scapy may rewrite snaplen to 65535.
pub fn normalize_snaplen_for_compare(buf: &[u8]) -> Vec<u8> {
    let mut out = buf.to_vec();
    if out.len() >= 20 {
        out[16..20].fill(0);
    }
    out
}

pub fn reference_slim_available() -> bool {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/golden_slim.py");
    let lib = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../PCAP_External_Cleaner/pcap_slim_lib.py");
    let scapy = std::process::Command::new("python3")
        .args(["-c", "import scapy"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    script.exists() && lib.exists() && scapy
}

pub fn fixture_pcaps(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .expect("read fixtures dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x == "pcap")
        })
        .collect();
    paths.sort();
    paths
}

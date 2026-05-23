//! Table-driven fixture stats and slim/analyze consistency.

mod common;

use pcap_slim::pcap_io::{analyze_pcap, slim_pcap};
use tempfile::tempdir;

#[test]
fn fixtures_match_expected_stats() {
    let dir = common::fixtures_dir();
    let expected = common::load_expected();

    for src in common::fixture_pcaps(&dir) {
        let name = src.file_name().unwrap().to_str().unwrap().to_string();
        let exp = expected
            .get(&name)
            .unwrap_or_else(|| panic!("missing entry in fixtures/expected.json for {name}"));

        let analyze = analyze_pcap(&src, None).expect("analyze");
        assert_eq!(analyze.in_pkts, exp.in_pkts, "{name} in_pkts");
        assert_eq!(analyze.truncated, exp.truncated, "{name} truncated");
        assert_eq!(analyze.kept, exp.kept, "{name} kept");
        assert_eq!(analyze.in_bytes, exp.in_bytes, "{name} in_bytes");
        assert_eq!(analyze.out_bytes, exp.out_bytes, "{name} out_bytes");
    }
}

#[test]
fn fixtures_slim_matches_analyze() {
    let dir = common::fixtures_dir();
    let work = tempdir().unwrap();

    for src in common::fixture_pcaps(&dir) {
        let dst = work.path().join(
            src.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
                + ".out",
        );
        let analyze = analyze_pcap(&src, None).expect("analyze");
        let slim = slim_pcap(&src, &dst, None).expect("slim");
        assert_eq!(slim.in_pkts, analyze.in_pkts, "{}", src.display());
        assert_eq!(slim.truncated, analyze.truncated, "{}", src.display());
        assert_eq!(slim.kept, analyze.kept, "{}", src.display());
        assert_eq!(slim.out_bytes, analyze.out_bytes, "{}", src.display());
    }
}

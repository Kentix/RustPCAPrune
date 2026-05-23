//! --check-only and JSON output smoke tests.

use pcap_slim::pcap_io::analyze_pcap;
use pcap_slim::testutil::pcap_fixtures::write_minimal_pcap;
use tempfile::tempdir;

#[test]
fn analyze_matches_slim_stats() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("in.pcap");
    let dst = dir.path().join("out.pcap");
    write_minimal_pcap(&src, 10).unwrap();

    let analyze = analyze_pcap(&src, None).unwrap();
    let slim = pcap_slim::pcap_io::slim_pcap(&src, &dst, None).unwrap();

    assert_eq!(analyze.in_pkts, slim.in_pkts);
    assert_eq!(analyze.truncated, slim.truncated);
    assert_eq!(analyze.out_bytes, slim.out_bytes);
}

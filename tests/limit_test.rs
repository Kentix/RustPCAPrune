//! Integration tests for resource governors.

use std::sync::Arc;

use pcap_slim::limit::LimitConfig;
use pcap_slim::pcap_io::slim_pcap;
use pcap_slim::testutil::pcap_fixtures::write_minimal_pcap;
use tempfile::tempdir;

#[test]
fn slim_with_io_limit_succeeds() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("in.pcap");
    let dst = dir.path().join("out.pcap");
    write_minimal_pcap(&src, 50).unwrap();

    let limits = Arc::new(
        LimitConfig {
            max_io_mbps: Some(50.0),
            ..Default::default()
        }
        .build()
        .unwrap(),
    );
    let stats = slim_pcap(&src, &dst, Some(&limits)).unwrap();
    assert_eq!(stats.in_pkts, 50);
}

#[test]
fn unlimited_limits_are_noop() {
    assert!(LimitConfig::default().build().is_none());
}

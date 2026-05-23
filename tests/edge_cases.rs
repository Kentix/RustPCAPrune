//! Spec edge cases: snaplen, fragments, TCP options, big-endian pcap.

mod common;

use pcap_slim::packet::process_packet;
use pcap_slim::pcap_io::{analyze_pcap, slim_pcap};
use pcap_slim::policy::{decide_action, Action};
use pcap_slim::testutil::pcap_fixtures::{write_minimal_pcap_be, write_pcap_records};
use pcap_slim::testutil::{eth_ipv4_tcp_frame, eth_ipv4_tcp_frame_with_tcp_opts};
use pcap_slim::parse::parse_frame;
use tempfile::tempdir;

#[test]
fn short_capture_keeps_tls_packet() {
    let full = eth_ipv4_tcp_frame(443, 12345, &[0x17; 40]);
    let incl = 14 + 20 + 20 + 10;
    let dir = tempdir().unwrap();
    let path = dir.path().join("short.pcap");
    write_pcap_records(&path, &[&full[..incl]], None).unwrap();

    let stats = analyze_pcap(&path, None).unwrap();
    assert_eq!(stats.truncated, 0);
    assert_eq!(stats.kept, 1);
}

#[test]
fn ipv4_fragment_kept() {
    let mut frame = eth_ipv4_tcp_frame(443, 12345, &[0x17; 40]);
    let ip = 14;
    let flags = u16::from_be_bytes([frame[ip + 6], frame[ip + 7]]) | 0x2000;
    frame[ip + 6] = (flags >> 8) as u8;
    frame[ip + 7] = (flags & 0xff) as u8;

    assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Keep);
    let (_, truncated) = process_packet(&frame);
    assert!(!truncated);
}

#[test]
fn tcp_options_tls_truncates() {
    let frame = eth_ipv4_tcp_frame_with_tcp_opts(443, 40000, &[0x17; 40]);
    let parsed = parse_frame(&frame).unwrap();
    assert!(parsed.l4.unwrap().header_len > 20);
    assert_eq!(decide_action(&parsed), Action::Truncate);

    let fixture = common::fixtures_dir().join("synth-tcp-options-tls.pcap");
    let stats = analyze_pcap(&fixture, None).unwrap();
    assert_eq!(stats.truncated, 4);
}

#[test]
fn big_endian_pcap_roundtrip() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("be_in.pcap");
    let dst = dir.path().join("be_out.pcap");
    write_minimal_pcap_be(&src, 2).unwrap();

    let before = std::fs::read(&src).unwrap();
    let orig_snap = before[16..20].to_vec();

    slim_pcap(&src, &dst, None).unwrap();
    let after = std::fs::read(&dst).unwrap();

    assert_eq!(&after[0..16], &before[0..16]);
    assert_eq!(&after[16..20], &orig_snap);
    assert!(after.len() < before.len());
}

#[test]
fn fixture_first_packet_parses_l4() {
    let fixture = common::fixtures_dir().join("synth-vlan-tls.pcap");
    let bytes = std::fs::read(&fixture).unwrap();
    let incl = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
    let frame = &bytes[40..40 + incl];
    assert!(parse_frame(frame).unwrap().l4.is_some());
}

//! pcap-slim: deterministic truncation of encrypted L4 payloads in pcaps.

pub mod testutil;

pub mod checksum;
pub mod output;
pub mod packet;
pub mod limit;
pub mod mmap_policy;
pub mod coord;
pub mod parse;
pub mod pcap_io;
pub mod policy;
pub mod truncate;

pub use limit::{LimitConfig, ResourceLimits};
pub use packet::{process_packet, PacketOutcome};
pub use pcap_io::{
    analyze_pcap, analyze_pcap_with_options, count_packets, count_packets_with_options, slim_pcap,
    slim_pcap_to_writer, slim_pcap_to_writer_with_options, slim_pcap_with_options, SlimStats,
};
pub use policy::{decide_action, Action};

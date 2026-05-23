//! Manual benchmark: cargo bench --bench slim_bench
//!
//! Generates a synthetic TLS-heavy pcap and times slim throughput.
//!
//! Production sensor budgets (cold cache, do not regress without cause):
//! - 200 MB single-worker, no mmap: ≤ 800 ms
//! - 800 MB single-worker, no mmap: ≤ 2500 ms
//! - 800 MB single-worker, mmap: ≤ 1100 ms
//! - 1.24 GB `--dir` 4 workers: ≤ 3200 ms
//! See `scripts/bench.sh` for the cold-cache bench harness.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use pcap_slim::pcap_io::slim_pcap;
use pcap_slim::testutil::eth_ipv4_tcp_frame;

fn write_synthetic_pcap(path: &PathBuf, packets: u32) -> std::io::Result<u64> {
    let mut f = File::create(path)?;
    let ghdr: [u8; 24] = [
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
        0, 0, 0x01, 0, 0, 0,
    ];
    f.write_all(&ghdr)?;
    let frame = eth_ipv4_tcp_frame(443, 443, &[0x17; 1400]);
    let incl = frame.len() as u32;
    for _ in 0..packets {
        let mut rec = [0u8; 16];
        rec[8..12].copy_from_slice(&incl.to_le_bytes());
        rec[12..16].copy_from_slice(&(incl + 100).to_le_bytes());
        f.write_all(&rec)?;
        f.write_all(&frame)?;
    }
    Ok(f.metadata()?.len())
}

fn main() {
    let tmp = std::env::temp_dir().join("pcap_slim_bench.pcap");
    let out = std::env::temp_dir().join("pcap_slim_bench_out.pcap");
    let packets = 10_000u32;
    let bytes = write_synthetic_pcap(&tmp, packets).expect("write pcap");
    let t0 = Instant::now();
    let stats = slim_pcap(&tmp, &out, None).expect("slim");
    let elapsed = t0.elapsed().as_secs_f64();
    let mb_s = (bytes as f64 / 1_000_000.0) / elapsed;
    eprintln!(
        "packets={} truncated={} bytes={} elapsed={elapsed:.3}s throughput={mb_s:.1} MB/s",
        stats.in_pkts, stats.truncated, bytes
    );
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&out);
}

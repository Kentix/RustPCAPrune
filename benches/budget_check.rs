//! Performance budget gate: `cargo run --release --bin budget_check`
//!
//! Reads `benches/budgets.txt` and runs synthetic scenarios; fails if any exceed
//! max_ms × headroom. CI-friendly sizes; production sensor targets are documented in the file.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use pcap_slim::coord::slim_file_in_place;
use pcap_slim::pcap_io::slim_pcap;
use pcap_slim::testutil::eth_ipv4_tcp_frame;
use rayon::prelude::*;
use tempfile::tempdir;

const HEADROOM: f64 = 1.10;

fn main() {
    if let Err(e) = run() {
        eprintln!("budget_check: {e}");
        std::process::exit(1);
    }
    eprintln!("budget_check: all scenarios within budget");
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let budgets = load_budgets(Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/budgets.txt"))?;
    let mut failures = Vec::new();

    for (name, max_ms) in &budgets {
        let limit = ((*max_ms as f64) * HEADROOM) as u128;
        let elapsed = match name.as_str() {
            "synthetic_single_10k_pkts" => bench_single_10k()?,
            "synthetic_dir_3files_4workers" => bench_dir_3files(4)?,
            "synthetic_dir_3files_2workers" => bench_dir_3files(2)?,
            "synthetic_dir_3files_1worker" => bench_dir_3files(1)?,
            other => {
                eprintln!("budget_check: skip unknown scenario {other}");
                continue;
            }
        };
        if elapsed > limit {
            failures.push(format!(
                "{name}: {elapsed}ms > limit {limit}ms (budget {max_ms}ms × {HEADROOM})"
            ));
        } else {
            eprintln!("budget_check: {name} ok ({elapsed}ms <= {limit}ms)");
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n").into())
    }
}

fn load_budgets(path: PathBuf) -> Result<Vec<(String, u64)>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let name = parts.next().ok_or("budget line missing name")?.to_string();
        let max_ms: u64 = parts.next().ok_or("budget line missing max_ms")?.parse()?;
        out.push((name, max_ms));
    }
    Ok(out)
}

fn write_synthetic_pcap(path: &Path, packets: u32) -> std::io::Result<u64> {
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

fn bench_single_10k() -> Result<u128, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let src = dir.path().join("bench.pcap");
    let dst = dir.path().join("out.pcap");
    write_synthetic_pcap(&src, 10_000)?;
    let t0 = Instant::now();
    slim_pcap(&src, &dst, None)?;
    Ok(t0.elapsed().as_millis())
}

fn bench_dir_3files(workers: usize) -> Result<u128, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    for (i, pkts) in [(0, 2000_u32), (1, 3000), (2, 5000)] {
        write_synthetic_pcap(&dir.path().join(format!("f{i}.pcap")), pkts)?;
    }
    let files: Vec<PathBuf> = (0..3).map(|i| dir.path().join(format!("f{i}.pcap"))).collect();
    let use_mmap = pcap_slim::mmap_policy::resolve_use_mmap(true, workers, false, false);
    let t0 = Instant::now();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers.max(1))
        .build()?;
    pool.install(|| {
        files.par_iter().for_each(|p| {
            slim_file_in_place(p, None, use_mmap).unwrap();
        });
    });
    Ok(t0.elapsed().as_millis())
}

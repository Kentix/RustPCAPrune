//! pcap-slim CLI — in-place deterministic pcap slimming.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, ValueEnum};
use rayon::prelude::*;

use pcap_slim::coord::{check_file, cleanup_stale_tmp, list_pending_pcaps, slim_file_in_place};
use pcap_slim::limit::{LimitConfig, ResourceLimits};
use pcap_slim::output::{print_human, print_json, FileReport, RunReport, RunSummary};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Parser, Debug)]
#[command(name = "pcap-slim", about = "Truncate encrypted L4 payloads in pcaps (deterministic)")]
struct Args {
    /// Directory containing .pcap files to slim in place
    #[arg(long, conflicts_with = "single")]
    dir: Option<PathBuf>,

    /// Slim a single pcap file in place
    #[arg(long, conflicts_with = "dir")]
    single: Option<PathBuf>,

    /// Number of parallel workers
    #[arg(long, default_value_t = 1)]
    workers: usize,

    /// List files that would be processed without modifying them
    #[arg(long)]
    dry_run: bool,

    /// Analyze what would be truncated; do not write or create markers
    #[arg(long)]
    check_only: bool,

    /// Output format for per-file results
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    output: OutputFormat,

    /// Cap aggregate read+write throughput (decimal MB/s), shared by all workers
    #[arg(long)]
    max_io_mbps: Option<f64>,

    /// Hard cap: max share of machine CPU capacity (1–100), process-wide
    #[arg(long)]
    max_cpu_percent: Option<f64>,

    /// When system CPU usage is above this %, voluntarily back off
    #[arg(long)]
    cpu_backoff_above: Option<f64>,

    /// Load-backoff aggressiveness (0.0–1.0)
    #[arg(long, default_value_t = 0.5)]
    cpu_backoff_strength: f64,

    /// Only process pcaps whose mtime is at least this many minutes old (`--dir` only)
    #[arg(long, value_name = "MINUTES")]
    age_minutes: Option<u32>,

    /// Disable mmap reads (overrides auto selection for `--dir`)
    #[cfg(feature = "mmap")]
    #[arg(long)]
    no_mmap: bool,

    /// Force mmap reads for `--single` (or override auto buffered I/O for `--dir`)
    #[cfg(feature = "mmap")]
    #[arg(long)]
    mmap: bool,
}

fn log_io_mode(use_mmap: bool, is_dir_mode: bool, worker_count: usize, force_mmap: bool) {
    if !is_dir_mode {
        return;
    }
    let max = pcap_slim::mmap_policy::DIR_MMAP_MAX_WORKERS;
    if use_mmap {
        if worker_count > max && !force_mmap {
            eprintln!(
                "io: mmap (use --no-mmap for buffered read with >{} workers)",
                max
            );
        }
    } else if worker_count > max {
        eprintln!(
            "io: buffered read (auto: >{} workers avoids mmap page-fault contention)",
            max
        );
    }
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn log_limits(config: &LimitConfig) {
    let mut parts = Vec::new();
    if let Some(mbps) = config.max_io_mbps {
        parts.push(format!("io={mbps}MB/s"));
    }
    if let Some(pct) = config.max_cpu_percent {
        parts.push(format!("cpu_cap={pct}%"));
    }
    if let Some(above) = config.cpu_backoff_above {
        parts.push(format!(
            "backoff_above={above}% strength={}",
            config.cpu_backoff_strength
        ));
    }
    if !parts.is_empty() {
        eprintln!("limits: {}", parts.join(" "));
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.single.is_some() && args.workers > 1 {
        eprintln!(
            "warning: --workers {} has no effect with --single (one file, one thread)",
            args.workers
        );
    }
    if args.age_minutes.is_some() && args.single.is_some() {
        eprintln!("warning: --age-minutes applies only to --dir mode");
    }

    let limit_config = LimitConfig {
        max_io_mbps: args.max_io_mbps,
        max_cpu_percent: args.max_cpu_percent,
        cpu_backoff_above: args.cpu_backoff_above,
        cpu_backoff_strength: args.cpu_backoff_strength,
    };
    log_limits(&limit_config);
    let limits: Option<Arc<ResourceLimits>> = limit_config.build().map(Arc::new);

    let files: Vec<PathBuf> = if let Some(ref single) = args.single {
        vec![single.clone()]
    } else if let Some(ref dir) = args.dir {
        if !args.check_only {
            let cleaned = cleanup_stale_tmp(dir)?;
            if cleaned > 0 {
                eprintln!("cleaned {cleaned} stale .pcap.tmp file(s)");
            }
        }
        list_pending_pcaps(dir, args.age_minutes)?
    } else {
        return Err("either --dir or --single is required".into());
    };

    if files.is_empty() {
        eprintln!("no pcaps to process");
        if matches!(args.output, OutputFormat::Json) {
            print_json(&RunReport {
                summary: RunSummary {
                    ok: 0,
                    skip: 0,
                    fail: 0,
                    elapsed_ms: 0,
                    check_only: args.check_only,
                },
                files: vec![],
            });
        }
        return Ok(());
    }

    if args.dry_run {
        for f in &files {
            if matches!(args.output, OutputFormat::Json) {
                println!(
                    "{}",
                    serde_json::json!({"file": f.display().to_string(), "status": "would_slim"})
                );
            } else {
                println!("would slim: {}", f.display());
            }
        }
        return Ok(());
    }

    let worker_count = args.workers.max(1).min(files.len());
    let limits_ref = limits.as_ref();
    let check_only = args.check_only;
    let is_dir_mode = args.dir.is_some();
    #[cfg(feature = "mmap")]
    let no_mmap = args.no_mmap;
    #[cfg(not(feature = "mmap"))]
    let no_mmap = false;
    #[cfg(feature = "mmap")]
    let force_mmap = args.mmap;
    #[cfg(not(feature = "mmap"))]
    let force_mmap = false;
    let use_mmap =
        pcap_slim::mmap_policy::resolve_use_mmap(is_dir_mode, worker_count, no_mmap, force_mmap);
    log_io_mode(use_mmap, is_dir_mode, worker_count, force_mmap);
    let t0 = Instant::now();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .build()?;

    let file_reports: Vec<FileReport> = pool.install(|| {
        files
            .par_iter()
            .map(|path| {
                let file_t0 = Instant::now();
                let result = if check_only {
                    check_file(path, limits_ref, use_mmap)
                } else {
                    slim_file_in_place(path, limits_ref, use_mmap)
                };

                let elapsed_ms = file_t0.elapsed().as_millis() as u64;
                match result {
                    Ok((pcap_slim::coord::FileResult::Ok, Some(stats))) => {
                        FileReport::ok(path, &stats, elapsed_ms)
                    }
                    Ok((pcap_slim::coord::FileResult::SkippedMarker, _)) => {
                        FileReport::skipped_marker(path)
                    }
                    Ok(_) => FileReport::fail(path, "unexpected empty result"),
                    Err(e) => FileReport::fail(path, e),
                }
            })
            .collect()
    });

    let mut summary = RunSummary {
        ok: 0,
        skip: 0,
        fail: 0,
        elapsed_ms: t0.elapsed().as_millis() as u64,
        check_only,
    };
    for r in &file_reports {
        use pcap_slim::output::FileStatus;
        match r.status {
            FileStatus::Ok => summary.ok += 1,
            FileStatus::SkippedMarker => summary.skip += 1,
            FileStatus::Fail => summary.fail += 1,
        }
    }

    let report = RunReport {
        summary,
        files: file_reports,
    };

    match args.output {
        OutputFormat::Human => print_human(&report),
        OutputFormat::Json => print_json(&report),
    }

    if report.summary.fail > 0 {
        return Err("one or more files failed".into());
    }
    Ok(())
}

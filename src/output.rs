//! CLI result types for human and JSON output.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Ok,
    SkippedMarker,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub file: String,
    pub status: FileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_pkts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kept: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    pub ok: u64,
    pub skip: u64,
    pub fail: u64,
    pub elapsed_ms: u64,
    pub check_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub summary: RunSummary,
    pub files: Vec<FileReport>,
}

impl FileReport {
    pub fn skipped_marker(path: &std::path::Path) -> Self {
        Self {
            file: path.display().to_string(),
            status: FileStatus::SkippedMarker,
            in_pkts: None,
            truncated: None,
            kept: None,
            in_bytes: None,
            out_bytes: None,
            elapsed_ms: None,
            error: None,
        }
    }

    pub fn fail(path: &std::path::Path, err: impl std::fmt::Display) -> Self {
        Self {
            file: path.display().to_string(),
            status: FileStatus::Fail,
            in_pkts: None,
            truncated: None,
            kept: None,
            in_bytes: None,
            out_bytes: None,
            elapsed_ms: None,
            error: Some(err.to_string()),
        }
    }

    pub fn ok(
        path: &std::path::Path,
        stats: &crate::pcap_io::SlimStats,
        elapsed_ms: u64,
    ) -> Self {
        Self {
            file: path.display().to_string(),
            status: FileStatus::Ok,
            in_pkts: Some(stats.in_pkts),
            truncated: Some(stats.truncated),
            kept: Some(stats.kept),
            in_bytes: Some(stats.in_bytes),
            out_bytes: Some(stats.out_bytes),
            elapsed_ms: Some(elapsed_ms),
            error: None,
        }
    }
}

pub fn print_human(report: &RunReport) {
    for f in &report.files {
        match f.status {
            FileStatus::Ok => eprintln!(
                "ok {} pkts={} truncated={} in={} out={} ({}ms)",
                f.file,
                f.in_pkts.unwrap_or(0),
                f.truncated.unwrap_or(0),
                f.in_bytes.unwrap_or(0),
                f.out_bytes.unwrap_or(0),
                f.elapsed_ms.unwrap_or(0),
            ),
            FileStatus::SkippedMarker => eprintln!("skip (marked): {}", f.file),
            FileStatus::Fail => eprintln!(
                "FAIL {}: {}",
                f.file,
                f.error.as_deref().unwrap_or("unknown error")
            ),
        }
    }
    let s = &report.summary;
    let mode = if s.check_only { "check" } else { "done" };
    eprintln!(
        "{mode}: ok={} skip={} fail={} elapsed={:.1}s",
        s.ok,
        s.skip,
        s.fail,
        s.elapsed_ms as f64 / 1000.0,
    );
}

pub fn print_json(report: &RunReport) {
    println!("{}", serde_json::to_string(report).expect("json serialize"));
}

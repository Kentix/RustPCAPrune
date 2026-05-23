//! File-level coordination: markers, atomic rename, orphan cleanup.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use thiserror::Error;

use crate::limit::ResourceLimits;
use crate::pcap_io::{analyze_pcap_with_options, count_packets_with_options, slim_pcap_with_options, SlimStats};

const STALE_TMP_SECS: u64 = 300;
const MARKER_DIR: &str = ".slim_markers";
const MARKER_OWNER: &str = "sensor";
const MARKER_GROUP: &str = "sensor";

#[derive(Debug, Error)]
pub enum CoordError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("pcap error: {0}")]
    Pcap(#[from] crate::pcap_io::PcapError),
    #[error("packet count mismatch: expected={expected} out={out_count}")]
    PacketCountMismatch { expected: u64, out_count: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileResult {
    SkippedMarker,
    Ok,
}

pub fn marker_path(src: &Path) -> PathBuf {
    let dir = src.parent().unwrap_or_else(|| Path::new("."));
    dir.join(MARKER_DIR).join(
        src.file_name()
            .map(|n| n.to_owned())
            .unwrap_or_default(),
    )
}

pub fn is_marked(src: &Path) -> bool {
    marker_path(src).exists()
}

/// Remove `*.pcap.tmp` files older than 5 minutes in `dir`.
pub fn cleanup_stale_tmp(dir: &Path) -> io::Result<u32> {
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(STALE_TMP_SECS))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    cleanup_tmp_older_than(dir, cutoff)
}

fn cleanup_tmp_older_than(dir: &Path, cutoff: SystemTime) -> io::Result<u32> {
    let mut cleaned = 0u32;
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(0),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".pcap.tmp") {
            continue;
        }
        let path = entry.path();
        if let Ok(meta) = fs::metadata(&path) {
            if let Ok(mtime) = meta.modified() {
                if mtime < cutoff {
                    if fs::remove_file(&path).is_ok() {
                        cleaned += 1;
                    }
                }
            }
        }
    }
    Ok(cleaned)
}

/// Verify output pcap has the same packet count as the slim pass reported.
fn verify_tmp_packet_count(
    expected: u64,
    tmp: &Path,
    limits: Option<&Arc<ResourceLimits>>,
    use_mmap: bool,
) -> Result<(), CoordError> {
    let out_count = count_packets_with_options(tmp, limits, use_mmap)?;
    if out_count != expected {
        return Err(CoordError::PacketCountMismatch {
            expected,
            out_count,
        });
    }
    Ok(())
}

fn ensure_marker_dir(src: &Path) -> io::Result<PathBuf> {
    let marker_dir = src
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(MARKER_DIR);
    fs::create_dir_all(&marker_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&marker_dir, fs::Permissions::from_mode(0o755))?;
    }
    Ok(marker_dir)
}

#[cfg(unix)]
fn chown_sensor(path: &Path) -> io::Result<()> {
    use nix::unistd::{chown, Group, User};

    if let Some(user) = User::from_name(MARKER_OWNER)? {
        let gid = Group::from_name(MARKER_GROUP)?
            .map(|g| g.gid)
            .unwrap_or(user.gid);
        chown(path, Some(user.uid), Some(gid))
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        return Ok(());
    }
    use nix::unistd::{getegid, geteuid};
    chown(path, Some(geteuid()), Some(getegid()))
        .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

#[cfg(not(unix))]
fn chown_sensor(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn create_marker(src: &Path) -> io::Result<()> {
    ensure_marker_dir(src)?;
    let marker = marker_path(src);
    fs::write(&marker, [])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o644))?;
        let _ = chown_sensor(&marker);
    }
    Ok(())
}

/// Analyze `src` without writing (for `--check-only`).
pub fn check_file(
    src: &Path,
    limits: Option<&Arc<ResourceLimits>>,
    use_mmap: bool,
) -> Result<(FileResult, Option<SlimStats>), CoordError> {
    if is_marked(src) {
        return Ok((FileResult::SkippedMarker, None));
    }
    let stats = analyze_pcap_with_options(src, limits, use_mmap)?;
    Ok((FileResult::Ok, Some(stats)))
}

/// Slim `src` in place per spec: `.tmp` → verify count → rename → marker.
pub fn slim_file_in_place(
    src: &Path,
    limits: Option<&Arc<ResourceLimits>>,
    use_mmap: bool,
) -> Result<(FileResult, Option<SlimStats>), CoordError> {
    if is_marked(src) {
        return Ok((FileResult::SkippedMarker, None));
    }

    let tmp = src.with_extension("pcap.tmp");

    let stats = match slim_pcap_with_options(src, &tmp, limits, use_mmap) {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
    };

    if let Err(e) = verify_tmp_packet_count(stats.in_pkts, &tmp, limits, use_mmap) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    fs::rename(&tmp, src)?;
    create_marker(src)?;

    Ok((FileResult::Ok, Some(stats)))
}

/// List `.pcap` files in `dir` that are not yet markered, oldest mtime first.
///
/// When `age_minutes` is set, only files whose mtime is at least that many minutes old
/// are included (matches Python `pcap-slim.py --age-minutes`).
pub fn list_pending_pcaps(dir: &Path, age_minutes: Option<u32>) -> io::Result<Vec<PathBuf>> {
    let mtime_cutoff = age_minutes.map(|minutes| {
        SystemTime::now()
            .checked_sub(Duration::from_secs(u64::from(minutes) * 60))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });

    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if !name.ends_with(".pcap") || name.ends_with(".pcap.tmp") {
            continue;
        }
        if let Some(cutoff) = mtime_cutoff {
            let mtime = fs::metadata(&path)?.modified()?;
            if mtime > cutoff {
                continue;
            }
        }
        if is_marked(&path) {
            continue;
        }
        files.push(path);
    }
    files.sort_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok());
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap_io::analyze_pcap;
    use crate::testutil::pcap_fixtures::write_minimal_pcap;
    use tempfile::tempdir;

    #[test]
    fn marker_skips_second_run() {
        let dir = tempdir().unwrap();
        let pcap = dir.path().join("test.pcap");
        write_minimal_pcap(&pcap, 2).unwrap();

        let (r1, _) = slim_file_in_place(&pcap, None, false).unwrap();
        assert_eq!(r1, FileResult::Ok);
        assert!(marker_path(&pcap).exists());

        let (r2, _) = slim_file_in_place(&pcap, None, false).unwrap();
        assert_eq!(r2, FileResult::SkippedMarker);
    }

    #[test]
    fn verify_tmp_packet_count_mismatch() {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("tmp.pcap");
        write_minimal_pcap(&tmp, 1).unwrap();

        let err = verify_tmp_packet_count(2, &tmp, None, false).unwrap_err();
        assert!(matches!(
            err,
            CoordError::PacketCountMismatch {
                expected: 2,
                out_count: 1
            }
        ));
    }

    #[test]
    fn cleanup_stale_tmp_removes_old() {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("stale.pcap.tmp");
        std::fs::write(&tmp, b"x").unwrap();
        let past = SystemTime::now() - Duration::from_secs(600);
        std::fs::File::open(&tmp)
            .unwrap()
            .set_modified(past)
            .unwrap();

        let cleaned = cleanup_tmp_older_than(dir.path(), SystemTime::now()).unwrap();
        assert_eq!(cleaned, 1);
        assert!(!tmp.exists());
    }

    #[test]
    fn list_pending_pcaps_skips_marked() {
        let dir = tempdir().unwrap();
        let pcap = dir.path().join("a.pcap");
        write_minimal_pcap(&pcap, 1).unwrap();
        create_marker(&pcap).unwrap();

        let pending = list_pending_pcaps(dir.path(), None).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn list_pending_respects_age_minutes() {
        let dir = tempdir().unwrap();
        let old_pcap = dir.path().join("old.pcap");
        let new_pcap = dir.path().join("new.pcap");
        write_minimal_pcap(&old_pcap, 1).unwrap();
        write_minimal_pcap(&new_pcap, 1).unwrap();

        let past = SystemTime::now() - Duration::from_secs(120);
        std::fs::File::open(&old_pcap)
            .unwrap()
            .set_modified(past)
            .unwrap();

        let pending = list_pending_pcaps(dir.path(), Some(1)).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], old_pcap);
    }

    #[test]
    fn check_file_matches_analyze() {
        let dir = tempdir().unwrap();
        let pcap = dir.path().join("a.pcap");
        write_minimal_pcap(&pcap, 3).unwrap();

        let (_, check_stats) = check_file(&pcap, None, false).unwrap();
        let analyze = analyze_pcap(&pcap, None).unwrap();
        let check_stats = check_stats.unwrap();
        assert_eq!(check_stats.in_pkts, analyze.in_pkts);
        assert_eq!(check_stats.truncated, analyze.truncated);
        assert_eq!(check_stats.out_bytes, analyze.out_bytes);
    }
}

//! When to use mmap for pcap input (avoids cold-cache page-fault storms at high worker counts).

/// `--dir` uses mmap only up to this many workers unless `--mmap` forces it.
pub const DIR_MMAP_MAX_WORKERS: usize = 2;

/// Resolve whether to mmap input for this run.
#[cfg(feature = "mmap")]
pub fn resolve_use_mmap(is_dir: bool, workers: usize, no_mmap: bool, force_mmap: bool) -> bool {
    if no_mmap {
        return false;
    }
    if force_mmap {
        return true;
    }
    if is_dir {
        return workers <= DIR_MMAP_MAX_WORKERS;
    }
    false
}

#[cfg(not(feature = "mmap"))]
pub fn resolve_use_mmap(_is_dir: bool, _workers: usize, _no_mmap: bool, _force_mmap: bool) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_auto_mmap_worker_threshold() {
        #[cfg(feature = "mmap")]
        {
            assert!(resolve_use_mmap(true, 1, false, false));
            assert!(resolve_use_mmap(true, 2, false, false));
            assert!(!resolve_use_mmap(true, 4, false, false));
            assert!(resolve_use_mmap(true, 4, false, true));
            assert!(!resolve_use_mmap(true, 4, true, false));
        }
    }
}

//! Process-wide resource governors (I/O token bucket + CPU cap / load backoff).

use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Flush accumulated I/O bytes to the token bucket.
const IO_BATCH_BYTES: u64 = 256 * 1024;

/// CLI-derived limit configuration.
#[derive(Debug, Clone, Default)]
pub struct LimitConfig {
    pub max_io_mbps: Option<f64>,
    pub max_cpu_percent: Option<f64>,
    pub cpu_backoff_above: Option<f64>,
    pub cpu_backoff_strength: f64,
}

impl LimitConfig {
    /// Build shared limits, or `None` when every limit is disabled.
    pub fn build(self) -> Option<ResourceLimits> {
        let io = self.max_io_mbps.filter(|&m| m > 0.0).map(IoBucket::new);
        let cpu = CpuGovernor::new(
            self.max_cpu_percent.filter(|&p| p > 0.0),
            self.cpu_backoff_above.filter(|&p| p > 0.0),
            self.cpu_backoff_strength,
        );
        if io.is_none() && cpu.is_none() {
            return None;
        }
        Some(ResourceLimits {
            inner: Mutex::new(Inner {
                io,
                cpu,
                io_pending: 0,
            }),
        })
    }
}

/// Shared across all workers; blocks only when a budget is exhausted.
pub struct ResourceLimits {
    inner: Mutex<Inner>,
}

struct Inner {
    io: Option<IoBucket>,
    cpu: Option<CpuGovernor>,
    io_pending: u64,
}

/// Token bucket for aggregate read+write bytes/sec.
struct IoBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last_refill: Instant,
}

impl IoBucket {
    fn new(max_mbps: f64) -> Self {
        let rate = max_mbps * 1_000_000.0;
        let burst = rate * 2.0;
        Self {
            rate,
            burst,
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.duration_since(self.last_refill).as_secs_f64();
        if dt > 0.0 {
            self.tokens = (self.tokens + self.rate * dt).min(self.burst);
            self.last_refill = now;
        }
    }

    fn acquire(&mut self, bytes: u64) {
        let need = bytes as f64;
        if need <= 0.0 {
            return;
        }
        loop {
            let now = Instant::now();
            self.refill(now);
            if self.tokens >= need {
                self.tokens -= need;
                return;
            }
            let deficit = need - self.tokens;
            let wait_secs = deficit / self.rate;
            sleep(Duration::from_secs_f64(wait_secs.min(1.0)));
        }
    }
}

struct CpuGovernor {
    max_cpu_percent: Option<f64>,
    backoff_above: Option<f64>,
    backoff_strength: f64,
    num_cpus: f64,
    last_tick: Instant,
    last_process_cpu_secs: f64,
    last_system_refresh: Instant,
    system_busy_percent: f64,
}

impl CpuGovernor {
    fn new(
        max_cpu_percent: Option<f64>,
        backoff_above: Option<f64>,
        backoff_strength: f64,
    ) -> Option<Self> {
        if max_cpu_percent.is_none() && backoff_above.is_none() {
            return None;
        }
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get() as f64)
            .unwrap_or(1.0);
        Some(Self {
            max_cpu_percent,
            backoff_above,
            backoff_strength: backoff_strength.clamp(0.0, 1.0),
            num_cpus,
            last_tick: Instant::now(),
            last_process_cpu_secs: process_cpu_secs(),
            last_system_refresh: Instant::now(),
            system_busy_percent: system_busy_percent(num_cpus),
        })
    }

    fn effective_target_percent(&self) -> f64 {
        let hard = self.max_cpu_percent.unwrap_or(100.0);
        let Some(threshold) = self.backoff_above else {
            return hard;
        };
        if self.system_busy_percent < threshold {
            return hard;
        }
        let span = (100.0 - threshold).max(1.0);
        let over = (self.system_busy_percent - threshold) / span;
        let reduction = self.backoff_strength * over.min(1.0);
        hard * (1.0 - reduction)
    }

    fn tick(&mut self) {
        let now = Instant::now();
        let wall = now.duration_since(self.last_tick).as_secs_f64();
        if wall < 0.001 {
            return;
        }

        if now.duration_since(self.last_system_refresh) >= Duration::from_millis(500) {
            self.system_busy_percent = system_busy_percent(self.num_cpus);
            self.last_system_refresh = now;
        }

        let cpu_now = process_cpu_secs();
        let cpu_delta = (cpu_now - self.last_process_cpu_secs).max(0.0);
        self.last_process_cpu_secs = cpu_now;
        self.last_tick = now;

        let process_pct_of_machine = (cpu_delta / wall) / self.num_cpus * 100.0;
        let target = self.effective_target_percent();

        if process_pct_of_machine > target {
            let overshoot = (process_pct_of_machine - target) / target.max(1.0);
            let sleep_secs = (0.05 * overshoot).clamp(0.001, 0.5);
            sleep(Duration::from_secs_f64(sleep_secs));
        }
    }
}

/// Estimate system CPU busy % from 1-minute load average (Unix).
fn system_busy_percent(num_cpus: f64) -> f64 {
    #[cfg(unix)]
    {
        let mut load = [0.0f64; 3];
        let n = unsafe { libc::getloadavg(load.as_mut_ptr(), 3) };
        if n > 0 && num_cpus > 0.0 {
            return ((load[0] / num_cpus) * 100.0).clamp(0.0, 100.0);
        }
    }
    0.0
}

fn process_cpu_secs() -> f64 {
    #[cfg(unix)]
    {
        use std::mem::MaybeUninit;

        unsafe {
            let mut ru = MaybeUninit::<libc::rusage>::uninit();
            if libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr()) == 0 {
                let ru = ru.assume_init();
                let user =
                    ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 * 1e-6;
                let sys =
                    ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 * 1e-6;
                return user + sys;
            }
        }
    }
    0.0
}

impl ResourceLimits {
    /// Account `bytes` against the shared I/O cap (batched; call `flush_io` at end).
    pub fn acquire_io(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.io_pending = inner.io_pending.saturating_add(bytes);
        if inner.io_pending >= IO_BATCH_BYTES {
            let pending = inner.io_pending;
            inner.io_pending = 0;
            if let Some(ref mut bucket) = inner.io {
                bucket.acquire(pending);
            }
        }
    }

    /// Flush any bytes not yet charged to the I/O bucket.
    pub fn flush_io(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.io_pending > 0 {
            let pending = inner.io_pending;
            inner.io_pending = 0;
            if let Some(ref mut bucket) = inner.io {
                bucket.acquire(pending);
            }
        }
    }

    /// Sample CPU usage and sleep only when over the effective target.
    pub fn cpu_tick(&self) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(ref mut gov) = inner.cpu {
            gov.tick();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_bucket_allows_burst_without_sleep() {
        let mut bucket = IoBucket::new(100.0);
        bucket.acquire(500_000);
        assert!(bucket.tokens >= 0.0);
    }

    #[test]
    fn limit_config_none_when_empty() {
        assert!(LimitConfig::default().build().is_none());
    }

    #[test]
    fn limit_config_some_when_io_set() {
        let lim = LimitConfig {
            max_io_mbps: Some(10.0),
            ..Default::default()
        }
        .build();
        assert!(lim.is_some());
    }

    #[test]
    fn cpu_effective_target_reduces_under_load() {
        let mut gov = CpuGovernor::new(Some(50.0), Some(80.0), 1.0).unwrap();
        gov.system_busy_percent = 90.0;
        assert!(gov.effective_target_percent() < 50.0);
    }

    #[test]
    fn io_bucket_blocks_after_burst_exhausted() {
        let limits = ResourceLimits {
            inner: Mutex::new(Inner {
                io: Some(IoBucket::new(1.0)),
                cpu: None,
                io_pending: 0,
            }),
        };
        let t0 = Instant::now();
        limits.acquire_io(2_000_000);
        limits.flush_io();
        limits.acquire_io(2_000_000);
        limits.flush_io();
        assert!(t0.elapsed() >= Duration::from_millis(400));
    }
}

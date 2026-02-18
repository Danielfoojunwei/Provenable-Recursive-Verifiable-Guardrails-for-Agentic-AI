//! Performance metrics tracking for Provenable.ai guard pipeline.
//!
//! Tracks guard evaluation latency, throughput, denial rates, and provides
//! the data backing the `/prove` performance dashboard.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::types::{GuardSurface, GuardVerdict};

/// Global metrics collector.
static METRICS: Mutex<Option<MetricsCollector>> = Mutex::new(None);

/// Individual guard evaluation timing record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvaluation {
    pub timestamp: DateTime<Utc>,
    pub surface: GuardSurface,
    pub verdict: GuardVerdict,
    pub duration_us: u64,
}

/// Accumulated metrics for the guard pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardMetrics {
    /// Total guard evaluations since startup.
    pub total_evaluations: u64,
    /// Total CPI evaluations.
    pub cpi_evaluations: u64,
    /// Total MI evaluations.
    pub mi_evaluations: u64,
    /// Total denials.
    pub total_denials: u64,
    /// Total allows.
    pub total_allows: u64,
    /// CPI denials.
    pub cpi_denials: u64,
    /// MI denials.
    pub mi_denials: u64,
    /// Total ConversationIO evaluations.
    pub cio_evaluations: u64,
    /// ConversationIO denials.
    pub cio_denials: u64,
    /// Average evaluation time in microseconds.
    pub avg_eval_us: u64,
    /// P50 evaluation time in microseconds.
    pub p50_eval_us: u64,
    /// P95 evaluation time in microseconds.
    pub p95_eval_us: u64,
    /// P99 evaluation time in microseconds.
    pub p99_eval_us: u64,
    /// Maximum evaluation time in microseconds.
    pub max_eval_us: u64,
    /// Minimum evaluation time in microseconds.
    pub min_eval_us: u64,
    /// Evaluations per second (throughput).
    pub evals_per_sec: f64,
    /// When metrics collection started.
    pub started_at: DateTime<Utc>,
    /// When this snapshot was taken.
    pub snapshot_at: DateTime<Utc>,
    /// Uptime in seconds.
    pub uptime_secs: u64,
}

/// Internal metrics collector state.
struct MetricsCollector {
    started: Instant,
    started_at: DateTime<Utc>,
    evaluations: Vec<GuardEvaluation>,
    total_evaluations: u64,
    cpi_evaluations: u64,
    mi_evaluations: u64,
    total_denials: u64,
    total_allows: u64,
    cpi_denials: u64,
    mi_denials: u64,
    cio_evaluations: u64,
    cio_denials: u64,
    /// Ring buffer of recent evaluation durations for percentile calculations.
    /// Keeps last 10,000 evaluations.
    recent_durations: Vec<u64>,
}

impl MetricsCollector {
    fn new() -> Self {
        MetricsCollector {
            started: Instant::now(),
            started_at: Utc::now(),
            evaluations: Vec::new(),
            total_evaluations: 0,
            cpi_evaluations: 0,
            mi_evaluations: 0,
            total_denials: 0,
            total_allows: 0,
            cpi_denials: 0,
            mi_denials: 0,
            cio_evaluations: 0,
            cio_denials: 0,
            recent_durations: Vec::with_capacity(10_000),
        }
    }

    fn record(&mut self, surface: GuardSurface, verdict: GuardVerdict, duration: Duration) {
        let duration_us = duration.as_micros() as u64;

        self.total_evaluations += 1;
        match surface {
            GuardSurface::ControlPlane => {
                self.cpi_evaluations += 1;
                if verdict == GuardVerdict::Deny {
                    self.cpi_denials += 1;
                }
            }
            GuardSurface::DurableMemory => {
                self.mi_evaluations += 1;
                if verdict == GuardVerdict::Deny {
                    self.mi_denials += 1;
                }
            }
            GuardSurface::ConversationIO => {
                self.cio_evaluations += 1;
                if verdict == GuardVerdict::Deny {
                    self.cio_denials += 1;
                }
            }
        }

        match verdict {
            GuardVerdict::Allow => self.total_allows += 1,
            GuardVerdict::Deny => self.total_denials += 1,
        }

        // Ring buffer: keep last 10,000
        if self.recent_durations.len() >= 10_000 {
            self.recent_durations.remove(0);
        }
        self.recent_durations.push(duration_us);

        let eval = GuardEvaluation {
            timestamp: Utc::now(),
            surface,
            verdict,
            duration_us,
        };
        // Keep last 1000 evaluations for detailed query
        if self.evaluations.len() >= 1000 {
            self.evaluations.remove(0);
        }
        self.evaluations.push(eval);
    }

    fn snapshot(&self) -> GuardMetrics {
        let now = Instant::now();
        let uptime = now.duration_since(self.started);

        let (avg, p50, p95, p99, min_val, max_val) = if self.recent_durations.is_empty() {
            (0, 0, 0, 0, 0, 0)
        } else {
            let mut sorted = self.recent_durations.clone();
            sorted.sort_unstable();
            let len = sorted.len();
            let avg = sorted.iter().sum::<u64>() / len as u64;
            let p50 = sorted[len / 2];
            let p95 = sorted[(len as f64 * 0.95) as usize];
            let p99 = sorted[std::cmp::min((len as f64 * 0.99) as usize, len - 1)];
            let min_val = sorted[0];
            let max_val = sorted[len - 1];
            (avg, p50, p95, p99, min_val, max_val)
        };

        let uptime_secs = uptime.as_secs().max(1);
        let evals_per_sec = self.total_evaluations as f64 / uptime_secs as f64;

        GuardMetrics {
            total_evaluations: self.total_evaluations,
            cpi_evaluations: self.cpi_evaluations,
            mi_evaluations: self.mi_evaluations,
            total_denials: self.total_denials,
            total_allows: self.total_allows,
            cpi_denials: self.cpi_denials,
            mi_denials: self.mi_denials,
            cio_evaluations: self.cio_evaluations,
            cio_denials: self.cio_denials,
            avg_eval_us: avg,
            p50_eval_us: p50,
            p95_eval_us: p95,
            p99_eval_us: p99,
            max_eval_us: max_val,
            min_eval_us: min_val,
            evals_per_sec,
            started_at: self.started_at,
            snapshot_at: Utc::now(),
            uptime_secs,
        }
    }

    fn recent_evaluations(&self, limit: usize) -> Vec<GuardEvaluation> {
        let start = self.evaluations.len().saturating_sub(limit);
        self.evaluations[start..].to_vec()
    }
}

/// Record a guard evaluation with its timing.
pub fn record_evaluation(surface: GuardSurface, verdict: GuardVerdict, duration: Duration) {
    let mut lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    let collector = lock.get_or_insert_with(MetricsCollector::new);
    collector.record(surface, verdict, duration);
}

/// Get a snapshot of current guard metrics.
pub fn get_metrics() -> GuardMetrics {
    let lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    match lock.as_ref() {
        Some(collector) => collector.snapshot(),
        None => GuardMetrics {
            total_evaluations: 0,
            cpi_evaluations: 0,
            mi_evaluations: 0,
            total_denials: 0,
            total_allows: 0,
            cpi_denials: 0,
            mi_denials: 0,
            cio_evaluations: 0,
            cio_denials: 0,
            avg_eval_us: 0,
            p50_eval_us: 0,
            p95_eval_us: 0,
            p99_eval_us: 0,
            max_eval_us: 0,
            min_eval_us: 0,
            evals_per_sec: 0.0,
            started_at: Utc::now(),
            snapshot_at: Utc::now(),
            uptime_secs: 0,
        },
    }
}

/// Get recent guard evaluations for detailed inspection.
pub fn get_recent_evaluations(limit: usize) -> Vec<GuardEvaluation> {
    let lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    match lock.as_ref() {
        Some(collector) => collector.recent_evaluations(limit),
        None => Vec::new(),
    }
}

/// Reset all metrics (primarily for testing).
pub fn reset_metrics() {
    let mut lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    *lock = Some(MetricsCollector::new());
}

/// A timing guard that records the evaluation duration on drop.
pub struct EvalTimer {
    start: Instant,
    surface: GuardSurface,
    verdict: Option<GuardVerdict>,
}

impl EvalTimer {
    /// Start timing a guard evaluation.
    pub fn start(surface: GuardSurface) -> Self {
        EvalTimer {
            start: Instant::now(),
            surface,
            verdict: None,
        }
    }

    /// Record the verdict and stop timing.
    pub fn finish(mut self, verdict: GuardVerdict) {
        self.verdict = Some(verdict);
        let duration = self.start.elapsed();
        record_evaluation(self.surface, verdict, duration);
    }
}

impl Drop for EvalTimer {
    fn drop(&mut self) {
        // If finish() was called, verdict is set and already recorded.
        // If not called (e.g. panic/early return), record as a denial.
        if self.verdict.is_none() {
            let duration = self.start.elapsed();
            record_evaluation(self.surface, GuardVerdict::Deny, duration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize metrics tests that mutate the process-global METRICS state.
    static METRICS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_metrics_recording() {
        let _lock = METRICS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_metrics();

        record_evaluation(
            GuardSurface::ControlPlane,
            GuardVerdict::Deny,
            Duration::from_micros(100),
        );
        record_evaluation(
            GuardSurface::DurableMemory,
            GuardVerdict::Allow,
            Duration::from_micros(50),
        );
        record_evaluation(
            GuardSurface::ControlPlane,
            GuardVerdict::Allow,
            Duration::from_micros(75),
        );

        let m = get_metrics();
        assert_eq!(m.total_evaluations, 3);
        assert_eq!(m.cpi_evaluations, 2);
        assert_eq!(m.mi_evaluations, 1);
        assert_eq!(m.total_denials, 1);
        assert_eq!(m.total_allows, 2);
        assert_eq!(m.cpi_denials, 1);
        assert_eq!(m.mi_denials, 0);
    }

    #[test]
    fn test_percentiles() {
        let _lock = METRICS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_metrics();

        for i in 1..=100 {
            record_evaluation(
                GuardSurface::ControlPlane,
                GuardVerdict::Allow,
                Duration::from_micros(i),
            );
        }

        let m = get_metrics();
        assert_eq!(m.total_evaluations, 100);
        assert!(m.p50_eval_us > 0);
        assert!(m.p95_eval_us >= m.p50_eval_us);
        assert!(m.p99_eval_us >= m.p95_eval_us);
        assert_eq!(m.min_eval_us, 1);
        assert_eq!(m.max_eval_us, 100);
    }

    #[test]
    fn test_eval_timer() {
        let _lock = METRICS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_metrics();

        let timer = EvalTimer::start(GuardSurface::ControlPlane);
        std::thread::sleep(Duration::from_micros(10));
        timer.finish(GuardVerdict::Deny);

        let m = get_metrics();
        assert_eq!(m.total_evaluations, 1);
        assert_eq!(m.total_denials, 1);
        assert!(m.avg_eval_us >= 10);
    }

    #[test]
    fn test_recent_evaluations() {
        let _lock = METRICS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_metrics();

        for _ in 0..5 {
            record_evaluation(
                GuardSurface::ControlPlane,
                GuardVerdict::Allow,
                Duration::from_micros(10),
            );
        }

        let recent = get_recent_evaluations(3);
        assert_eq!(recent.len(), 3);
    }
}

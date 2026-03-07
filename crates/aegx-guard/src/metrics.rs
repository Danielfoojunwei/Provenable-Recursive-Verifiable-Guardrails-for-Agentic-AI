//! Guard performance metrics tracking.
//!
//! Extracted from aer's prove.rs — provides EvalTimer and GuardMetrics
//! for tracking guard evaluation latencies per surface.

use aegx_types::*;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Instant;

/// Global metrics store.
static METRICS: Mutex<Option<MetricsStore>> = Mutex::new(None);

/// Internal raw metrics store (not serialized directly).
#[derive(Debug, Clone)]
struct MetricsStore {
    control_plane_evals: Vec<f64>,
    memory_evals: Vec<f64>,
    conversation_evals: Vec<f64>,
    start_time: Option<Instant>,
}

impl MetricsStore {
    fn new() -> Self {
        MetricsStore {
            control_plane_evals: Vec::new(),
            memory_evals: Vec::new(),
            conversation_evals: Vec::new(),
            start_time: Some(Instant::now()),
        }
    }
}

/// Guard evaluation metrics — computed summary of raw evaluation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardMetrics {
    /// Raw evaluation latencies per surface (ms).
    pub control_plane_evals: Vec<f64>,
    pub memory_evals: Vec<f64>,
    pub conversation_evals: Vec<f64>,
    /// Computed summary fields.
    pub evals_per_sec: f64,
    pub avg_eval_us: u64,
    pub p50_eval_us: u64,
    pub p95_eval_us: u64,
    pub p99_eval_us: u64,
    pub max_eval_us: u64,
    pub uptime_secs: u64,
}

impl GuardMetrics {
    pub fn new() -> Self {
        GuardMetrics {
            control_plane_evals: Vec::new(),
            memory_evals: Vec::new(),
            conversation_evals: Vec::new(),
            evals_per_sec: 0.0,
            avg_eval_us: 0,
            p50_eval_us: 0,
            p95_eval_us: 0,
            p99_eval_us: 0,
            max_eval_us: 0,
            uptime_secs: 0,
        }
    }
}

impl Default for GuardMetrics {
    fn default() -> Self {
        Self::new()
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn compute_summary(store: &MetricsStore) -> GuardMetrics {
    let mut all: Vec<f64> = store
        .control_plane_evals
        .iter()
        .chain(&store.memory_evals)
        .chain(&store.conversation_evals)
        .copied()
        .collect();

    let uptime_secs = store
        .start_time
        .map(|s| s.elapsed().as_secs())
        .unwrap_or(0);

    let total = all.len();
    let evals_per_sec = if uptime_secs > 0 {
        total as f64 / uptime_secs as f64
    } else {
        total as f64
    };

    // Convert ms to μs for percentile calculations
    let mut us_vals: Vec<f64> = all.iter().map(|ms| ms * 1000.0).collect();
    us_vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let avg_us = if us_vals.is_empty() {
        0.0
    } else {
        us_vals.iter().sum::<f64>() / us_vals.len() as f64
    };

    GuardMetrics {
        control_plane_evals: store.control_plane_evals.clone(),
        memory_evals: store.memory_evals.clone(),
        conversation_evals: store.conversation_evals.clone(),
        evals_per_sec,
        avg_eval_us: avg_us as u64,
        p50_eval_us: percentile(&us_vals, 50.0) as u64,
        p95_eval_us: percentile(&us_vals, 95.0) as u64,
        p99_eval_us: percentile(&us_vals, 99.0) as u64,
        max_eval_us: us_vals.last().copied().unwrap_or(0.0) as u64,
        uptime_secs,
    }
}

/// Timer for guard evaluations.
pub struct EvalTimer {
    start: Instant,
    surface: GuardSurface,
}

impl EvalTimer {
    pub fn start(surface: GuardSurface) -> Self {
        EvalTimer {
            start: Instant::now(),
            surface,
        }
    }

    pub fn finish(self, _verdict: GuardVerdict) {
        let elapsed_ms = self.start.elapsed().as_secs_f64() * 1000.0;
        record_evaluation(self.surface, elapsed_ms);
    }
}

/// Record an evaluation time for a surface.
pub fn record_evaluation(surface: GuardSurface, elapsed_ms: f64) {
    let mut lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    let store = lock.get_or_insert_with(MetricsStore::new);
    match surface {
        GuardSurface::ControlPlane => store.control_plane_evals.push(elapsed_ms),
        GuardSurface::DurableMemory => store.memory_evals.push(elapsed_ms),
        GuardSurface::ConversationIO => store.conversation_evals.push(elapsed_ms),
    }
}

/// Get a computed snapshot of the current metrics.
pub fn get_metrics() -> GuardMetrics {
    let lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    match &*lock {
        Some(store) => compute_summary(store),
        None => GuardMetrics::new(),
    }
}

/// Reset all metrics.
pub fn reset_metrics() {
    let mut lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    *lock = Some(MetricsStore::new());
}

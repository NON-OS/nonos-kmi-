use std::collections::VecDeque;
use std::time::Instant;

use crate::crypto_harness::{HarnessEvent, TestMetrics, BenchmarkSample};

#[derive(Debug, Clone)]
pub struct VisualizationState {
    pub test_history: VecDeque<TestResult>,
    pub benchmark_samples: VecDeque<BenchmarkSample>,
    pub performance_timeline: VecDeque<PerformancePoint>,
    pub current_test_progress: Option<TestProgress>,
    pub max_samples: usize,
}

#[derive(Debug, Clone)]
pub struct TestResult {
    pub id: u64,
    pub name: String,
    pub success: bool,
    pub metrics: TestMetrics,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub struct TestProgress {
    pub id: u64,
    pub name: String,
    pub done: usize,
    pub total: usize,
    pub started: Instant,
}

#[derive(Debug, Clone)]
pub struct PerformancePoint {
    pub timestamp: Instant,
    pub ops_per_sec: f64,
    pub latency_ns: u128,
}

impl VisualizationState {
    pub fn new() -> Self {
        Self {
            test_history: VecDeque::new(),
            benchmark_samples: VecDeque::new(),
            performance_timeline: VecDeque::new(),
            current_test_progress: None,
            max_samples: 1000,
        }
    }

    pub fn process_harness_event(&mut self, event: HarnessEvent) {
        match event {
            HarnessEvent::TestStarted { id, name, total_cases } => {
                self.current_test_progress = Some(TestProgress {
                    id,
                    name,
                    done: 0,
                    total: total_cases,
                    started: Instant::now(),
                });
            }
            HarnessEvent::TestProgress { id, done, total } => {
                if let Some(ref mut progress) = self.current_test_progress {
                    if progress.id == id {
                        progress.done = done;
                        progress.total = total;
                    }
                }
            }
            HarnessEvent::TestCompleted { id, name, success, metrics } => {
                let result = TestResult {
                    id,
                    name,
                    success,
                    metrics,
                    timestamp: Instant::now(),
                };
                self.test_history.push_back(result);
                if self.test_history.len() > self.max_samples {
                    self.test_history.pop_front();
                }
                if let Some(ref progress) = self.current_test_progress {
                    if progress.id == id {
                        self.current_test_progress = None;
                    }
                }
            }
            HarnessEvent::BenchmarkSample { id: _, sample } => {
                self.benchmark_samples.push_back(sample.clone());
                if self.benchmark_samples.len() > self.max_samples {
                    self.benchmark_samples.pop_front();
                }
                
                let perf_point = PerformancePoint {
                    timestamp: Instant::now(),
                    ops_per_sec: 1_000_000_000.0 / (sample.latency_ns as f64),
                    latency_ns: sample.latency_ns,
                };
                self.performance_timeline.push_back(perf_point);
                if self.performance_timeline.len() > self.max_samples {
                    self.performance_timeline.pop_front();
                }
            }
            HarnessEvent::Error { id: _, msg: _ } => {
            }
        }
    }

    pub fn get_latest_benchmark_data(&self) -> Vec<(f64, f64)> {
        self.performance_timeline
            .iter()
            .enumerate()
            .map(|(i, point)| (i as f64, point.ops_per_sec))
            .collect()
    }

    pub fn get_latency_data(&self) -> Vec<(f64, f64)> {
        self.benchmark_samples
            .iter()
            .enumerate()
            .map(|(i, sample)| (i as f64, sample.latency_ns as f64 / 1_000_000.0))
            .collect()
    }

    pub fn get_test_success_rate(&self) -> f64 {
        if self.test_history.is_empty() {
            return 0.0;
        }
        let successful = self.test_history.iter().filter(|t| t.success).count();
        successful as f64 / self.test_history.len() as f64
    }

    pub fn get_average_latency(&self) -> Option<f64> {
        if self.benchmark_samples.is_empty() {
            return None;
        }
        let sum: u128 = self.benchmark_samples.iter().map(|s| s.latency_ns).sum();
        Some(sum as f64 / self.benchmark_samples.len() as f64)
    }

    pub fn get_throughput_stats(&self) -> (f64, f64, f64) {
        if self.performance_timeline.is_empty() {
            return (0.0, 0.0, 0.0);
        }
        let ops: Vec<f64> = self.performance_timeline.iter().map(|p| p.ops_per_sec).collect();
        let min = ops.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = ops.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = ops.iter().sum::<f64>() / ops.len() as f64;
        (min, max, avg)
    }

    pub fn clear_data(&mut self) {
        self.test_history.clear();
        self.benchmark_samples.clear();
        self.performance_timeline.clear();
        self.current_test_progress = None;
    }
}

impl Default for VisualizationState {
    fn default() -> Self {
        Self::new()
    }
}

use crossbeam_channel::Sender;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::crypto_provider::DynProvider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HarnessEvent {
    TestStarted { id: u64, name: String, total_cases: usize },
    TestProgress { id: u64, done: usize, total: usize },
    TestCompleted { id: u64, name: String, success: bool, metrics: TestMetrics },
    BenchmarkSample { id: u64, sample: BenchmarkSample },
    Error { id: Option<u64>, msg: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMetrics {
    pub duration_ms: u128,
    pub ops_per_sec: f64,
    pub bytes_processed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSample {
    pub timestamp_ms: u128,
    pub latency_ns: u128,
}

pub struct CryptoHarness {
    provider: DynProvider,
    sender: Sender<HarnessEvent>,
    _workers: usize,
}

impl CryptoHarness {
    pub fn new(provider: DynProvider, sender: Sender<HarnessEvent>, workers: usize) -> Self {
        Self { provider, sender, _workers: workers.max(1) }
    }

    pub fn run_aes_gcm_vectors(&self, id: u64, name: &str, vectors: Vec<AesGcmVector>) {
        let prov = Arc::clone(&self.provider);
        let tx = self.sender.clone();
        let name = name.to_string();
        thread::spawn(move || {
            if tx.send(HarnessEvent::TestStarted { id, name: name.clone(), total_cases: vectors.len() }).is_err() { return; }
            let t0 = Instant::now();
            let mut ok = true;
            let mut processed = 0usize;
            let vector_count = vectors.len();
            for (i, v) in vectors.into_iter().enumerate() {
                match prov.aes_gcm_encrypt(&v.key, &v.nonce, &v.aad, &v.plaintext) {
                    Ok(ct) => {
                        processed += v.plaintext.len();
                        if let Some(expected) = v.expected_ciphertext {
                            if expected != ct {
                                let _ = tx.send(HarnessEvent::Error { id: Some(id), msg: format!("vector {} ciphertext mismatch", i) });
                                ok = false;
                            }
                        }
                        match prov.aes_gcm_decrypt(&v.key, &v.nonce, &v.aad, &ct) {
                            Ok(pt) => {
                                if pt != v.plaintext {
                                    let _ = tx.send(HarnessEvent::Error { id: Some(id), msg: format!("vector {} roundtrip mismatch", i) });
                                    ok = false;
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(HarnessEvent::Error { id: Some(id), msg: format!("vector {} decrypt failed: {}", i, e) });
                                ok = false;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(HarnessEvent::Error { id: Some(id), msg: format!("vector {} encrypt failed: {}", i, e) });
                        ok = false;
                    }
                }
                if tx.send(HarnessEvent::TestProgress { id, done: i + 1, total: vector_count }).is_err() { return; }
            }
            let elapsed = t0.elapsed().as_millis();
            let ops_per_sec = if elapsed == 0 { 0.0 } else { (vector_count as f64) * 1000.0 / (elapsed as f64) };
            let metrics = TestMetrics { duration_ms: elapsed, ops_per_sec, bytes_processed: processed };
            let _ = tx.send(HarnessEvent::TestCompleted { id, name, success: ok, metrics });
        });
    }

    pub fn run_benchmark_stream(&self, id: u64, interval_ms: u64) {
        let prov = Arc::clone(&self.provider);
        let tx = self.sender.clone();
        thread::spawn(move || {
            let key = vec![0xAAu8; 32];
            let nonce = vec![0xBBu8; 12];
            let aad = vec![];
            let plaintext = vec![0xCCu8; 1024];
            loop {
                let t0 = Instant::now();
                match prov.aes_gcm_encrypt(&key, &nonce, &aad, &plaintext) {
                    Ok(_) => {
                        let latency = t0.elapsed().as_nanos() as u128;
                        let sample = BenchmarkSample { timestamp_ms: (Instant::now().elapsed().as_millis()) as u128, latency_ns: latency };
                        if tx.send(HarnessEvent::BenchmarkSample { id, sample }).is_err() { return; }
                    }
                    Err(e) => {
                        let _ = tx.send(HarnessEvent::Error { id: Some(id), msg: format!("benchmark error: {}", e) });
                        return;
                    }
                }
                thread::sleep(Duration::from_millis(interval_ms));
            }
        });
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AesGcmVector {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    #[serde(default)]
    pub aad: Vec<u8>,
    pub plaintext: Vec<u8>,
    #[serde(default)]
    pub expected_ciphertext: Option<Vec<u8>>,
}

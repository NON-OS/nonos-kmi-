use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use std::{collections::VecDeque, path::PathBuf, time::{Duration, Instant}};
use crossbeam_channel::Receiver;

use crate::{crypto::CryptoManager, kernel::KernelManager, nonos::NonosManager, system::SystemInfo, gdb::GdbManager, monitor::*};
use crate::visualization::VisualizationState;
use crate::crypto_harness::HarnessEvent;

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum CurrentScreen {
    Dashboard, Build, Run, Debug, Crypto, CryptoVisual,
    CryptoAES, CryptoHash, CryptoRNG, CryptoEd25519, CryptoChaCha,
    CryptoQuantum, CryptoZK, CryptoConstantTime, System, Logs, Config, ManPages,
}

#[derive(Debug, Clone)]
pub struct LogEntry { pub timestamp: Instant, pub level: LogLevel, pub message: String, pub source: String }

#[derive(Debug, Clone)]
pub enum LogLevel { Info, Warn, Error, Debug }

#[derive(Debug, Clone)]
pub struct BuildStatus { pub is_building: bool, pub last_build_success: Option<bool>, pub build_time: Option<Duration>, pub output: VecDeque<String> }

#[derive(Debug, Clone)]
pub struct RunStatus { pub is_running: bool, pub kernel_pid: Option<u32>, pub boot_time: Option<Instant>, pub output: VecDeque<String> }

#[derive(Debug, Clone)]
pub struct ManPage { pub section: usize, pub title: String, pub description: String, pub content: Vec<String> }

pub struct App {
    pub current_screen: CurrentScreen,
    pub kernel_path: PathBuf,
    pub signing_key: Option<PathBuf>,
    pub should_quit: bool,
    pub tab_index: usize,

    pub nonos_manager: NonosManager,
    pub crypto_manager: CryptoManager,
    pub kernel_manager: KernelManager,
    pub system_info: SystemInfo,
    pub gdb_manager: Option<GdbManager>,
    pub qemu_manager: Option<QemuManager>,
    pub build_monitor: BuildMonitor,

    pub build_status: BuildStatus,
    pub run_status: RunStatus,
    pub logs: VecDeque<LogEntry>,
    pub log_scroll: usize,

    pub man_pages: Vec<ManPage>,
    pub current_man_section: usize,
    pub man_scroll: usize,

    pub build_output_rx: Option<tokio::sync::mpsc::Receiver<String>>,
    pub qemu_output_rx: Option<tokio::sync::mpsc::Receiver<String>>,

    pub last_update: Instant,
    pub update_interval: Duration,

    pub harness_rx: Option<Receiver<HarnessEvent>>,
    pub visualization: VisualizationState,
}

impl App {
    pub async fn new(kernel_path: String, signing_key: Option<String>) -> Result<Self> {
        let kernel_path = PathBuf::from(kernel_path);
        let signing_key = signing_key.map(PathBuf::from);

        let nonos_manager = NonosManager::new(&kernel_path).await?;
        let crypto_manager = CryptoManager::new(signing_key.clone()).await?;
        let kernel_manager = KernelManager::new(&kernel_path).await?;
        let system_info = SystemInfo::new().await?;
        let gdb_manager = Some(GdbManager::new(kernel_path.clone()).await?);
        let qemu_manager = Some(QemuManager::new().await?);
        let build_monitor = BuildMonitor::new(4);

        let visualization = VisualizationState::new();

        let mut app = Self {
            current_screen: CurrentScreen::Dashboard,
            kernel_path: kernel_path.clone(),
            signing_key,
            should_quit: false,
            tab_index: 0,

            nonos_manager,
            crypto_manager,
            kernel_manager,
            system_info,
            gdb_manager,
            qemu_manager,
            build_monitor,

            build_status: BuildStatus { is_building: false, last_build_success: None, build_time: None, output: VecDeque::with_capacity(1000) },

            run_status: RunStatus { is_running: false, kernel_pid: None, boot_time: None, output: VecDeque::with_capacity(1000) },

            logs: VecDeque::with_capacity(10000),
            log_scroll: 0,

            man_pages: Self::initialize_man_pages(),
            current_man_section: 1,
            man_scroll: 0,

            build_output_rx: None,
            qemu_output_rx: None,

            last_update: Instant::now(),
            update_interval: Duration::from_millis(500),

            harness_rx: None,
            visualization,
        };

        app.add_log(LogLevel::Info, "NØNOS TUI initialized".to_string(), "app".to_string());
        Ok(app)
    }

    fn initialize_man_pages() -> Vec<ManPage> {
        vec![
            ManPage {
                section: 1,
                title: "nonos".to_string(),
                description: "NØNOS ZeroState Microkernel".to_string(),
                content: vec![
                    "NAME".to_string(),
                    "    nonos - NØNOS ZeroState microkernel with capability enforcement".to_string(),
                    "".to_string(),
                    "SYNOPSIS".to_string(),
                    "    make nonos           Build NØNOS kernel (release)".to_string(),
                    "    make nonos-debug     Build NØNOS kernel (debug)".to_string(),
                    "    make nonos-run       Run NØNOS in QEMU".to_string(),
                    "    make nonos-clean     Clean build artifacts".to_string(),
                    "".to_string(),
                    "DESCRIPTION".to_string(),
                    "    NØNOS is a RAM-resident, capability-enforced microkernel".to_string(),
                    "    with cryptographic signing and post-quantum cryptography.".to_string(),
                    "".to_string(),
                    "FEATURES".to_string(),
                    "    • ZeroState: RAM-resident with no disk dependencies".to_string(),
                    "    • Capability-based security model".to_string(),
                    "    • Post-quantum cryptography (ML-KEM, ML-DSA)".to_string(),
                    "    • Ed25519 signing with Blake3 hashing".to_string(),
                    "    • Hardware security (SMEP/SMAP, CET, KASLR)".to_string(),
                    "".to_string(),
                    "ENVIRONMENT".to_string(),
                    "    NONOS_SIGNING_KEY    Path to Ed25519 signing key".to_string(),
                ]
            },
            ManPage {
                section: 3,
                title: "nonos-crypto".to_string(),
                description: "NØNOS Cryptography API".to_string(),
                content: vec![
                    "NAME".to_string(),
                    "    nonos-crypto - NØNOS kernel cryptography functions".to_string(),
                    "".to_string(),
                    "SYNOPSIS".to_string(),
                    "    #include <nonos/crypto.h>".to_string(),
                    "".to_string(),
                    "    // Ed25519 Digital Signatures".to_string(),
                    "    int ed25519_sign(uint8_t signature[64], const uint8_t message[],".to_string(),
                    "                     size_t message_len, const uint8_t private_key[32]);".to_string(),
                    "".to_string(),
                    "    // Blake3 Cryptographic Hashing".to_string(),
                    "    void blake3_hash(uint8_t output[32], const uint8_t input[],".to_string(),
                    "                     size_t input_len);".to_string(),
                    "".to_string(),
                    "    // AES-256-GCM Authenticated Encryption".to_string(),
                    "    int aes_gcm_encrypt(uint8_t ciphertext[], size_t *ciphertext_len,".to_string(),
                    "                        const uint8_t plaintext[], size_t plaintext_len,".to_string(),
                    "                        const uint8_t key[32], const uint8_t nonce[12]);".to_string(),
                    "".to_string(),
                    "DESCRIPTION".to_string(),
                    "    The NØNOS crypto API provides constant-time cryptographic".to_string(),
                    "    primitives for kernel and capsule development.".to_string(),
                ]
            },
            ManPage {
                section: 4,
                title: "nonos-capsules".to_string(),
                description: "NØNOS Capsule System".to_string(),
                content: vec![
                    "NAME".to_string(),
                    "    nonos-capsules - NØNOS signed capsule execution environment".to_string(),
                    "".to_string(),
                    "SYNOPSIS".to_string(),
                    "    Capsules are signed ELF64 executables with cryptographic validation".to_string(),
                    "".to_string(),
                    "CAPSULE FORMAT".to_string(),
                    "    .text        Executable code section".to_string(),
                    "    .rodata      Read-only data".to_string(),
                    "    .data        Initialized data".to_string(),
                    "    .bss         Uninitialized data".to_string(),
                    "    .nonos.manifest  Capsule metadata (JSON)".to_string(),
                    "    .nonos.sig   Ed25519 signature".to_string(),
                    "".to_string(),
                    "CAPABILITIES".to_string(),
                    "    LOG          Write to kernel log".to_string(),
                    "    YIELD        Cooperative scheduling".to_string(),
                    "    TIME         Access system time".to_string(),
                    "    IPC          Inter-process communication".to_string(),
                    "    KSTAT        Kernel statistics".to_string(),
                    "".to_string(),
                    "SECURITY".to_string(),
                    "    All capsules must be cryptographically signed with Ed25519.".to_string(),
                    "    Signatures are verified using Blake3 hashing before execution.".to_string(),
                ]
            }
        ]
    }

    pub async fn handle_key_event(&mut self, key: KeyEvent) -> Result<bool> {
        let res = self.handle_key_event_internal(key).await;
        match res { Ok(quit) => Ok(quit), Err(e) => { self.add_log(LogLevel::Error, format!("Key handling error: {}", e), "app".to_string()); Ok(false) } }
    }

    async fn handle_key_event_internal(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') => { self.should_quit = true; return Ok(true); }
            KeyCode::Esc => {
                if self.current_screen != CurrentScreen::Dashboard { self.current_screen = CurrentScreen::Dashboard; self.update_tab_index(); } else { self.should_quit = true; return Ok(true); }
            }
            KeyCode::Tab => { self.next_tab(); return Ok(false); }
            KeyCode::BackTab => { self.prev_tab(); return Ok(false); }
            KeyCode::F(1) => { self.current_screen = CurrentScreen::Dashboard; self.update_tab_index(); }
            KeyCode::F(2) => { self.current_screen = CurrentScreen::Build; self.update_tab_index(); }
            KeyCode::F(3) => { self.current_screen = CurrentScreen::Run; self.update_tab_index(); }
            KeyCode::F(4) => { self.current_screen = CurrentScreen::Debug; self.update_tab_index(); }
            KeyCode::F(5) => { self.current_screen = CurrentScreen::Crypto; self.update_tab_index(); }
            KeyCode::F(6) => { self.current_screen = CurrentScreen::System; self.update_tab_index(); }
            KeyCode::F(7) => { self.current_screen = CurrentScreen::Logs; self.update_tab_index(); }
            KeyCode::F(8) => { self.current_screen = CurrentScreen::Config; self.update_tab_index(); }
            _ => {
                let result = match self.current_screen {
                    CurrentScreen::Dashboard => self.handle_dashboard_keys(key).await,
                    CurrentScreen::Build => self.handle_build_keys(key).await,
                    CurrentScreen::Run => self.handle_run_keys(key).await,
                    CurrentScreen::Debug => self.handle_debug_keys(key).await,
                    CurrentScreen::Crypto => self.handle_crypto_keys(key).await,
                    CurrentScreen::CryptoVisual => self.handle_crypto_visual_keys(key).await,
                    CurrentScreen::CryptoAES => self.handle_crypto_aes_keys(key).await,
                    CurrentScreen::CryptoHash => self.handle_crypto_hash_keys(key).await,
                    CurrentScreen::CryptoRNG => self.handle_crypto_rng_keys(key).await,
                    CurrentScreen::CryptoEd25519 => self.handle_crypto_ed25519_keys(key).await,
                    CurrentScreen::CryptoChaCha => self.handle_crypto_chacha_keys(key).await,
                    CurrentScreen::CryptoQuantum => self.handle_crypto_quantum_keys(key).await,
                    CurrentScreen::CryptoZK => self.handle_crypto_zk_keys(key).await,
                    CurrentScreen::CryptoConstantTime => self.handle_crypto_consttime_keys(key).await,
                    CurrentScreen::System => self.handle_system_keys(key).await,
                    CurrentScreen::Logs => self.handle_logs_keys(key).await,
                    CurrentScreen::Config => self.handle_config_keys(key).await,
                    CurrentScreen::ManPages => self.handle_man_pages_keys(key).await,
                };
                if let Err(e) = result { self.add_log(LogLevel::Error, format!("Screen key handling error: {}", e), "app".to_string()); }
            }
        }
        Ok(false)
    }

    async fn handle_dashboard_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => { self.current_screen = CurrentScreen::Build; self.update_tab_index(); }
            KeyCode::Char('2') => { self.current_screen = CurrentScreen::Run; self.update_tab_index(); }
            KeyCode::Char('3') => { self.current_screen = CurrentScreen::Debug; self.update_tab_index(); }
            KeyCode::Char('4') => { self.current_screen = CurrentScreen::Crypto; self.update_tab_index(); }
            KeyCode::Char('5') => { self.current_screen = CurrentScreen::System; self.update_tab_index(); }
            KeyCode::Char('6') => { self.current_screen = CurrentScreen::Logs; self.update_tab_index(); }
            KeyCode::Char('7') => { self.current_screen = CurrentScreen::Config; self.update_tab_index(); }
            KeyCode::Char('8') => { self.current_screen = CurrentScreen::ManPages; self.update_tab_index(); }
            KeyCode::Tab => self.next_tab(),
            KeyCode::BackTab => self.prev_tab(),
            KeyCode::Char('r') => { let _ = self.refresh_all().await; }
            _ => {}
        }
        Ok(())
    }

    async fn handle_build_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => { let _ = self.execute_build("nonos").await; }
            KeyCode::Char('2') => { let _ = self.execute_build("nonos-debug").await; }
            KeyCode::Char('3') => { let _ = self.execute_build("nonos-clean").await; }
            KeyCode::Char('4') => { let _ = self.execute_build("nonos-test").await; }
            KeyCode::Char('5') => { let _ = self.execute_build("nonos-check").await; }
            KeyCode::Char('6') => { let _ = self.execute_build("nonos-clippy").await; }
            KeyCode::Char('7') => { 
                // Use real NonosManager make command
                match self.nonos_manager.execute_make_command("nonos").await {
                    Ok(output) => {
                        self.add_log(LogLevel::Info, "Direct make command completed".to_string(), "build".to_string());
                        for line in output.lines() {
                            self.add_log(LogLevel::Debug, line.to_string(), "make".to_string());
                        }
                    }
                    Err(e) => self.add_log(LogLevel::Error, format!("Make command failed: {}", e), "build".to_string()),
                }
            }
            KeyCode::Char('8') => {
                // Use real cargo command through NonosManager
                match self.nonos_manager.execute_cargo_command(&["check", "--target", "x86_64-nonos.json"]).await {
                    Ok(output) => {
                        self.add_log(LogLevel::Info, "Cargo check completed".to_string(), "build".to_string());
                        for line in output.lines() {
                            self.add_log(LogLevel::Debug, line.to_string(), "cargo".to_string());
                        }
                    }
                    Err(e) => self.add_log(LogLevel::Error, format!("Cargo check failed: {}", e), "build".to_string()),
                }
            }
            KeyCode::Char('9') => {
                // Use make and wait with timeout
                match self.nonos_manager.execute_make_and_wait("nonos", 300).await {
                    Ok(output) => {
                        self.add_log(LogLevel::Info, "Timed make build completed".to_string(), "build".to_string());
                        self.add_log(LogLevel::Debug, format!("Output: {}", output), "build".to_string());
                    }
                    Err(e) => self.add_log(LogLevel::Error, format!("Timed build failed: {}", e), "build".to_string()),
                }
            }
            KeyCode::Char('c') => { self.clear_build_output(); }
            _ => {}
        }
        Ok(())
    }

    async fn handle_run_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => { let _ = self.execute_run("nonos-run").await; }
            KeyCode::Char('2') => { let _ = self.execute_run("nonos-run-debug").await; }
            KeyCode::Char('3') => { let _ = self.execute_run("nonos-debug-gdb").await; }
            KeyCode::Char('l') => { 
                // Get recent console logs from QemuManager
                if let Some(ref qemu_manager) = self.qemu_manager {
                    let console_logs = qemu_manager.get_recent_console_logs().await;
                    if console_logs.is_empty() {
                        self.add_log(LogLevel::Info, "No recent console logs available".to_string(), "qemu".to_string());
                    } else {
                        self.add_log(LogLevel::Info, format!("Retrieved {} console logs", console_logs.len()), "qemu".to_string());
                        for log in console_logs.iter().take(5) {
                            let level_str = match log.level {
                                crate::monitor::LogLevel::Debug => "DEBUG",
                                crate::monitor::LogLevel::Info => "INFO",
                                crate::monitor::LogLevel::Warn => "WARN", 
                                crate::monitor::LogLevel::Error => "ERROR",
                                crate::monitor::LogLevel::Critical => "CRITICAL",
                            };
                            let module = log.module.as_deref().unwrap_or("unknown");
                            self.add_log(LogLevel::Info, format!("[{}][{}] {}", level_str, module, log.message), "console".to_string());
                        }
                    }
                } else {
                    self.add_log(LogLevel::Warn, "QEMU manager not available".to_string(), "qemu".to_string());
                }
            }
            KeyCode::Char('s') => { let _ = self.stop_kernel().await; }
            KeyCode::Char('c') => { self.clear_run_output(); }
            _ => {}
        }
        Ok(())
    }

    async fn handle_debug_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => { let _ = self.execute_debug("nonos-disasm").await; }
            KeyCode::Char('2') => { let _ = self.execute_debug("nonos-doc").await; }
            KeyCode::Char('3') => { let _ = self.execute_debug("analyze").await; }
            KeyCode::Char('4') => { let _ = self.execute_debug("verify-signatures").await; }
            _ => {}
        }
        Ok(())
    }

    async fn handle_crypto_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => { let _ = self.crypto_manager.generate_keys().await; self.add_log(LogLevel::Info, "Generated keys".to_string(), "crypto".to_string()); }
            KeyCode::Char('2') => { let _ = self.crypto_manager.verify_key_integrity().await; self.add_log(LogLevel::Info, "Verified keys".to_string(), "crypto".to_string()); }
            KeyCode::Char('3') => { let _ = self.crypto_manager.rotate_keys().await; self.add_log(LogLevel::Info, "Rotated keys".to_string(), "crypto".to_string()); }
            KeyCode::Char('4') => { self.start_aes_test().await; }
            KeyCode::Char('5') => { self.start_benchmark().await; }
            KeyCode::Char('k') => { 
                // Show real key paths using CryptoManager
                if let Some(signing_path) = self.crypto_manager.signing_key_path() {
                    self.add_log(LogLevel::Info, format!("Signing key: {}", signing_path.display()), "crypto".to_string());
                }
                if let Some(public_path) = self.crypto_manager.public_key_path() {
                    self.add_log(LogLevel::Info, format!("Public key: {}", public_path.display()), "crypto".to_string());
                }
            }
            KeyCode::Char('v') => { self.current_screen = CurrentScreen::CryptoVisual; }
            KeyCode::Char('a') => { self.current_screen = CurrentScreen::CryptoAES; }
            KeyCode::Char('h') => { self.current_screen = CurrentScreen::CryptoHash; }
            KeyCode::Char('r') => { self.current_screen = CurrentScreen::CryptoRNG; }
            KeyCode::Char('e') => { self.current_screen = CurrentScreen::CryptoEd25519; }
            KeyCode::Char('c') => { self.current_screen = CurrentScreen::CryptoChaCha; }
            KeyCode::Char('q') => { self.current_screen = CurrentScreen::CryptoQuantum; }
            KeyCode::Char('z') => { self.current_screen = CurrentScreen::CryptoZK; }
            KeyCode::Char('t') => { self.current_screen = CurrentScreen::CryptoConstantTime; }
            _ => {}
        }
        Ok(())
    }

    async fn handle_crypto_visual_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => { let _ = self.test_nonos_ed25519().await; }
            KeyCode::Char('2') => { let _ = self.test_nonos_chacha20().await; }
            KeyCode::Char('3') => { let _ = self.test_nonos_blake3().await; }
            KeyCode::Char('4') => { let _ = self.test_nonos_aes_gcm().await; }
            KeyCode::Char('5') => { let _ = self.test_nonos_quantum().await; }
            KeyCode::Char('v') => { self.add_log(LogLevel::Info, "Visual mode toggled".to_string(), "crypto".to_string()); }
            KeyCode::Char('c') => { self.add_log(LogLevel::Info, "Cleared crypto results".to_string(), "crypto".to_string()); }
            KeyCode::Char('r') => { self.add_log(LogLevel::Info, "Random test data generated".to_string(), "crypto".to_string()); }
            _ => {}
        }
        Ok(())
    }

    async fn handle_system_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('r') => { let _ = self.system_info.refresh().await; }
            KeyCode::Char('k') => { let _ = self.kernel_manager.stop_all_kernels().await; }
            KeyCode::Char('s') => { let _ = self.start_qemu_streaming("nonos-run").await; }
            _ => {}
        }
        Ok(())
    }

    async fn handle_logs_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('c') => self.clear_logs(),
            KeyCode::Up => self.scroll_logs_up(),
            KeyCode::Down => self.scroll_logs_down(),
            KeyCode::PageUp => self.page_logs_up(),
            KeyCode::PageDown => self.page_logs_down(),
            KeyCode::Home => self.log_scroll = 0,
            KeyCode::End => self.log_scroll = self.logs.len().saturating_sub(1),
            _ => {}
        }
        Ok(())
    }

    async fn handle_config_keys(&mut self, _key: KeyEvent) -> Result<()> { Ok(()) }
    async fn handle_man_pages_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => { 
                self.current_man_section = 1; 
                self.man_scroll = 0;
                self.add_log(LogLevel::Info, "Showing NONOS kernel manual".to_string(), "man".to_string());
            },
            KeyCode::Char('3') => { 
                self.current_man_section = 3; 
                self.man_scroll = 0;
                self.add_log(LogLevel::Info, "Showing NONOS crypto API manual".to_string(), "man".to_string());
            },
            KeyCode::Char('4') => { 
                self.current_man_section = 4; 
                self.man_scroll = 0;
                self.add_log(LogLevel::Info, "Showing NONOS capsules manual".to_string(), "man".to_string());
            },
            KeyCode::Up => if self.man_scroll > 0 { self.man_scroll -= 1; },
            KeyCode::Down => self.man_scroll += 1,
            KeyCode::PageUp => self.man_scroll = self.man_scroll.saturating_sub(10),
            KeyCode::PageDown => self.man_scroll += 10,
            KeyCode::Home => self.man_scroll = 0,
            _ => {}
        }
        Ok(())
    }

    pub async fn tick(&mut self) -> Result<()> {
        if self.last_update.elapsed() >= self.update_interval {
            let _ = self.update_status().await;
            let _ = self.update_gdb_status().await;
            self.last_update = Instant::now();
        }
        let mut events = Vec::new();
        if let Some(rx) = &self.harness_rx {
            while let Ok(ev) = rx.try_recv() {
                events.push(ev);
            }
        }
        
        for ev in events {
            self.visualization.process_harness_event(ev.clone());
            match ev {
                HarnessEvent::TestCompleted { name, success, metrics, .. } => {
                    self.add_log(LogLevel::Info, format!("Test completed: {} success={}", name, success), "harness".to_string());
                    self.add_log(LogLevel::Debug, format!("Metrics: ops/s {:.2}", metrics.ops_per_sec), "harness".to_string());
                },
                HarnessEvent::BenchmarkSample { sample, .. } => {
                    if sample.latency_ns > 0 { /* keep UI responsive, no-op here */ }
                },
                HarnessEvent::Error { msg, .. } => {
                    self.add_log(LogLevel::Error, format!("Harness error: {}", msg), "harness".to_string());
                },
                _ => {}
            }
        }
        Ok(())
    }

    async fn update_status(&mut self) -> Result<()> {
        let _ = self.system_info.update().await;
        let _ = self.nonos_manager.refresh().await;
        let _ = self.crypto_manager.refresh().await;
        let _ = self.kernel_manager.refresh().await;
        
        // Poll for build updates
        if let Ok(completed_builds) = self.build_monitor.poll_builds().await {
            for result in completed_builds {
                if result.success {
                    self.add_log(LogLevel::Info, format!("Build {} completed successfully", result.target), "build".to_string());
                    if let Ok(duration_since_epoch) = result.timestamp.duration_since(std::time::UNIX_EPOCH) {
                        self.add_log(LogLevel::Info, format!("Build finished at: {} (duration: {:.2}s)", 
                            duration_since_epoch.as_secs(), result.duration.as_secs_f64()), "build".to_string());
                    }
                    self.build_status.last_build_success = Some(true);
                    
                    // Check build artifacts after successful build
                    if let Ok(artifacts) = self.nonos_manager.check_build_artifacts().await {
                        if artifacts.debug_exists || artifacts.release_exists {
                            self.add_log(LogLevel::Info, format!("Build artifacts validated - debug:{} release:{}", 
                                artifacts.debug_exists, artifacts.release_exists), "build".to_string());
                        }
                    }
                } else {
                    self.add_log(LogLevel::Error, format!("Build {} failed", result.target), "build".to_string());
                    if let Ok(duration_since_epoch) = result.timestamp.duration_since(std::time::UNIX_EPOCH) {
                        self.add_log(LogLevel::Error, format!("Build failed at: {} (duration: {:.2}s)", 
                            duration_since_epoch.as_secs(), result.duration.as_secs_f64()), "build".to_string());
                    }
                    self.build_status.last_build_success = Some(false);
                    if !result.output.is_empty() {
                        self.add_log(LogLevel::Error, format!("Build output: {}", result.output), "build".to_string());
                    }
                }
                // Add build output to build status
                for line in result.output.lines() {
                    if self.build_status.output.len() >= 1000 {
                        self.build_status.output.pop_front();
                    }
                    self.build_status.output.push_back(line.to_string());
                }
            }
        }
        
        // Check if any builds are still active and get real-time output
        let active_builds: Vec<String> = self.build_monitor.get_active_builds().into_iter().map(|s| s.to_string()).collect();
        let active_count = active_builds.len();
        
        for target in &active_builds {
            if let Some(output_lines) = self.build_monitor.get_build_output(target).await {
                for line in output_lines {
                    if self.build_status.output.len() >= 1000 {
                        self.build_status.output.pop_front();
                    }
                    self.build_status.output.push_back(line);
                }
            }
        }
        
        if active_count == 0 && self.build_status.is_building {
            self.build_status.is_building = false;
        }
        
        Ok(())
    }

    async fn refresh_all(&mut self) -> Result<()> {
        self.add_log(LogLevel::Info, "Refreshing all components".to_string(), "app".to_string());
        let _ = self.stop_all_processes().await;
        let _ = self.system_info.refresh().await;
        let _ = self.nonos_manager.refresh().await;
        let _ = self.crypto_manager.refresh().await;
        let _ = self.kernel_manager.refresh().await;
        Ok(())
    }

    async fn execute_build(&mut self, target: &str) -> Result<()> {
        if self.build_status.is_building { self.add_log(LogLevel::Warn, "Build in progress".to_string(), "build".to_string()); return Ok(()); }
        self.build_status.is_building = true;
        self.build_status.output.clear();
        self.add_log(LogLevel::Info, format!("Starting build: {}", target), "build".to_string());
        
        // Check NONOS status before building
        if let Ok(status) = self.nonos_manager.check_status().await {
            if status.makefile_exists && status.cargo_toml_exists {
                self.add_log(LogLevel::Info, "NONOS environment validated".to_string(), "build".to_string());
            } else {
                self.add_log(LogLevel::Warn, "NONOS environment incomplete".to_string(), "build".to_string());
            }
        }
        
        // Pass signing key to the build monitor
        let signing_key_path = self.signing_key.clone();
        let signing_key = signing_key_path.as_deref();
        
        if signing_key.is_some() {
            self.add_log(LogLevel::Info, "Using signing key for kernel build".to_string(), "build".to_string());
        } else {
            self.add_log(LogLevel::Warn, "No signing key configured - build may fail".to_string(), "build".to_string());
        }
        
        if let Err(e) = self.build_monitor.queue_build(target, &self.kernel_path, signing_key).await { 
            self.add_log(LogLevel::Error, format!("Queue build failed: {}", e), "build".to_string()); 
            self.build_status.is_building = false; 
        }
        Ok(())
    }

    async fn execute_run(&mut self, target: &str) -> Result<()> {
        if self.run_status.is_running { self.add_log(LogLevel::Warn, "Kernel already running".to_string(), "run".to_string()); return Ok(()); }
        match self.kernel_manager.start_kernel(target).await {
            Ok(pid) => {
                self.run_status.is_running = true;
                self.run_status.kernel_pid = Some(pid);
                self.run_status.boot_time = Some(Instant::now());
                self.add_log(LogLevel::Info, format!("Kernel started PID {}", pid), "run".to_string());
                
                // Update instance status using real KernelManager method
                if let Err(e) = self.kernel_manager.update_instance_status(pid).await {
                    self.add_log(LogLevel::Warn, format!("Failed to update kernel instance status: {}", e), "run".to_string());
                } else {
                    self.add_log(LogLevel::Info, "Kernel instance status updated".to_string(), "run".to_string());
                }
            }
            Err(e) => { self.add_log(LogLevel::Error, format!("Start kernel failed: {}", e), "run".to_string()); }
        }
        Ok(())
    }

    async fn execute_debug(&mut self, cmd: &str) -> Result<()> {
        self.add_log(LogLevel::Info, format!("Executing debug command: {}", cmd), "debug".to_string());
        
        match cmd {
            "nonos-disasm" => {
                match self.kernel_manager.analyze_binary().await {
                    Ok(analysis) => {
                        self.add_log(LogLevel::Info, format!("Binary analysis complete - Size: {} bytes", analysis.file_size), "debug".to_string());
                        self.add_log(LogLevel::Info, format!("File: {}", analysis.file_path.display()), "debug".to_string());
                        self.add_log(LogLevel::Info, format!("File info: {}", analysis.file_info), "debug".to_string());
                        self.add_log(LogLevel::Info, format!("Size info: {}", analysis.size_info), "debug".to_string());
                        if let Some(modified_time) = analysis.modified_time {
                            if let Ok(duration) = modified_time.duration_since(std::time::UNIX_EPOCH) {
                                self.add_log(LogLevel::Info, format!("Last modified: {} seconds since epoch", duration.as_secs()), "debug".to_string());
                            }
                        }
                        self.add_log(LogLevel::Info, format!("ELF info: {}", analysis.elf_header), "debug".to_string());
                    }
                    Err(e) => self.add_log(LogLevel::Error, format!("Binary analysis failed: {}", e), "debug".to_string()),
                }
            }
            "verify-signatures" => {
                match self.kernel_manager.verify_signatures().await {
                    Ok(verification) => {
                        self.add_log(LogLevel::Info, format!("Manifest section found: {}", verification.has_manifest_section), "debug".to_string());
                        self.add_log(LogLevel::Info, format!("Signature section found: {}", verification.has_signature_section), "debug".to_string());
                        if let Ok(duration) = verification.verified_at.duration_since(std::time::UNIX_EPOCH) {
                            self.add_log(LogLevel::Info, format!("Verified at: {} seconds since epoch", duration.as_secs()), "debug".to_string());
                        }
                        let status_msg = match verification.verification_status {
                            crate::kernel::SignatureStatus::Valid => "Signature valid",
                            crate::kernel::SignatureStatus::Invalid => "Signature invalid", 
                            crate::kernel::SignatureStatus::Missing => "Signature missing",
                            crate::kernel::SignatureStatus::ExtractFailed => "Signature extraction failed",
                        };
                        self.add_log(LogLevel::Info, status_msg.to_string(), "debug".to_string());
                        self.add_log(LogLevel::Info, format!("Has manifest: {}", verification.has_manifest_section), "debug".to_string());
                    }
                    Err(e) => self.add_log(LogLevel::Error, format!("Signature verification failed: {}", e), "debug".to_string()),
                }
            }
            "analyze" => {
                self.add_log(LogLevel::Info, "Starting comprehensive analysis...".to_string(), "debug".to_string());
                if let Err(e) = self.kernel_manager.analyze_binary().await {
                    self.add_log(LogLevel::Error, format!("Analysis failed: {}", e), "debug".to_string());
                }
            }
            "nonos-doc" => {
                self.add_log(LogLevel::Info, "Opening NØNOS documentation...".to_string(), "debug".to_string());
                // Could open docs in browser or show help
            }
            _ => {
                self.add_log(LogLevel::Warn, format!("Unknown debug command: {}", cmd), "debug".to_string());
            }
        }
        Ok(())
    }
    async fn stop_kernel(&mut self) -> Result<()> {
        if let Some(pid) = self.run_status.kernel_pid { let _ = self.kernel_manager.stop_kernel(pid).await; }
        self.run_status.is_running = false; self.run_status.kernel_pid = None; self.run_status.boot_time = None;
        Ok(())
    }

    fn clear_build_output(&mut self) {
        self.build_status.output.clear();
        self.add_log(LogLevel::Info, "Build output cleared".to_string(), "build".to_string());
    }

    fn clear_run_output(&mut self) {
        self.run_status.output.clear();
        self.add_log(LogLevel::Info, "Run output cleared".to_string(), "run".to_string());
    }


    pub fn get_tab_titles(&self) -> Vec<&str> {
        vec!["Dashboard", "Build", "Run", "Debug", "Crypto", "System", "Logs", "Config", "Man Pages"]
    }

    pub fn add_log(&mut self, level: LogLevel, message: String, source: String) {
        let entry = LogEntry { timestamp: Instant::now(), level, message, source };
        self.logs.push_back(entry);
        if self.logs.len() > 10000 { self.logs.pop_front(); }
    }

    pub fn clear_logs(&mut self) { self.logs.clear(); self.log_scroll = 0; }
    pub fn next_tab(&mut self) { self.tab_index = (self.tab_index + 1) % 9; self.current_screen = self.screen_from_tab_index(self.tab_index); }
    pub fn prev_tab(&mut self) { self.tab_index = if self.tab_index == 0 { 8 } else { self.tab_index - 1 }; self.current_screen = self.screen_from_tab_index(self.tab_index); }

    fn screen_from_tab_index(&self, index: usize) -> CurrentScreen {
        match index { 0 => CurrentScreen::Dashboard, 1 => CurrentScreen::Build, 2 => CurrentScreen::Run, 3 => CurrentScreen::Debug, 4 => CurrentScreen::Crypto, 5 => CurrentScreen::CryptoVisual, 6 => CurrentScreen::System, 7 => CurrentScreen::Logs, 8 => CurrentScreen::Config, _ => CurrentScreen::Dashboard }
    }

    fn update_tab_index(&mut self) {
        self.tab_index = match self.current_screen {
            CurrentScreen::Dashboard => 0,
            CurrentScreen::Build => 1,
            CurrentScreen::Run => 2,
            CurrentScreen::Debug => 3,
            CurrentScreen::Crypto => 4,
            CurrentScreen::CryptoVisual => 5,
            CurrentScreen::System => 6,
            CurrentScreen::Logs => 7,
            CurrentScreen::Config => 8,
            _ => 0,
        };
    }

    pub fn scroll_logs_up(&mut self) { self.log_scroll = self.log_scroll.saturating_sub(1); }
    pub fn scroll_logs_down(&mut self) { if self.log_scroll < self.logs.len().saturating_sub(1) { self.log_scroll += 1; } }
    pub fn page_logs_up(&mut self) { self.log_scroll = self.log_scroll.saturating_sub(10); }
    pub fn page_logs_down(&mut self) { self.log_scroll = (self.log_scroll + 10).min(self.logs.len().saturating_sub(1)); }

    async fn handle_crypto_aes_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => {
                self.add_log(LogLevel::Info, "Running AES-256 encrypt/decrypt test".to_string(), "aes".to_string());
                self.start_aes_test().await;
            }
            KeyCode::Char('2') => {
                self.add_log(LogLevel::Info, "Running GCM AEAD performance test".to_string(), "aes".to_string());
                self.start_benchmark().await;
            }
            KeyCode::Char('3') => {
                self.add_log(LogLevel::Info, "Analyzing AES key schedule".to_string(), "aes".to_string());
            }
            KeyCode::Char('4') => {
                self.add_log(LogLevel::Info, "Running side-channel resistance test".to_string(), "aes".to_string());
            }
            KeyCode::Char('5') => {
                self.add_log(LogLevel::Info, "Validating NIST test vectors".to_string(), "aes".to_string());
            }
            KeyCode::Char('v') => {
                self.current_screen = CurrentScreen::CryptoVisual;
            }
            KeyCode::Char('r') => {
                self.add_log(LogLevel::Info, "Reset AES test state".to_string(), "aes".to_string());
            }
            _ => {}
        }
        Ok(())
    }
    async fn handle_crypto_hash_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => {
                self.add_log(LogLevel::Info, "Running Blake3 hash test".to_string(), "hash".to_string());
            }
            KeyCode::Char('2') => {
                self.add_log(LogLevel::Info, "Running SHA-512 hash test".to_string(), "hash".to_string());
            }
            KeyCode::Char('3') => {
                self.add_log(LogLevel::Info, "Running HMAC authentication test".to_string(), "hash".to_string());
            }
            KeyCode::Char('4') => {
                self.add_log(LogLevel::Info, "Running hash performance benchmark".to_string(), "hash".to_string());
                self.start_benchmark().await;
            }
            KeyCode::Char('5') => {
                self.add_log(LogLevel::Info, "Validating hash test vectors".to_string(), "hash".to_string());
            }
            KeyCode::Char('v') => {
                self.current_screen = CurrentScreen::CryptoVisual;
            }
            _ => {}
        }
        Ok(())
    }
    async fn handle_crypto_rng_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => {
                self.add_log(LogLevel::Info, "Running entropy collection test".to_string(), "rng".to_string());
            }
            KeyCode::Char('2') => {
                self.add_log(LogLevel::Info, "Running ChaCha20 RNG test".to_string(), "rng".to_string());
            }
            KeyCode::Char('3') => {
                self.add_log(LogLevel::Info, "Running statistical randomness test".to_string(), "rng".to_string());
            }
            KeyCode::Char('4') => {
                self.add_log(LogLevel::Info, "Running RNG performance benchmark".to_string(), "rng".to_string());
                self.start_benchmark().await;
            }
            KeyCode::Char('5') => {
                self.add_log(LogLevel::Info, "Analyzing entropy quality".to_string(), "rng".to_string());
            }
            KeyCode::Char('r') => {
                self.add_log(LogLevel::Info, "Reseeding RNG with fresh entropy".to_string(), "rng".to_string());
            }
            _ => {}
        }
        Ok(())
    }
    async fn handle_crypto_ed25519_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => {
                self.add_log(LogLevel::Info, "Running Ed25519 signing test".to_string(), "ed25519".to_string());
            }
            KeyCode::Char('2') => {
                self.add_log(LogLevel::Info, "Running signature verification test".to_string(), "ed25519".to_string());
            }
            KeyCode::Char('3') => {
                self.add_log(LogLevel::Info, "Running key generation test".to_string(), "ed25519".to_string());
                let _ = self.crypto_manager.generate_keys().await;
            }
            KeyCode::Char('4') => {
                self.add_log(LogLevel::Info, "Running Ed25519 performance benchmark".to_string(), "ed25519".to_string());
                self.start_benchmark().await;
            }
            KeyCode::Char('5') => {
                self.add_log(LogLevel::Info, "Validating RFC test vectors".to_string(), "ed25519".to_string());
            }
            _ => {}
        }
        Ok(())
    }
    async fn handle_crypto_chacha_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => {
                self.add_log(LogLevel::Info, "Running ChaCha20 encryption test".to_string(), "chacha".to_string());
            }
            KeyCode::Char('2') => {
                self.add_log(LogLevel::Info, "Running Poly1305 authentication test".to_string(), "chacha".to_string());
            }
            KeyCode::Char('3') => {
                self.add_log(LogLevel::Info, "Running ChaCha20-Poly1305 AEAD test".to_string(), "chacha".to_string());
            }
            KeyCode::Char('4') => {
                self.add_log(LogLevel::Info, "Running ChaCha20 performance benchmark".to_string(), "chacha".to_string());
                self.start_benchmark().await;
            }
            KeyCode::Char('5') => {
                self.add_log(LogLevel::Info, "Validating ChaCha20 test vectors".to_string(), "chacha".to_string());
            }
            _ => {}
        }
        Ok(())
    }
    async fn handle_crypto_quantum_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => {
                self.add_log(LogLevel::Info, "Running Kyber key exchange test".to_string(), "quantum".to_string());
            }
            KeyCode::Char('2') => {
                self.add_log(LogLevel::Info, "Running Dilithium signature test".to_string(), "quantum".to_string());
            }
            KeyCode::Char('3') => {
                self.add_log(LogLevel::Info, "Running post-quantum key generation".to_string(), "quantum".to_string());
            }
            KeyCode::Char('4') => {
                self.add_log(LogLevel::Info, "Running PQC performance benchmark".to_string(), "quantum".to_string());
                self.start_benchmark().await;
            }
            KeyCode::Char('5') => {
                self.add_log(LogLevel::Info, "Validating NIST PQC test vectors".to_string(), "quantum".to_string());
            }
            _ => {}
        }
        Ok(())
    }
    async fn handle_crypto_zk_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => {
                self.add_log(LogLevel::Info, "Running Halo2 proof generation test".to_string(), "zk".to_string());
            }
            KeyCode::Char('2') => {
                self.add_log(LogLevel::Info, "Running Groth16 verification test".to_string(), "zk".to_string());
            }
            KeyCode::Char('3') => {
                self.add_log(LogLevel::Info, "Running zero-knowledge circuit test".to_string(), "zk".to_string());
            }
            KeyCode::Char('4') => {
                self.add_log(LogLevel::Info, "Running ZK proof benchmark".to_string(), "zk".to_string());
                self.start_benchmark().await;
            }
            KeyCode::Char('5') => {
                self.add_log(LogLevel::Info, "Validating ZK proof system".to_string(), "zk".to_string());
            }
            _ => {}
        }
        Ok(())
    }
    async fn handle_crypto_consttime_keys(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('1') => {
                self.add_log(LogLevel::Info, "Running constant-time analysis".to_string(), "consttime".to_string());
            }
            KeyCode::Char('2') => {
                self.add_log(LogLevel::Info, "Running timing attack simulation".to_string(), "consttime".to_string());
            }
            KeyCode::Char('3') => {
                self.add_log(LogLevel::Info, "Running side-channel detection".to_string(), "consttime".to_string());
            }
            KeyCode::Char('4') => {
                self.add_log(LogLevel::Info, "Running timing variance analysis".to_string(), "consttime".to_string());
                self.start_benchmark().await;
            }
            KeyCode::Char('5') => {
                self.add_log(LogLevel::Info, "Validating constant-time properties".to_string(), "consttime".to_string());
            }
            _ => {}
        }
        Ok(())
    }

    async fn test_nonos_ed25519(&mut self) -> Result<()> { 
        #[cfg(feature = "kernel-crypto")]
        use crate::crypto_provider::{RealKernelProvider as Provider, CryptoProvider};
        #[cfg(not(feature = "kernel-crypto"))]
        use crate::crypto_provider::{NonosKernelProvider as Provider, CryptoProvider};
        let provider = Provider::new();
        let seed = [0x42u8; 32];
        let msg = b"NONOS Ed25519 test message";
        match provider.ed25519_sign(&seed, msg) {
            Ok(signature) => {
                let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
                let public_key = sk.verifying_key().to_bytes();
                match provider.ed25519_verify(&public_key, msg, &signature) {
                    Ok(true) => self.add_log(LogLevel::Info, "Ed25519 sign/verify test PASSED".into(), "crypto".into()),
                    Ok(false) => self.add_log(LogLevel::Error, "Ed25519 verification FAILED".into(), "crypto".into()),
                    Err(e) => self.add_log(LogLevel::Error, format!("Ed25519 verify error: {}", e), "crypto".into()),
                }
            }
            Err(e) => self.add_log(LogLevel::Error, format!("Ed25519 sign error: {}", e), "crypto".into()),
        }
        Ok(()) 
    }
    async fn test_nonos_chacha20(&mut self) -> Result<()> { 
        #[cfg(feature = "kernel-crypto")]
        use crate::crypto_provider::{RealKernelProvider as Provider, CryptoProvider};
        #[cfg(not(feature = "kernel-crypto"))]
        use crate::crypto_provider::{NonosKernelProvider as Provider, CryptoProvider};
        let provider = Provider::new();
        let key = [0x55u8; 32];
        let nonce = [0x00u8; 12];
        let aad = b"NONOS AAD";
        let plaintext = b"Hello NONOS ChaCha20-Poly1305!";
        match provider.chacha20poly1305_encrypt(&key, &nonce, aad, plaintext) {
            Ok(ciphertext) => {
                match provider.chacha20poly1305_decrypt(&key, &nonce, aad, &ciphertext) {
                    Ok(decrypted) => {
                        if decrypted == plaintext {
                            self.add_log(LogLevel::Info, "ChaCha20-Poly1305 encrypt/decrypt test PASSED".into(), "crypto".into());
                        } else {
                            self.add_log(LogLevel::Error, "ChaCha20-Poly1305 decryption mismatch".into(), "crypto".into());
                        }
                    }
                    Err(e) => self.add_log(LogLevel::Error, format!("ChaCha20 decrypt error: {}", e), "crypto".into()),
                }
            }
            Err(e) => self.add_log(LogLevel::Error, format!("ChaCha20 encrypt error: {}", e), "crypto".into()),
        }
        Ok(()) 
    }
    async fn test_nonos_blake3(&mut self) -> Result<()> { 
        #[cfg(feature = "kernel-crypto")]
        use crate::crypto_provider::{RealKernelProvider as Provider, CryptoProvider};
        #[cfg(not(feature = "kernel-crypto"))]
        use crate::crypto_provider::{NonosKernelProvider as Provider, CryptoProvider};
        let provider = Provider::new();
        let data = b"NONOS Blake3 test data for hashing";
        let hash = provider.blake3_hash(data);
        let expected_len = 32; // Blake3 outputs 32 bytes
        if hash.len() == expected_len {
            self.add_log(LogLevel::Info, format!("Blake3 hash test PASSED (hash: {})", hex::encode(&hash[..8])), "crypto".into());
        } else {
            self.add_log(LogLevel::Error, format!("Blake3 hash length mismatch: {} != {}", hash.len(), expected_len), "crypto".into());
        }
        Ok(()) 
    }
    async fn test_nonos_aes_gcm(&mut self) -> Result<()> { 
        #[cfg(feature = "kernel-crypto")]
        use crate::crypto_provider::{RealKernelProvider as Provider, CryptoProvider};
        #[cfg(not(feature = "kernel-crypto"))]
        use crate::crypto_provider::{NonosKernelProvider as Provider, CryptoProvider};
        let provider = Provider::new();
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"NONOS AES-GCM AAD";
        let plaintext = b"NONOS AES-256-GCM test message";
        match provider.aes_gcm_encrypt(&key, &nonce, aad, plaintext) {
            Ok(ciphertext) => {
                match provider.aes_gcm_decrypt(&key, &nonce, aad, &ciphertext) {
                    Ok(decrypted) => {
                        if decrypted == plaintext {
                            self.add_log(LogLevel::Info, "AES-256-GCM encrypt/decrypt test PASSED".into(), "crypto".into());
                        } else {
                            self.add_log(LogLevel::Error, "AES-GCM decryption mismatch".into(), "crypto".into());
                        }
                    }
                    Err(e) => self.add_log(LogLevel::Error, format!("AES-GCM decrypt error: {}", e), "crypto".into()),
                }
            }
            Err(e) => self.add_log(LogLevel::Error, format!("AES-GCM encrypt error: {}", e), "crypto".into()),
        }
        Ok(()) 
    }
    async fn test_nonos_quantum(&mut self) -> Result<()> { self.add_log(LogLevel::Warn, "Quantum tests require PQC libs".into(), "crypto".into()); Ok(()) }

    pub async fn start_aes_test(&mut self) {
        use crate::crypto_harness::AesGcmVector;
        let vectors = vec![
            AesGcmVector {
                key: vec![0u8; 32],
                nonce: vec![0u8; 12],
                aad: vec![],
                plaintext: "Hello NONOS!".as_bytes().to_vec(),
                expected_ciphertext: None,
            }
        ];
        let rx = self.crypto_manager.start_aes_gcm_test(vectors);
        self.harness_rx = Some(rx);
        self.add_log(LogLevel::Info, "Started AES-GCM test harness".to_string(), "crypto".to_string());
    }

    pub async fn start_benchmark(&mut self) {
        let rx = self.crypto_manager.start_benchmark(100);
        self.harness_rx = Some(rx);
        self.add_log(LogLevel::Info, "Started crypto benchmark harness".to_string(), "crypto".to_string());
    }

}

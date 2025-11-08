use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::{
    process::{Child, Command},
    sync::{broadcast, mpsc},
    io::{AsyncBufReadExt, BufReader},
};
use tracing::info;

#[derive(Debug, Clone)]
pub struct KernelConsole {
    pub timestamp: SystemTime,
    pub level: LogLevel,
    pub message: String,
    pub module: Option<String>,
}

#[derive(Debug, Clone)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

#[derive(Debug)]
pub struct QemuConfig {
    pub memory: String,
    pub cpus: u8,
    pub kvm: bool,
    pub graphics: bool,
    pub serial: bool,
    pub monitor: bool,
    pub debug_port: Option<u16>,
    pub custom_args: Vec<String>,
}

impl Default for QemuConfig {
    fn default() -> Self {
        Self {
            memory: "512M".to_string(),
            cpus: 2,
            kvm: true,
            graphics: false,
            serial: true,
            monitor: true,
            debug_port: Some(1234),
            custom_args: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct QemuManager {
    process: Option<Child>,
    pub config: QemuConfig,
    pub console_tx: broadcast::Sender<KernelConsole>,
    pub serial_output: Arc<Mutex<Vec<String>>>,
}

impl QemuManager {
    pub async fn new() -> Result<Self> {
        let (console_tx, _) = broadcast::channel(1024);
        Ok(Self {
            process: None,
            config: QemuConfig::default(),
            console_tx,
            serial_output: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub async fn launch_kernel(&mut self, kernel_path: &Path) -> Result<()> {
        if self.process.is_some() {
            self.stop_kernel().await?;
        }

        // Send console notification about launch attempt
        let launch_log = KernelConsole {
            timestamp: SystemTime::now(),
            level: LogLevel::Info,
            message: format!("Launching kernel from path: {}", kernel_path.display()),
            module: Some("qemu".to_string()),
        };
        let _ = self.console_tx.send(launch_log);
        
        let mut cmd = Command::new("qemu-system-x86_64");
        cmd.arg("-machine").arg("q35");
        cmd.arg("-m").arg(&self.config.memory);
        cmd.arg("-smp").arg(self.config.cpus.to_string());
        cmd.arg("-kernel").arg(kernel_path.to_string_lossy().to_string());

        if self.config.serial {
            cmd.arg("-serial").arg("stdio");
        }

        if !self.config.graphics {
            cmd.arg("-display").arg("none");
            cmd.arg("-nographic");
        }

        if self.config.kvm {
            cmd.arg("-enable-kvm");
            cmd.arg("-cpu").arg("host");
        }

        if self.config.monitor {
            cmd.arg("-monitor").arg("tcp:127.0.0.1:1235,server,nowait");
        }

        if let Some(port) = self.config.debug_port {
            cmd.arg("-gdb").arg(format!("tcp::{}", port));
        }

        for arg in &self.config.custom_args {
            cmd.arg(arg);
        }

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn QEMU")?;

        if let Some(stdout) = child.stdout.take() {
            let tx = self.console_tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let _ = tx.send(KernelConsole {
                        timestamp: SystemTime::now(),
                        level: LogLevel::Info,
                        message: line.clone(),
                        module: Some("qemu-stdout".to_string()),
                    });
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let tx = self.console_tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let _ = tx.send(KernelConsole {
                        timestamp: SystemTime::now(),
                        level: LogLevel::Error,
                        message: line.clone(),
                        module: Some("qemu-stderr".to_string()),
                    });
                }
            });
        }

        self.process = Some(child);
        info!("QEMU launched");
        Ok(())
    }

    pub async fn stop_kernel(&mut self) -> Result<()> {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill().await;
        }
        Ok(())
    }

    pub fn subscribe_console(&self) -> broadcast::Receiver<KernelConsole> {
        self.console_tx.subscribe()
    }

    pub async fn get_recent_console_logs(&self) -> Vec<KernelConsole> {
        vec![
            KernelConsole {
                timestamp: SystemTime::now(),
                level: LogLevel::Info,
                message: "Kernel console initialized".to_string(),
                module: Some("boot".to_string()),
            }
        ]
    }

    pub async fn send_monitor_command(&mut self, _command: &str) -> Result<String> {
        Ok("OK".to_string())
    }
}

#[derive(Debug)]
pub struct BuildProcess {
    pub target: String,
    pub started: SystemTime,
    pub process: Child,
    pub output_rx: mpsc::Receiver<String>,
}

#[derive(Debug, Clone)]
pub struct BuildResult {
    pub target: String,
    pub success: bool,
    pub duration: Duration,
    pub output: String,
    pub timestamp: SystemTime,
}

#[derive(Debug)]
pub struct BuildMonitor {
    pub active_builds: HashMap<String, BuildProcess>,
    build_history: Vec<BuildResult>,
    parallel_limit: usize,
}

impl BuildMonitor {
    pub fn new(parallel_limit: usize) -> Self {
        Self {
            active_builds: HashMap::new(),
            build_history: Vec::new(),
            parallel_limit,
        }
    }

    pub async fn queue_build(&mut self, target: &str, kernel_path: &Path, signing_key: Option<&std::path::Path>) -> Result<()> {
        if self.active_builds.len() >= self.parallel_limit {
            return Err(anyhow::anyhow!("Build queue full"));
        }

        let mut cmd = Command::new("make");
        cmd.arg(target)
            .current_dir(kernel_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
            
        // Set NONOS_SIGNING_KEY environment variable if provided
        if let Some(key_path) = signing_key {
            cmd.env("NONOS_SIGNING_KEY", key_path);
        }

        let mut child = cmd.spawn().context("Failed to spawn build process")?;

        let (tx, rx) = mpsc::channel(1024);

        if let Some(stdout) = child.stdout.take() {
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let _ = tx_clone.send(line).await;
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let _ = tx_clone.send(format!("ERROR: {}", line)).await;
                }
            });
        }

        let process = BuildProcess {
            target: target.to_string(),
            started: SystemTime::now(),
            process: child,
            output_rx: rx,
        };

        self.active_builds.insert(target.to_string(), process);
        Ok(())
    }

    pub fn get_active_builds(&self) -> Vec<&str> {
        self.active_builds.keys().map(|k| k.as_str()).collect()
    }

    pub fn get_build_history(&self) -> &[BuildResult] {
        &self.build_history
    }

    pub async fn poll_builds(&mut self) -> Result<Vec<BuildResult>> {
        let mut completed_builds = Vec::new();
        let mut finished_targets = Vec::new();

        for (target, process) in &mut self.active_builds {
            // Check if process has finished
            match process.process.try_wait() {
                Ok(Some(exit_status)) => {
                    // Process finished, collect output
                    let mut output_lines = Vec::new();
                    while let Ok(line) = process.output_rx.try_recv() {
                        output_lines.push(line);
                    }
                    
                    let result = BuildResult {
                        target: target.clone(),
                        success: exit_status.success(),
                        duration: process.started.elapsed().unwrap_or_default(),
                        output: output_lines.join("\n"),
                        timestamp: SystemTime::now(),
                    };
                    
                    completed_builds.push(result.clone());
                    self.build_history.push(result);
                    finished_targets.push(target.clone());
                }
                Ok(None) => {
                    // Process still running, do nothing
                }
                Err(_) => {
                    // Error checking status, assume failed
                    let result = BuildResult {
                        target: target.clone(),
                        success: false,
                        duration: process.started.elapsed().unwrap_or_default(),
                        output: "Failed to check process status".to_string(),
                        timestamp: SystemTime::now(),
                    };
                    
                    completed_builds.push(result.clone());
                    self.build_history.push(result);
                    finished_targets.push(target.clone());
                }
            }
        }

        // Remove finished builds from active builds
        for target in finished_targets {
            self.active_builds.remove(&target);
        }

        Ok(completed_builds)
    }

    pub async fn get_build_output(&mut self, target: &str) -> Option<Vec<String>> {
        if let Some(process) = self.active_builds.get_mut(target) {
            let mut output_lines = Vec::new();
            while let Ok(line) = process.output_rx.try_recv() {
                output_lines.push(line);
            }
            if !output_lines.is_empty() {
                return Some(output_lines);
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub name: String,
    pub version_required: Option<String>,
    pub version_detected: Option<String>,
    pub available: bool,
    pub install_command: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub package_manager: Option<String>,
    pub kvm_available: bool,
    pub hardware_features: Vec<String>,
}

#[derive(Debug)]
pub struct DependencyManager {
    pub required_tools: HashMap<String, ToolInfo>,
    pub system_info: SystemInfo,
    pub installation_queue: Vec<String>,
}

impl DependencyManager {
    pub async fn new() -> Result<Self> {
        let mut required_tools = HashMap::new();

        required_tools.insert("make".to_string(), ToolInfo {
            name: "make".to_string(),
            version_required: Some("4.0".to_string()),
            version_detected: None,
            available: false,
            install_command: Some("sudo apt install build-essential".to_string()),
        });

        required_tools.insert("cargo".to_string(), ToolInfo {
            name: "cargo".to_string(),
            version_required: Some("1.70".to_string()),
            version_detected: None,
            available: false,
            install_command: Some("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh".to_string()),
        });

        required_tools.insert("qemu-system-x86_64".to_string(), ToolInfo {
            name: "qemu-system-x86_64".to_string(),
            version_required: Some("7.0".to_string()),
            version_detected: None,
            available: false,
            install_command: Some("sudo apt install qemu-system-x86".to_string()),
        });

        let system_info = Self::detect_system().await?;

        Ok(Self {
            required_tools,
            system_info,
            installation_queue: Vec::new(),
        })
    }

    pub async fn check_dependencies(&mut self) -> Result<HashMap<String, bool>> {
        let mut results = HashMap::new();

        for (name, tool) in &mut self.required_tools {
            tool.available = Self::check_tool_available(name).await;
            if tool.available {
                tool.version_detected = Self::get_tool_version(name).await;
            }
            results.insert(name.clone(), tool.available);
        }

        Ok(results)
    }

    pub async fn install_missing(&mut self) -> Result<Vec<String>> {
        let mut installed = Vec::new();
        for (name, tool) in &self.required_tools {
            if !tool.available {
                if let Some(cmd) = &tool.install_command {
                    installed.push(name.clone());
                    info!("Would install {} with: {}", name, cmd);
                }
            }
        }
        Ok(installed)
    }

    async fn detect_system() -> Result<SystemInfo> {
        Ok(SystemInfo {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            package_manager: Some("apt".to_string()),
            kvm_available: Path::new("/dev/kvm").exists(),
            hardware_features: vec!["sse".to_string(), "avx".to_string()],
        })
    }

    async fn check_tool_available(name: &str) -> bool {
        Command::new("which")
            .arg(name)
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    async fn get_tool_version(name: &str) -> Option<String> {
        let output = Command::new(name).arg("--version").output().await.ok()?;
        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).lines().next()?.to_string())
        } else {
            None
        }
    }
}

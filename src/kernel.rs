use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    process::{Child as TokioChild, Command},
    time::timeout,
};
use tracing::{error, info, warn};

#[derive(Debug)]
pub struct KernelManager {
    kernel_path: PathBuf,
    running_instances: HashMap<u32, KernelInstance>,
    qemu_available: bool,
    gdb_available: bool,
}

#[derive(Debug)]
pub struct KernelInstance {
    pub pid: u32,
    pub command: String,
    pub start_time: Instant,
    pub process: Option<TokioChild>,
    pub status: KernelStatus,
}

#[derive(Debug, Clone)]
pub enum KernelStatus {
    Starting,
    Running,
    Stopping,
    Stopped,
    Error(String),
}

impl KernelManager {
    pub async fn new(kernel_path: &Path) -> Result<Self> {
        let kernel_path = kernel_path
            .canonicalize()
            .context("Failed to canonicalize kernel path")?;

        let qemu_available = Self::check_command("qemu-system-x86_64").await;
        let gdb_available = Self::check_command("gdb").await;

        if !qemu_available {
            warn!("QEMU not available - kernel execution will be limited");
        }

        if !gdb_available {
            warn!("GDB not available - debugging features will be limited");
        }

        info!("KernelManager initialized for path: {}", kernel_path.display());

        Ok(Self {
            kernel_path,
            running_instances: HashMap::new(),
            qemu_available,
            gdb_available,
        })
    }

    async fn check_command(cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|status| status.success())
            .unwrap_or(false)
    }

    pub async fn start_kernel(&mut self, target: &str) -> Result<u32> {
        if !self.qemu_available {
            return Err(anyhow::anyhow!("QEMU not available"));
        }

        info!("Starting kernel target: {}", target);

        let mut cmd = Command::new("make");
        cmd.arg(target)
            .current_dir(&self.kernel_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        let child = cmd.spawn().context("Failed to spawn kernel process")?;

        let pid = child
            .id()
            .context("Failed to obtain kernel process id")?;

        let instance = KernelInstance {
            pid,
            command: target.to_string(),
            start_time: Instant::now(),
            process: Some(child),
            status: KernelStatus::Starting,
        };

        self.running_instances.insert(pid, instance);
        
        // Update status to Running after successful spawn
        if let Some(instance) = self.running_instances.get_mut(&pid) {
            instance.status = KernelStatus::Running;
        }

        info!("Kernel started with PID: {}", pid);
        Ok(pid)
    }

    pub async fn stop_kernel(&mut self, pid: u32) -> Result<()> {
        let instance = self
            .running_instances
            .get_mut(&pid)
            .context("Kernel instance not found")?;

        info!("Stopping kernel PID: {}", pid);
        instance.status = KernelStatus::Stopping;

        if let Some(mut process) = instance.process.take() {
            if let Err(e) = process.kill().await {
                warn!("Failed to kill kernel process {}: {}", pid, e);
                instance.status = KernelStatus::Error(format!("Failed to kill process: {}", e));
            } else {
                match timeout(Duration::from_secs(5), process.wait()).await {
                    Ok(Ok(status)) => {
                        info!("Kernel PID {} exited with status: {}", pid, status);
                        instance.status = KernelStatus::Stopped;
                    }
                    Ok(Err(e)) => {
                        warn!("Error waiting for kernel PID {}: {}", pid, e);
                        instance.status = KernelStatus::Error(format!("Wait error: {}", e));
                    }
                    Err(_) => {
                        warn!("Timeout waiting for kernel PID {} to exit", pid);
                        instance.status = KernelStatus::Error("Stop timeout".to_string());
                    }
                }
            }
        } else {
            instance.status = KernelStatus::Stopped;
        }

        self.running_instances.remove(&pid);
        info!("Kernel PID {} stopped", pid);
        Ok(())
    }

    pub async fn stop_all_kernels(&mut self) -> Result<()> {
        let pids: Vec<u32> = self.running_instances.keys().cloned().collect();
        for pid in pids {
            if let Err(e) = self.stop_kernel(pid).await {
                error!("Failed to stop kernel PID {}: {}", pid, e);
            }
        }
        Ok(())
    }

    pub async fn analyze_binary(&self) -> Result<BinaryAnalysis> {
        let release_kernel = self
            .kernel_path
            .join("target")
            .join("x86_64-nonos")
            .join("release")
            .join("nonos_kernel");

        if !release_kernel.exists() {
            return Err(anyhow::anyhow!("Release kernel binary not found"));
        }

        let file_output = Command::new("file")
            .arg(&release_kernel)
            .output()
            .await
            .context("Failed to run file command")?;

        let file_info = String::from_utf8_lossy(&file_output.stdout).into_owned();

        let size_output = Command::new("size")
            .arg(&release_kernel)
            .output()
            .await
            .context("Failed to run size command")?;

        let size_info = String::from_utf8_lossy(&size_output.stdout).into_owned();

        let readelf_output = Command::new("readelf")
            .args(&["-h", release_kernel.to_str().unwrap()])
            .output()
            .await
            .context("Failed to run readelf")?;

        let elf_header = String::from_utf8_lossy(&readelf_output.stdout).into_owned();

        let metadata = std::fs::metadata(&release_kernel).context("Failed to stat release kernel")?;

        Ok(BinaryAnalysis {
            file_path: release_kernel,
            file_size: metadata.len(),
            file_info: file_info.trim().to_string(),
            size_info: size_info.trim().to_string(),
            elf_header: elf_header.trim().to_string(),
            modified_time: metadata.modified().ok(),
        })
    }

    pub async fn verify_signatures(&self) -> Result<SignatureVerification> {
        let release_kernel = self
            .kernel_path
            .join("target")
            .join("x86_64-nonos")
            .join("release")
            .join("nonos_kernel");

        if !release_kernel.exists() {
            return Err(anyhow::anyhow!("Release kernel binary not found"));
        }

        let sections_output = Command::new("readelf")
            .args(&["-S", release_kernel.to_str().unwrap()])
            .output()
            .await
            .context("Failed to read ELF sections")?;

        let sections = String::from_utf8_lossy(&sections_output.stdout);

        let has_manifest = sections.contains(".nonos.manifest");
        let has_signature = sections.contains(".nonos.sig");

        let verification_status = if has_manifest && has_signature {
            let manifest_dump = Command::new("objcopy")
                .args(&[
                    "--dump-section",
                    ".nonos.manifest=/tmp/nonos_manifest.bin",
                    release_kernel.to_str().unwrap(),
                ])
                .output()
                .await;

            let signature_dump = Command::new("objcopy")
                .args(&[
                    "--dump-section",
                    ".nonos.sig=/tmp/nonos_signature.bin",
                    release_kernel.to_str().unwrap(),
                ])
                .output()
                .await;

            match (manifest_dump, signature_dump) {
                (Ok(m), Ok(s)) if m.status.success() && s.status.success() => {
                    let m_stdout = String::from_utf8_lossy(&m.stdout);
                    if m_stdout.contains("NONOS_MANIFEST") && s.stdout.len() > 32 {
                        SignatureStatus::Valid
                    } else {
                        SignatureStatus::Invalid
                    }
                }
                _ => SignatureStatus::ExtractFailed,
            }
        } else if has_manifest || has_signature {
            SignatureStatus::Invalid
        } else {
            SignatureStatus::Missing
        };

        Ok(SignatureVerification {
            has_manifest_section: has_manifest,
            has_signature_section: has_signature,
            verification_status,
            verified_at: std::time::SystemTime::now(),
        })
    }

    pub async fn refresh(&self) -> Result<()> {
        Ok(())
    }

    pub fn get_running_instances(&self) -> &HashMap<u32, KernelInstance> {
        &self.running_instances
    }

    pub fn is_qemu_available(&self) -> bool {
        self.qemu_available
    }

    pub fn is_gdb_available(&self) -> bool {
        self.gdb_available
    }

    pub async fn update_instance_status(&mut self, pid: u32) -> Result<()> {
        if let Some(instance) = self.running_instances.get_mut(&pid) {
            if let Some(process) = instance.process.as_mut() {
                match process.try_wait() {
                    Ok(Some(exit_status)) => {
                        if exit_status.success() {
                            instance.status = KernelStatus::Stopped;
                        } else {
                            instance.status = KernelStatus::Error(format!(
                                "Process exited with code: {:?}",
                                exit_status.code()
                            ));
                        }
                        instance.process = None;
                    }
                    Ok(None) => {
                        if matches!(instance.status, KernelStatus::Starting) {
                            if instance.start_time.elapsed() > Duration::from_secs(3) {
                                instance.status = KernelStatus::Running;
                            }
                        }
                    }
                    Err(e) => {
                        instance.status = KernelStatus::Error(format!("Process error: {}", e));
                        instance.process = None;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BinaryAnalysis {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub file_info: String,
    pub size_info: String,
    pub elf_header: String,
    pub modified_time: Option<std::time::SystemTime>,
}

#[derive(Debug, Clone)]
pub struct SignatureVerification {
    pub has_manifest_section: bool,
    pub has_signature_section: bool,
    pub verification_status: SignatureStatus,
    pub verified_at: std::time::SystemTime,
}

#[derive(Debug, Clone)]
pub enum SignatureStatus {
    Valid,
    Invalid,
    Missing,
    ExtractFailed,
}

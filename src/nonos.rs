use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc,
    time::timeout,
};

#[derive(Debug)]
pub struct NonosManager {
    kernel_path: PathBuf,
    make_available: bool,
    environment: HashMap<String, String>,
}

impl NonosManager {
    pub async fn new(kernel_path: &Path) -> Result<Self> {
        let kernel_path = kernel_path
            .canonicalize()
            .context("Failed to canonicalize kernel path")?;

        let make_available = Self::check_command("make").await;
        let mut environment = HashMap::new();
        environment.insert("RUST_TARGET_PATH".to_string(), kernel_path.to_string_lossy().to_string());

        if let Some(key) = Self::discover_signing_key(&kernel_path).await? {
            environment.insert("NONOS_SIGNING_KEY".to_string(), key);
        }

        Ok(Self {
            kernel_path,
            make_available,
            environment,
        })
    }

    async fn check_command(cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    async fn discover_signing_key(kernel_path: &Path) -> Result<Option<String>> {
        let keys_dir = kernel_path.join(".keys");
        let signing_key = keys_dir.join("signing.seed");
        if signing_key.exists() {
            return Ok(Some(signing_key.to_string_lossy().to_string()));
        }

        if let Ok(env_key) = env::var("NONOS_SIGNING_KEY") {
            if Path::new(&env_key).exists() {
                return Ok(Some(env_key));
            }
        }

        if let Some(home) = dirs::home_dir() {
            let home_key = home.join("nonos-kernel").join(".keys").join("signing.seed");
            if home_key.exists() {
                return Ok(Some(home_key.to_string_lossy().to_string()));
            }
        }

        Ok(None)
    }

    pub async fn execute_make_with_streaming(&self, target: &str, tx: mpsc::Sender<String>) -> Result<()> {
        if !self.make_available {
            return Err(anyhow::anyhow!("make command not available"));
        }

        let mut cmd = Command::new("make");
        cmd.arg(target)
            .current_dir(&self.kernel_path)
            .envs(&self.environment)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn make process")?;

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

        let tx_final = tx.clone();
        tokio::spawn(async move {
            match child.wait().await {
                Ok(status) => {
                    if status.success() {
                        let _ = tx_final.send("Build completed successfully".to_string()).await;
                    } else {
                        let code = status.code().map(|c| c.to_string()).unwrap_or_else(|| "unknown".to_string());
                        let _ = tx_final.send(format!("Build failed with exit code: {}", code)).await;
                    }
                }
                Err(e) => {
                    let _ = tx_final.send(format!("Build process error: {}", e)).await;
                }
            }
        });

        Ok(())
    }

    pub async fn execute_make_command(&self, target: &str) -> Result<String> {
        if !self.make_available {
            return Err(anyhow::anyhow!("make command not available"));
        }

        let mut cmd = Command::new("make");
        cmd.arg(target)
            .current_dir(&self.kernel_path)
            .envs(&self.environment);

        let output = timeout(Duration::from_secs(300), cmd.output())
            .await
            .context("Make command timed out")?
            .context("Failed to execute make command")?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(anyhow::anyhow!(
                "Make command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    pub async fn execute_cargo_command(&self, args: &[&str]) -> Result<String> {
        if !Self::check_command("cargo").await {
            return Err(anyhow::anyhow!("cargo not available"));
        }

        let mut cmd = Command::new("cargo");
        cmd.args(args)
            .current_dir(&self.kernel_path)
            .envs(&self.environment);

        let output = cmd.output().await.context("Failed to execute cargo command")?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(anyhow::anyhow!(format!("Cargo command failed: {}", String::from_utf8_lossy(&output.stderr))))
        }
    }

    pub async fn launch_qemu_with_monitoring(&self, target: &str, tx: mpsc::Sender<String>) -> Result<()> {
        if !Self::check_command("qemu-system-x86_64").await {
            return Err(anyhow::anyhow!("QEMU not available"));
        }

        let kernel_binary = self
            .kernel_path
            .join("target")
            .join("x86_64-nonos")
            .join("release")
            .join("nonos_kernel");

        if !kernel_binary.exists() {
            return Err(anyhow::anyhow!("Kernel binary not found. Build first."));
        }

        let mut cmd = Command::new("qemu-system-x86_64");
        cmd.args(&[
            "-machine", "q35",
            "-m", "512M",
            "-smp", "2",
            "-kernel", &kernel_binary.to_string_lossy(),
            "-serial", "stdio",
            "-display", "none",
        ])
        .current_dir(&self.kernel_path)
        .envs(&self.environment)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        if std::path::Path::new("/dev/kvm").exists() {
            cmd.args(&["-enable-kvm", "-cpu", "host"]);
        }

        let mut child = cmd.spawn().context("Failed to spawn QEMU")?;

        if let Some(stdout) = child.stdout.take() {
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let _ = tx_clone.send(format!("KERNEL: {}", line.trim())).await;
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let _ = tx_clone.send(format!("QEMU_ERR: {}", line.trim())).await;
                }
            });
        }

        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let _ = tx_clone.send("QEMU launched successfully".to_string()).await;
        });

        Ok(())
    }

    pub async fn execute_make_and_wait(&self, target: &str, timeout_secs: u64) -> Result<String> {
        if !self.make_available {
            return Err(anyhow::anyhow!("make command not available"));
        }

        let mut cmd = Command::new("make");
        cmd.arg(target)
            .current_dir(&self.kernel_path)
            .envs(&self.environment);

        let out = timeout(Duration::from_secs(timeout_secs), cmd.output())
            .await
            .context("Command timed out")?
            .context("Failed to execute command")?;

        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(anyhow::anyhow!(format!("Command failed: {}", String::from_utf8_lossy(&out.stderr))))
        }
    }

    pub async fn check_status(&self) -> Result<NonosStatus> {
        let makefile_exists = self.kernel_path.join("Makefile").exists();
        let cargo_toml_exists = self.kernel_path.join("Cargo.toml").exists();
        let target_exists = self.kernel_path.join("x86_64-nonos.json").exists();
        let linker_exists = self.kernel_path.join("linker.ld").exists();

        let git_repo = Self::check_command("git").await && {
            Command::new("git")
                .args(&["rev-parse", "--git-dir"])
                .current_dir(&self.kernel_path)
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false)
        };

        let build_artifacts = self.check_build_artifacts().await?;

        Ok(NonosStatus {
            makefile_exists,
            cargo_toml_exists,
            target_exists,
            linker_exists,
            git_repo,
            build_artifacts,
        })
    }

    async fn check_build_artifacts(&self) -> Result<BuildArtifacts> {
        let target_dir = self.kernel_path.join("target");
        let debug_dir = target_dir.join("x86_64-nonos").join("debug");
        let release_dir = target_dir.join("x86_64-nonos").join("release");

        let debug_kernel = debug_dir.join("nonos_kernel");
        let release_kernel = release_dir.join("nonos_kernel");

        let debug_exists = debug_kernel.exists();
        let release_exists = release_kernel.exists();

        let debug_size = if debug_exists {
            std::fs::metadata(&debug_kernel).map(|m| m.len()).unwrap_or(0)
        } else {
            0
        };

        let release_size = if release_exists {
            std::fs::metadata(&release_kernel).map(|m| m.len()).unwrap_or(0)
        } else {
            0
        };

        Ok(BuildArtifacts {
            debug_exists,
            release_exists,
            debug_size,
            release_size,
        })
    }

    pub async fn refresh(&self) -> Result<()> {
        Ok(())
    }

    pub fn kernel_path(&self) -> &Path {
        &self.kernel_path
    }

    pub fn is_make_available(&self) -> bool {
        self.make_available
    }
}

#[derive(Debug, Clone)]
pub struct NonosStatus {
    pub makefile_exists: bool,
    pub cargo_toml_exists: bool,
    pub target_exists: bool,
    pub linker_exists: bool,
    pub git_repo: bool,
    pub build_artifacts: BuildArtifacts,
}

#[derive(Debug, Clone)]
pub struct BuildArtifacts {
    pub debug_exists: bool,
    pub release_exists: bool,
    pub debug_size: u64,
    pub release_size: u64,
}

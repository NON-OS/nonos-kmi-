use anyhow::Result;
use tokio::sync::mpsc::error::TryRecvError;

use crate::app::{App, LogLevel};

impl App {
    pub async fn update_streaming_outputs(&mut self) -> Result<()> {
        self.update_build_output().await?;
        self.update_qemu_output().await?;
        Ok(())
    }

    async fn update_build_output(&mut self) -> Result<()> {
        if let Some(rx) = &mut self.build_output_rx {
            let mut status_updates: Vec<(bool, Option<bool>, String)> = Vec::new();
            let mut lines_to_add: Vec<String> = Vec::new();

            loop {
                match rx.try_recv() {
                    Ok(line) => {
                        if line.contains("Build completed successfully") {
                            status_updates.push((false, Some(true), "Build completed successfully".to_string()));
                        } else if line.contains("Build failed") || line.contains("error") || line.contains("ERROR:") {
                            status_updates.push((false, Some(false), line.clone()));
                        }
                        lines_to_add.push(line);
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.build_output_rx = None;
                        break;
                    }
                }
            }

            for line in lines_to_add {
                self.build_status.output.push_back(line.clone());
                if self.build_status.output.len() > 1000 {
                    self.build_status.output.pop_front();
                }
            }

            for (is_building, success, msg) in status_updates {
                self.build_status.is_building = is_building;
                self.build_status.last_build_success = success;
                self.add_log(
                    if success == Some(true) { LogLevel::Info } else { LogLevel::Error },
                    msg,
                    "build".to_string(),
                );
            }
        }

        Ok(())
    }

    async fn update_qemu_output(&mut self) -> Result<()> {
        if let Some(rx) = &mut self.qemu_output_rx {
            let mut status_updates: Vec<(bool, Option<std::time::Instant>, String)> = Vec::new();
            let mut lines_to_add: Vec<String> = Vec::new();

            loop {
                match rx.try_recv() {
                    Ok(line) => {
                        if line.contains("QEMU launched successfully") {
                            status_updates.push((true, Some(std::time::Instant::now()), "QEMU launched successfully".to_string()));
                        } else if line.starts_with("KERNEL:") {
                            let kernel_line = line.replacen("KERNEL: ", "", 1);
                            status_updates.push((false, None, kernel_line.clone()));
                        }
                        lines_to_add.push(line);
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.qemu_output_rx = None;
                        break;
                    }
                }
            }

            for line in lines_to_add {
                self.run_status.output.push_back(line.clone());
                if self.run_status.output.len() > 1000 {
                    self.run_status.output.pop_front();
                }
            }

            for (is_running, boot_time, log_msg) in status_updates {
                if is_running {
                    self.run_status.is_running = true;
                    self.run_status.boot_time = boot_time;
                    self.add_log(LogLevel::Info, log_msg, "qemu".to_string());
                } else {
                    self.add_log(LogLevel::Info, log_msg, "kernel".to_string());
                }
            }
        }

        Ok(())
    }

    pub async fn start_qemu_streaming(&mut self, target: &str) -> Result<()> {
        if self.run_status.is_running {
            return Ok(());
        }

        let (tx, rx) = tokio::sync::mpsc::channel::<String>(1024);
        self.qemu_output_rx = Some(rx);

        let target_name = target.to_string();
        if let Err(e) = self.nonos_manager.launch_qemu_with_monitoring(&target_name, tx).await {
            self.add_log(LogLevel::Error, format!("QEMU streaming failed: {}", e), "qemu".to_string());
        } else {
            self.add_log(LogLevel::Info, format!("Starting QEMU: {}", target), "qemu".to_string());
        }

        Ok(())
    }

    pub async fn update_gdb_status(&mut self) -> Result<()> {
        if let Some(ref mut gdb) = self.gdb_manager {
            if let Some(mut rx) = gdb.take_response_receiver() {
                loop {
                    match rx.try_recv() {
                        Ok(response) => {
                            if response.success {
                                self.add_log(LogLevel::Info, response.output, "gdb".to_string());
                            } else {
                                self.add_log(LogLevel::Error, response.output, "gdb".to_string());
                            }
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn attach_gdb(&mut self, port: u16) -> Result<()> {
        if let Some(ref mut gdb) = self.gdb_manager {
            gdb.attach(port).await?;
            self.add_log(LogLevel::Info, format!("GDB attached to port {}", port), "gdb".to_string());
        } else {
            self.add_log(LogLevel::Error, "GDB manager not configured".to_string(), "gdb".to_string());
        }
        Ok(())
    }

    pub async fn set_breakpoint(&mut self, symbol: &str) -> Result<()> {
        if let Some(ref mut gdb) = self.gdb_manager {
            let bp_id = gdb.set_breakpoint(symbol).await?;
            self.add_log(LogLevel::Info, format!("Breakpoint {} set at {}", bp_id, symbol), "gdb".to_string());
        } else {
            self.add_log(LogLevel::Error, "GDB manager not configured".to_string(), "gdb".to_string());
        }
        Ok(())
    }

    pub async fn continue_execution(&mut self) -> Result<()> {
        if let Some(ref mut gdb) = self.gdb_manager {
            gdb.continue_execution().await?;
            self.add_log(LogLevel::Info, "Execution continued".to_string(), "gdb".to_string());
        } else {
            self.add_log(LogLevel::Error, "GDB manager not configured".to_string(), "gdb".to_string());
        }
        Ok(())
    }

    pub async fn step_execution(&mut self) -> Result<()> {
        if let Some(ref mut gdb) = self.gdb_manager {
            gdb.step_instruction().await?;
            self.add_log(LogLevel::Info, "Single step executed".to_string(), "gdb".to_string());
        } else {
            self.add_log(LogLevel::Error, "GDB manager not configured".to_string(), "gdb".to_string());
        }
        Ok(())
    }

    pub async fn get_backtrace(&mut self) -> Result<Vec<String>> {
        if let Some(ref mut gdb) = self.gdb_manager {
            let frames = gdb.get_backtrace().await?;
            let trace: Vec<String> = frames.iter()
                .map(|f| format!("#{}: {} at 0x{:x}", f.level, f.function, f.address))
                .collect();
            for line in &trace {
                self.add_log(LogLevel::Info, line.clone(), "gdb".to_string());
            }
            Ok(trace)
        } else {
            Ok(vec!["GDB not available".to_string()])
        }
    }

    pub async fn examine_memory(&mut self, address: u64, size: usize) -> Result<Vec<u8>> {
        if let Some(ref mut gdb) = self.gdb_manager {
            let data = gdb.examine_memory(address, size).await?;
            self.add_log(LogLevel::Info, format!("Memory at 0x{:x}: {} bytes", address, size), "gdb".to_string());
            Ok(data)
        } else {
            Ok(vec![])
        }
    }

    pub async fn disassemble_at(&mut self, address: u64, count: usize) -> Result<Vec<String>> {
        if let Some(ref mut gdb) = self.gdb_manager {
            let instructions = gdb.disassemble(address, count).await?;
            for instr in &instructions {
                self.add_log(LogLevel::Info, instr.clone(), "gdb".to_string());
            }
            Ok(instructions)
        } else {
            Ok(vec!["GDB not available".to_string()])
        }
    }

    pub fn is_gdb_attached(&self) -> bool {
        self.gdb_manager.as_ref()
            .map(|gdb| gdb.is_attached())
            .unwrap_or(false)
    }

    pub fn get_build_progress(&self) -> f32 {
        if self.build_status.is_building {
            0.5
        } else if self.build_status.last_build_success.is_some() {
            1.0
        } else {
            0.0
        }
    }

    pub fn get_qemu_uptime(&self) -> Option<std::time::Duration> {
        if self.run_status.is_running {
            self.run_status.boot_time.map(|start| start.elapsed())
        } else {
            None
        }
    }

    pub async fn stop_all_processes(&mut self) -> Result<()> {
        if let Some(ref mut gdb) = self.gdb_manager {
            if gdb.is_attached() {
                let _ = gdb.detach().await;
                self.add_log(LogLevel::Info, "GDB detached".to_string(), "gdb".to_string());
            }
        }

        if self.run_status.is_running {
            if let Some(pid) = self.run_status.kernel_pid {
                if let Err(e) = self.kernel_manager.stop_kernel(pid).await {
                    self.add_log(LogLevel::Error, format!("Failed to stop kernel {}: {}", pid, e), "kernel".to_string());
                } else {
                    self.add_log(LogLevel::Info, format!("Kernel {} stopped", pid), "kernel".to_string());
                }
            }
            self.run_status.is_running = false;
            self.run_status.kernel_pid = None;
            self.run_status.boot_time = None;
            self.add_log(LogLevel::Info, "QEMU stopped".to_string(), "qemu".to_string());
        }

        if self.build_status.is_building {
            self.build_status.is_building = false;
            self.add_log(LogLevel::Info, "Build process stopped".to_string(), "build".to_string());
        }

        Ok(())
    }
}

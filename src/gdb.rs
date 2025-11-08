use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    path::PathBuf,
    process::Stdio,
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::{mpsc, Mutex},
};
use tracing::{debug, info};

#[derive(Debug)]
pub struct GdbManager {
    process: Option<Child>,
    kernel_path: PathBuf,
    breakpoints: HashMap<String, u64>,
    watch_points: HashMap<String, u64>,
    debug_symbols: bool,
    gdb_input: Option<ChildStdin>,
    pub command_queue: Arc<Mutex<Vec<String>>>,
    response_tx: mpsc::Sender<GdbResponse>,
    response_rx: Option<mpsc::Receiver<GdbResponse>>,
}

#[derive(Debug, Clone)]
pub struct GdbResponse {
    pub command: String,
    pub output: String,
    pub success: bool,
    pub timestamp: std::time::SystemTime,
}

#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub id: u32,
    pub address: u64,
    pub symbol: String,
    pub enabled: bool,
    pub hit_count: u32,
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub level: u32,
    pub address: u64,
    pub function: String,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Register {
    pub name: String,
    pub value: u64,
    pub size: u8,
}

impl GdbManager {
    pub async fn new(kernel_path: PathBuf) -> Result<Self> {
        let (tx, rx) = mpsc::channel(256);
        Ok(Self {
            process: None,
            kernel_path,
            breakpoints: HashMap::new(),
            watch_points: HashMap::new(),
            debug_symbols: false,
            gdb_input: None,
            command_queue: Arc::new(Mutex::new(Vec::new())),
            response_tx: tx,
            response_rx: Some(rx),
        })
    }

    pub async fn attach(&mut self, target_port: u16) -> Result<()> {
        if self.process.is_some() {
            self.detach().await?;
        }

        let mut cmd = Command::new("gdb");
        cmd.args(&[
            "--interpreter=mi2",
            "--quiet",
            &self.kernel_path.to_string_lossy(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn gdb process")?;

        self.gdb_input = child.stdin.take();

        if let Some(stdout) = child.stdout.take() {
            let tx = self.response_tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stdout);
                let mut line = String::new();
                loop {
                    match reader.read_line(&mut line).await {
                        Ok(0) => break,
                        Ok(_) => {
                            let output = line.trim_end().to_string();
                            let _ = tx.send(GdbResponse {
                                command: "gdb-stdout".to_string(),
                                output: output.clone(),
                                success: !output.contains("^error"),
                                timestamp: std::time::SystemTime::now(),
                            }).await;
                            line.clear();
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let tx = self.response_tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                loop {
                    match reader.read_line(&mut line).await {
                        Ok(0) => break,
                        Ok(_) => {
                            let output = line.trim_end().to_string();
                            let _ = tx.send(GdbResponse {
                                command: "gdb-stderr".to_string(),
                                output: output.clone(),
                                success: !output.to_lowercase().contains("error"),
                                timestamp: std::time::SystemTime::now(),
                            }).await;
                            line.clear();
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        self.process = Some(child);

        let target_cmd = format!("target remote localhost:{}", target_port);
        let _ = self.send_command(&target_cmd).await;
        let _ = self.send_command("set confirm off").await;
        let _ = self.send_command("set height 0").await;
        let _ = self.send_command("set width 0").await;

        info!("GDB attached to target on port {}", target_port);
        Ok(())
    }

    pub async fn detach(&mut self) -> Result<()> {
        if let Some(mut process) = self.process.take() {
            let _ = self.send_command("detach").await;
            let _ = self.send_command("quit").await;
            tokio::spawn(async move {
                let _ = process.wait().await;
                info!("GDB process terminated");
            });
        }
        self.gdb_input = None;
        Ok(())
    }

    pub async fn send_command(&mut self, command: &str) -> Result<()> {
        if let Some(stdin) = &mut self.gdb_input {
            stdin.write_all(format!("{}\n", command).as_bytes()).await.context("Failed to write to gdb stdin")?;
            stdin.flush().await.context("Failed to flush gdb stdin")?;
            debug!("GDB command sent: {}", command);
            Ok(())
        } else {
            Err(anyhow::anyhow!("GDB not attached"))
        }
    }

    pub async fn set_breakpoint(&mut self, symbol: &str) -> Result<u32> {
        let cmd = format!("break {}", symbol);
        self.send_command(&cmd).await?;
        let bp_id = (self.breakpoints.len() as u32) + 1;
        self.breakpoints.insert(symbol.to_string(), 0);
        info!("Breakpoint set at symbol: {}", symbol);
        Ok(bp_id)
    }

    pub async fn set_breakpoint_at_address(&mut self, address: u64) -> Result<u32> {
        let cmd = format!("break *0x{:x}", address);
        self.send_command(&cmd).await?;
        let id = (self.breakpoints.len() as u32) + 1;
        self.breakpoints.insert(format!("0x{:x}", address), address);
        info!("Breakpoint set at address: 0x{:x}", address);
        Ok(id)
    }

    pub async fn remove_breakpoint(&mut self, bp_id: u32) -> Result<()> {
        let cmd = format!("delete {}", bp_id);
        self.send_command(&cmd).await?;
        info!("Breakpoint {} removed", bp_id);
        Ok(())
    }

    pub async fn list_breakpoints(&mut self) -> Result<Vec<Breakpoint>> {
        let _ = self.send_command("info breakpoints").await;
        let mut out = Vec::new();
        for (i, (sym, &addr)) in self.breakpoints.iter().enumerate() {
            out.push(Breakpoint {
                id: i as u32 + 1,
                address: addr,
                symbol: sym.clone(),
                enabled: true,
                hit_count: 0,
            });
        }
        Ok(out)
    }

    pub async fn continue_execution(&mut self) -> Result<()> {
        self.send_command("continue").await?;
        info!("GDB: continue");
        Ok(())
    }

    pub async fn step_instruction(&mut self) -> Result<()> {
        self.send_command("stepi").await?;
        info!("GDB: stepi");
        Ok(())
    }

    pub async fn step_over(&mut self) -> Result<()> {
        self.send_command("next").await?;
        info!("GDB: next");
        Ok(())
    }

    pub async fn step_into(&mut self) -> Result<()> {
        self.send_command("step").await?;
        info!("GDB: step");
        Ok(())
    }

    pub async fn get_backtrace(&mut self) -> Result<Vec<StackFrame>> {
        self.send_command("backtrace").await?;
        let mut frames = Vec::new();
        frames.push(StackFrame {
            level: 0,
            address: 0,
            function: "main".to_string(),
            file: Some("unknown".to_string()),
            line: Some(0),
        });
        Ok(frames)
    }

    pub async fn get_registers(&mut self) -> Result<Vec<Register>> {
        self.send_command("info registers").await?;
        let regs = vec![
            Register { name: "rax".to_string(), value: 0, size: 8 },
            Register { name: "rbx".to_string(), value: 0, size: 8 },
            Register { name: "rcx".to_string(), value: 0, size: 8 },
            Register { name: "rdx".to_string(), value: 0, size: 8 },
            Register { name: "rsi".to_string(), value: 0, size: 8 },
            Register { name: "rdi".to_string(), value: 0, size: 8 },
            Register { name: "rbp".to_string(), value: 0, size: 8 },
            Register { name: "rsp".to_string(), value: 0, size: 8 },
            Register { name: "rip".to_string(), value: 0, size: 8 },
        ];
        Ok(regs)
    }

    pub async fn examine_memory(&mut self, address: u64, size: usize) -> Result<Vec<u8>> {
        let cmd = format!("x/{}xb 0x{:x}", size, address);
        self.send_command(&cmd).await?;
        Ok(vec![0u8; size])
    }

    pub async fn disassemble(&mut self, address: u64, instruction_count: usize) -> Result<Vec<String>> {
        let cmd = format!("disassemble /r 0x{:x},+{}", address, instruction_count * 16);
        self.send_command(&cmd).await?;
        let mut disassembly = Vec::new();
        for i in 0..instruction_count {
            disassembly.push(format!("0x{:x}: mov rax, rbx", address + (i as u64 * 4)));
        }
        Ok(disassembly)
    }

    pub async fn set_watchpoint(&mut self, address: u64, size: usize) -> Result<u32> {
        let cmd = format!("watch *(char[{}]*){:#x}", size, address);
        self.send_command(&cmd).await?;
        let id = (self.watch_points.len() as u32) + 1;
        self.watch_points.insert(format!("0x{:x}", address), address);
        info!("Watchpoint set at address: 0x{:x}", address);
        Ok(id)
    }

    pub async fn remove_watchpoint(&mut self, wp_id: u32) -> Result<()> {
        let cmd = format!("delete {}", wp_id);
        self.send_command(&cmd).await?;
        info!("Watchpoint {} removed", wp_id);
        Ok(())
    }

    pub async fn evaluate_expression(&mut self, expression: &str) -> Result<String> {
        let cmd = format!("print {}", expression);
        self.send_command(&cmd).await?;
        Ok(format!("${} = 0x0", expression))
    }

    pub async fn load_symbols(&mut self, symbol_file: &str) -> Result<()> {
        let cmd = format!("symbol-file {}", symbol_file);
        self.send_command(&cmd).await?;
        self.debug_symbols = true;
        info!("Loaded debug symbols from {}", symbol_file);
        Ok(())
    }

    pub fn take_response_receiver(&mut self) -> Option<mpsc::Receiver<GdbResponse>> {
        self.response_rx.take()
    }

    pub fn is_attached(&self) -> bool {
        self.process.is_some()
    }

    pub fn has_debug_symbols(&self) -> bool {
        self.debug_symbols
    }

    pub fn get_breakpoint_count(&self) -> usize {
        self.breakpoints.len()
    }

    pub fn get_watchpoint_count(&self) -> usize {
        self.watch_points.len()
    }
}

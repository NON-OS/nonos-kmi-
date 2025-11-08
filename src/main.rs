use anyhow::Result;
use clap::{Arg, Command};
use crossterm::{event::{self, Event, KeyEventKind}, execute, terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io, time::{Duration, Instant}};
use tracing::error;

mod app;
mod nonos;
mod ui;
mod crypto;
mod kernel;
mod system;
mod monitor;
mod gdb;
mod streaming;
mod crypto_provider;
mod crypto_harness;
mod visualization;

use app::App;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let matches = Command::new("nonos-tui")
        .version("0.2.0")
        .author("NØNOS Team <dev@nonos.systems>")
        .about("NØNOS Kernel Management Interface")
        .arg(Arg::new("kernel-path").long("kernel-path").value_name("PATH").help("Path to NØNOS kernel repository").default_value("../"))
        .arg(Arg::new("signing-key").long("signing-key").value_name("PATH").help("Path to Ed25519 signing key").env("NONOS_SIGNING_KEY"))
        .arg(Arg::new("test-crypto").long("test-crypto").help("Run crypto tests in CLI mode (no TUI)").action(clap::ArgAction::SetTrue))
        .arg(Arg::new("build-kernel").long("build-kernel").help("Build NONOS kernel in CLI mode").action(clap::ArgAction::SetTrue))
        .get_matches();

    let kernel_path = matches.get_one::<String>("kernel-path").unwrap().clone();
    let mut signing_key = matches.get_one::<String>("signing-key").cloned();
    
    // Use default signing key if none specified
    if signing_key.is_none() {
        let default_key_path = std::path::Path::new(&kernel_path).join(".keys/signing.seed");
        if default_key_path.exists() {
            signing_key = Some(default_key_path.to_string_lossy().to_string());
            println!("Using default signing key: {}", default_key_path.display());
        } else {
            println!("Warning: No signing key found at default path: {}", default_key_path.display());
        }
    }
    let test_crypto = matches.get_flag("test-crypto");
    let build_kernel = matches.get_flag("build-kernel");

    if test_crypto || build_kernel {
        return run_cli_mode(kernel_path, signing_key, test_crypto, build_kernel).await;
    }

    let app = App::new(kernel_path.clone(), signing_key.clone()).await?;
    if let Err(e) = enable_raw_mode() { eprintln!("enable_raw_mode failed: {}", e); return Err(e.into()); }
    let mut stdout = io::stdout();
    let _ = execute!(stdout, EnterAlternateScreen);

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let res = run_app(&mut terminal, app).await;

    disable_raw_mode()?;
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    terminal.show_cursor()?;

    if let Err(err) = res { error!("Application error: {}", err); println!("{:?}", err); }
    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, mut app: App) -> Result<()> {
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(100);

    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;
        let timeout = tick_rate.checked_sub(last_tick.elapsed()).unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if app.handle_key_event(key).await? { return Ok(()) }
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            app.tick().await?;
            let _ = app.update_streaming_outputs().await;
            last_tick = Instant::now();
        }
    }
}

async fn run_cli_mode(kernel_path: String, signing_key: Option<String>, test_crypto: bool, build_kernel: bool) -> Result<()> {
    println!("NONOS CLI Mode");
    if test_crypto {
        println!("Running crypto quick sanity checks (reference provider)...");
        use aes_gcm::{Aes256Gcm, Key, Nonce, aead::Aead};
        use blake3;
        use ed25519_dalek::{SigningKey, Signer, Verifier};
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce as CNonce, aead::AeadInPlace};
        let key = Key::<Aes256Gcm>::from([0x42; 32]);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from([0x01; 12]);
        let pt = b"NONOS test data";
        match cipher.encrypt(&nonce, pt.as_ref()) {
            Ok(ct) => { let dec = cipher.decrypt(&nonce, ct.as_ref()).unwrap_or_default(); if dec == pt { println!("AES-GCM OK"); } else { println!("AES-GCM mismatch"); } }
            Err(e) => println!("AES-GCM err: {}", e),
        }
        let h = blake3::hash(b"abc"); println!("blake3: {}", hex::encode(h.as_bytes()));
        let sk = SigningKey::from_bytes(&[0x42u8; 32]); let sig = sk.sign(b"msg"); let vk = sk.verifying_key(); println!("ed25519 verify: {}", vk.verify(b"msg", &sig).is_ok());
        let ch_key = chacha20poly1305::Key::from([0x55u8; 32]);
        let ch = ChaCha20Poly1305::new(&ch_key);
        let mut data = b"hello".to_vec();
        let nonce = CNonce::from([0;12]);
        match ch.encrypt_in_place(&nonce, b"", &mut data) { Ok(_) => { let mut d2 = data.clone(); ch.decrypt_in_place(&nonce, b"", &mut d2).unwrap(); println!("chacha ok"); } Err(_) => println!("chacha err") }
    }
    if build_kernel {
        println!("Building NONOS kernel at {}", kernel_path);
        use std::process::Command;
        
        let mut cmd = Command::new("make");
        cmd.arg("nonos").current_dir(&kernel_path);
        
        // Set signing key environment variable
        if let Some(k) = signing_key { 
            cmd.env("NONOS_SIGNING_KEY", k);
            println!("Using signing key for build");
        }
        
        println!("Executing: make nonos");
        let output = cmd.output();
        match output { 
            Ok(o) => { 
                if o.status.success() { 
                    println!("✅ NONOS kernel build completed successfully!");
                    println!("{}", String::from_utf8_lossy(&o.stdout));
                } else { 
                    eprintln!("❌ Build failed:");
                    eprintln!("{}", String::from_utf8_lossy(&o.stderr));
                    eprintln!("{}", String::from_utf8_lossy(&o.stdout));
                } 
            } 
            Err(e) => eprintln!("Failed to execute make: {}", e) 
        }
    }
    Ok(())
}

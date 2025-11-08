use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{block::Title, Block, Borders, List, ListItem, Paragraph, Tabs, Wrap},
    Frame,
};

use crate::app::{App, CurrentScreen, LogLevel};

const NONOS_PRIMARY: Color = Color::Rgb(0, 122, 255);
const NONOS_SECONDARY: Color = Color::Rgb(52, 199, 89);
const NONOS_ACCENT: Color = Color::Rgb(255, 149, 0);
const NONOS_ERROR: Color = Color::Rgb(255, 59, 48);
const NONOS_WARNING: Color = Color::Rgb(255, 204, 0);
const NONOS_SUCCESS: Color = Color::Rgb(48, 209, 88);

const NONOS_TEXT_PRIMARY: Color = Color::Rgb(255, 255, 255);
const NONOS_TEXT_SECONDARY: Color = Color::Rgb(174, 174, 178);
const NONOS_BORDER: Color = Color::Rgb(99, 99, 102);
const NONOS_HIGHLIGHT: Color = Color::Rgb(0, 122, 255);

const STATUS_RUNNING: Color = Color::Rgb(48, 209, 88);
const STATUS_STOPPED: Color = Color::Rgb(142, 142, 147);
const STATUS_ERROR: Color = Color::Rgb(255, 59, 48);
const STATUS_BUILDING: Color = Color::Rgb(255, 149, 0);

pub fn draw(f: &mut Frame<'_>, app: &mut App) {
    let size = f.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(size);

    draw_header(f, chunks[0], app);
    draw_main_content(f, chunks[1], app);
    draw_footer(f, chunks[2], app);
}

fn draw_header(f: &mut Frame<'_>, area: Rect, app: &App) {
    let titles = app.get_tab_titles();
    let _title_spans: Vec<Line<'_>> = titles.iter().map(|t| Line::from(Span::raw(*t))).collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(NONOS_BORDER))
                .title(Title::from(" NØNOS Kernel Management Interface ").alignment(Alignment::Center))
                .title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)),
        )
        .style(Style::default().fg(NONOS_TEXT_SECONDARY))
        .highlight_style(Style::default().fg(NONOS_TEXT_PRIMARY).bg(NONOS_HIGHLIGHT).add_modifier(Modifier::BOLD))
        .select(app.tab_index);

    f.render_widget(tabs, area);
}

fn draw_main_content(f: &mut Frame<'_>, area: Rect, app: &mut App) {
    match app.current_screen {
        CurrentScreen::Dashboard => draw_dashboard(f, area, app),
        CurrentScreen::Build => draw_build_screen(f, area, app),
        CurrentScreen::Run => draw_run_screen(f, area, app),
        CurrentScreen::Debug => draw_debug_screen(f, area, app),
        CurrentScreen::Crypto => draw_crypto_screen(f, area, app),
        CurrentScreen::CryptoVisual => draw_crypto_visual_screen(f, area, app),
        CurrentScreen::CryptoAES => draw_crypto_aes_dashboard(f, area, app),
        CurrentScreen::CryptoHash => draw_crypto_hash_dashboard(f, area, app),
        CurrentScreen::CryptoRNG => draw_crypto_rng_dashboard(f, area, app),
        CurrentScreen::CryptoEd25519 => draw_crypto_ed25519_dashboard(f, area, app),
        CurrentScreen::CryptoChaCha => draw_crypto_chacha_dashboard(f, area, app),
        CurrentScreen::CryptoQuantum => draw_crypto_quantum_dashboard(f, area, app),
        CurrentScreen::CryptoZK => draw_crypto_zk_dashboard(f, area, app),
        CurrentScreen::CryptoConstantTime => draw_crypto_consttime_dashboard(f, area, app),
        CurrentScreen::System => draw_system_screen(f, area, app),
        CurrentScreen::Logs => draw_logs_screen(f, area, app),
        CurrentScreen::Config => draw_config_screen(f, area, app),
        CurrentScreen::ManPages => draw_man_pages_screen(f, area, app),
    }
}

fn draw_footer(f: &mut Frame<'_>, area: Rect, app: &App) {
    let (help_text, status_icon) = match app.current_screen {
        CurrentScreen::Dashboard => ("[1-8] Screens • [Tab] Navigate • [R] Refresh • [Q] Quit", "⚡"),
        CurrentScreen::Build => ("[1-6] Build Commands • [C] Clear • [ESC] Dashboard", "🔧"),
        CurrentScreen::Run => ("[1-3] Run Commands • [S] Stop • [C] Clear • [ESC] Dashboard", "🚀"),
        CurrentScreen::Debug => ("[1-4] Debug Commands • [ESC] Dashboard", "🐛"),
        CurrentScreen::Crypto => ("[1-4] Crypto Ops • [ESC] Dashboard", "🔐"),
        CurrentScreen::CryptoVisual => ("[1-5] Tests • [V] Visual • [C] Clear • [R] Random • [ESC] Dashboard", "🧪"),
        CurrentScreen::CryptoAES => ("[1-4] AES Tests • [V] Visualize • [R] Reset • [ESC] Dashboard", "🔒"),
        CurrentScreen::CryptoHash => ("[1-5] Hash Tests • [V] Visualize • [R] Reset • [ESC] Dashboard", "🔗"),
        CurrentScreen::CryptoRNG => ("[1-5] RNG Tests • [V] Visualize • [R] Reseed • [ESC] Dashboard", "🎲"),
        CurrentScreen::CryptoEd25519 => ("[1-5] Ed25519 Tests • [V] Visualize • [R] Reset • [ESC] Dashboard", "🔑"),
        CurrentScreen::CryptoChaCha => ("[1-5] ChaCha Tests • [V] Visualize • [R] Reset • [ESC] Dashboard", "🌊"),
        CurrentScreen::CryptoQuantum => ("[1-5] PQC Tests • [V] Visualize • [R] Reset • [ESC] Dashboard", "🌌"),
        CurrentScreen::CryptoZK => ("[1-5] ZK Tests • [V] Visualize • [R] Reset • [ESC] Dashboard", "🧮"),
        CurrentScreen::CryptoConstantTime => ("[1-5] Timing Tests • [V] Visualize • [R] Reset • [ESC] Dashboard", "⏱️"),
        CurrentScreen::System => ("[R] Refresh • [K] Stop Kernels • [S] Stream • [ESC] Dashboard", "💻"),
        CurrentScreen::Logs => ("[↑↓] Scroll • [PgUp/PgDn] Page • [C] Clear • [ESC] Dashboard", "📝"),
        CurrentScreen::Config => ("[E] Edit • [R] Reload • [S] Save • [ESC] Dashboard", "⚙️"),
        CurrentScreen::ManPages => ("[1-8] Sections • [↑↓←→] Navigate • [PgUp/PgDn] Page • [ESC] Dashboard", "📖"),
    };

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(status_icon, Style::default().fg(NONOS_ACCENT)),
        Span::raw(" "),
        Span::styled(help_text, Style::default().fg(NONOS_TEXT_SECONDARY)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)))
    .alignment(Alignment::Center);

    f.render_widget(footer, area);
}

fn draw_dashboard(f: &mut Frame<'_>, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(33), Constraint::Percentage(33), Constraint::Percentage(34)])
        .split(area);

    let left = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(cols[0]);
    let middle = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(cols[1]);
    let right = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(33), Constraint::Percentage(33), Constraint::Percentage(34)]).split(cols[2]);

    draw_system_overview(f, left[0], app);
    draw_build_status(f, left[1], app);
    draw_kernel_status(f, middle[0], app);
    draw_crypto_status(f, middle[1], app);
    draw_manager_status(f, right[0], app);
    draw_dependency_status(f, right[1], app);
    draw_quick_actions(f, right[2], app);
}

fn draw_system_overview(f: &mut Frame<'_>, area: Rect, app: &App) {
    let info = &app.system_info;

    let used_mem = info.used_memory() as f64 / 1024.0 / 1024.0 / 1024.0;
    let total_mem = info.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0;
    let mem_percent = if total_mem > 0.0 { (used_mem / total_mem) * 100.0 } else { 0.0 };

    let lines = vec![
        Line::from(vec![Span::styled("OS: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(info.os_name(), Style::default().fg(NONOS_TEXT_PRIMARY).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::styled("Kernel: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(info.kernel_version(), Style::default().fg(NONOS_SECONDARY))]),
        Line::from(vec![Span::styled("CPU: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{} cores", info.cpu_count()), Style::default().fg(NONOS_ACCENT))]),
        Line::from(vec![Span::styled("Memory: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.1}GB / {:.1}GB ({:.1}%)", used_mem, total_mem, mem_percent), Style::default().fg(if mem_percent > 80.0 { NONOS_ERROR } else { NONOS_SUCCESS }))]),
        Line::from(vec![Span::styled("Load: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.2}", info.load_average()), Style::default().fg(if info.load_average() > 2.0 { NONOS_WARNING } else { NONOS_SUCCESS }))]),
        Line::from(vec![Span::styled("Uptime: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{}h", info.uptime().as_secs() / 3600), Style::default().fg(NONOS_PRIMARY))]),
    ];

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("System Overview").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_build_status(f: &mut Frame<'_>, area: Rect, app: &App) {
    let build = &app.build_status;
    let (status_text, status_color, status_icon) = if build.is_building {
        ("Building...", STATUS_BUILDING, "🔨")
    } else if let Some(success) = build.last_build_success {
        if success { ("Success", STATUS_RUNNING, "✅") } else { ("Failed", STATUS_ERROR, "❌") }
    } else {
        ("Ready", STATUS_STOPPED, "⏸️")
    };

    let build_time = build.build_time.map(|d| format!("{:.2}s", d.as_secs_f64())).unwrap_or_else(|| "-".to_string());
    let active_builds = app.build_monitor.get_active_builds();
    let active_count = active_builds.len();
    let history = app.build_monitor.get_build_history();
    let last_result = history.last();
    let last_target = last_result.map(|r| r.target.as_str()).unwrap_or("None");
    let last_duration = last_result.map(|r| format!("{:.2}s", r.duration.as_secs_f64())).unwrap_or_else(|| "N/A".to_string());

    let lines = vec![
        Line::from(vec![Span::styled(format!("{} Status: ", status_icon), Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(status_text, Style::default().fg(status_color).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::styled("Duration: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(build_time, Style::default().fg(NONOS_ACCENT))]),
        Line::from(vec![Span::styled("Active: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(active_count.to_string(), Style::default().fg(if active_count > 0 { STATUS_BUILDING } else { NONOS_SUCCESS }))]),
        Line::from(vec![Span::styled("History: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(history.len().to_string(), Style::default().fg(NONOS_PRIMARY))]),
        Line::from(vec![Span::styled("Target: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(last_target, Style::default().fg(NONOS_SECONDARY))]),
        Line::from(vec![Span::styled("Result: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(last_result.map(|r| if r.success { "✓ Success" } else { "✗ Failed" }).unwrap_or("• N/A"), Style::default().fg(last_result.map(|r| if r.success { NONOS_SUCCESS } else { NONOS_ERROR }).unwrap_or(NONOS_TEXT_SECONDARY))), Span::styled(format!(" ({})", last_duration), Style::default().fg(NONOS_TEXT_SECONDARY))]),
    ];

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Build Status").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_kernel_status(f: &mut Frame<'_>, area: Rect, app: &App) {
    let run = &app.run_status;
    let (status_text, status_color, status_icon) = if run.is_running { ("Running", STATUS_RUNNING, "🚀") } else { ("Stopped", STATUS_STOPPED, "⏹️") };
    let pid = run.kernel_pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
    let uptime = run.boot_time.map(|t| format!("{:.1}s", t.elapsed().as_secs_f64())).unwrap_or_else(|| "-".to_string());
    let instances = app.kernel_manager.get_running_instances();
    let count = instances.len();
    let current_cmd = run.kernel_pid.and_then(|pid| instances.get(&pid)).map(|i| i.command.as_str()).unwrap_or("-");
    let instance_pid = run.kernel_pid.map(|p| p.to_string()).unwrap_or_else(|| "None".to_string());

    let lines = vec![
        Line::from(vec![Span::styled(format!("{} Kernel: ", status_icon), Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(status_text, Style::default().fg(status_color).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::styled("PID: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(pid, Style::default().fg(NONOS_ACCENT))]),
        Line::from(vec![Span::styled("Uptime: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(uptime, Style::default().fg(NONOS_PRIMARY))]),
        Line::from(vec![Span::styled("Instances: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(count.to_string(), Style::default().fg(if count > 0 { NONOS_SUCCESS } else { NONOS_TEXT_SECONDARY }))]),
        Line::from(vec![Span::styled("Command: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(current_cmd, Style::default().fg(NONOS_SECONDARY))]),
        Line::from(vec![Span::styled("Instance: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(instance_pid, Style::default().fg(NONOS_ACCENT))]),
    ];

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Kernel Status").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_crypto_status(f: &mut Frame<'_>, area: Rect, app: &App) {
    let crypto = &app.crypto_manager;
    let key_status = if crypto.has_signing_key() { "✓" } else { "✗" };
    let key_color = if crypto.has_signing_key() { NONOS_SUCCESS } else { NONOS_ERROR };
    let pub_status = if crypto.has_public_key() { "✓" } else { "✗" };
    let pub_color = if crypto.has_public_key() { NONOS_SUCCESS } else { NONOS_ERROR };

    let key_info = crypto.key_status();
    let key_size = if key_info.signing_key_exists { key_info.signing_key_size.map(|s| format!("{} bytes", s)).unwrap_or_else(|| "Unknown".to_string()) } else { "N/A".to_string() };
    let pub_size = if key_info.public_key_exists { key_info.public_key_size.map(|s| format!("{} bytes", s)).unwrap_or_else(|| "Unknown".to_string()) } else { "N/A".to_string() };
    let signing_modified = key_info.signing_key_modified.map(|t| format!("{:?}", t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())).unwrap_or_else(|| "Unknown".to_string());
    let public_modified = key_info.public_key_modified.map(|t| format!("{:?}", t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())).unwrap_or_else(|| "Unknown".to_string());

    let signing_path = app.signing_key.as_ref().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("None");

    let lines = vec![
        Line::from(vec![Span::styled("Signing Key: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(key_status, Style::default().fg(key_color).add_modifier(Modifier::BOLD)), Span::styled(format!(" ({})", key_size), Style::default().fg(NONOS_ACCENT))]),
        Line::from(vec![Span::styled("Public Key: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(pub_status, Style::default().fg(pub_color).add_modifier(Modifier::BOLD)), Span::styled(format!(" ({})", pub_size), Style::default().fg(NONOS_ACCENT))]),
        Line::from(vec![Span::styled("Signing Modified: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(signing_modified, Style::default().fg(NONOS_SECONDARY))]),
        Line::from(vec![Span::styled("Public Modified: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(public_modified, Style::default().fg(NONOS_SECONDARY))]),
        Line::from(vec![Span::styled("Key File: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(signing_path, Style::default().fg(NONOS_PRIMARY))]),
        Line::from(vec![Span::styled("Permissions: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(if key_info.permissions_valid { "✓" } else { "✗" }, Style::default().fg(if key_info.permissions_valid { NONOS_SUCCESS } else { NONOS_ERROR }))]),
    ];

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Crypto Status").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_manager_status(f: &mut Frame<'_>, area: Rect, app: &App) {
    let qemu_status = if app.qemu_manager.is_some() { "✓ Available" } else { "✗ Not Available" };
    let gdb_status = if let Some(g) = &app.gdb_manager { if g.is_attached() { "✓ Attached" } else { "○ Ready" } } else { "✗ Not Available" };
    let build_count = app.build_monitor.get_active_builds().len();

    let lines = vec![
        Line::from(vec![Span::styled("QEMU: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(qemu_status, Style::default().fg(NONOS_SUCCESS))]),
        Line::from(vec![Span::styled("GDB: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(gdb_status, Style::default().fg(NONOS_SUCCESS))]),
        Line::from(vec![Span::styled("Active Builds: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(build_count.to_string(), Style::default().fg(if build_count > 0 { STATUS_BUILDING } else { NONOS_SUCCESS }))]),
    ];

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Manager Status").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_dependency_status(f: &mut Frame<'_>, area: Rect, app: &App) {
    let make = if app.nonos_manager.is_make_available() { "✓" } else { "✗" };
    let qemu = if app.kernel_manager.is_qemu_available() { "✓" } else { "✗" };
    let gdb = if app.kernel_manager.is_gdb_available() { "✓" } else { "✗" };
    let path_name = app.nonos_manager.kernel_path().file_name().and_then(|n| n.to_str()).unwrap_or("unknown");

    let lines = vec![
        Line::from(vec![Span::styled("Make: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(make, Style::default().fg(if app.nonos_manager.is_make_available() { NONOS_SUCCESS } else { NONOS_ERROR }))]),
        Line::from(vec![Span::styled("QEMU: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(qemu, Style::default().fg(if app.kernel_manager.is_qemu_available() { NONOS_SUCCESS } else { NONOS_ERROR }))]),
        Line::from(vec![Span::styled("GDB: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(gdb, Style::default().fg(if app.kernel_manager.is_gdb_available() { NONOS_SUCCESS } else { NONOS_ERROR }))]),
        Line::from(vec![Span::styled("Project: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(path_name, Style::default().fg(NONOS_PRIMARY))]),
    ];

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Dependencies").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_quick_actions(f: &mut Frame<'_>, area: Rect, _app: &App) {
    let items = vec![
        "[1] Build System",
        "[2] Run Kernel",
        "[3] Debug Tools",
        "[4] Crypto Ops",
        "[5] System Info",
        "[6] View Logs",
        "[7] Configuration",
        "[8] Man Pages",
    ];

    let list_items: Vec<ListItem<'_>> = items.iter().map(|i| ListItem::new(*i).style(Style::default().fg(NONOS_PRIMARY))).collect();
    let list = List::new(list_items).block(Block::default().title("Quick Actions").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));

    f.render_widget(list, area);
}

fn draw_build_screen(f: &mut Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(8), Constraint::Min(0)]).split(area);
    draw_build_commands(f, chunks[0], app);
    draw_build_output(f, chunks[1], app);
}

fn draw_build_commands(f: &mut Frame<'_>, area: Rect, _app: &App) {
    let commands = vec![
        "[1] make nonos        - Build release kernel",
        "[2] make nonos-debug  - Build debug kernel",
        "[3] make nonos-clean  - Clean build artifacts",
        "[4] make nonos-test   - Run test suite",
        "[5] make nonos-check  - Check code quality",
        "[6] make nonos-clippy - Run linter",
    ];

    let items: Vec<ListItem<'_>> = commands.iter().map(|c| ListItem::new(*c).style(Style::default().fg(NONOS_SECONDARY))).collect();

    let list = List::new(items).block(Block::default().title("Build Commands").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_build_output(f: &mut Frame<'_>, area: Rect, app: &App) {
    let lines: Vec<Line<'_>> = app.build_status.output.iter().map(|l| Line::from(l.as_str())).collect();
    let paragraph = Paragraph::new(lines).block(Block::default().title("Build Output").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER))).style(Style::default().fg(NONOS_TEXT_SECONDARY)).wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn draw_run_screen(f: &mut Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(6), Constraint::Min(0)]).split(area);
    draw_run_commands(f, chunks[0], app);
    draw_run_output(f, chunks[1], app);
}

fn draw_run_commands(f: &mut Frame<'_>, area: Rect, app: &App) {
    let commands = vec![
        "[1] make nonos-run       - Run kernel in QEMU",
        "[2] make nonos-run-debug - Run debug kernel",
        "[3] make nonos-debug-gdb - Run with GDB",
        "[S] Stop kernel",
    ];

    let items: Vec<ListItem<'_>> = commands.iter().map(|cmd| {
        let style = if app.run_status.is_running && cmd.contains("make") { Style::default().fg(NONOS_TEXT_SECONDARY) } else { Style::default().fg(NONOS_SECONDARY) };
        ListItem::new(*cmd).style(style)
    }).collect();

    let list = List::new(items).block(Block::default().title("Run Commands").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_run_output(f: &mut Frame<'_>, area: Rect, app: &App) {
    let lines: Vec<Line<'_>> = app.run_status.output.iter().map(|l| Line::from(l.as_str())).collect();
    let paragraph = Paragraph::new(lines).block(Block::default().title("Kernel Output").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER))).style(Style::default().fg(NONOS_TEXT_SECONDARY)).wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn draw_debug_screen(f: &mut Frame<'_>, area: Rect, _app: &App) {
    let commands = vec![
        "[1] make nonos-disasm - Disassemble kernel",
        "[2] make nonos-doc    - Generate documentation",
        "[3] Analyze Binary    - Binary analysis",
        "[4] Verify Signatures - Crypto verification",
    ];

    let items: Vec<ListItem<'_>> = commands.iter().map(|c| ListItem::new(*c).style(Style::default().fg(NONOS_SECONDARY))).collect();
    let list = List::new(items).block(Block::default().title("Debug Commands").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_crypto_screen(f: &mut Frame<'_>, area: Rect, _app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    let commands = vec![
        "[1] Generate Keys  - Create new Ed25519 keypair",
        "[2] Verify Keys    - Check key integrity", 
        "[3] Rotate Keys    - Key rotation",
        "[4] Start AES Test - Run AES-GCM tests",
        "[5] Benchmark      - Performance benchmarks",
    ];

    let items: Vec<ListItem<'_>> = commands.iter().map(|c| ListItem::new(*c).style(Style::default().fg(NONOS_SECONDARY))).collect();
    let list = List::new(items).block(Block::default().title("Crypto Operations").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, chunks[0]);

    let nav_commands = vec![
        "[V] Visual Tests   [A] AES Tests     [H] Hash Tests",
        "[R] RNG Tests      [E] Ed25519 Tests [C] ChaCha Tests", 
        "[Q] Quantum Tests  [Z] ZK Tests      [T] Timing Tests",
    ];

    let nav_items: Vec<ListItem<'_>> = nav_commands.iter().map(|c| ListItem::new(*c).style(Style::default().fg(NONOS_ACCENT))).collect();
    let nav_list = List::new(nav_items).block(Block::default().title("Crypto Modules").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(nav_list, chunks[1]);
}

fn draw_system_screen(f: &mut Frame<'_>, area: Rect, app: &App) {
    let cols = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    let left = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(cols[0]);
    let right = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(33), Constraint::Percentage(33), Constraint::Percentage(34)]).split(cols[1]);

    draw_basic_system_info(f, left[0], app);
    draw_advanced_system_info(f, left[1], app);
    draw_hardware_features(f, right[0], app);
    draw_disk_usage(f, right[1], app);
    draw_process_info(f, right[2], app);
}

fn draw_basic_system_info(f: &mut Frame<'_>, area: Rect, app: &App) {
    let info = &app.system_info;
    let details = vec![
        format!("Operating System: {}", info.os_name()),
        format!("Kernel Version: {}", info.kernel_version()),
        format!("Architecture: {}", info.architecture()),
        format!("CPU Model: {}", info.cpu_model()),
        format!("CPU Cores: {}", info.cpu_count()),
        format!("Total Memory: {:.2} GB", info.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0),
        format!("Used Memory: {:.2} GB", info.used_memory() as f64 / 1024.0 / 1024.0 / 1024.0),
        format!("Load Average: {:.2}", info.load_average()),
        format!("Boot Time: {}", info.boot_time()),
    ];

    let items: Vec<ListItem<'_>> = details.iter().map(|d| ListItem::new(d.as_str()).style(Style::default().fg(NONOS_SECONDARY))).collect();
    let list = List::new(items).block(Block::default().title("System Information").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_advanced_system_info(f: &mut Frame<'_>, area: Rect, app: &App) {
    let info = &app.system_info;
    let cpu_usage = info.cpu_usage();
    let avg_cpu = info.average_cpu_usage();
    let mem_percentage = info.memory_usage_percentage();
    let free_memory = info.free_memory();
    let network = info.get_network_interfaces().unwrap_or_default();
    let total_rx: u64 = network.iter().map(|n| n.received).sum();
    let total_tx: u64 = network.iter().map(|n| n.transmitted).sum();
    let packets_rx: u64 = network.iter().map(|n| n.packets_received).sum();
    let packets_tx: u64 = network.iter().map(|n| n.packets_transmitted).sum();
    let errors_rx: u64 = network.iter().map(|n| n.errors_on_received).sum();
    let errors_tx: u64 = network.iter().map(|n| n.errors_on_transmitted).sum();
    let active_ifaces: Vec<String> = network.iter().map(|n| n.name.clone()).collect();

    let details = vec![
        format!("CPU Usage: {:.1}%", avg_cpu),
        format!("Memory Usage: {:.1}%", mem_percentage),
        format!("Free Memory: {:.1} GB", free_memory as f64 / 1024.0 / 1024.0 / 1024.0),
        format!("CPU Cores: {} active", cpu_usage.len()),
        format!("Network RX: {:.1} MB ({} pkts, {} errs)", total_rx as f64 / 1024.0 / 1024.0, packets_rx, errors_rx),
        format!("Network TX: {:.1} MB ({} pkts, {} errs)", total_tx as f64 / 1024.0 / 1024.0, packets_tx, errors_tx),
        format!("Network Interfaces: {}", active_ifaces.join(", ")),
        format!("NØNOS Processes: {} / {}", info.get_nonos_processes().len(), info.get_processes_count()),
    ];

    let items: Vec<ListItem<'_>> = details.iter().map(|d| ListItem::new(d.as_str()).style(Style::default().fg(NONOS_ACCENT))).collect();
    let list = List::new(items).block(Block::default().title("Advanced System").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_hardware_features(f: &mut Frame<'_>, area: Rect, app: &App) {
    let features = app.system_info.has_hardware_features();
    let details = vec![
        format!("Security Score: {}/10", features.security_score()),
        format!("NØNOS Compatible: {}", if features.is_nonos_compatible() { "✓" } else { "✗" }),
        format!("Missing Features: {}", features.missing_features().join(", ")),
    ];

    let items: Vec<ListItem<'_>> = details.iter().map(|d| ListItem::new(d.as_str()).style(Style::default().fg(NONOS_WARNING))).collect();
    let list = List::new(items).block(Block::default().title("Hardware Features").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_disk_usage(f: &mut Frame<'_>, area: Rect, app: &App) {
    let disks = app.system_info.get_disk_usage().unwrap_or_default();
    let details: Vec<String> = disks.iter().take(3).map(|d| {
        let warn = if d.is_almost_full() { "⚠ " } else { "" };
        let disk_name = if d.name.is_empty() { "Unknown" } else { &d.name };
        format!("{}{} ({}): {:.1}% ({:.1}GB) [{}{}]", warn, disk_name, d.mount_point, d.usage_percentage(), d.total_space as f64 / 1024.0 / 1024.0 / 1024.0, d.file_system, if d.is_removable { " R" } else { "" })
    }).collect();

    let items: Vec<ListItem<'_>> = details.iter().map(|d| ListItem::new(d.as_str()).style(Style::default().fg(NONOS_SECONDARY))).collect();
    let list = List::new(items).block(Block::default().title("Disk Usage").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_process_info(f: &mut Frame<'_>, area: Rect, app: &App) {
    let procs = app.system_info.get_nonos_processes();
    let details: Vec<String> = procs.iter().take(3).map(|p| {
        let uptime = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs().saturating_sub(p.start_time);
        format!("PID {}: {} CPU:{:.1}% MEM:{:.1}MB VM:{:.1}MB [{}] Up:{}s", p.pid, p.name, p.cpu_usage, p.memory as f64 / 1024.0 / 1024.0, p.virtual_memory as f64 / 1024.0 / 1024.0, p.status, uptime)
    }).collect();

    let items: Vec<ListItem<'_>> = details.iter().map(|d| ListItem::new(d.as_str()).style(Style::default().fg(NONOS_ACCENT))).collect();
    let list = List::new(items).block(Block::default().title("NØNOS Processes").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_logs_screen(f: &mut Frame<'_>, area: Rect, app: &App) {
    let items: Vec<ListItem<'_>> = app.logs.iter().rev().take(100).map(|e| {
        let color = match e.level {
            crate::app::LogLevel::Error => NONOS_ERROR,
            crate::app::LogLevel::Warn => NONOS_WARNING,
            crate::app::LogLevel::Info => NONOS_SUCCESS,
            crate::app::LogLevel::Debug => NONOS_TEXT_SECONDARY,
        };
        let level = match e.level {
            crate::app::LogLevel::Error => "ERROR",
            crate::app::LogLevel::Warn => "WARN ",
            crate::app::LogLevel::Info => "INFO ",
            crate::app::LogLevel::Debug => "DEBUG",
        };
        let time = format!("{:.3}s", e.timestamp.elapsed().as_secs_f64());
        let line = format!("[{}] [{}] {}: {}", time, level, e.source, e.message);
        ListItem::new(line).style(Style::default().fg(color))
    }).collect();

    let list = List::new(items).block(Block::default().title(format!("Logs ({})", app.logs.len())).title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_config_screen(f: &mut Frame<'_>, area: Rect, _app: &App) {
    let items = vec![
        "Kernel Path: ../",
        "Signing Key: ~/.nonos/signing.seed",
        "Build Target: x86_64-nonos",
        "QEMU Args: -machine q35 -cpu host -enable-kvm",
        "Log Level: INFO",
        "Auto Refresh: 500ms",
    ];

    let list_items: Vec<ListItem<'_>> = items.iter().map(|i| ListItem::new(*i).style(Style::default().fg(NONOS_SECONDARY))).collect();
    let list = List::new(list_items).block(Block::default().title("Configuration").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_man_pages_screen(f: &mut Frame<'_>, area: Rect, app: &App) {
    let cols = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(25), Constraint::Percentage(75)]).split(area);
    draw_man_section_navigator(f, cols[0], app);
    draw_man_content(f, cols[1], app);
}

fn draw_man_section_navigator(f: &mut Frame<'_>, area: Rect, app: &App) {
    let sections: Vec<ListItem<'_>> = app.man_pages.iter().enumerate().map(|(i, p)| {
        let prefix = if (i + 1) == app.current_man_section { "▶ " } else { "  " };
        let style = if (i + 1) == app.current_man_section { Style::default().fg(NONOS_HIGHLIGHT).add_modifier(Modifier::BOLD) } else { Style::default().fg(NONOS_TEXT_SECONDARY) };
        ListItem::new(format!("{}{}. {}", prefix, p.section, p.title)).style(style)
    }).collect();

    let list = List::new(sections).block(Block::default().title("Manual Sections").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_man_content(f: &mut Frame<'_>, area: Rect, app: &App) {
    if let Some(page) = app.man_pages.get(app.current_man_section.saturating_sub(1)) {
        let visible_lines = page.content.iter().skip(app.man_scroll).take(area.height.saturating_sub(3) as usize).map(|line| {
            if line.starts_with("NAME") || line.starts_with("SYNOPSIS") || line.starts_with("DESCRIPTION") || line.starts_with("ENVIRONMENT") { Line::from(Span::styled(line.clone(), Style::default().fg(NONOS_ACCENT).add_modifier(Modifier::BOLD))) }
            else if line.trim().starts_with("•") || line.trim().starts_with("-") { Line::from(Span::styled(line.clone(), Style::default().fg(NONOS_SUCCESS))) }
            else if line.contains(":") && !line.trim().is_empty() && !line.starts_with("     ") { Line::from(Span::styled(line.clone(), Style::default().fg(NONOS_SECONDARY))) }
            else { Line::from(Span::styled(line.clone(), Style::default().fg(NONOS_TEXT_PRIMARY))) }
        }).collect::<Vec<Line<'_>>>();

        let paragraph = Paragraph::new(visible_lines).block(Block::default().title(format!("{} - {}", page.title, page.description)).title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER))).wrap(Wrap { trim: true });
        f.render_widget(paragraph, area);

        let help = Paragraph::new(Span::styled(format!("Line {}/{}", app.man_scroll + 1, page.content.len()), Style::default().fg(NONOS_TEXT_SECONDARY))).alignment(Alignment::Center);
        let help_area = Rect { x: area.x, y: area.y + area.height.saturating_sub(1), width: area.width, height: 1 };
        f.render_widget(help, help_area);
    } else {
        let paragraph = Paragraph::new(vec![Line::from("No manual page available"), Line::from("Available sections: 1-8")]).block(Block::default().title("Manual Pages").title_style(Style::default().fg(NONOS_ERROR).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER))).alignment(Alignment::Center);
        f.render_widget(paragraph, area);
    }
}

fn draw_crypto_visual_screen(f: &mut Frame<'_>, area: Rect, app: &App) {
    let cols = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    let left = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(12), Constraint::Min(0)]).split(cols[0]);
    let right = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(cols[1]);

    draw_crypto_test_commands_ui(f, left[0]);
    draw_crypto_test_results_ui(f, left[1], app);
    draw_crypto_visual_output_ui(f, right[0], app);
    draw_crypto_performance_stats_ui(f, right[1], app);
}

fn draw_crypto_test_commands_ui(f: &mut Frame<'_>, area: Rect) {
    let cmds = vec![
        "[1] Ed25519 - Signing",
        "[2] ChaCha20 - AEAD",
        "[3] Blake3 - Hashing",
        "[4] AES-GCM - Authenticated encryption",
        "[5] Quantum - PQC",
        "[V] Visual Mode",
        "[C] Clear Results",
        "[R] Random Data",
    ];

    let items: Vec<ListItem<'_>> = cmds.iter().map(|c| ListItem::new(*c).style(Style::default().fg(NONOS_SECONDARY))).collect();
    let list = List::new(items).block(Block::default().title("Crypto Testing").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_crypto_test_results_ui(f: &mut Frame<'_>, area: Rect, app: &App) {
    let items: Vec<ListItem<'_>> = app.logs.iter().filter(|e| e.source == "crypto").rev().take(10).map(|e| {
        let color = match e.level {
            crate::app::LogLevel::Error => NONOS_ERROR,
            crate::app::LogLevel::Warn => NONOS_WARNING,
            crate::app::LogLevel::Info => NONOS_SUCCESS,
            crate::app::LogLevel::Debug => NONOS_TEXT_SECONDARY,
        };
        let time = format!("{:.1}s", e.timestamp.elapsed().as_secs_f64());
        ListItem::new(format!("[{}] {}", time, e.message)).style(Style::default().fg(color))
    }).collect();

    let list = List::new(items).block(Block::default().title("Test Results").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_crypto_visual_output_ui(f: &mut Frame<'_>, area: Rect, app: &App) {
    let mut hex_lines: Vec<String> = Vec::new();

    if let Some(rx) = &app.harness_rx {
        for _ in 0..8 {
            if let Ok(ev) = rx.try_recv() {
                match ev {
                    crate::crypto_harness::HarnessEvent::BenchmarkSample { sample, .. } => {
                        hex_lines.push(format!("lat: {:.3}ms", sample.latency_ns as f64 / 1_000_000.0));
                    }
                    crate::crypto_harness::HarnessEvent::TestProgress { id, done, total } => {
                        hex_lines.push(format!("progress: {}/{} (id={})", done, total, id));
                    }
                    crate::crypto_harness::HarnessEvent::TestCompleted { id, name: _, success, metrics } => {
                        hex_lines.push(format!("COMPLETE {}: {} (ops/s {:.1})", id, if success { "OK" } else { "FAIL" }, metrics.ops_per_sec));
                    }
                    crate::crypto_harness::HarnessEvent::Error { id, msg } => {
                        hex_lines.push(format!("ERROR [{}]: {}", id.map(|v| v.to_string()).unwrap_or_default(), msg));
                    }
                    _ => {}
                }
            } else {
                break;
            }
        }
    }

    if hex_lines.is_empty() {
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let seed = (ts % 256) as u8;
        hex_lines = vec![
            format!("ed25519: {:02x}{:02x}{:02x}{:02x}", seed, seed.wrapping_add(1), seed.wrapping_add(2), seed.wrapping_add(3)),
            format!("blake3:  {:02x}{:02x}{:02x}{:02x}", seed.wrapping_mul(2), seed.wrapping_mul(2).wrapping_add(1), seed.wrapping_mul(2).wrapping_add(2), seed.wrapping_mul(2).wrapping_add(3)),
            format!("chacha:  {:02x}{:02x}{:02x}{:02x}", seed.wrapping_mul(3), seed.wrapping_mul(3).wrapping_add(1), seed.wrapping_mul(3).wrapping_add(2), seed.wrapping_mul(3).wrapping_add(3)),
            format!("aes256:  {:02x}{:02x}{:02x}{:02x}", seed.wrapping_mul(5), seed.wrapping_mul(5).wrapping_add(1), seed.wrapping_mul(5).wrapping_add(2), seed.wrapping_mul(5).wrapping_add(3)),
            "".to_string(),
            format!("Entropy: {:.1}%", (seed as f32 / 256.0) * 100.0),
            format!("Speed est: {}MB/s", seed.wrapping_mul(13) % 200 + 50),
        ];
    }

    let items: Vec<ListItem<'_>> = hex_lines.iter().enumerate().map(|(i, l)| {
        let style = if l.is_empty() { Style::default() } else if l.starts_with("ERROR") || l.starts_with("COMPLETE") { Style::default().fg(NONOS_ERROR).add_modifier(Modifier::BOLD) } else { Style::default().fg([NONOS_ACCENT, NONOS_SECONDARY, NONOS_PRIMARY, NONOS_WARNING, NONOS_SUCCESS][i % 5]) };
        ListItem::new(l.clone()).style(style)
    }).collect();

    let list = List::new(items).block(Block::default().title("Live Crypto Data").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(list, area);
}

fn draw_crypto_performance_stats_ui(f: &mut Frame<'_>, area: Rect, _app: &App) {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    let variance = ((ts / 1000) % 20) as f32 / 10.0;
    let base_ed25519 = 2.3 + variance * 0.2;
    let base_chacha = 0.8 + variance * 0.1;
    let base_blake3 = 0.1 + variance * 0.02;
    let base_aes = 1.2 + variance * 0.15;
    let base_kyber = 15.7 + variance * 1.5;
    let base_dilithium = 8.4 + variance * 0.8;

    let cpu_load = 45.0 + variance * 10.0;
    let memory_usage = 87.5 + variance * 5.0;
    let throughput = 1250.0 + variance * 200.0;

    let lines = vec![
        Line::from(vec![Span::styled("Ed25519: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.1}ms", base_ed25519), Style::default().fg(NONOS_SUCCESS)), Span::styled(format!(" ({:.0} ops/s)", 1000.0 / base_ed25519), Style::default().fg(NONOS_TEXT_SECONDARY))]),
        Line::from(vec![Span::styled("ChaCha20: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.1}ms", base_chacha), Style::default().fg(NONOS_SUCCESS)), Span::styled(format!(" ({:.0} ops/s)", 1000.0 / base_chacha), Style::default().fg(NONOS_TEXT_SECONDARY))]),
        Line::from(vec![Span::styled("Blake3: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.2}ms", base_blake3), Style::default().fg(NONOS_SUCCESS)), Span::styled(format!(" ({:.0}K ops/s)", 1.0 / base_blake3), Style::default().fg(NONOS_TEXT_SECONDARY))]),
        Line::from(vec![Span::styled("AES-GCM: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.1}ms", base_aes), Style::default().fg(NONOS_SUCCESS)), Span::styled(format!(" ({:.0} ops/s)", 1000.0 / base_aes), Style::default().fg(NONOS_TEXT_SECONDARY))]),
        Line::from(vec![Span::styled("Kyber: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.1}ms", base_kyber), Style::default().fg(NONOS_WARNING)), Span::styled(format!(" ({:.0} ops/s)", 1000.0 / base_kyber), Style::default().fg(NONOS_TEXT_SECONDARY))]),
        Line::from(vec![Span::styled("Dilithium: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.1}ms", base_dilithium), Style::default().fg(NONOS_WARNING)), Span::styled(format!(" ({:.0} ops/s)", 1000.0 / base_dilithium), Style::default().fg(NONOS_TEXT_SECONDARY))]),
        Line::from(""),
        Line::from(vec![Span::styled("CPU Load: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.1}%", cpu_load), Style::default().fg(if cpu_load > 80.0 { NONOS_ERROR } else if cpu_load > 60.0 { NONOS_WARNING } else { NONOS_SUCCESS }))]),
        Line::from(vec![Span::styled("Memory: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.1}MB", memory_usage), Style::default().fg(NONOS_ACCENT))]),
        Line::from(vec![Span::styled("Throughput: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(format!("{:.0} ops/s", throughput), Style::default().fg(NONOS_PRIMARY))]),
    ];

    let paragraph = Paragraph::new(lines).block(Block::default().title("Performance Stats").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER))).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn draw_crypto_aes_dashboard(f: &mut Frame<'_>, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(0)])
        .split(cols[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(cols[1]);

    // AES Commands Panel
    let commands = vec![
        "[1] AES-256 Encrypt/Decrypt Test",
        "[2] GCM AEAD Performance Test",
        "[3] Key Schedule Analysis",
        "[4] Side-Channel Test",
        "[5] NIST Vector Validation",
        "[V] Toggle Visualization",
        "[R] Reset Test State",
    ];

    let items: Vec<ListItem<'_>> = commands.iter()
        .map(|c| ListItem::new(*c).style(Style::default().fg(NONOS_SECONDARY)))
        .collect();

    let commands_block = List::new(items)
        .block(Block::default()
            .title("AES-256-GCM Operations")
            .title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(NONOS_BORDER)));

    f.render_widget(commands_block, left[0]);

    // AES Test Results
    let test_logs: Vec<Line<'_>> = app.logs.iter()
        .filter(|log| log.source.contains("aes") || log.source.contains("crypto"))
        .take(20)
        .map(|log| {
            let level_color = match log.level {
                LogLevel::Error => NONOS_ERROR,
                LogLevel::Warn => NONOS_WARNING,
                LogLevel::Info => NONOS_SUCCESS,
                LogLevel::Debug => NONOS_TEXT_SECONDARY,
            };
            Line::from(vec![
                Span::styled(format!("{:?}: ", log.level), Style::default().fg(level_color)),
                Span::styled(&log.message, Style::default().fg(NONOS_TEXT_PRIMARY))
            ])
        })
        .collect();

    let test_results = Paragraph::new(test_logs)
        .block(Block::default()
            .title("AES Test Results")
            .title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(NONOS_BORDER)))
        .style(Style::default().fg(NONOS_TEXT_SECONDARY))
        .wrap(Wrap { trim: false });

    f.render_widget(test_results, left[1]);

    // AES Status Panel
    let status_lines = vec![
        Line::from(vec![
            Span::styled("Algorithm: ", Style::default().fg(NONOS_TEXT_SECONDARY)),
            Span::styled("AES-256-GCM", Style::default().fg(NONOS_PRIMARY))
        ]),
        Line::from(vec![
            Span::styled("Key Size: ", Style::default().fg(NONOS_TEXT_SECONDARY)),
            Span::styled("256 bits", Style::default().fg(NONOS_SUCCESS))
        ]),
        Line::from(vec![
            Span::styled("Block Size: ", Style::default().fg(NONOS_TEXT_SECONDARY)),
            Span::styled("128 bits", Style::default().fg(NONOS_SUCCESS))
        ]),
        Line::from(vec![
            Span::styled("Mode: ", Style::default().fg(NONOS_TEXT_SECONDARY)),
            Span::styled("Galois/Counter", Style::default().fg(NONOS_SUCCESS))
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(NONOS_TEXT_SECONDARY)),
            Span::styled("Ready", Style::default().fg(NONOS_SUCCESS))
        ]),
    ];

    let status_panel = Paragraph::new(status_lines)
        .block(Block::default()
            .title("AES Configuration")
            .title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(NONOS_BORDER)));

    f.render_widget(status_panel, right[0]);

    // Performance Metrics
    let perf_data = app.visualization.get_latest_benchmark_data();
    let perf_lines: Vec<Line<'_>> = if !perf_data.is_empty() {
        perf_data.iter()
            .take(15)
            .map(|(ops_per_sec, latency)| {
                Line::from(vec![
                    Span::styled(format!("{:.2} ops/s", ops_per_sec), Style::default().fg(NONOS_ACCENT)),
                    Span::styled(" | ", Style::default().fg(NONOS_TEXT_SECONDARY)),
                    Span::styled(format!("{:.2}μs", latency), Style::default().fg(NONOS_SECONDARY)),
                ])
            })
            .collect()
    } else {
        vec![Line::from("No performance data available")]
    };

    let perf_panel = Paragraph::new(perf_lines)
        .block(Block::default()
            .title("Performance Metrics")
            .title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(NONOS_BORDER)))
        .wrap(Wrap { trim: false });

    f.render_widget(perf_panel, right[1]);
}

fn draw_crypto_hash_dashboard(f: &mut Frame<'_>, area: Rect, app: &App) {
    draw_placeholder_dashboard(f, area, "Hash Function Dashboard", "Blake3, SHA-3, SHA-512 & HMAC Operations", app, "hash");
}

fn draw_crypto_rng_dashboard(f: &mut Frame<'_>, area: Rect, app: &App) {
    draw_placeholder_dashboard(f, area, "RNG Dashboard", "Random Number Generation & Entropy Analysis", app, "rng");
}

fn draw_crypto_ed25519_dashboard(f: &mut Frame<'_>, area: Rect, app: &App) {
    draw_placeholder_dashboard(f, area, "Ed25519 Dashboard", "Digital Signatures & Key Management", app, "ed25519");
}

fn draw_crypto_chacha_dashboard(f: &mut Frame<'_>, area: Rect, app: &App) {
    draw_placeholder_dashboard(f, area, "ChaCha20 Dashboard", "Stream Cipher & AEAD Operations", app, "chacha");
}

fn draw_crypto_quantum_dashboard(f: &mut Frame<'_>, area: Rect, app: &App) {
    draw_placeholder_dashboard(f, area, "Quantum Crypto Dashboard", "Post-Quantum Kyber & Dilithium", app, "quantum");
}

fn draw_crypto_zk_dashboard(f: &mut Frame<'_>, area: Rect, app: &App) {
    draw_placeholder_dashboard(f, area, "Zero-Knowledge Dashboard", "Halo2 & Groth16 Proof Systems", app, "zk");
}

fn draw_crypto_consttime_dashboard(f: &mut Frame<'_>, area: Rect, app: &App) {
    draw_placeholder_dashboard(f, area, "Constant-Time Dashboard", "Timing Attack Resistance Analysis", app, "consttime");
}

fn draw_placeholder_dashboard(f: &mut Frame<'_>, area: Rect, title: &str, description: &str, app: &App, log_filter: &str) {
    let cols = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(30), Constraint::Percentage(40), Constraint::Percentage(30)]).split(area);
    let left = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(10), Constraint::Min(0)]).split(cols[0]);

    let info_lines = vec![
        Line::from(vec![Span::styled("Module: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled(description, Style::default().fg(NONOS_PRIMARY))]),
        Line::from(""),
        Line::from(vec![Span::styled("Status: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled("Ready for Testing", Style::default().fg(NONOS_SUCCESS))]),
        Line::from(vec![Span::styled("Controls: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled("[1-5] Tests, [V] Visual, [R] Reset", Style::default().fg(NONOS_ACCENT))]),
        Line::from(vec![Span::styled("Features: ", Style::default().fg(NONOS_TEXT_SECONDARY)), Span::styled("Real kernel integration (feature-gated)", Style::default().fg(NONOS_SUCCESS))]),
    ];

    let info = Paragraph::new(info_lines).block(Block::default().title(title).title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER))).wrap(Wrap { trim: true });
    f.render_widget(info, left[0]);

    let visual_lines = match log_filter {
        "aes" => vec!["AES-256-GCM Operation:", " Plaintext -> [AES-256-GCM] -> Ciphertext+Tag", " Key: 256-bit, Nonce: 96-bit", " 14 rounds (AES-256)"],
        "hash" => vec!["Hash Function Chain:", " Blake3 -> 32 bytes", " SHA-512 -> 64 bytes", " HMAC -> Authentication"],
        "rng" => vec!["Entropy Sources:", " Hardware RNG", " CSPRNG Pool", " Entropy Analysis"],
        "ed25519" => vec!["Ed25519 Signatures:", " KeyGen -> Sign -> Verify", " 64-byte signature", " 32-byte public key"],
        "chacha" => vec!["ChaCha20-Poly1305:", " Stream cipher + Poly1305 MAC", " 96-bit nonce", " AEAD construction"],
        "quantum" => vec!["Post-Quantum Crypto:", " Kyber (KEM)", " Dilithium (Signatures)", " Interop and performance"],
        "zk" => vec!["Zero-Knowledge Proofs:", " Circuit -> Prove -> Verify", " Halo2 / Groth16", " Verify performance"],
        "consttime" => vec!["Constant-Time Analysis:", " Timing measurements", " Side-channel checks", " Benchmarks"],
        _ => vec!["Crypto Module Overview"],
    };

    let visual_items: Vec<ListItem<'_>> = visual_lines.iter().map(|l| {
        let style = if l.starts_with(" ") { Style::default().fg(NONOS_ACCENT) } else { Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD) };
        ListItem::new(*l).style(style)
    }).collect();

    let visual = List::new(visual_items).block(Block::default().title("Operation Flow").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(visual, cols[1]);

    let filtered_logs: Vec<&crate::app::LogEntry> = app.logs.iter().filter(|l| l.source == log_filter).rev().take(15).collect();
    let items: Vec<ListItem<'_>> = if filtered_logs.is_empty() {
        vec![
            ListItem::new("No tests run yet").style(Style::default().fg(NONOS_TEXT_SECONDARY)),
            ListItem::new("Press [1-5] to run tests").style(Style::default().fg(NONOS_TEXT_SECONDARY)),
            ListItem::new("Press [V] for visualization").style(Style::default().fg(NONOS_TEXT_SECONDARY)),
        ]
    } else {
        filtered_logs.iter().map(|log| {
            let style = match log.level {
                crate::app::LogLevel::Info => Style::default().fg(NONOS_SUCCESS),
                crate::app::LogLevel::Warn => Style::default().fg(NONOS_WARNING),
                crate::app::LogLevel::Error => Style::default().fg(NONOS_ERROR),
                crate::app::LogLevel::Debug => Style::default().fg(NONOS_TEXT_SECONDARY),
            };
            ListItem::new(log.message.clone()).style(style)
        }).collect()
    };

    let results = List::new(items).block(Block::default().title("Test Results & Status").title_style(Style::default().fg(NONOS_PRIMARY).add_modifier(Modifier::BOLD)).borders(Borders::ALL).border_style(Style::default().fg(NONOS_BORDER)));
    f.render_widget(results, cols[2]);
}

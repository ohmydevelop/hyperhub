use crate::config_cli;
use crossterm::cursor::SetCursorStyle;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use hyperhub_core::config::{
    new_config_uuid, Config, EnvironmentVariable, FileSandboxOperation, FileSandboxPattern,
    FileSandboxRule, FirewallAction, FirewallDefaultRule, FirewallEndpoint, FirewallRule,
    HttpAuthScheme, PluginConfig, PluginKind, PluginProtocol, ProcessSandboxPattern,
    ProcessSandboxRule, RouteEndpoint, RouteRule, SandboxAction, SandboxDefaultRule, SecretValue,
    Upstream, UpstreamKind,
};
use hyperhub_core::config_store::{default_config_path, load_encrypted};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const MODEL_SHA256: &str = "c9d915eca282ed42d1a09b143b592adb4cc6744ffe2d294adf5cfc5548170c38";
const EMBEDDED_MODEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/needle3.cact"));
const EMBEDDED_RUNNER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/needle3-runner.bin"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChatConfig {
    pub(crate) password_file: Option<PathBuf>,
}

pub(crate) fn parse(args: &[OsString]) -> Result<ChatConfig, String> {
    let mut password_file = None;
    let mut index = 0;
    while index < args.len() {
        let option = args[index].to_string_lossy();
        index += 1;
        match option.as_ref() {
            "--password-file" => {
                password_file = Some(
                    args.get(index)
                        .ok_or("--password-file requires a value")?
                        .clone()
                        .into(),
                );
                index += 1;
            }
            _ => return Err(format!("unknown chat option '{option}'")),
        }
    }
    Ok(ChatConfig { password_file })
}

pub(crate) fn run(options: ChatConfig) -> Result<i32, String> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("chat requires an interactive terminal".into());
    }
    let path = default_config_path().map_err(|error| error.to_string())?;
    let first_run = !path.is_file();
    let password = crate::password::acquire(options.password_file.as_deref(), first_run)?;
    let mut config = if first_run {
        let mut config = Config::default();
        config.apply_managed_audit_paths(&path);
        config.environment = crate::default_environment();
        config
    } else {
        load_encrypted(&path, password.as_bytes())
            .map_err(|error| error.to_string())?
            .config
    };

    run_tui(&path, &password, &mut config)?;
    Ok(0)
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            std::io::stdout(),
            LeaveAlternateScreen,
            SetCursorStyle::DefaultUserShape
        );
    }
}

fn run_tui(path: &Path, password: &Zeroizing<String>, config: &mut Config) -> Result<(), String> {
    enable_raw_mode().map_err(|error| error.to_string())?;
    let _guard = TerminalGuard;
    execute!(
        std::io::stdout(),
        EnterAlternateScreen,
        SetCursorStyle::SteadyBar
    )
    .map_err(|error| error.to_string())?;
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|error| error.to_string())?;
    let mut app = ChatApp::new(path.to_owned());

    loop {
        terminal
            .draw(|frame| draw(frame, &app))
            .map_err(|error| error.to_string())?;
        match event::read().map_err(|error| error.to_string())? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if handle_key(&mut app, key) == ChatAction::Exit {
                    return Ok(());
                }
                if app.submit_requested {
                    app.submit_requested = false;
                    let query = std::mem::take(&mut app.input);
                    app.cursor = 0;
                    if query.trim().is_empty() {
                        continue;
                    }
                    app.messages.push(ChatMessage::user(query.clone()));
                    app.busy = true;
                    app.status = "Needle 3 正在本地处理…".into();
                    terminal
                        .draw(|frame| draw(frame, &app))
                        .map_err(|error| error.to_string())?;
                    let answer =
                        NeedleSession::start(path, config, &query).and_then(|mut model| {
                            process_turn(&mut model, path, password, config, &query)
                        });
                    app.busy = false;
                    match answer {
                        Ok(answer) => {
                            app.status = "配置已加密保存；无需 approve".into();
                            app.messages.push(ChatMessage::assistant(answer));
                        }
                        Err(error) => {
                            app.status = "本次操作未写入配置".into();
                            app.messages.push(ChatMessage::error(error));
                        }
                    }
                }
            }
            Event::Paste(value) => insert_text(&mut app, &value),
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatAction {
    Continue,
    Exit,
}

fn handle_key(app: &mut ChatApp, key: KeyEvent) -> ChatAction {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return ChatAction::Exit;
    }
    if app.busy {
        return ChatAction::Continue;
    }
    match (key.modifiers, key.code) {
        (modifiers, KeyCode::Char('j')) if modifiers.contains(KeyModifiers::CONTROL) => {
            insert_text(app, "\n")
        }
        (_, KeyCode::Enter) => app.submit_requested = true,
        (_, KeyCode::Backspace) => input_backspace(app),
        (_, KeyCode::Delete) => input_delete(app),
        (_, KeyCode::Left) => app.cursor = app.cursor.saturating_sub(1),
        (_, KeyCode::Right) => app.cursor = (app.cursor + 1).min(char_count(&app.input)),
        (_, KeyCode::Home) => app.cursor = line_start(&app.input, app.cursor),
        (_, KeyCode::End) => app.cursor = line_end(&app.input, app.cursor),
        (_, KeyCode::PageUp) => app.scroll = app.scroll.saturating_sub(8),
        (_, KeyCode::PageDown) => app.scroll = app.scroll.saturating_add(8),
        (_, KeyCode::Esc) => {
            app.input.clear();
            app.cursor = 0;
        }
        (modifiers, KeyCode::Char('u')) if modifiers.contains(KeyModifiers::CONTROL) => {
            app.input.clear();
            app.cursor = 0;
        }
        (_, KeyCode::Char(character)) => insert_text(app, &character.to_string()),
        _ => {}
    }
    ChatAction::Continue
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageRole {
    User,
    Assistant,
    Error,
}

#[derive(Debug, Clone)]
struct ChatMessage {
    role: MessageRole,
    content: String,
}

impl ChatMessage {
    fn user(content: String) -> Self {
        Self {
            role: MessageRole::User,
            content,
        }
    }

    fn assistant(content: String) -> Self {
        Self {
            role: MessageRole::Assistant,
            content,
        }
    }

    fn error(content: String) -> Self {
        Self {
            role: MessageRole::Error,
            content,
        }
    }
}

struct ChatApp {
    path: PathBuf,
    messages: Vec<ChatMessage>,
    input: String,
    cursor: usize,
    scroll: u16,
    busy: bool,
    submit_requested: bool,
    status: String,
}

impl ChatApp {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            messages: vec![ChatMessage::assistant(
                "我是 HyperHub 的本地配置助手。Needle 3 模型和推理引擎均嵌入当前二进制；你可以直接输入令牌、密码和其他敏感配置。识别出的变更会立即校验、加密保存，并在 Serve 运行时热更新，不进入 approve 队列。".into(),
            )],
            input: String::new(),
            cursor: 0,
            scroll: u16::MAX,
            busy: false,
            submit_requested: false,
            status: "本地模式 · 不发送到远端".into(),
        }
    }
}

fn draw(frame: &mut Frame, app: &ChatApp) {
    let area = frame.area();
    if area.width < 70 || area.height < 20 {
        frame.render_widget(
            Paragraph::new("终端过小，请调整到至少 70×20")
                .block(Block::bordered().title("HyperHub Chat")),
            area,
        );
        return;
    }
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let accent = if no_color { Color::Reset } else { Color::Cyan };
    let muted = if no_color {
        Color::Reset
    } else {
        Color::DarkGray
    };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(7),
            Constraint::Length(input_height(&app.input, area.width)),
            Constraint::Length(1),
        ])
        .split(area);
    let body = centered(rows[1], 110);
    let composer = centered(rows[2], 110);
    let footer = centered(rows[3], 110);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " HyperHub",
                Style::default().fg(accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  local configuration agent", Style::default().fg(muted)),
        ])),
        centered(rows[0], 110),
    );
    frame.render_widget(
        Paragraph::new("Needle 3 · local")
            .style(Style::default().fg(muted))
            .alignment(Alignment::Right),
        centered(rows[0], 110),
    );

    let mut lines = Vec::new();
    for message in &app.messages {
        let (symbol, name, style) = match message.role {
            MessageRole::User => (
                "›",
                "You",
                Style::default().fg(accent).add_modifier(Modifier::BOLD),
            ),
            MessageRole::Assistant => (
                "•",
                "HyperHub",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            MessageRole::Error => (
                "!",
                "Error",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{symbol} "), style),
            Span::styled(name, style),
        ]));
        for line in message.content.lines() {
            lines.push(Line::from(format!("  {line}")));
        }
        lines.push(Line::default());
    }
    if app.busy {
        lines.push(Line::from(vec![
            Span::styled("• ", Style::default().fg(accent)),
            Span::styled("Working locally…", Style::default().fg(muted)),
        ]));
    }
    let visible = body.height.saturating_sub(1) as usize;
    let bottom = lines.len().saturating_sub(visible) as u16;
    let scroll = if app.scroll == u16::MAX {
        bottom
    } else {
        app.scroll.min(bottom)
    };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        body,
    );

    let input_display = if app.input.is_empty() {
        Line::from(vec![
            Span::styled("› ", Style::default().fg(accent)),
            Span::styled("描述你希望完成的配置…", Style::default().fg(muted)),
        ])
    } else {
        Line::from(vec![
            Span::styled("› ", Style::default().fg(accent)),
            Span::raw(app.input.clone()),
        ])
    };
    frame.render_widget(
        Paragraph::new(input_display)
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(if app.busy { muted } else { accent })),
            ),
        composer,
    );
    if !app.busy {
        let (x, y) = input_cursor_position(composer, &app.input, app.cursor);
        frame.set_cursor_position((x, y));
    }

    let footer_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(footer);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" 发送  ", Style::default().fg(muted)),
            Span::styled("Ctrl+J", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" 换行  ", Style::default().fg(muted)),
            Span::styled("Ctrl+C", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" 退出", Style::default().fg(muted)),
        ])),
        footer_columns[0],
    );
    let config_name = app
        .path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("config.bin");
    let right_status = truncate_chars(
        &format!("{} · {config_name}", app.status),
        footer_columns[1].width as usize,
    );
    frame.render_widget(
        Paragraph::new(right_status)
            .style(Style::default().fg(muted))
            .alignment(Alignment::Right),
        footer_columns[1],
    );
}

fn truncate_chars(value: &str, width: usize) -> String {
    if char_count(value) <= width {
        return value.to_owned();
    }
    if width <= 1 {
        return "…".chars().take(width).collect();
    }
    let mut result = value.chars().take(width - 1).collect::<String>();
    result.push('…');
    result
}

fn centered(area: Rect, max_width: u16) -> Rect {
    if area.width <= max_width {
        area
    } else {
        let margin = (area.width - max_width) / 2;
        Rect::new(area.x + margin, area.y, max_width, area.height)
    }
}

fn input_height(input: &str, terminal_width: u16) -> u16 {
    let width = terminal_width.min(110).saturating_sub(4).max(1) as usize;
    let rows = input
        .split('\n')
        .map(|line| char_count(line).max(1).div_ceil(width))
        .sum::<usize>()
        .clamp(1, 5);
    rows as u16 + 2
}

fn input_cursor_position(area: Rect, input: &str, cursor: usize) -> (u16, u16) {
    let width = area.width.saturating_sub(4).max(1) as usize;
    let prefix = input.chars().take(cursor).collect::<String>();
    let mut row = 0usize;
    let mut column = 0usize;
    for character in prefix.chars() {
        if character == '\n' {
            row += 1;
            column = 0;
        } else {
            column += 1;
            if column >= width {
                row += 1;
                column = 0;
            }
        }
    }
    (
        area.x + 2 + column as u16,
        area.y + 1 + row.min(area.height.saturating_sub(2) as usize) as u16,
    )
}

fn char_count(value: &str) -> usize {
    value.chars().count()
}

fn byte_index(value: &str, character_index: usize) -> usize {
    value
        .char_indices()
        .nth(character_index)
        .map(|(index, _)| index)
        .unwrap_or(value.len())
}

fn insert_text(app: &mut ChatApp, value: &str) {
    let index = byte_index(&app.input, app.cursor);
    app.input.insert_str(index, value);
    app.cursor += char_count(value);
}

fn input_backspace(app: &mut ChatApp) {
    if app.cursor == 0 {
        return;
    }
    let start = byte_index(&app.input, app.cursor - 1);
    let end = byte_index(&app.input, app.cursor);
    app.input.replace_range(start..end, "");
    app.cursor -= 1;
}

fn input_delete(app: &mut ChatApp) {
    if app.cursor >= char_count(&app.input) {
        return;
    }
    let start = byte_index(&app.input, app.cursor);
    let end = byte_index(&app.input, app.cursor + 1);
    app.input.replace_range(start..end, "");
}

fn line_start(value: &str, cursor: usize) -> usize {
    value
        .chars()
        .take(cursor)
        .collect::<String>()
        .rfind('\n')
        .map(|index| char_count(&value[..index]) + 1)
        .unwrap_or(0)
}

fn line_end(value: &str, cursor: usize) -> usize {
    let start = byte_index(value, cursor);
    value[start..]
        .find('\n')
        .map(|index| cursor + char_count(&value[start..start + index]))
        .unwrap_or_else(|| char_count(value))
}

fn process_turn(
    model: &mut NeedleSession,
    path: &Path,
    password: &Zeroizing<String>,
    config: &mut Config,
    query: &str,
) -> Result<String, String> {
    let envelope = model.complete(query)?;
    if envelope.function_calls.is_empty() {
        let mut answer = envelope
            .reasoning
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("我没有识别出可执行的配置操作。请明确说明要新增、修改或删除的配置项。")
            .to_owned();
        if let Some(confidence) = envelope.confidence {
            answer.push_str(&format!("\n\n本地模型置信度：{:.1}%", confidence * 100.0));
        }
        return Ok(answer);
    }

    let mut next = config.clone();
    let mut summaries = Vec::new();
    let mut errors = Vec::new();
    for call in &envelope.function_calls {
        match execute_tool(&mut next, call, query) {
            Ok(summary) => summaries.push(summary),
            Err(error) => errors.push(error),
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("；"));
    }

    next.apply_managed_audit_paths(path);
    next.validate().map_err(|error| error.to_string())?;
    let outcome = config_cli::save_direct_config(path, password, next.clone())?;
    *config = next;
    if let Some(error) = outcome.live_update_error {
        summaries.push(format!("配置已保存，但 Serve 热更新失败：{error}"));
    } else if outcome.live_update {
        summaries.push("已热更新到运行中的 Serve".into());
    }

    let mut answer = String::from("已直接完成并保存：\n");
    for summary in summaries {
        answer.push_str(&format!("- {summary}\n"));
    }
    if let Some(confidence) = envelope.confidence {
        answer.push_str(&format!("\n本地模型置信度：{:.1}%", confidence * 100.0));
    }
    Ok(answer.trim_end().to_owned())
}

#[derive(Debug, Deserialize)]
struct ModelEnvelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    function_calls: Vec<ModelCall>,
    #[serde(default)]
    reasoning: Option<String>,
    #[serde(default)]
    confidence: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct ModelCall {
    name: String,
    #[serde(default)]
    arguments: Map<String, Value>,
}

struct NeedleSession {
    child: Child,
    address: SocketAddrV4,
    session_directory: PathBuf,
}

impl NeedleSession {
    fn start(config_path: &Path, config: &Config, query: &str) -> Result<Self, String> {
        let asset_directory = materialize_assets(config_path)?;
        let session_directory = create_session_directory(config_path)?;
        let tools_path = session_directory.join("tools.json");
        let system_path = session_directory.join("system.txt");
        write_private(&tools_path, tools_json(query).as_bytes(), false)?;
        let redacted =
            serde_json::to_string_pretty(&config.redacted()).map_err(|error| error.to_string())?;
        let system = format!(
            "You are the local HyperHub configuration assistant. Use only the provided configuration tools. Never claim to browse the web or read files. All inference is offline, so exact secrets from the user may be passed to tools. Existing configuration values marked <redacted> already exist and must never be invented or repeated. Current redacted configuration JSON:\n{redacted}"
        );
        write_private(&system_path, system.as_bytes(), false)?;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| format!("cannot reserve Needle 3 port: {error}"))?;
        let address = match listener.local_addr().map_err(|error| error.to_string())? {
            std::net::SocketAddr::V4(address) => address,
            _ => return Err("Needle 3 requires an IPv4 loopback address".into()),
        };
        drop(listener);

        let runner = asset_directory.join(runner_name());
        let model = asset_directory.join("needle3.cact");
        let force_tool = selected_tool_names(query).len() == 1;
        let mut command = Command::new(&runner);
        command
            .arg("--model")
            .arg(&model)
            .arg("--tools")
            .arg(&tools_path)
            .arg("--system")
            .arg(&system_path)
            .arg("--serve")
            .arg("--port")
            .arg(address.port().to_string())
            .arg("--threads")
            .arg("4")
            .arg("--max")
            .arg("1024");
        if force_tool {
            command.arg("--forced");
        }
        let child = command
            .env("NEEDLE_TELEMETRY", "0")
            .env("DO_NOT_TRACK", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("cannot start embedded Needle 3 runner: {error}"))?;
        let mut session = Self {
            child,
            address,
            session_directory,
        };
        session.wait_until_ready()?;
        Ok(session)
    }

    fn wait_until_ready(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().map_err(|error| error.to_string())? {
                return Err(format!(
                    "embedded Needle 3 runner exited during startup: {status}"
                ));
            }
            if TcpStream::connect_timeout(
                &std::net::SocketAddr::V4(self.address),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err("timed out starting embedded Needle 3".into())
    }

    fn complete(&mut self, input: &str) -> Result<ModelEnvelope, String> {
        let body =
            serde_json::to_vec(&json!({"input": input})).map_err(|error| error.to_string())?;
        let response = http_post(self.address, "/complete", &body)?;
        let envelope: ModelEnvelope = serde_json::from_slice(&response)
            .map_err(|error| format!("Needle 3 returned invalid JSON: {error}"))?;
        if !envelope.success {
            return Err(envelope
                .error
                .clone()
                .unwrap_or_else(|| "Needle 3 inference failed".into()));
        }
        Ok(envelope)
    }
}

impl Drop for NeedleSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        remove_directory(&self.session_directory);
    }
}

fn http_post(address: SocketAddrV4, path: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream =
        TcpStream::connect_timeout(&std::net::SocketAddr::V4(address), Duration::from_secs(2))
            .map_err(|error| format!("cannot connect to local Needle 3: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|error| error.to_string())?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        address.port(),
        body.len()
    )
    .map_err(|error| error.to_string())?;
    stream.write_all(body).map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("cannot read local Needle 3 response: {error}"))?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("local Needle 3 returned an invalid HTTP response")?;
    let headers = String::from_utf8_lossy(&response[..split]);
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err(format!(
            "local Needle 3 returned {}",
            headers.lines().next().unwrap_or("an HTTP error")
        ));
    }
    Ok(response[split + 4..].to_vec())
}

fn materialize_assets(config_path: &Path) -> Result<PathBuf, String> {
    let base = config_path
        .parent()
        .ok_or("configuration path has no parent directory")?
        .join("runtime")
        .join("needle3")
        .join(MODEL_SHA256);
    std::fs::create_dir_all(&base)
        .map_err(|error| format!("cannot create Needle 3 runtime directory: {error}"))?;
    set_directory_private(&base)?;
    let model = base.join("needle3.cact");
    let runner = base.join(runner_name());
    ensure_embedded_file(&model, EMBEDDED_MODEL, false)?;
    ensure_embedded_file(&runner, EMBEDDED_RUNNER, true)?;
    Ok(base)
}

fn ensure_embedded_file(path: &Path, bytes: &[u8], executable: bool) -> Result<(), String> {
    let expected = hex_sha256(bytes);
    let current = std::fs::read(path).ok().map(|value| hex_sha256(&value));
    if current.as_deref() != Some(expected.as_str()) {
        write_private(path, bytes, executable)?;
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8], executable: bool) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        set_directory_private(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    set_file_private(&temporary, executable)?;
    if path.exists() {
        std::fs::remove_file(path).map_err(|error| error.to_string())?;
    }
    std::fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    set_file_private(path, executable)
}

fn create_session_directory(config_path: &Path) -> Result<PathBuf, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = config_path
        .parent()
        .ok_or("configuration path has no parent directory")?
        .join("runtime")
        .join(format!("chat-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&path).map_err(|error| error.to_string())?;
    set_directory_private(&path)?;
    Ok(path)
}

fn remove_directory(path: &Path) {
    if path.is_dir() {
        let _ = std::fs::remove_dir_all(path);
    }
}

fn runner_name() -> &'static str {
    if cfg!(windows) {
        "needle.exe"
    } else {
        "needle"
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn set_directory_private(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn set_directory_private(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_file_private(path: &Path, executable: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn set_file_private(_path: &Path, _executable: bool) -> Result<(), String> {
    Ok(())
}

fn tools_json(query: &str) -> String {
    let all: Vec<Value> = serde_json::from_str(include_str!("../assets/needle3-tools.json"))
        .expect("embedded Needle 3 tool schemas are valid JSON");
    let selected = selected_tool_names(query);
    let tools = all
        .into_iter()
        .filter(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| selected.iter().any(|selected| *selected == name))
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&tools).expect("Needle tool schemas are serializable")
}

fn selected_tool_names(query: &str) -> Vec<&'static str> {
    let query = query.to_ascii_lowercase();
    let mut selected = Vec::new();
    let deleting = contains_any(&query, &["delete", "remove", "删除", "移除"]);
    let environment_intent = contains_any(&query, &["environment", " env ", "环境变量"]);
    let route_intent = contains_any(&query, &["route", "路由"]);
    let credential_mention = contains_any(
        &query,
        &[
            "credential",
            "token",
            "bearer",
            "basic auth",
            "header",
            "凭证",
            "令牌",
            "请求头",
        ],
    );
    let explicit_credential_change = contains_any(
        &query,
        &[
            "add credential",
            "set credential",
            "create credential",
            "update credential",
            "delete credential",
            "bearer credential",
            "basic credential",
            "header credential",
            "添加凭证",
            "设置凭证",
            "创建凭证",
            "修改凭证",
            "删除凭证",
            "bearer 凭证",
            "basic 凭证",
            "请求头凭证",
        ],
    );

    if environment_intent {
        add_tool_names(
            &mut selected,
            &[if deleting {
                "delete_environment_variable"
            } else {
                "set_environment_variable"
            }],
        );
    }

    if credential_mention && (explicit_credential_change || (!route_intent && !environment_intent))
    {
        let tool = if deleting {
            "delete_credential"
        } else if contains_any(&query, &["basic", "用户名", "username"]) {
            "set_basic_credential"
        } else if contains_any(&query, &["header", "请求头", "x-api-key"]) {
            "set_header_credential"
        } else {
            "set_bearer_credential"
        };
        add_tool_names(&mut selected, &[tool]);
    }

    if route_intent {
        let tool = if deleting {
            "delete_route"
        } else if contains_any(&query, &["default route", "默认路由"]) {
            "set_default_route"
        } else if credential_mention {
            "set_authenticated_route"
        } else {
            "set_route"
        };
        add_tool_names(&mut selected, &[tool]);
    }

    if contains_any(
        &query,
        &["firewall", "network rule", "防火墙", "网络规则", "网络策略"],
    ) {
        let tool = if deleting {
            "delete_firewall_rule"
        } else if contains_any(&query, &["rule", "规则"]) {
            "set_firewall_rule"
        } else {
            "set_firewall_policy"
        };
        add_tool_names(&mut selected, &[tool]);
    }

    if contains_any(
        &query,
        &["file sandbox", "file rule", "文件沙盒", "文件规则"],
    ) {
        let tool = if deleting {
            "delete_file_rule"
        } else if contains_any(&query, &["rule", "规则"]) {
            "set_file_rule"
        } else {
            "set_file_sandbox_policy"
        };
        add_tool_names(&mut selected, &[tool]);
    }

    if contains_any(
        &query,
        &[
            "process sandbox",
            "process rule",
            "child process",
            "进程沙盒",
            "进程规则",
            "子进程",
        ],
    ) {
        let tool = if deleting {
            "delete_process_rule"
        } else if contains_any(&query, &["rule", "规则"]) {
            "set_process_rule"
        } else {
            "set_process_sandbox_policy"
        };
        add_tool_names(&mut selected, &[tool]);
    }

    if contains_any(&query, &["upstream", "proxy", "上游", "代理"]) {
        add_tool_names(&mut selected, &["set_upstream_proxy"]);
    }
    if contains_any(&query, &["listener", "socks", "监听", "会话超时"]) {
        add_tool_names(&mut selected, &["set_listener"]);
    }
    if contains_any(&query, &["audit", "审计"]) {
        add_tool_names(&mut selected, &["set_audit_policy"]);
    }
    if contains_any(
        &query,
        &["mode", "debug", "enforce", "observe", "模式", "调试"],
    ) {
        add_tool_names(&mut selected, &["set_runtime_mode"]);
    }

    if selected.is_empty() {
        add_tool_names(
            &mut selected,
            &[
                "set_environment_variable",
                "set_bearer_credential",
                "set_route",
                "set_runtime_mode",
            ],
        );
    }
    selected
}

fn add_tool_names(selected: &mut Vec<&'static str>, names: &[&'static str]) {
    for name in names {
        if !selected.contains(name) {
            selected.push(*name);
        }
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn execute_tool(config: &mut Config, call: &ModelCall, query: &str) -> Result<String, String> {
    let args = &call.arguments;
    match call.name.as_str() {
        "set_environment_variable" => {
            let mut name = required_arg(args, "name")?.to_owned();
            if let Some(candidate) = environment_name_from_query(query) {
                name = candidate;
            }
            if !valid_environment_name(&name) {
                return Err(format!("无效的环境变量名：{name}"));
            }
            let value = required_arg(args, "value")?.to_owned();
            if let Some(variable) = config.environment.iter_mut().find(|item| item.name == name) {
                variable.value = SecretValue::Inline { value };
            } else {
                config.environment.push(EnvironmentVariable {
                    uuid: new_config_uuid(),
                    name: name.clone(),
                    value: SecretValue::Inline { value },
                });
            }
            Ok(format!("已设置环境变量 {name}（值已加密）"))
        }
        "delete_environment_variable" => {
            let name = required_arg(args, "name")?;
            remove_by(
                &mut config.environment,
                |item| item.name == name,
                format!("环境变量 {name}"),
            )?;
            Ok(format!("已删除环境变量 {name}"))
        }
        "set_bearer_credential" => {
            let id = normalize_identifier(required_arg(args, "credential_id")?, query, "凭证");
            let token = required_arg(args, "token")?.to_owned();
            upsert_credential(
                config,
                &id,
                HttpAuthScheme::Bearer,
                Some(SecretValue::Inline { value: token }),
                None,
                None,
                None,
                HashMap::new(),
            );
            Ok(format!("已设置 Bearer 凭证 {id}（令牌已加密）"))
        }
        "set_basic_credential" => {
            let id = normalize_identifier(required_arg(args, "credential_id")?, query, "凭证");
            let username = required_arg(args, "username")?.to_owned();
            let password = required_arg(args, "password")?.to_owned();
            upsert_credential(
                config,
                &id,
                HttpAuthScheme::Basic,
                None,
                None,
                Some(username),
                Some(SecretValue::Inline { value: password }),
                HashMap::new(),
            );
            Ok(format!("已设置 Basic 凭证 {id}（密码已加密）"))
        }
        "set_header_credential" => {
            let id = normalize_identifier(required_arg(args, "credential_id")?, query, "凭证");
            let header = required_arg(args, "header_name")?.to_owned();
            let value = required_arg(args, "header_value")?.to_owned();
            let mut headers = HashMap::new();
            headers.insert(header, SecretValue::Inline { value });
            upsert_credential(
                config,
                &id,
                HttpAuthScheme::CustomHeaders,
                None,
                None,
                None,
                None,
                headers,
            );
            Ok(format!("已设置请求头凭证 {id}（值已加密）"))
        }
        "delete_credential" => {
            let id = required_arg(args, "credential_id")?;
            if config
                .rules
                .iter()
                .any(|route| route.plugins.iter().any(|plugin| plugin == id))
                || config
                    .default_route
                    .plugins
                    .iter()
                    .any(|plugin| plugin == id)
            {
                return Err(format!("凭证 {id} 仍被路由引用，请先修改相关路由"));
            }
            remove_by(
                &mut config.plugins,
                |plugin| plugin.kind == PluginKind::Credential && plugin.id == id,
                format!("凭证 {id}"),
            )?;
            Ok(format!("已删除凭证 {id}"))
        }
        "set_route" | "set_authenticated_route" => {
            let mut id = normalize_identifier(required_arg(args, "route_id")?, query, "路由");
            let mut target = required_arg(args, "target")?.to_owned();
            if let Some(candidate) = route_target_from_query(query) {
                target = candidate;
            }
            if id == target || !query.contains(&id) {
                if let Some(candidate) = identifier_after(query, "路由") {
                    id = candidate;
                }
            }
            let credential = if call.name == "set_authenticated_route" {
                Some(normalize_identifier(
                    required_arg(args, "credential_id")?,
                    query,
                    "凭证",
                ))
            } else {
                None
            };
            if let Some(credential) = &credential {
                if !config
                    .plugins
                    .iter()
                    .any(|plugin| plugin.kind == PluginKind::Credential && plugin.id == *credential)
                {
                    return Err(format!("路由引用了不存在的凭证 {credential}"));
                }
            }
            let upstream = contains_any(
                &query.to_ascii_lowercase(),
                &["upstream", "proxy", "上游", "代理"],
            )
            .then(|| optional_arg(args, "upstream_id").map(str::to_owned))
            .flatten();
            if let Some(upstream) = &upstream {
                if !config.upstreams.iter().any(|item| item.id == *upstream) {
                    return Err(format!("路由引用了不存在的上游代理 {upstream}"));
                }
            }
            let enabled = boolean_arg(args, "enabled").unwrap_or(true);
            let deny = boolean_arg(args, "deny").unwrap_or(false);
            let priority = integer_arg(args, "priority").unwrap_or(100) as i32;
            let uuid = config
                .rules
                .iter()
                .find(|route| route.id == id)
                .map(|route| route.uuid.clone())
                .unwrap_or_else(new_config_uuid);
            let route = RouteRule {
                uuid,
                id: id.clone(),
                enabled,
                priority,
                endpoints: vec![RouteEndpoint { target, port: None }],
                deny,
                rewrite_host: None,
                rewrite_port: None,
                upstream,
                plugins: credential.into_iter().collect(),
                legacy: HashMap::new(),
            };
            upsert_by(&mut config.rules, |item| item.id == id, route);
            Ok(format!("已设置路由 {id}"))
        }
        "delete_route" => {
            let id = required_arg(args, "route_id")?;
            remove_by(
                &mut config.rules,
                |route| route.id == id,
                format!("路由 {id}"),
            )?;
            Ok(format!("已删除路由 {id}"))
        }
        "set_default_route" => {
            config.default_route.enabled = required_bool(args, "enabled")?;
            config.default_route.deny = required_bool(args, "deny")?;
            Ok(format!(
                "已设置默认路由：{}",
                if config.default_route.deny {
                    "拒绝"
                } else {
                    "放行"
                }
            ))
        }
        "set_runtime_mode" => {
            config.mode = match required_arg(args, "mode")? {
                "enforce" => hyperhub_core::config::EnforcementMode::Enforce,
                "observe" => hyperhub_core::config::EnforcementMode::Observe,
                value => return Err(format!("未知运行模式 {value}")),
            };
            if let Some(debug) = boolean_arg(args, "debug") {
                config.debug = debug;
            }
            Ok(format!("已设置运行模式为 {}", required_arg(args, "mode")?))
        }
        "set_listener" => {
            if let Some(value) = optional_arg(args, "socks_listen") {
                config.listener.socks_listen = value.to_owned();
            }
            if let Some(value) = integer_arg(args, "pending_session_ttl_secs") {
                config.listener.pending_session_ttl_secs = value as u64;
            }
            Ok("已更新本地监听设置".into())
        }
        "set_audit_policy" => {
            if let Some(value) = integer_arg(args, "retention_days") {
                config.audit.retention_days = value as u32;
            }
            if let Some(value) = boolean_arg(args, "connections") {
                config.audit.connections = value;
            }
            if let Some(value) = optional_arg(args, "header_allowlist") {
                config.audit.header_allowlist = comma_values(value);
            }
            Ok("已更新审计策略".into())
        }
        "set_upstream_proxy" => {
            let id = required_arg(args, "upstream_id")?.to_owned();
            let kind = match required_arg(args, "proxy_type")? {
                "socks5" => UpstreamKind::Socks5,
                "http_connect" => UpstreamKind::HttpConnect,
                value => return Err(format!("未知上游代理类型 {value}")),
            };
            let uuid = config
                .upstreams
                .iter()
                .find(|item| item.id == id)
                .map(|item| item.uuid.clone())
                .unwrap_or_else(new_config_uuid);
            let upstream = Upstream {
                uuid,
                id: id.clone(),
                kind,
                address: required_arg(args, "address")?.to_owned(),
                timeout_ms: integer_arg(args, "timeout_ms").unwrap_or(10_000) as u64,
                username: optional_arg(args, "username").map(|value| SecretValue::Inline {
                    value: value.into(),
                }),
                password: optional_arg(args, "password").map(|value| SecretValue::Inline {
                    value: value.into(),
                }),
                headers: HashMap::new(),
            };
            upsert_by(&mut config.upstreams, |item| item.id == id, upstream);
            Ok(format!("已设置上游代理 {id}"))
        }
        "set_firewall_policy" => {
            config.firewall.enabled = required_bool(args, "enabled")?;
            config.firewall.default = Some(FirewallDefaultRule {
                action: firewall_action(required_arg(args, "default_action")?)?,
            });
            config.firewall.error_action = firewall_action(required_arg(args, "error_action")?)?;
            Ok("已更新网络防火墙策略".into())
        }
        "set_firewall_rule" => {
            let id = required_arg(args, "rule_id")?.to_owned();
            let uuid = config
                .firewall
                .rules
                .iter()
                .find(|item| item.id == id)
                .map(|item| item.uuid.clone())
                .unwrap_or_else(new_config_uuid);
            let port = integer_arg(args, "port")
                .map(u16::try_from)
                .transpose()
                .map_err(|_| "端口必须在 0..65535 范围内".to_string())?;
            let rule = FirewallRule {
                uuid,
                id: id.clone(),
                enabled: boolean_arg(args, "enabled").unwrap_or(true),
                priority: integer_arg(args, "priority").unwrap_or(100) as i32,
                action: firewall_action(required_arg(args, "action")?)?,
                endpoints: vec![FirewallEndpoint {
                    target: required_arg(args, "target")?.to_owned(),
                    port,
                }],
                legacy: HashMap::new(),
            };
            upsert_by(&mut config.firewall.rules, |item| item.id == id, rule);
            Ok(format!("已设置网络规则 {id}"))
        }
        "delete_firewall_rule" => {
            let id = required_arg(args, "rule_id")?;
            remove_by(
                &mut config.firewall.rules,
                |item| item.id == id,
                format!("网络规则 {id}"),
            )?;
            Ok(format!("已删除网络规则 {id}"))
        }
        "set_file_sandbox_policy" => {
            config.sandbox.file.enabled = required_bool(args, "enabled")?;
            config.sandbox.file.default = SandboxDefaultRule {
                action: sandbox_action(required_arg(args, "default_action")?)?,
            };
            config.sandbox.file.error_action = sandbox_action(required_arg(args, "error_action")?)?;
            Ok("已更新文件沙盒策略".into())
        }
        "set_file_rule" => {
            let id = required_arg(args, "rule_id")?.to_owned();
            let uuid = config
                .sandbox
                .file
                .rules
                .iter()
                .find(|item| item.id == id)
                .map(|item| item.uuid.clone())
                .unwrap_or_else(new_config_uuid);
            let operations = comma_values(required_arg(args, "operations")?)
                .into_iter()
                .map(|value| match value.as_str() {
                    "read" => Ok(FileSandboxOperation::Read),
                    "write" => Ok(FileSandboxOperation::Write),
                    "create" => Ok(FileSandboxOperation::Create),
                    "delete" => Ok(FileSandboxOperation::Delete),
                    "rename" => Ok(FileSandboxOperation::Rename),
                    other => Err(format!("未知文件操作 {other}")),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let rule = FileSandboxRule {
                uuid,
                id: id.clone(),
                enabled: boolean_arg(args, "enabled").unwrap_or(true),
                priority: integer_arg(args, "priority").unwrap_or(100) as i32,
                action: sandbox_action(required_arg(args, "action")?)?,
                patterns: vec![FileSandboxPattern {
                    enabled: true,
                    pattern: required_arg(args, "pattern")?.to_owned(),
                }],
                operations,
                legacy: HashMap::new(),
            };
            upsert_by(&mut config.sandbox.file.rules, |item| item.id == id, rule);
            Ok(format!("已设置文件规则 {id}"))
        }
        "delete_file_rule" => {
            let id = required_arg(args, "rule_id")?;
            remove_by(
                &mut config.sandbox.file.rules,
                |item| item.id == id,
                format!("文件规则 {id}"),
            )?;
            Ok(format!("已删除文件规则 {id}"))
        }
        "set_process_sandbox_policy" => {
            config.sandbox.process.enabled = required_bool(args, "enabled")?;
            config.sandbox.process.default = SandboxDefaultRule {
                action: sandbox_action(required_arg(args, "default_action")?)?,
            };
            config.sandbox.process.error_action =
                sandbox_action(required_arg(args, "error_action")?)?;
            Ok("已更新子进程沙盒策略".into())
        }
        "set_process_rule" => {
            let id = required_arg(args, "rule_id")?.to_owned();
            let uuid = config
                .sandbox
                .process
                .rules
                .iter()
                .find(|item| item.id == id)
                .map(|item| item.uuid.clone())
                .unwrap_or_else(new_config_uuid);
            let rule = ProcessSandboxRule {
                uuid,
                id: id.clone(),
                enabled: boolean_arg(args, "enabled").unwrap_or(true),
                priority: integer_arg(args, "priority").unwrap_or(100) as i32,
                action: sandbox_action(required_arg(args, "action")?)?,
                patterns: vec![ProcessSandboxPattern {
                    enabled: true,
                    executable: optional_arg(args, "executable").unwrap_or("").to_owned(),
                    command_line: optional_arg(args, "command_line").unwrap_or("").to_owned(),
                }],
                legacy: HashMap::new(),
            };
            upsert_by(
                &mut config.sandbox.process.rules,
                |item| item.id == id,
                rule,
            );
            Ok(format!("已设置子进程规则 {id}"))
        }
        "delete_process_rule" => {
            let id = required_arg(args, "rule_id")?;
            remove_by(
                &mut config.sandbox.process.rules,
                |item| item.id == id,
                format!("子进程规则 {id}"),
            )?;
            Ok(format!("已删除子进程规则 {id}"))
        }
        other => Err(format!("Needle 3 requested unknown tool {other}")),
    }
}

#[allow(clippy::too_many_arguments)]
fn upsert_credential(
    config: &mut Config,
    id: &str,
    scheme: HttpAuthScheme,
    secret: Option<SecretValue>,
    http_name: Option<String>,
    username: Option<String>,
    password: Option<SecretValue>,
    headers: HashMap<String, SecretValue>,
) {
    let uuid = config
        .plugins
        .iter()
        .find(|item| item.kind == PluginKind::Credential && item.id == id)
        .map(|item| item.uuid.clone())
        .unwrap_or_else(new_config_uuid);
    let plugin = PluginConfig {
        uuid,
        id: id.to_owned(),
        kind: PluginKind::Credential,
        protocols: vec![PluginProtocol::Http],
        http_scheme: Some(scheme),
        secret,
        http_name,
        username,
        password,
        ssh_accounts: Vec::new(),
        headers,
        legacy: HashMap::new(),
        ..PluginConfig::default()
    };
    upsert_by(
        &mut config.plugins,
        |item| item.kind == PluginKind::Credential && item.id == id,
        plugin,
    );
}

fn upsert_by<T>(items: &mut Vec<T>, predicate: impl Fn(&T) -> bool, value: T) {
    if let Some(index) = items.iter().position(predicate) {
        items[index] = value;
    } else {
        items.push(value);
    }
}

fn remove_by<T>(
    items: &mut Vec<T>,
    predicate: impl Fn(&T) -> bool,
    description: String,
) -> Result<(), String> {
    let index = items
        .iter()
        .position(predicate)
        .ok_or_else(|| format!("找不到{description}"))?;
    items.remove(index);
    Ok(())
}

fn required_arg<'a>(args: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    optional_arg(args, name).ok_or_else(|| format!("工具参数缺少 {name}"))
}

fn optional_arg<'a>(args: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn required_bool(args: &Map<String, Value>, name: &str) -> Result<bool, String> {
    boolean_arg(args, name).ok_or_else(|| format!("工具参数缺少 {name}"))
}

fn boolean_arg(args: &Map<String, Value>, name: &str) -> Option<bool> {
    args.get(name).and_then(Value::as_bool)
}

fn integer_arg(args: &Map<String, Value>, name: &str) -> Option<i64> {
    args.get(name).and_then(Value::as_i64)
}

fn firewall_action(value: &str) -> Result<FirewallAction, String> {
    match value {
        "pass" => Ok(FirewallAction::Pass),
        "deny" => Ok(FirewallAction::Deny),
        other => Err(format!("未知网络动作 {other}")),
    }
}

fn sandbox_action(value: &str) -> Result<SandboxAction, String> {
    match value {
        "pass" => Ok(SandboxAction::Pass),
        "deny" => Ok(SandboxAction::Deny),
        other => Err(format!("未知沙盒动作 {other}")),
    }
}

fn comma_values(value: &str) -> Vec<String> {
    value
        .split([',', '，'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn environment_name_from_query(query: &str) -> Option<String> {
    for marker in ["环境变量", "environment variable", " env "] {
        if let Some(candidate) =
            identifier_after(query, marker).filter(|candidate| valid_environment_name(candidate))
        {
            return Some(candidate);
        }
    }
    query
        .split(|character: char| {
            character.is_whitespace() || matches!(character, ',' | '，' | ':' | '：' | '=' | '。')
        })
        .filter(|token| valid_environment_name(token))
        .max_by_key(|token| {
            let uppercase = token.bytes().filter(u8::is_ascii_uppercase).count();
            (uppercase, token.len())
        })
        .map(str::to_owned)
}

fn normalize_identifier(value: &str, query: &str, marker: &str) -> String {
    identifier_after(query, marker).unwrap_or_else(|| value.to_owned())
}

fn identifier_after(query: &str, marker: &str) -> Option<String> {
    let candidates: &[&str] = match marker {
        "路由" => &["路由", "route"],
        "凭证" => &["凭证", "credential"],
        _ => &[marker],
    };
    let lowered = query.to_ascii_lowercase();
    for candidate in candidates {
        let Some(position) = lowered.find(candidate) else {
            continue;
        };
        let tail = &query[position + candidate.len()..];
        if let Some(value) = tail
            .trim_start_matches(|character: char| {
                character.is_whitespace() || matches!(character, ':' | '：' | ',' | '，')
            })
            .split(|character: char| {
                character.is_whitespace() || matches!(character, ':' | '：' | ',' | '，')
            })
            .find(|value| !value.is_empty())
        {
            return Some(value.to_owned());
        }
    }
    None
}

fn route_target_from_query(query: &str) -> Option<String> {
    let start = query.find("https://").or_else(|| query.find("http://"))?;
    let tail = &query[start..];
    let end = tail
        .char_indices()
        .find(|(_, character)| {
            character.is_whitespace() || matches!(character, ',' | '，' | '。' | ';' | '；')
        })
        .map(|(index, _)| index)
        .unwrap_or(tail.len());
    Some(tail[..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn call(name: &str, arguments: Value) -> ModelCall {
        ModelCall {
            name: name.into(),
            arguments: arguments.as_object().unwrap().clone(),
        }
    }

    #[test]
    fn chat_parser_accepts_only_password_file() {
        assert_eq!(
            parse(&[OsString::from("--password-file"), OsString::from("secret")]).unwrap(),
            ChatConfig {
                password_file: Some("secret".into())
            }
        );
        assert!(parse(&[OsString::from("--unknown")]).is_err());
    }

    #[test]
    fn semantic_tool_selection_keeps_route_references_out_of_credential_mutation() {
        assert_eq!(
            selected_tool_names(
                "添加认证路由 local-route，目标 https://example.com/api，使用凭证 local-api"
            ),
            ["set_authenticated_route"]
        );
        assert_eq!(
            selected_tool_names("添加 Bearer 凭证 local-api，token 是 secret"),
            ["set_bearer_credential"]
        );
        assert_eq!(
            selected_tool_names("添加环境变量 CHAT_TOKEN，值是 secret"),
            ["set_environment_variable"]
        );
    }

    #[test]
    fn environment_name_prefers_the_full_identifier_after_the_intent() {
        assert_eq!(
            environment_name_from_query("添加环境变量 CHAT_FINAL_TOKEN，值是 final-secret")
                .as_deref(),
            Some("CHAT_FINAL_TOKEN")
        );
        assert_eq!(
            environment_name_from_query("Set environment variable NEEDLE_TEST_ENV to local-value")
                .as_deref(),
            Some("NEEDLE_TEST_ENV")
        );
    }

    #[test]
    fn direct_tools_preserve_item_uuid_and_never_echo_secrets() {
        let mut config = Config::default();
        let first = call(
            "set_environment_variable",
            json!({"name": "API_KEY", "value": "first-secret"}),
        );
        let summary = execute_tool(&mut config, &first, "set environment variable").unwrap();
        let uuid = config.environment[0].uuid.clone();
        assert!(!summary.contains("first-secret"));
        let second = call(
            "set_environment_variable",
            json!({"name": "API_KEY", "value": "second-secret"}),
        );
        execute_tool(&mut config, &second, "set environment variable").unwrap();
        assert_eq!(config.environment[0].uuid, uuid);
        assert!(matches!(
            &config.environment[0].value,
            SecretValue::Inline { value } if value == "second-secret"
        ));
    }

    #[test]
    fn credential_and_authenticated_route_are_valid_together() {
        let mut config = Config::default();
        execute_tool(
            &mut config,
            &call(
                "set_bearer_credential",
                json!({"credential_id": "api-token", "token": "secret"}),
            ),
            "set bearer credential api-token",
        )
        .unwrap();
        execute_tool(
            &mut config,
            &call(
                "set_authenticated_route",
                json!({
                    "route_id": "api",
                    "target": "https://example.com/api",
                    "credential_id": "api-token"
                }),
            ),
            "set route api with credential api-token",
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.rules[0].plugins, ["api-token"]);
    }

    #[test]
    fn chat_layout_matches_single_column_conversation_and_bottom_composer() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = ChatApp::new("/tmp/config.bin".into());
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("HyperHub"));
        assert!(rendered.contains("Needle 3 · local"));
        assert!(rendered.contains("local configuration agent"));
        assert!(rendered.contains("Enter"));
    }

    #[test]
    fn input_editor_supports_unicode_middle_edits() {
        let mut app = ChatApp::new("config.bin".into());
        app.input.clear();
        app.cursor = 0;
        insert_text(&mut app, "ab中d");
        app.cursor = 3;
        input_backspace(&mut app);
        insert_text(&mut app, "文");
        assert_eq!(app.input, "ab文d");
    }

    #[test]
    fn embedded_needle3_model_dispatches_a_configuration_tool() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-needle-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.bin");
        let mut config = Config::default();
        config.apply_managed_audit_paths(&path);
        let password = Zeroizing::new("needle-test-password".to_owned());
        let query = "Set environment variable NEEDLE_TEST_ENV to local-value";
        let mut session = NeedleSession::start(&path, &config, query).unwrap();
        let answer = process_turn(&mut session, &path, &password, &mut config, query).unwrap();
        assert!(answer.contains("NEEDLE_TEST_ENV"), "answer={answer:?}");
        let saved = load_encrypted(&path, password.as_bytes()).unwrap().config;
        assert!(saved.environment.iter().any(|variable| {
            variable.name == "NEEDLE_TEST_ENV"
                && matches!(
                    &variable.value,
                    SecretValue::Inline { value } if value == "local-value"
                )
        }));
        drop(session);

        execute_tool(
            &mut config,
            &call(
                "set_bearer_credential",
                json!({"credential_id": "local-api", "token": "route-secret"}),
            ),
            "添加 Bearer 凭证 local-api，token 是 route-secret",
        )
        .unwrap();
        let route_query =
            "添加认证路由 local-route，目标 https://example.com/api，使用凭证 local-api";
        let mut route_session = NeedleSession::start(&path, &config, route_query).unwrap();
        let route_response = route_session.complete(route_query).unwrap();
        assert!(
            !route_response.function_calls.is_empty(),
            "route_response={route_response:?}"
        );
        assert!(route_response
            .function_calls
            .iter()
            .all(|call| call.name == "set_authenticated_route"));
        for route_call in &route_response.function_calls {
            execute_tool(&mut config, route_call, route_query).unwrap();
        }
        config.validate().unwrap();
        assert!(
            config.rules.iter().any(|route| {
                route.id == "local-route"
                    && route.endpoints[0].target == "https://example.com/api"
                    && route.plugins == ["local-api"]
            }),
            "routes={:?} calls={:?}",
            config.rules,
            route_response.function_calls
        );
        drop(route_session);
        let _ = std::fs::remove_dir_all(root);
    }
}

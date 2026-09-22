use crate::config_semantics::ConfigSection;
use crossterm::cursor::SetCursorStyle;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use hyperhub_core::config::{
    parse_route_target, Config, DataProtectionConfig, EnforcementMode, EnvironmentVariable,
    FileSandboxOperation, FileSandboxPattern, FileSandboxRule, FirewallAction, FirewallDefaultRule,
    FirewallEndpoint, FirewallRule, HttpAuthScheme, IntelligenceProtectionConfig,
    IntelligenceProviderConfig, IntelligenceProviderKind, PluginConfig, PluginKind, PluginProtocol,
    ProcessSandboxPattern, ProcessSandboxRule, ProtectionAction, ProtectionMode, ProtectionProfile,
    RootCertificate, RouteEndpoint, RouteRule, RouteTarget, RuleAction, SandboxAction, SecretValue,
    SshAccount, SshHostKey, SshPrivateKey, Upstream, UpstreamKind, WebSocketCapture,
    DEFAULT_ROUTE_ID,
};
use hyperhub_core::config_store;
use hyperhub_core::control::{control_request, discovery_control_endpoint};
use hyperhub_core::session::{
    config_update_proof, ControlRequest, ControlResponse, InjectedProcessSnapshot,
};
use hyperhub_core::ssh_keys::{
    generate_rsa_private_key, import_private_key, public_key_info, short_label, PublicKeyInfo,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NavNode {
    Gateway,
    Basic,
    Proxy,
    Credential,
    Audit,
    Protection,
    Route,
    Certificate,
    Sandbox,
    Network,
    SandboxProcess,
    Files,
    Process,
    Environment,
}

const NAV_ITEMS: &[NavNode] = &[
    NavNode::Process,
    NavNode::Gateway,
    NavNode::Basic,
    NavNode::Proxy,
    NavNode::Credential,
    NavNode::Audit,
    NavNode::Route,
    NavNode::Certificate,
    NavNode::Sandbox,
    NavNode::Network,
    NavNode::Files,
    NavNode::SandboxProcess,
    NavNode::Protection,
    NavNode::Environment,
];

const CATEGORY_GATEWAY: NavNode = NavNode::Gateway;
const CATEGORY_BASIC: NavNode = NavNode::Basic;
const CATEGORY_PROXY: NavNode = NavNode::Proxy;
const CATEGORY_CREDENTIAL: NavNode = NavNode::Credential;
const CATEGORY_AUDIT: NavNode = NavNode::Audit;
const CATEGORY_PROTECTION: NavNode = NavNode::Protection;
const CATEGORY_ROUTE: NavNode = NavNode::Route;
const CATEGORY_CERTIFICATE: NavNode = NavNode::Certificate;
const CATEGORY_SANDBOX: NavNode = NavNode::Sandbox;
const CATEGORY_FIREWALL: NavNode = NavNode::Network;
const CATEGORY_SANDBOX_PROCESS: NavNode = NavNode::SandboxProcess;
const CATEGORY_FILES: NavNode = NavNode::Files;
const CATEGORY_PROCESS: NavNode = NavNode::Process;
const CATEGORY_ENVIRONMENT: NavNode = NavNode::Environment;
const DEFAULT_HTTP_HEADER_REMOVAL: &str = "PRIVATE-TOKEN";

impl NavNode {
    fn section(self) -> ConfigSection {
        match self {
            Self::Gateway => ConfigSection::Gateway,
            Self::Basic => ConfigSection::Basic,
            Self::Proxy => ConfigSection::Proxy,
            Self::Credential => ConfigSection::Credential,
            Self::Audit => ConfigSection::Audit,
            Self::Protection => ConfigSection::Protection,
            Self::Route => ConfigSection::Route,
            Self::Certificate => ConfigSection::Certificate,
            Self::Sandbox => ConfigSection::Sandbox,
            Self::Network => ConfigSection::Network,
            Self::SandboxProcess => ConfigSection::SandboxProcess,
            Self::Files => ConfigSection::Files,
            Self::Process => ConfigSection::Process,
            Self::Environment => ConfigSection::Environment,
        }
    }

    fn label(self) -> &'static str {
        self.section().label()
    }

    fn sidebar_label(self) -> String {
        if self.is_child() {
            format!("  {}", self.label())
        } else {
            self.label().to_string()
        }
    }

    fn is_group(self) -> bool {
        matches!(self, Self::Gateway | Self::Sandbox)
    }

    fn is_child(self) -> bool {
        matches!(
            self,
            Self::Basic
                | Self::Proxy
                | Self::Credential
                | Self::Audit
                | Self::Route
                | Self::Certificate
                | Self::Network
                | Self::SandboxProcess
                | Self::Files
        )
    }

    fn index(self) -> usize {
        NAV_ITEMS
            .iter()
            .position(|node| *node == self)
            .expect("navigation node must be registered")
    }

    fn breadcrumb(self) -> String {
        self.section().breadcrumb()
    }
}

pub struct TuiResult {
    pub password: Zeroizing<String>,
}

enum Focus {
    Sidebar,
    Detail,
}

#[derive(Clone, Copy)]
enum ObjectEditor {
    DefaultRoute,
    Upstream(usize),
    Credential(usize),
    AuditProfile(usize),
    Protection(usize),
    ProtectionLocal(usize),
    ProtectionIntelligence(usize),
    Route(usize),
    FirewallRule(usize),
    SandboxProcessRule(usize),
    FileSandboxRule(usize),
    RootCertificate(usize),
}

#[derive(Clone, Copy)]
enum TextField {
    SocksListen,
    PendingTtl,
    UpstreamId(usize),
    UpstreamAddress(usize),
    UpstreamTimeout(usize),
    CredentialId(usize),
    CredentialUsername(usize),
    CredentialHttpName(usize),
    SshAccountUsername(usize, usize),
    SshKeyName(usize, usize, usize),
    AuditId(usize),
    AuditBodyLimit(usize),
    AuditRetentionDays,
    ProtectionId(usize),
    ProtectionMaxScanBytes(usize),
    ProtectionProvenanceWindow(usize),
    ProtectionProvenanceMatches(usize),
    ProtectionTimeoutMs(usize),
    ProtectionMinConfidence(usize),
    ProtectionCacheTtlMs(usize),
    ProtectionProviderEndpoint(usize),
    ProtectionProviderModel(usize),
    RouteId(usize),
    RoutePriority(usize),
    FirewallId(usize),
    FirewallPriority(usize),
    SandboxProcessId(usize),
    SandboxProcessPriority(usize),
    FileSandboxId(usize),
    FileSandboxPriority(usize),
}

#[derive(Clone, Copy)]
enum SecretField {
    UpstreamUsername(usize),
    UpstreamPassword(usize),
    CredentialPassword(usize),
    CredentialHttpSecret(usize),
    ProtectionProviderApiKey(usize),
    SshPassword(usize, usize, Option<usize>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderField {
    Upstream(usize),
    Credential(usize),
}

enum InputAction {
    Text(TextField),
    Secret(SecretField),
    HeaderName(HeaderField),
    HeaderValue(HeaderField, String, bool),
    ListValue(ListEditorKind, Option<usize>),
    RouteTarget(usize, Option<usize>),
    RoutePort(usize, Option<usize>, String),
    FirewallTarget(usize, Option<usize>),
    FirewallPort(usize, Option<usize>, String),
    FilePattern(usize, Option<usize>),
    ProcessExecutable(usize, Option<usize>),
    ProcessCommandLine(usize, Option<usize>, String),
    EnvironmentName,
    EnvironmentValue(Option<usize>, String, bool),
    ImportRootCertificate,
    AddSshAccount(usize),
    ImportSshKeyPath(usize, usize),
    AddSshKeyPaste(usize, usize),
    Search,
    NewPassword,
    ConfirmPassword(Zeroizing<String>),
}

struct InputModal {
    title: String,
    value: Zeroizing<String>,
    cursor: usize,
    masked: bool,
    multiline: bool,
    action: InputAction,
}

#[derive(Clone, Copy)]
struct HeaderEditor {
    field: HeaderField,
    selected: usize,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum ListEditorKind {
    RouteTargets(usize),
    FirewallTargets(usize),
    FirewallPorts(usize),
    FilePaths(usize),
    SandboxExecutables(usize),
    SandboxCommandLines(usize),
}

impl ListEditorKind {
    fn label(self) -> &'static str {
        match self {
            Self::RouteTargets(_) => "路由目标",
            Self::FirewallTargets(_) => "网络目标",
            Self::FirewallPorts(_) => "端口",
            Self::FilePaths(_) => "文件路径",
            Self::SandboxExecutables(_) => "可执行文件",
            Self::SandboxCommandLines(_) => "命令行",
        }
    }
}

#[derive(Clone, Copy)]
struct ListEditor {
    kind: ListEditorKind,
    selected: usize,
}

#[derive(Clone, Copy)]
struct SshAccountEditor {
    credential: usize,
    selected: usize,
}

#[derive(Clone, Copy)]
struct SshAccountDetail {
    credential: usize,
    account: usize,
    field: usize,
}

#[derive(Clone, Copy)]
struct SshKeyEditor {
    credential: usize,
    account: usize,
    selected: usize,
}

#[derive(Clone, Copy)]
struct SshPasswordEditor {
    credential: usize,
    account: usize,
    selected: usize,
}

#[derive(Clone, Copy)]
struct SshKeyAddPicker {
    credential: usize,
    account: usize,
    selected: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReferenceKind {
    Proxy,
    Credential,
    Audit,
    Protection,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReferenceTarget {
    DefaultRoute,
    Route(usize),
    Firewall(usize),
    Process(usize),
    File(usize),
}

#[derive(Clone, Copy)]
struct ReferencePicker {
    target: ReferenceTarget,
    kind: ReferenceKind,
    /// Zero represents “not configured”; configured objects start at one.
    selected: usize,
}

#[derive(Clone, PartialEq, Eq)]
struct ManagedProcessView {
    session_id: String,
    process: InjectedProcessSnapshot,
}

/// 后台轮询线程下发给 UI 的进程快照。
struct ProcessPoll {
    live: bool,
    processes: Vec<ManagedProcessView>,
}

struct App {
    config: Config,
    password: Zeroizing<String>,
    previous_password: Option<Zeroizing<String>>,
    path: PathBuf,
    root_certificate_cache: Option<Vec<RootCertificateView>>,
    category: NavNode,
    field: usize,
    editor: Option<ObjectEditor>,
    focus: Focus,
    dirty: bool,
    help: bool,
    exit_prompt: bool,
    modal: Option<InputModal>,
    header_editor: Option<HeaderEditor>,
    list_editor: Option<ListEditor>,
    ssh_account_editor: Option<SshAccountEditor>,
    ssh_account_detail: Option<SshAccountDetail>,
    ssh_key_editor: Option<SshKeyEditor>,
    ssh_password_editor: Option<SshPasswordEditor>,
    ssh_key_add_picker: Option<SshKeyAddPicker>,
    reference_picker: Option<ReferencePicker>,
    ssh_key_preview: Option<SshKeyPreview>,
    managed_processes: Vec<ManagedProcessView>,
    status: String,
    saved: bool,
    discarded: bool,
    live: bool,
}

struct RootCertificateView {
    fingerprint: String,
    name: String,
    summary: String,
}

struct SshKeyPreview {
    algorithm: String,
    /// 用于复制到剪贴板的完整 OpenSSH 公钥行。
    openssh: String,
    fingerprint: String,
    /// 弹窗内展示复制结果，避免底部全局状态被弹窗遮挡。
    copy_message: Option<String>,
}

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            SetCursorStyle::DefaultUserShape,
            LeaveAlternateScreen
        );
    }
}

pub fn run(
    path: &Path,
    password: Zeroizing<String>,
    config: Config,
    live: bool,
    newly_initialized: bool,
) -> Result<TuiResult, String> {
    enable_raw_mode().map_err(|error| error.to_string())?;
    let _guard = TerminalGuard;
    execute!(
        io::stdout(),
        EnterAlternateScreen,
        SetCursorStyle::SteadyBar
    )
    .map_err(|error| error.to_string())?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|error| error.to_string())?;
    let status = if newly_initialized {
        format!("✓ 已生成基础配置：{}", config.listener.socks_listen)
    } else {
        "✓ 配置有效".into()
    };
    let mut app = App {
        config,
        password,
        previous_password: None,
        path: path.to_owned(),
        root_certificate_cache: None,
        category: CATEGORY_GATEWAY,
        field: 0,
        editor: None,
        focus: Focus::Sidebar,
        dirty: !path.is_file(),
        help: false,
        exit_prompt: false,
        modal: None,
        header_editor: None,
        list_editor: None,
        ssh_account_editor: None,
        ssh_account_detail: None,
        ssh_key_editor: None,
        ssh_password_editor: None,
        ssh_key_add_picker: None,
        reference_picker: None,
        ssh_key_preview: None,
        managed_processes: if live {
            query_managed_processes().unwrap_or_default()
        } else {
            Vec::new()
        },
        status,
        saved: false,
        discarded: false,
        live,
    };
    // 进程轮询放到后台线程，UI 循环只在收到新快照或发生终端事件时重绘，
    // 避免每秒在 UI 线程执行同步控制面请求造成卡顿。
    let (process_tx, process_rx) = std::sync::mpsc::channel::<ProcessPoll>();
    std::thread::Builder::new()
        .name("hyperhub-tui-process-poll".into())
        .spawn(move || {
            let Ok(runtime) = control_runtime() else {
                return;
            };
            loop {
                let snapshot = match query_managed_processes_with(runtime) {
                    Ok(processes) => ProcessPoll {
                        live: true,
                        processes,
                    },
                    Err(_) => ProcessPoll {
                        live: false,
                        processes: Vec::new(),
                    },
                };
                if process_tx.send(snapshot).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        })
        .map_err(|error| format!("cannot start process poll thread: {error}"))?;
    terminal
        .draw(|frame| draw(frame, &app))
        .map_err(|error| error.to_string())?;
    loop {
        while let Ok(snapshot) = process_rx.try_recv() {
            if snapshot.live != app.live || snapshot.processes != app.managed_processes {
                app.live = snapshot.live;
                app.managed_processes = snapshot.processes;
                if app.category == CATEGORY_PROCESS {
                    app.field = app.field.min(app.managed_processes.len().saturating_sub(1));
                }
                terminal
                    .draw(|frame| draw(frame, &app))
                    .map_err(|error| error.to_string())?;
            }
        }
        if !event::poll(Duration::from_millis(250)).map_err(|error| error.to_string())? {
            continue;
        }
        let Event::Key(key) = event::read().map_err(|error| error.to_string())? else {
            terminal
                .draw(|frame| draw(frame, &app))
                .map_err(|error| error.to_string())?;
            continue;
        };
        if handle_key(&mut app, key)? {
            break;
        }
        terminal
            .draw(|frame| draw(frame, &app))
            .map_err(|error| error.to_string())?;
    }
    terminal.show_cursor().map_err(|error| error.to_string())?;
    if !app.saved && app.dirty && !app.discarded {
        return Err("configuration changes were not saved".into());
    }
    Ok(TuiResult {
        password: app.password,
    })
}

fn handle_key(app: &mut App, key: KeyEvent) -> Result<bool, String> {
    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return Ok(false);
    }
    if app.exit_prompt {
        match key.code {
            KeyCode::Char('s') => match save(app) {
                Ok(()) => return Ok(true),
                Err(error) => {
                    app.status = format!("✗ {error}");
                    app.exit_prompt = false;
                }
            },
            KeyCode::Char('d') => {
                app.discarded = true;
                return Ok(true);
            }
            KeyCode::Esc | KeyCode::Char('c') => app.exit_prompt = false,
            _ => {}
        }
        return Ok(false);
    }
    if let Some(mut modal) = app.modal.take() {
        match key.code {
            KeyCode::Esc => {}
            KeyCode::Left => {
                modal.cursor = modal.cursor.saturating_sub(1);
                app.modal = Some(modal);
            }
            KeyCode::Right => {
                modal.cursor = (modal.cursor + 1).min(modal.value.chars().count());
                app.modal = Some(modal);
            }
            KeyCode::Home => {
                modal.cursor = input_line_start(&modal.value, modal.cursor, modal.multiline);
                app.modal = Some(modal);
            }
            KeyCode::End => {
                modal.cursor = input_line_end(&modal.value, modal.cursor, modal.multiline);
                app.modal = Some(modal);
            }
            KeyCode::Delete => {
                input_delete_at_cursor(&mut modal);
                app.modal = Some(modal);
            }
            KeyCode::Backspace => {
                input_backspace(&mut modal);
                app.modal = Some(modal);
            }
            KeyCode::Char('s')
                if modal.multiline && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                if let Err(error) = apply_input(app, modal) {
                    app.status = format!("✗ {error}");
                }
            }
            KeyCode::Char(value) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                input_insert(&mut modal, value);
                app.modal = Some(modal);
            }
            KeyCode::Enter => {
                if modal.multiline {
                    input_insert(&mut modal, '\n');
                    app.modal = Some(modal);
                } else if let Err(error) = apply_input(app, modal) {
                    app.status = format!("✗ {error}");
                }
            }
            _ => app.modal = Some(modal),
        }
        return Ok(false);
    }
    if app.help {
        app.help = false;
        return Ok(false);
    }
    if app.ssh_key_preview.is_some() {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => app.ssh_key_preview = None,
            KeyCode::Enter | KeyCode::Char('c') => copy_previewed_ssh_key(app),
            _ => {}
        }
        return Ok(false);
    }
    if app.ssh_key_add_picker.is_some() {
        handle_ssh_key_add_picker_key(app, key);
        return Ok(false);
    }
    if app.ssh_key_editor.is_some() {
        handle_ssh_key_editor_key(app, key);
        return Ok(false);
    }
    if app.ssh_password_editor.is_some() {
        handle_ssh_password_editor_key(app, key);
        return Ok(false);
    }
    if app.ssh_account_detail.is_some() {
        handle_ssh_account_detail_key(app, key);
        return Ok(false);
    }
    if app.ssh_account_editor.is_some() {
        handle_ssh_account_editor_key(app, key);
        return Ok(false);
    }
    if app.reference_picker.is_some() {
        handle_reference_picker_key(app, key);
        return Ok(false);
    }
    if app.list_editor.is_some() {
        handle_list_editor_key(app, key);
        return Ok(false);
    }
    if app.header_editor.is_some() {
        handle_header_editor_key(app, key);
        return Ok(false);
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
        if let Err(error) = save(app) {
            app.status = format!("✗ {error}");
        }
        return Ok(false);
    }
    match key.code {
        KeyCode::Char('?') => app.help = true,
        KeyCode::Esc | KeyCode::Char('h') if app.editor.is_some() => {
            if let Some(
                ObjectEditor::ProtectionLocal(index) | ObjectEditor::ProtectionIntelligence(index),
            ) = app.editor
            {
                app.editor = Some(ObjectEditor::Protection(index));
                app.field = 0;
                app.status = "已返回智能防护概览".into();
            } else {
                app.editor = None;
                app.field = 0;
                app.focus = Focus::Detail;
                app.status = "已返回对象列表".into();
            }
        }
        KeyCode::Esc if matches!(app.focus, Focus::Detail) => {
            app.focus = Focus::Sidebar;
            app.status = "已返回分类列表".into();
        }
        KeyCode::Tab | KeyCode::BackTab => {
            if app.editor.is_none() {
                app.focus = match app.focus {
                    Focus::Sidebar => Focus::Detail,
                    Focus::Detail => Focus::Sidebar,
                }
            }
        }
        KeyCode::Up | KeyCode::Char('k') => move_selection(app, -1),
        KeyCode::Down | KeyCode::Char('j') => move_selection(app, 1),
        KeyCode::Enter | KeyCode::Char('e') => {
            if matches!(app.editor, Some(ObjectEditor::ProtectionLocal(_)))
                && matches!(app.field, 4..=7)
            {
                app.status = "扫描策略请按 Space 启停".into();
            } else if selected_is_toggle(app) {
                toggle_selected(app);
            } else {
                edit_selected(app);
            }
        }
        KeyCode::Char(' ') => toggle_selected(app),
        KeyCode::Char('a') if app.editor.is_some() => add_editor_pattern(app),
        KeyCode::Char('a') => add_selected(app),
        KeyCode::Char('d') if app.editor.is_some() => delete_editor_pattern(app),
        KeyCode::Char('d') => delete_selected(app),
        KeyCode::Char('r') if app.category == CATEGORY_PROCESS => {
            app.status = if refresh_managed_processes(app) {
                "✓ 已刷新受管进程列表".into()
            } else {
                "⚠ Serve 未运行，无法刷新受管进程列表".into()
            };
        }
        KeyCode::Char('/') => open_input(app, "搜索配置", "", false, InputAction::Search),
        KeyCode::Char('p') if app.live => {
            app.status = "⚠ Serve 正在运行：密码需停止 Serve 后修改（其他配置保存即热更新）".into()
        }
        KeyCode::Char('p') => open_input(app, "设置新密码", "", true, InputAction::NewPassword),
        KeyCode::Esc | KeyCode::Char('q') if !app.dirty => return Ok(true),
        KeyCode::Esc | KeyCode::Char('q') => {
            app.exit_prompt = true;
        }
        KeyCode::Char('Q') => {
            app.discarded = true;
            return Ok(true);
        }
        _ => {}
    }
    if app.category == CATEGORY_CERTIFICATE && root_certificate_cache_stale(app) {
        refresh_root_certificate_cache(app);
    }
    Ok(false)
}

fn open_list_editor(app: &mut App, kind: ListEditorKind) {
    app.list_editor = Some(ListEditor { kind, selected: 0 });
    app.status = format!(
        "{}列表：[a]添加 [Enter/e]修改 [d]删除 [Esc]返回",
        kind.label()
    );
}

fn list_values(app: &App, kind: ListEditorKind) -> Vec<String> {
    match kind {
        ListEditorKind::RouteTargets(route) => app.config.rules[route]
            .endpoints
            .iter()
            .map(|endpoint| match endpoint.port {
                Some(port) => format!("{}  （端口 {port}）", endpoint.target),
                None => format!("{}  （任意端口）", endpoint.target),
            })
            .collect(),
        ListEditorKind::FirewallTargets(rule) => app.config.firewall.rules[rule]
            .endpoints
            .iter()
            .map(|e| e.target.clone())
            .collect(),
        ListEditorKind::FirewallPorts(rule) => app.config.firewall.rules[rule]
            .endpoints
            .iter()
            .filter_map(|e| e.port.map(|p| p.to_string()))
            .collect(),
        ListEditorKind::FilePaths(rule) => app.config.sandbox.file.rules[rule]
            .patterns
            .iter()
            .map(|p| p.pattern.clone())
            .collect(),
        ListEditorKind::SandboxExecutables(rule) => app.config.sandbox.process.rules[rule]
            .patterns
            .iter()
            .map(|p| p.executable.clone())
            .collect(),
        ListEditorKind::SandboxCommandLines(rule) => app.config.sandbox.process.rules[rule]
            .patterns
            .iter()
            .map(|p| p.command_line.clone())
            .collect(),
    }
}

fn list_count(app: &App, kind: ListEditorKind) -> usize {
    list_values(app, kind).len()
}

fn handle_list_editor_key(app: &mut App, key: KeyEvent) {
    let Some(editor) = app.list_editor else {
        return;
    };
    let count = list_count(app, editor.kind);
    match key.code {
        KeyCode::Char('?') => app.help = true,
        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q') => {
            app.list_editor = None;
            app.status = "已返回规则表单".into();
        }
        KeyCode::Up | KeyCode::Char('k') => move_list_selection(app, -1),
        KeyCode::Down | KeyCode::Char('j') => move_list_selection(app, 1),
        KeyCode::Char('a') => {
            let title = format!("添加{}", editor.kind.label());
            let action = match editor.kind {
                ListEditorKind::RouteTargets(route) => InputAction::RouteTarget(route, None),
                _ => InputAction::ListValue(editor.kind, None),
            };
            open_input(app, &title, "", false, action);
        }
        KeyCode::Enter | KeyCode::Char('e') => {
            if count == 0 {
                app.status = format!("{}为空，按 a 添加", editor.kind.label());
            } else {
                let values = list_values(app, editor.kind);
                let value = match editor.kind {
                    ListEditorKind::RouteTargets(route) => app.config.rules[route].endpoints
                        [editor.selected]
                        .target
                        .clone(),
                    _ => values[editor.selected].clone(),
                };
                let title = format!("修改{}", editor.kind.label());
                let action = match editor.kind {
                    ListEditorKind::RouteTargets(route) => {
                        InputAction::RouteTarget(route, Some(editor.selected))
                    }
                    _ => InputAction::ListValue(editor.kind, Some(editor.selected)),
                };
                open_input(app, &title, &value, false, action);
            }
        }
        KeyCode::Char('d') => {
            if count == 0 {
                app.status = format!("{}为空", editor.kind.label());
            } else {
                let removed = remove_list_value(app, editor.kind, editor.selected);
                let max = app
                    .list_editor
                    .map(|editor| list_count(app, editor.kind).saturating_sub(1))
                    .unwrap_or(0);
                if let Some(current) = &mut app.list_editor {
                    current.selected = current.selected.min(max);
                }
                changed(app);
                app.status = format!("✓ 已删除{} '{removed}'", editor.kind.label());
            }
        }
        _ => {}
    }
}

fn move_list_selection(app: &mut App, delta: isize) {
    let Some(editor) = app.list_editor else {
        return;
    };
    let count = list_count(app, editor.kind);
    if let Some(current) = &mut app.list_editor {
        current.selected = if count == 0 {
            0
        } else {
            (current.selected as isize + delta).clamp(0, count as isize - 1) as usize
        };
    }
}

fn remove_list_value(app: &mut App, kind: ListEditorKind, selected: usize) -> String {
    match kind {
        ListEditorKind::RouteTargets(route) => {
            app.config.rules[route].endpoints.remove(selected).target
        }
        ListEditorKind::FirewallTargets(rule) => {
            app.config.firewall.rules[rule]
                .endpoints
                .remove(selected)
                .target
        }
        ListEditorKind::FirewallPorts(rule) => app.config.firewall.rules[rule]
            .endpoints
            .remove(selected)
            .port
            .map(|p| p.to_string())
            .unwrap_or_default(),
        ListEditorKind::FilePaths(rule) => {
            app.config.sandbox.file.rules[rule]
                .patterns
                .remove(selected)
                .pattern
        }
        ListEditorKind::SandboxExecutables(rule) => {
            app.config.sandbox.process.rules[rule]
                .patterns
                .remove(selected)
                .executable
        }
        ListEditorKind::SandboxCommandLines(rule) => {
            app.config.sandbox.process.rules[rule]
                .patterns
                .remove(selected)
                .command_line
        }
    }
}

fn handle_reference_picker_key(app: &mut App, key: KeyEvent) {
    let Some(mut picker) = app.reference_picker else {
        return;
    };
    let count = reference_count(app, picker.kind) + 1;
    match key.code {
        KeyCode::Char('?') => app.help = true,
        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q') => {
            app.reference_picker = None;
            app.status = "已取消选择".into();
        }
        KeyCode::Up | KeyCode::Char('k') => {
            picker.selected = picker.selected.saturating_sub(1);
            app.reference_picker = Some(picker);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            picker.selected = (picker.selected + 1).min(count.saturating_sub(1));
            app.reference_picker = Some(picker);
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            let selected = reference_id(app, picker.kind, picker.selected).map(str::to_owned);
            let kind = match picker.kind {
                ReferenceKind::Credential => Some(PluginKind::Credential),
                ReferenceKind::Audit => Some(PluginKind::Audit),
                ReferenceKind::Proxy | ReferenceKind::Protection => None,
            };
            if picker.kind == ReferenceKind::Protection {
                apply_protection_reference(app, picker.target, selected);
            } else if let Some(kind) = kind {
                let ids: Vec<String> = app
                    .config
                    .plugins
                    .iter()
                    .filter(|plugin| plugin.kind == kind)
                    .map(|plugin| plugin.id.clone())
                    .collect();
                let plugins = match picker.target {
                    ReferenceTarget::Route(route) => &mut app.config.rules[route].plugins,
                    ReferenceTarget::DefaultRoute => &mut app.config.default_route.plugins,
                    _ => {
                        app.status = "该对象不支持插件引用".into();
                        app.reference_picker = None;
                        return;
                    }
                };
                plugins.retain(|id| !ids.contains(id));
                if let Some(id) = selected {
                    plugins.push(id);
                }
            } else if let ReferenceTarget::Route(route) = picker.target {
                app.config.rules[route].upstream = selected;
            }
            app.reference_picker = None;
            changed(app);
        }
        _ => app.reference_picker = Some(picker),
    }
}

fn handle_ssh_account_editor_key(app: &mut App, key: KeyEvent) {
    let Some(editor) = app.ssh_account_editor else {
        return;
    };
    let credential = editor.credential;
    let idx = credential_plugin_index(&app.config, credential);
    let count = app.config.plugins[idx].ssh_accounts.len();
    match key.code {
        KeyCode::Char('?') => app.help = true,
        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q') => {
            app.ssh_account_editor = None;
            app.status = "已返回凭证表单".into();
        }
        KeyCode::Up | KeyCode::Char('k') => move_ssh_account_selection(app, -1),
        KeyCode::Down | KeyCode::Char('j') => move_ssh_account_selection(app, 1),
        KeyCode::Char('a') => open_input(
            app,
            "SSH 用户名",
            "",
            false,
            InputAction::AddSshAccount(credential),
        ),
        KeyCode::Enter | KeyCode::Char('e') => {
            if count == 0 {
                app.status = "账号列表为空，按 a 添加".into();
            } else {
                app.ssh_account_detail = Some(SshAccountDetail {
                    credential,
                    account: editor.selected,
                    field: 0,
                });
                app.status = "账号详情：Enter/e 编辑，Esc 返回账号列表".into();
            }
        }
        KeyCode::Char('r') => {
            if count == 0 {
                app.status = "账号列表为空".into();
            } else {
                let username = app.config.plugins[idx].ssh_accounts[editor.selected]
                    .username
                    .clone();
                open_text(
                    app,
                    "SSH 用户名",
                    username,
                    TextField::SshAccountUsername(credential, editor.selected),
                );
            }
        }
        KeyCode::Char('d') => {
            if count == 0 {
                app.status = "账号列表为空".into();
            } else {
                let removed = app.config.plugins[idx].ssh_accounts.remove(editor.selected);
                if let Some(current) = &mut app.ssh_account_editor {
                    current.selected = current
                        .selected
                        .min(app.config.plugins[idx].ssh_accounts.len().saturating_sub(1));
                }
                changed(app);
                app.status = format!("✓ 已删除 SSH 账号 '{}'", removed.username);
            }
        }
        _ => {}
    }
}

fn move_ssh_account_selection(app: &mut App, delta: isize) {
    let Some(editor) = app.ssh_account_editor else {
        return;
    };
    let count = app.config.plugins[credential_plugin_index(&app.config, editor.credential)]
        .ssh_accounts
        .len();
    if let Some(current) = &mut app.ssh_account_editor {
        current.selected = if count == 0 {
            0
        } else {
            (current.selected as isize + delta).clamp(0, count as isize - 1) as usize
        };
    }
}

fn handle_ssh_account_detail_key(app: &mut App, key: KeyEvent) {
    let Some(mut detail) = app.ssh_account_detail else {
        return;
    };
    let idx = credential_plugin_index(&app.config, detail.credential);
    if detail.account >= app.config.plugins[idx].ssh_accounts.len() {
        app.ssh_account_detail = None;
        return;
    }
    match key.code {
        KeyCode::Char('?') => app.help = true,
        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q') => {
            app.ssh_account_detail = None;
            app.status = "已返回 SSH 账号列表".into();
        }
        KeyCode::Up | KeyCode::Char('k') => {
            detail.field = detail.field.saturating_sub(1);
            app.ssh_account_detail = Some(detail);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            detail.field = (detail.field + 1).min(2);
            app.ssh_account_detail = Some(detail);
        }
        KeyCode::Enter | KeyCode::Char('e') => match detail.field {
            0 => {
                let username = app.config.plugins[idx].ssh_accounts[detail.account]
                    .username
                    .clone();
                open_text(
                    app,
                    "SSH 用户名",
                    username,
                    TextField::SshAccountUsername(detail.credential, detail.account),
                );
            }
            1 => open_ssh_key_editor(app, detail.credential, detail.account),
            2 => open_ssh_password_editor(app, detail.credential, detail.account),
            _ => {}
        },
        _ => {}
    }
}

fn handle_ssh_key_editor_key(app: &mut App, key: KeyEvent) {
    let Some(editor) = app.ssh_key_editor else {
        return;
    };
    let credential = editor.credential;
    let account = editor.account;
    let idx = credential_plugin_index(&app.config, credential);
    let count = app.config.plugins[idx].ssh_accounts[account]
        .private_keys
        .len();
    match key.code {
        KeyCode::Char('?') => app.help = true,
        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q') => {
            app.ssh_key_editor = None;
            app.status = "已返回 SSH 账号详情".into();
        }
        KeyCode::Up | KeyCode::Char('k') => move_ssh_key_selection(app, -1),
        KeyCode::Down | KeyCode::Char('j') => move_ssh_key_selection(app, 1),
        KeyCode::Char('a') => open_ssh_key_add_picker(app, credential, account),
        KeyCode::Char('c') => {
            if count == 0 {
                app.status = "私钥列表为空".into();
            } else {
                copy_ssh_key(app, credential, account, editor.selected);
            }
        }
        KeyCode::Enter | KeyCode::Char('e') => {
            if count == 0 {
                app.status = "私钥列表为空，按 a 添加".into();
            } else {
                preview_ssh_key(app, credential, account, editor.selected);
            }
        }
        KeyCode::Char('r') => {
            if count == 0 {
                app.status = "私钥列表为空".into();
            } else {
                let value = app.config.plugins[idx].ssh_accounts[account].private_keys
                    [editor.selected]
                    .name
                    .clone();
                open_text(
                    app,
                    "私钥名称",
                    value,
                    TextField::SshKeyName(credential, account, editor.selected),
                );
            }
        }
        KeyCode::Char('d') => {
            if count == 0 {
                app.status = "私钥列表为空".into();
            } else {
                let removed = app.config.plugins[idx].ssh_accounts[account]
                    .private_keys
                    .remove(editor.selected);
                if let Some(current) = &mut app.ssh_key_editor {
                    current.selected = current.selected.min(
                        app.config.plugins[idx].ssh_accounts[account]
                            .private_keys
                            .len()
                            .saturating_sub(1),
                    );
                }
                changed(app);
                app.status = format!("✓ 已删除私钥 '{}'", removed.name);
            }
        }
        _ => {}
    }
}

fn move_ssh_key_selection(app: &mut App, delta: isize) {
    let Some(editor) = app.ssh_key_editor else {
        return;
    };
    let count = app.config.plugins[credential_plugin_index(&app.config, editor.credential)]
        .ssh_accounts[editor.account]
        .private_keys
        .len();
    if let Some(current) = &mut app.ssh_key_editor {
        current.selected = if count == 0 {
            0
        } else {
            (current.selected as isize + delta).clamp(0, count as isize - 1) as usize
        };
    }
}

fn handle_ssh_password_editor_key(app: &mut App, key: KeyEvent) {
    let Some(editor) = app.ssh_password_editor else {
        return;
    };
    let credential = editor.credential;
    let account = editor.account;
    let idx = credential_plugin_index(&app.config, credential);
    let count = app.config.plugins[idx].ssh_accounts[account]
        .passwords
        .len();
    match key.code {
        KeyCode::Char('?') => app.help = true,
        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q') => {
            app.ssh_password_editor = None;
            app.status = "已返回 SSH 账号详情".into();
        }
        KeyCode::Up | KeyCode::Char('k') => move_ssh_password_selection(app, -1),
        KeyCode::Down | KeyCode::Char('j') => move_ssh_password_selection(app, 1),
        KeyCode::Char('a') => open_secret(
            app,
            "SSH 密码",
            SecretField::SshPassword(credential, account, None),
        ),
        KeyCode::Enter | KeyCode::Char('e') => {
            if count == 0 {
                app.status = "密码列表为空，按 a 添加".into();
            } else {
                open_secret(
                    app,
                    "修改 SSH 密码",
                    SecretField::SshPassword(credential, account, Some(editor.selected)),
                );
            }
        }
        KeyCode::Char('d') => {
            if count == 0 {
                app.status = "密码列表为空".into();
            } else {
                app.config.plugins[idx].ssh_accounts[account]
                    .passwords
                    .remove(editor.selected);
                if let Some(current) = &mut app.ssh_password_editor {
                    current.selected = current.selected.min(
                        app.config.plugins[idx].ssh_accounts[account]
                            .passwords
                            .len()
                            .saturating_sub(1),
                    );
                }
                changed(app);
                app.status = "✓ 已删除密码".into();
            }
        }
        _ => {}
    }
}

fn move_ssh_password_selection(app: &mut App, delta: isize) {
    let Some(editor) = app.ssh_password_editor else {
        return;
    };
    let count = app.config.plugins[credential_plugin_index(&app.config, editor.credential)]
        .ssh_accounts[editor.account]
        .passwords
        .len();
    if let Some(current) = &mut app.ssh_password_editor {
        current.selected = if count == 0 {
            0
        } else {
            (current.selected as isize + delta).clamp(0, count as isize - 1) as usize
        };
    }
}

fn handle_ssh_key_add_picker_key(app: &mut App, key: KeyEvent) {
    let Some(mut picker) = app.ssh_key_add_picker else {
        return;
    };
    match key.code {
        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q') => {
            app.ssh_key_add_picker = None;
            app.status = "已取消导入".into();
        }
        KeyCode::Up | KeyCode::Char('k') => {
            picker.selected = picker.selected.saturating_sub(1);
            app.ssh_key_add_picker = Some(picker);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            picker.selected = (picker.selected + 1).min(2);
            app.ssh_key_add_picker = Some(picker);
        }
        KeyCode::Enter => {
            app.ssh_key_add_picker = None;
            match picker.selected {
                0 => open_input(
                    app,
                    "导入 RSA 私钥路径",
                    "",
                    false,
                    InputAction::ImportSshKeyPath(picker.credential, picker.account),
                ),
                1 => generate_ssh_key(app, picker.credential, picker.account),
                _ => open_multiline(
                    app,
                    "粘贴 OpenSSH 私钥（Ctrl+S 确认，Enter 换行）",
                    InputAction::AddSshKeyPaste(picker.credential, picker.account),
                ),
            }
        }
        _ => app.ssh_key_add_picker = Some(picker),
    }
}

fn reference_count(app: &App, kind: ReferenceKind) -> usize {
    match kind {
        ReferenceKind::Proxy => app.config.upstreams.len(),
        ReferenceKind::Credential => credential_plugin_indices(&app.config).len(),
        ReferenceKind::Audit => audit_plugin_indices(&app.config).len(),
        ReferenceKind::Protection => app.config.protections.len(),
    }
}

fn reference_id<'a>(app: &'a App, kind: ReferenceKind, selected: usize) -> Option<&'a str> {
    let index = selected.checked_sub(1)?;
    match kind {
        ReferenceKind::Proxy => app.config.upstreams.get(index).map(|item| item.id.as_str()),
        ReferenceKind::Credential => credential_plugin_indices(&app.config)
            .get(index)
            .copied()
            .and_then(|index| app.config.plugins.get(index))
            .map(|item| item.id.as_str()),
        ReferenceKind::Audit => audit_plugin_indices(&app.config)
            .get(index)
            .copied()
            .and_then(|index| app.config.plugins.get(index))
            .map(|item| item.id.as_str()),
        ReferenceKind::Protection => app
            .config
            .protections
            .get(index)
            .map(|item| item.id.as_str()),
    }
}

fn move_selection(app: &mut App, delta: isize) {
    match app.focus {
        Focus::Sidebar => {
            let index = (app.category.index() as isize + delta)
                .clamp(0, NAV_ITEMS.len() as isize - 1) as usize;
            app.category = NAV_ITEMS[index];
            app.field = 0;
        }
        Focus::Detail => {
            let count = detail_lines(app).len().max(1);
            app.field = (app.field as isize + delta).clamp(0, count as isize - 1) as usize;
        }
    }
}

fn handle_header_editor_key(app: &mut App, key: KeyEvent) {
    let Some(editor) = app.header_editor else {
        return;
    };
    match key.code {
        KeyCode::Char('?') => app.help = true,
        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q') => {
            app.header_editor = None;
            app.status = "已返回凭证表单".into();
        }
        KeyCode::Up | KeyCode::Char('k') => move_header_selection(app, -1),
        KeyCode::Down | KeyCode::Char('j') => move_header_selection(app, 1),
        KeyCode::Char('a') => open_input(
            app,
            "Header 名称",
            "",
            false,
            InputAction::HeaderName(editor.field),
        ),
        KeyCode::Enter | KeyCode::Char('e') => {
            if let Some(name) = selected_header_name(app, editor) {
                open_input(
                    app,
                    &format!("{name} 的新值（空为不修改，- 表示删除客户端 Header）"),
                    "",
                    true,
                    InputAction::HeaderValue(editor.field, name, true),
                );
            } else {
                app.status = "Header 列表为空，按 a 添加".into();
            }
        }
        KeyCode::Char('d') => {
            if let Some(name) = selected_header_name(app, editor) {
                match remove_header(app, editor.field, &name) {
                    Ok(()) => {
                        let count = sorted_header_names(app, editor.field).len();
                        if let Some(current) = &mut app.header_editor {
                            current.selected = current.selected.min(count.saturating_sub(1));
                        }
                        changed(app);
                        app.status = format!("✓ 已删除 Header '{name}'");
                    }
                    Err(error) => app.status = format!("✗ {error}"),
                }
            } else {
                app.status = "Header 列表为空".into();
            }
        }
        _ => {}
    }
}

fn move_header_selection(app: &mut App, delta: isize) {
    let Some(editor) = app.header_editor else {
        return;
    };
    let count = sorted_header_names(app, editor.field).len();
    if let Some(current) = &mut app.header_editor {
        current.selected = if count == 0 {
            0
        } else {
            (current.selected as isize + delta).clamp(0, count as isize - 1) as usize
        };
    }
}

fn selected_header_name(app: &App, editor: HeaderEditor) -> Option<String> {
    sorted_header_names(app, editor.field)
        .get(editor.selected)
        .cloned()
}

fn selected_is_toggle(app: &App) -> bool {
    if let Some(editor) = app.editor {
        return object_field_is_toggle(app, editor, app.field);
    }
    match (app.category, app.field) {
        (CATEGORY_BASIC, 0 | 3) => true,
        (CATEGORY_SANDBOX_PROCESS, 0..=2) => true,
        (CATEGORY_FILES, 0..=2) => true,
        (CATEGORY_CERTIFICATE, field) => {
            field >= app.config.root_certificates.len()
                && field < app.config.root_certificates.len() + app.config.ssh_host_keys.len()
        }
        _ => false,
    }
}

fn object_field_is_toggle(app: &App, editor: ObjectEditor, field: usize) -> bool {
    match editor {
        ObjectEditor::Upstream(_) => field == 1,
        ObjectEditor::Credential(index) => {
            field == 1
                || (field == 2
                    && credential_carrier_is_http(
                        &app.config.plugins[credential_plugin_index(&app.config, index)],
                    ))
        }
        ObjectEditor::AuditProfile(_) => matches!(field, 1..=10),
        ObjectEditor::Protection(_) => matches!(field, 1 | 2),
        ObjectEditor::ProtectionLocal(_) => matches!(field, 0 | 4..=7),
        ObjectEditor::ProtectionIntelligence(_) => matches!(field, 0 | 1 | 8 | 9),
        ObjectEditor::DefaultRoute => matches!(field, 1 | 2),
        ObjectEditor::Route(_) => matches!(field, 1 | 4 | 9),
        ObjectEditor::FirewallRule(_) => matches!(field, 1 | 3),
        ObjectEditor::SandboxProcessRule(_) => matches!(field, 1 | 3),
        ObjectEditor::FileSandboxRule(_) => matches!(field, 1 | 3 | 4..=8),
        ObjectEditor::RootCertificate(_) => field == 1,
    }
}

fn toggle_selected(app: &mut App) {
    if let Some(editor) = app.editor {
        match editor {
            ObjectEditor::SandboxProcessRule(rule) if app.field >= 5 => {
                let pattern = &mut app.config.sandbox.process.rules[rule].patterns[app.field - 5];
                pattern.enabled = !pattern.enabled;
                changed(app);
                return;
            }
            ObjectEditor::FileSandboxRule(rule) if app.field >= 10 => {
                let pattern = &mut app.config.sandbox.file.rules[rule].patterns[app.field - 10];
                pattern.enabled = !pattern.enabled;
                changed(app);
                return;
            }
            _ => {}
        }
        if object_field_is_toggle(app, editor, app.field) {
            edit_object_field(app, editor);
        } else {
            app.status = "当前字段不是可切换选项，请按 Enter/e 编辑".into();
        }
        return;
    }
    match (app.category, app.field) {
        (CATEGORY_BASIC, 0) => {
            app.config.mode = match app.config.mode {
                EnforcementMode::Enforce => EnforcementMode::Observe,
                EnforcementMode::Observe => EnforcementMode::Enforce,
            };
            changed(app);
            app.status = match app.config.mode {
                EnforcementMode::Enforce => "网关故障策略：失败关闭".into(),
                EnforcementMode::Observe => "网关故障策略：失败放行".into(),
            };
        }
        (CATEGORY_BASIC, 3) => {
            app.config.debug = !app.config.debug;
            changed(app);
            app.status = if app.config.debug {
                "调试事件：已开启，保存后立即热更新".into()
            } else {
                "调试事件：已关闭，保存后立即热更新".into()
            };
        }
        (CATEGORY_FIREWALL, 0) => {
            app.config.firewall.enabled = !app.config.firewall.enabled;
            changed(app);
        }
        (CATEGORY_FIREWALL, 1) => {
            cycle_firewall_default(&mut app.config.firewall.default);
            changed(app);
        }
        (CATEGORY_FIREWALL, 2) => {
            app.config.firewall.error_action =
                opposite_firewall_action(app.config.firewall.error_action);
            changed(app);
        }
        (CATEGORY_FIREWALL, field) if field >= 3 && field - 3 < app.config.firewall.rules.len() => {
            let rule = &mut app.config.firewall.rules[field - 3];
            rule.enabled = !rule.enabled;
            changed(app);
        }
        (CATEGORY_SANDBOX_PROCESS, 0) => {
            app.config.sandbox.process.enabled = !app.config.sandbox.process.enabled;
            changed(app);
        }
        (CATEGORY_SANDBOX_PROCESS, 1) => {
            app.config.sandbox.process.default.action =
                opposite_sandbox_action(app.config.sandbox.process.default.action);
            changed(app);
        }
        (CATEGORY_SANDBOX_PROCESS, 2) => {
            app.config.sandbox.process.error_action =
                opposite_sandbox_action(app.config.sandbox.process.error_action);
            changed(app);
        }
        (CATEGORY_SANDBOX_PROCESS, field)
            if field >= 3 && field - 3 < app.config.sandbox.process.rules.len() =>
        {
            app.config.sandbox.process.rules[field - 3].enabled =
                !app.config.sandbox.process.rules[field - 3].enabled;
            changed(app);
        }
        (CATEGORY_FILES, 0) => {
            app.config.sandbox.file.enabled = !app.config.sandbox.file.enabled;
            changed(app);
        }
        (CATEGORY_FILES, 1) => {
            app.config.sandbox.file.default.action =
                opposite_sandbox_action(app.config.sandbox.file.default.action);
            changed(app);
        }
        (CATEGORY_FILES, 2) => {
            app.config.sandbox.file.error_action =
                opposite_sandbox_action(app.config.sandbox.file.error_action);
            changed(app);
        }
        (CATEGORY_FILES, field)
            if field >= 3 && field - 3 < app.config.sandbox.file.rules.len() =>
        {
            app.config.sandbox.file.rules[field - 3].enabled =
                !app.config.sandbox.file.rules[field - 3].enabled;
            changed(app);
        }
        (CATEGORY_PROTECTION, field) if field < app.config.protections.len() => {
            app.config.protections[field].enabled = !app.config.protections[field].enabled;
            changed(app);
        }
        (CATEGORY_ROUTE, 0) => {
            app.config.default_route.enabled = !app.config.default_route.enabled;
            changed(app);
        }
        (CATEGORY_ROUTE, field) if field - 1 < app.config.rules.len() => {
            let route = &mut app.config.rules[field - 1];
            route.enabled = !route.enabled;
            changed(app);
        }
        (CATEGORY_CERTIFICATE, index) if index < app.config.root_certificates.len() => {
            app.config.root_certificates[index].enabled =
                !app.config.root_certificates[index].enabled;
            changed(app);
        }
        (CATEGORY_CERTIFICATE, field)
            if field >= app.config.root_certificates.len()
                && field < app.config.root_certificates.len() + app.config.ssh_host_keys.len() =>
        {
            let key_index = field - app.config.root_certificates.len();
            app.config.ssh_host_keys[key_index].enabled =
                !app.config.ssh_host_keys[key_index].enabled;
            changed(app);
        }
        _ => app.status = "当前项目不是可切换选项，请按 Enter/e 编辑".into(),
    }
}

fn edit_selected(app: &mut App) {
    if let Some(editor) = app.editor {
        edit_object_field(app, editor);
        return;
    }
    match (app.category, app.field) {
        (CATEGORY_GATEWAY, _) => {
            app.focus = Focus::Detail;
            app.status = "网关概览为只读汇总".into();
        }
        (CATEGORY_SANDBOX, _) => {
            app.focus = Focus::Detail;
            app.status = "沙盒概览显示网络、文件与子进程沙盒能力摘要".into();
        }
        (CATEGORY_PROCESS, _) => {
            app.focus = Focus::Detail;
            app.status = "进程概览显示活跃的受管进程".into();
        }
        (CATEGORY_BASIC, 0) => app.status = "网关故障策略请按 Space 切换".into(),
        (CATEGORY_BASIC, 3) => app.status = "Debug 请按 Space 切换".into(),
        (CATEGORY_BASIC, 1) => open_input(
            app,
            "SOCKS5 监听地址",
            &app.config.listener.socks_listen.clone(),
            false,
            InputAction::Text(TextField::SocksListen),
        ),
        (CATEGORY_BASIC, 2) => open_input(
            app,
            "Pending Session 秒数",
            &app.config.listener.pending_session_ttl_secs.to_string(),
            false,
            InputAction::Text(TextField::PendingTtl),
        ),
        (CATEGORY_AUDIT, 0) => open_input(
            app,
            "审计保留天数（0 为永久）",
            &app.config.audit.retention_days.to_string(),
            false,
            InputAction::Text(TextField::AuditRetentionDays),
        ),
        (CATEGORY_PROXY, index) if index < app.config.upstreams.len() => {
            enter_editor(app, ObjectEditor::Upstream(index))
        }
        (CATEGORY_CREDENTIAL, index) if index < credential_plugin_indices(&app.config).len() => {
            enter_editor(app, ObjectEditor::Credential(index))
        }
        (CATEGORY_AUDIT, field)
            if field >= 1 && field - 1 < audit_plugin_indices(&app.config).len() =>
        {
            enter_editor(app, ObjectEditor::AuditProfile(field - 1))
        }
        (CATEGORY_FIREWALL, 0) => app.status = "网络沙盒启停请按 Space 切换".into(),
        (CATEGORY_FIREWALL, 1) => app.status = "默认动作请按 Space 循环切换".into(),
        (CATEGORY_FIREWALL, 2) => app.status = "出错动作请按 Space 循环切换".into(),
        (CATEGORY_FIREWALL, field) if field >= 3 && field - 3 < app.config.firewall.rules.len() => {
            enter_editor(app, ObjectEditor::FirewallRule(field - 3))
        }
        (CATEGORY_SANDBOX_PROCESS, 0..=2) => app.status = "请按 Space 切换".into(),
        (CATEGORY_SANDBOX_PROCESS, field)
            if field >= 3 && field - 3 < app.config.sandbox.process.rules.len() =>
        {
            enter_editor(app, ObjectEditor::SandboxProcessRule(field - 3))
        }
        (CATEGORY_FILES, 0..=2) => app.status = "请按 Space 切换".into(),
        (CATEGORY_FILES, field)
            if field >= 3 && field - 3 < app.config.sandbox.file.rules.len() =>
        {
            enter_editor(app, ObjectEditor::FileSandboxRule(field - 3))
        }
        (CATEGORY_PROTECTION, field) if field < app.config.protections.len() => {
            enter_editor(app, ObjectEditor::Protection(field))
        }
        (CATEGORY_ROUTE, 0) => enter_editor(app, ObjectEditor::DefaultRoute),
        (CATEGORY_ROUTE, field) if field - 1 < app.config.rules.len() => {
            enter_editor(app, ObjectEditor::Route(field - 1))
        }
        (CATEGORY_ENVIRONMENT, index) if index < app.config.environment.len() => {
            let variable = &app.config.environment[index];
            open_input(
                app,
                &format!("修改环境变量 {}（空为不修改，- 清空）", variable.name),
                "",
                true,
                InputAction::EnvironmentValue(Some(index), variable.name.clone(), true),
            );
        }
        (CATEGORY_CERTIFICATE, index) if index < app.config.root_certificates.len() => {
            enter_editor(app, ObjectEditor::RootCertificate(index))
        }
        (CATEGORY_CERTIFICATE, index)
            if index - app.config.root_certificates.len() < app.config.ssh_host_keys.len() =>
        {
            app.status = "SSH 主机密钥请按 Space 启用或禁用".into();
        }
        _ => app.status = "按 a 新增对象，Enter/e 打开完整表单".into(),
    }
}

fn root_certificate_view(app: &App, fingerprint: &str) -> Result<RootCertificateView, String> {
    let certificate =
        config_store::read_root_certificate(&app.path, app.password.as_bytes(), fingerprint)
            .map_err(|error| format!("无法读取已加密的证书：{error}"))?;
    let name = hyperhub_core::certificate::certificate_name(&certificate)
        .unwrap_or_else(|_| hyperhub_core::certificate::short_fingerprint(fingerprint));
    let summary = hyperhub_core::certificate::preview_certificate(&certificate)
        .map_err(|error| error.to_string())?;
    Ok(RootCertificateView {
        fingerprint: fingerprint.to_owned(),
        name,
        summary,
    })
}

/// Returns true when the cached certificate summaries no longer match the
/// fingerprints referenced by the configuration.
fn root_certificate_cache_stale(app: &App) -> bool {
    let Some(entries) = &app.root_certificate_cache else {
        return true;
    };
    if entries.len() != app.config.root_certificates.len() {
        return true;
    }
    app.config.root_certificates.iter().any(|certificate| {
        !entries
            .iter()
            .any(|entry| entry.fingerprint == certificate.fingerprint)
    })
}

/// Refreshes the certificate cache incrementally: existing entries are kept,
/// new fingerprints are decrypted and parsed, removed ones are dropped, and the
/// result is re-ordered to match the configuration.
fn refresh_root_certificate_cache(app: &mut App) {
    let mut entries = app.root_certificate_cache.take().unwrap_or_default();
    entries.retain(|entry| {
        app.config
            .root_certificates
            .iter()
            .any(|certificate| certificate.fingerprint == entry.fingerprint)
    });
    for certificate in &app.config.root_certificates {
        if entries
            .iter()
            .any(|entry| entry.fingerprint == certificate.fingerprint)
        {
            continue;
        }
        let view = match root_certificate_view(app, &certificate.fingerprint) {
            Ok(view) => view,
            Err(error) => RootCertificateView {
                fingerprint: certificate.fingerprint.clone(),
                name: format!(
                    "{}（无法读取）",
                    hyperhub_core::certificate::short_fingerprint(&certificate.fingerprint)
                ),
                summary: error,
            },
        };
        entries.push(view);
    }
    entries.sort_by_key(|entry| {
        app.config
            .root_certificates
            .iter()
            .position(|certificate| certificate.fingerprint == entry.fingerprint)
            .unwrap_or(usize::MAX)
    });
    app.root_certificate_cache = Some(entries);
}

fn enter_editor(app: &mut App, editor: ObjectEditor) {
    app.editor = Some(editor);
    app.field = 0;
    app.focus = Focus::Detail;
    app.status = "↑↓ 选择字段，Enter/e 编辑或切换，Space 也可切换，Esc 返回列表".into();
}

fn edit_protection_field(app: &mut App, index: usize, field: usize) {
    match field {
        0 => open_text(
            app,
            "智能防护 ID",
            app.config.protections[index].id.clone(),
            TextField::ProtectionId(index),
        ),
        1 => {
            app.config.protections[index].enabled ^= true;
            changed(app);
        }
        2 => {
            app.config.protections[index].mode = match app.config.protections[index].mode {
                ProtectionMode::Observe => ProtectionMode::Enforce,
                ProtectionMode::Enforce => ProtectionMode::Observe,
            };
            changed(app);
        }
        3 => enter_editor(app, ObjectEditor::ProtectionLocal(index)),
        4 => enter_editor(app, ObjectEditor::ProtectionIntelligence(index)),
        _ => app.status = "当前字段不可编辑".into(),
    }
}

fn edit_protection_local_field(app: &mut App, index: usize, field: usize) {
    match field {
        0 => {
            app.config.protections[index].data.enabled ^= true;
            changed(app);
        }
        1 => open_text(
            app,
            "最大扫描字节数",
            app.config.protections[index]
                .data
                .max_scan_bytes
                .to_string(),
            TextField::ProtectionMaxScanBytes(index),
        ),
        2 => open_text(
            app,
            "来源追踪窗口字节数",
            app.config.protections[index]
                .data
                .provenance_window_bytes
                .to_string(),
            TextField::ProtectionProvenanceWindow(index),
        ),
        3 => open_text(
            app,
            "来源追踪命中阈值",
            app.config.protections[index]
                .data
                .provenance_min_matches
                .to_string(),
            TextField::ProtectionProvenanceMatches(index),
        ),
        4 => {
            app.config.protections[index].data.detect_managed_secrets ^= true;
            changed(app);
        }
        5 => {
            app.config.protections[index].data.detect_known_tokens ^= true;
            changed(app);
        }
        6 => {
            app.config.protections[index].data.detect_private_keys ^= true;
            changed(app);
        }
        7 => {
            app.config.protections[index].data.detect_prompt_injection ^= true;
            changed(app);
        }
        _ => app.status = "当前字段不可编辑".into(),
    }
}

fn edit_protection_intelligence_field(app: &mut App, index: usize, field: usize) {
    match field {
        0 => {
            let item = &mut app.config.protections[index].intelligence;
            item.enabled ^= true;
            if item.enabled && item.provider.is_none() {
                item.provider = Some(default_intelligence_provider());
            }
            changed(app);
        }
        1 => {
            let provider = app.config.protections[index]
                .intelligence
                .provider
                .get_or_insert_with(default_intelligence_provider);
            provider.provider = match provider.provider {
                IntelligenceProviderKind::Typesafe => IntelligenceProviderKind::Openrouter,
                IntelligenceProviderKind::Openrouter => IntelligenceProviderKind::Custom,
                IntelligenceProviderKind::Custom => IntelligenceProviderKind::Typesafe,
            };
            changed(app);
        }
        2 => open_text(
            app,
            "Provider endpoint（官方可留空）",
            app.config.protections[index]
                .intelligence
                .provider
                .as_ref()
                .and_then(|p| p.endpoint.clone())
                .unwrap_or_default(),
            TextField::ProtectionProviderEndpoint(index),
        ),
        3 => open_text(
            app,
            "Provider model（官方可留空）",
            app.config.protections[index]
                .intelligence
                .provider
                .as_ref()
                .and_then(|p| p.model.clone())
                .unwrap_or_default(),
            TextField::ProtectionProviderModel(index),
        ),
        4 => open_secret(
            app,
            "Provider API Key",
            SecretField::ProtectionProviderApiKey(index),
        ),
        5 => open_text(
            app,
            "智能判定超时（ms）",
            app.config.protections[index]
                .intelligence
                .timeout_ms
                .to_string(),
            TextField::ProtectionTimeoutMs(index),
        ),
        6 => open_text(
            app,
            "最低置信度（0-1）",
            app.config.protections[index]
                .intelligence
                .min_confidence
                .to_string(),
            TextField::ProtectionMinConfidence(index),
        ),
        7 => open_text(
            app,
            "缓存时间（ms）",
            app.config.protections[index]
                .intelligence
                .cache_ttl_ms
                .to_string(),
            TextField::ProtectionCacheTtlMs(index),
        ),
        8 => {
            let value = &mut app.config.protections[index].intelligence.error_action;
            *value = opposite_protection_action(*value);
            changed(app);
        }
        9 => {
            let value = &mut app.config.protections[index]
                .intelligence
                .low_confidence_action;
            *value = opposite_protection_action(*value);
            changed(app);
        }
        _ => app.status = "当前字段不可编辑".into(),
    }
}

fn default_intelligence_provider() -> IntelligenceProviderConfig {
    IntelligenceProviderConfig {
        uuid: hyperhub_core::config::new_config_uuid(),
        id: "jev-primary".into(),
        provider: IntelligenceProviderKind::Typesafe,
        endpoint: None,
        model: None,
        api_key: None,
    }
}

fn edit_object_field(app: &mut App, editor: ObjectEditor) {
    match (editor, app.field) {
        (ObjectEditor::Upstream(index), 0) => open_text(
            app,
            "代理 ID",
            app.config.upstreams[index].id.clone(),
            TextField::UpstreamId(index),
        ),
        (ObjectEditor::Upstream(index), 1) => {
            app.config.upstreams[index].kind = match app.config.upstreams[index].kind {
                UpstreamKind::Socks5 => UpstreamKind::HttpConnect,
                UpstreamKind::HttpConnect => UpstreamKind::Socks5,
            };
            changed(app);
        }
        (ObjectEditor::Upstream(index), 2) => open_text(
            app,
            "上游地址 host:port",
            app.config.upstreams[index].address.clone(),
            TextField::UpstreamAddress(index),
        ),
        (ObjectEditor::Upstream(index), 3) => open_text(
            app,
            "连接超时（毫秒）",
            app.config.upstreams[index].timeout_ms.to_string(),
            TextField::UpstreamTimeout(index),
        ),
        (ObjectEditor::Upstream(index), 4) => {
            open_secret(app, "代理用户名", SecretField::UpstreamUsername(index))
        }
        (ObjectEditor::Upstream(index), 5) => {
            open_secret(app, "代理密码", SecretField::UpstreamPassword(index))
        }
        (ObjectEditor::Upstream(index), 6) => open_header(app, HeaderField::Upstream(index)),

        (ObjectEditor::Credential(index), field) => edit_credential_field(app, index, field),

        (ObjectEditor::AuditProfile(index), field) => edit_audit_field(app, index, field),
        (ObjectEditor::Protection(index), field) => edit_protection_field(app, index, field),
        (ObjectEditor::ProtectionLocal(index), field) => {
            edit_protection_local_field(app, index, field)
        }
        (ObjectEditor::ProtectionIntelligence(index), field) => {
            edit_protection_intelligence_field(app, index, field)
        }

        (ObjectEditor::DefaultRoute, 0) => {
            app.status = "默认路由 ID 固定为 'default'，不能修改".into();
        }
        (ObjectEditor::DefaultRoute, 1) => {
            app.config.default_route.enabled = !app.config.default_route.enabled;
            changed(app);
        }
        (ObjectEditor::DefaultRoute, 2) => {
            let action = cycle_rule_action(app.config.default_route.action);
            app.config.default_route.action = action;
            if action != RuleAction::Smart {
                app.config.default_route.protection = None;
            } else if app.config.default_route.protection.is_none() {
                open_reference_picker(
                    app,
                    ReferenceTarget::DefaultRoute,
                    ReferenceKind::Protection,
                );
            }
            changed(app);
        }
        (ObjectEditor::DefaultRoute, 3) => open_reference_picker(
            app,
            ReferenceTarget::DefaultRoute,
            ReferenceKind::Credential,
        ),
        (ObjectEditor::DefaultRoute, 4) => {
            open_reference_picker(app, ReferenceTarget::DefaultRoute, ReferenceKind::Audit)
        }
        (ObjectEditor::DefaultRoute, 5) => open_reference_picker(
            app,
            ReferenceTarget::DefaultRoute,
            ReferenceKind::Protection,
        ),

        (ObjectEditor::Route(index), 0) => open_text(
            app,
            "路由 ID",
            app.config.rules[index].id.clone(),
            TextField::RouteId(index),
        ),
        (ObjectEditor::Route(index), 1) => {
            app.config.rules[index].enabled = !app.config.rules[index].enabled;
            changed(app);
        }
        (ObjectEditor::Route(index), 2) => open_text(
            app,
            "优先级",
            app.config.rules[index].priority.to_string(),
            TextField::RoutePriority(index),
        ),
        (ObjectEditor::Route(index), 3) => open_target_editor(app, index),
        (ObjectEditor::Route(index), 4) => {
            let action = cycle_rule_action(app.config.rules[index].action);
            app.config.rules[index].action = action;
            if action != RuleAction::Smart {
                app.config.rules[index].protection = None;
            } else if app.config.rules[index].protection.is_none() {
                open_reference_picker(
                    app,
                    ReferenceTarget::Route(index),
                    ReferenceKind::Protection,
                );
            }
            changed(app);
        }
        (ObjectEditor::Route(index), 5) => {
            open_reference_picker(app, ReferenceTarget::Route(index), ReferenceKind::Proxy)
        }
        (ObjectEditor::Route(index), 6) => open_reference_picker(
            app,
            ReferenceTarget::Route(index),
            ReferenceKind::Credential,
        ),
        (ObjectEditor::Route(index), 7) => {
            open_reference_picker(app, ReferenceTarget::Route(index), ReferenceKind::Audit)
        }
        (ObjectEditor::Route(index), 8) => open_reference_picker(
            app,
            ReferenceTarget::Route(index),
            ReferenceKind::Protection,
        ),
        (ObjectEditor::Route(index), 9) => {
            app.config.rules[index].allow_sensitive_upload =
                !app.config.rules[index].allow_sensitive_upload;
            changed(app);
        }

        (ObjectEditor::FirewallRule(index), 0) => open_text(
            app,
            "网络规则 ID",
            app.config.firewall.rules[index].id.clone(),
            TextField::FirewallId(index),
        ),
        (ObjectEditor::FirewallRule(index), 1) => {
            app.config.firewall.rules[index].enabled = !app.config.firewall.rules[index].enabled;
            changed(app);
        }
        (ObjectEditor::FirewallRule(index), 2) => open_text(
            app,
            "优先级",
            app.config.firewall.rules[index].priority.to_string(),
            TextField::FirewallPriority(index),
        ),
        (ObjectEditor::FirewallRule(index), 3) => {
            let action = cycle_firewall_action(app.config.firewall.rules[index].action);
            app.config.firewall.rules[index].action = action;
            if action != FirewallAction::Smart {
                app.config.firewall.rules[index].protection = None;
            } else if app.config.firewall.rules[index].protection.is_none() {
                open_reference_picker(
                    app,
                    ReferenceTarget::Firewall(index),
                    ReferenceKind::Protection,
                );
            }
            changed(app);
        }
        (ObjectEditor::FirewallRule(index), 4) => open_reference_picker(
            app,
            ReferenceTarget::Firewall(index),
            ReferenceKind::Protection,
        ),
        (ObjectEditor::FirewallRule(index), field) if field >= 5 => {
            let value = app.config.firewall.rules[index].endpoints[field - 5]
                .target
                .clone();
            open_input(
                app,
                "目标（域名、IP 或 CIDR）",
                &value,
                false,
                InputAction::FirewallTarget(index, Some(field - 5)),
            )
        }

        (ObjectEditor::SandboxProcessRule(index), 0) => open_text(
            app,
            "规则 ID",
            app.config.sandbox.process.rules[index].id.clone(),
            TextField::SandboxProcessId(index),
        ),
        (ObjectEditor::SandboxProcessRule(index), 1) => {
            app.config.sandbox.process.rules[index].enabled =
                !app.config.sandbox.process.rules[index].enabled;
            changed(app);
        }
        (ObjectEditor::SandboxProcessRule(index), 2) => open_text(
            app,
            "优先级",
            app.config.sandbox.process.rules[index].priority.to_string(),
            TextField::SandboxProcessPriority(index),
        ),
        (ObjectEditor::SandboxProcessRule(index), 3) => {
            app.config.sandbox.process.rules[index].action =
                cycle_sandbox_action(app.config.sandbox.process.rules[index].action);
            changed(app);
        }
        (ObjectEditor::SandboxProcessRule(index), 4) => open_reference_picker(
            app,
            ReferenceTarget::Process(index),
            ReferenceKind::Protection,
        ),
        (ObjectEditor::SandboxProcessRule(index), field) if field >= 5 => {
            let value = app.config.sandbox.process.rules[index].patterns[field - 5]
                .executable
                .clone();
            open_input(
                app,
                "可执行文件正则（可留空）",
                &value,
                false,
                InputAction::ProcessExecutable(index, Some(field - 5)),
            )
        }
        (ObjectEditor::FileSandboxRule(index), 0) => open_text(
            app,
            "规则 ID",
            app.config.sandbox.file.rules[index].id.clone(),
            TextField::FileSandboxId(index),
        ),
        (ObjectEditor::FileSandboxRule(index), 1) => {
            app.config.sandbox.file.rules[index].enabled =
                !app.config.sandbox.file.rules[index].enabled;
            changed(app);
        }
        (ObjectEditor::FileSandboxRule(index), 2) => open_text(
            app,
            "优先级",
            app.config.sandbox.file.rules[index].priority.to_string(),
            TextField::FileSandboxPriority(index),
        ),
        (ObjectEditor::FileSandboxRule(index), 3) => {
            app.config.sandbox.file.rules[index].action =
                cycle_sandbox_action(app.config.sandbox.file.rules[index].action);
            changed(app);
        }
        (ObjectEditor::FileSandboxRule(index), field @ 4..=8) => {
            let op = [
                FileSandboxOperation::Read,
                FileSandboxOperation::Write,
                FileSandboxOperation::Create,
                FileSandboxOperation::Delete,
                FileSandboxOperation::Rename,
            ][field - 4];
            let ops = &mut app.config.sandbox.file.rules[index].operations;
            if let Some(pos) = ops.iter().position(|x| *x == op) {
                ops.remove(pos);
            } else {
                ops.push(op);
            }
            changed(app);
        }
        (ObjectEditor::FileSandboxRule(index), 9) => {
            open_reference_picker(app, ReferenceTarget::File(index), ReferenceKind::Protection)
        }
        (ObjectEditor::FileSandboxRule(index), field) if field >= 10 => {
            let value = app.config.sandbox.file.rules[index].patterns[field - 10]
                .pattern
                .clone();
            open_input(
                app,
                "路径正则",
                &value,
                false,
                InputAction::FilePattern(index, Some(field - 10)),
            )
        }

        (ObjectEditor::RootCertificate(_), 0) => {
            app.status = "指纹不可修改，如需更换请删除后重新导入".into();
        }
        (ObjectEditor::RootCertificate(index), 1) => {
            app.config.root_certificates[index].enabled =
                !app.config.root_certificates[index].enabled;
            changed(app);
        }
        _ => app.status = "当前字段不可编辑".into(),
    }
}

fn edit_credential_field(app: &mut App, index: usize, field: usize) {
    let idx = credential_plugin_index(&app.config, index);
    if field == 0 {
        open_text(
            app,
            "凭证插件 ID",
            app.config.plugins[idx].id.clone(),
            TextField::CredentialId(index),
        );
        return;
    }
    if field == 1 {
        let http = credential_carrier_is_http(&app.config.plugins[idx]);
        {
            let plugin = &mut app.config.plugins[idx];
            if http {
                plugin.protocols = vec![PluginProtocol::Ssh];
                plugin.http_scheme = None;
                plugin.secret = None;
                plugin.http_name = None;
                plugin.username = None;
                plugin.password = None;
                plugin.headers.clear();
            } else {
                plugin.protocols = vec![PluginProtocol::Http];
                plugin.http_scheme = Some(HttpAuthScheme::Bearer);
                plugin.ssh_accounts.clear();
                add_default_http_header_removal(plugin);
            }
        }
        changed(app);
        return;
    }
    if credential_carrier_is_http(&app.config.plugins[idx]) {
        match field {
            2 => {
                let plugin = &mut app.config.plugins[idx];
                let current = plugin.http_scheme.unwrap_or(HttpAuthScheme::CustomHeaders);
                let next = match current {
                    HttpAuthScheme::Basic => HttpAuthScheme::Bearer,
                    HttpAuthScheme::Bearer => HttpAuthScheme::Token,
                    HttpAuthScheme::Token | HttpAuthScheme::LegacyScopedToken => {
                        HttpAuthScheme::XApiKey
                    }
                    HttpAuthScheme::XApiKey => HttpAuthScheme::Cookie,
                    HttpAuthScheme::Cookie => HttpAuthScheme::QueryParameter,
                    HttpAuthScheme::QueryParameter => HttpAuthScheme::CustomHeaders,
                    HttpAuthScheme::CustomHeaders => HttpAuthScheme::Basic,
                };
                select_http_scheme(plugin, current, next);
                changed(app);
            }
            field => edit_http_credential_field(app, index, field),
        }
    } else if field == 2 {
        app.ssh_account_editor = Some(SshAccountEditor {
            credential: index,
            selected: 0,
        });
        app.status = "SSH 账号列表：[a]新增 [Enter/e]详情 [r]改名 [d]删除 [Esc]返回".into();
    } else {
        app.status = "当前字段不可编辑".into();
    }
}

fn open_ssh_key_editor(app: &mut App, credential: usize, account: usize) {
    app.ssh_key_editor = Some(SshKeyEditor {
        credential,
        account,
        selected: 0,
    });
    app.status = "私钥列表：[a]新增 [Enter/e]预览公钥 [r]重命名 [d]删除 [Esc]返回".into();
}

fn open_ssh_password_editor(app: &mut App, credential: usize, account: usize) {
    app.ssh_password_editor = Some(SshPasswordEditor {
        credential,
        account,
        selected: 0,
    });
    app.status = "密码列表：[a]新增 [Enter/e]修改 [d]删除 [Esc]返回".into();
}

fn open_ssh_key_add_picker(app: &mut App, credential: usize, account: usize) {
    app.ssh_key_add_picker = Some(SshKeyAddPicker {
        credential,
        account,
        selected: 0,
    });
    app.status = "选择私钥导入方式：↑↓ 选择，Enter 确认，Esc 取消".into();
}

fn generate_ssh_key(app: &mut App, credential: usize, account: usize) {
    match generate_rsa_private_key() {
        Ok(pem) => {
            let name = short_label(pem.as_str()).unwrap_or_else(|_| "generated-rsa".into());
            let idx = credential_plugin_index(&app.config, credential);
            app.config.plugins[idx].ssh_accounts[account]
                .private_keys
                .push(SshPrivateKey {
                    name,
                    value: SecretValue::Inline {
                        value: pem.to_string(),
                    },
                });
            changed(app);
            app.status = "✓ 已生成 RSA 私钥".into();
        }
        Err(error) => app.status = format!("✗ {error}"),
    }
}

fn import_ssh_key_path(
    app: &mut App,
    credential: usize,
    account: usize,
    input: &str,
) -> Result<(), String> {
    let path = PathBuf::from(required(input, "私钥路径")?);
    if !path.is_file() {
        return Err(format!("文件不存在或不可读：{}", path.display()));
    }
    let pem = import_private_key(&path)?;
    let name = short_label(pem.as_str())?;
    let idx = credential_plugin_index(&app.config, credential);
    app.config.plugins[idx].ssh_accounts[account]
        .private_keys
        .push(SshPrivateKey {
            name,
            value: SecretValue::File {
                file: path,
                prefix: String::new(),
            },
        });
    changed(app);
    Ok(())
}

fn add_ssh_key_pem(
    app: &mut App,
    credential: usize,
    account: usize,
    pem: &str,
) -> Result<(), String> {
    let name = short_label(pem)?;
    let idx = credential_plugin_index(&app.config, credential);
    app.config.plugins[idx].ssh_accounts[account]
        .private_keys
        .push(SshPrivateKey {
            name,
            value: SecretValue::Inline {
                value: pem.to_string(),
            },
        });
    changed(app);
    Ok(())
}

fn ssh_key_public_info(
    app: &App,
    credential: usize,
    account: usize,
    key_index: usize,
) -> Result<PublicKeyInfo, String> {
    let idx = credential_plugin_index(&app.config, credential);
    let key = app.config.plugins[idx].ssh_accounts[account]
        .private_keys
        .get(key_index)
        .ok_or_else(|| "私钥不存在".to_owned())?;
    let pem = key
        .value
        .resolve()
        .map_err(|error| format!("读取私钥失败：{error}"))?;
    public_key_info(&pem)
}

fn copy_ssh_key(app: &mut App, credential: usize, account: usize, key_index: usize) {
    match ssh_key_public_info(app, credential, account, key_index)
        .and_then(|info| crate::clipboard::copy_to_clipboard(&info.openssh))
    {
        Ok(()) => app.status = "✓ 完整 OpenSSH 公钥已复制到剪贴板".into(),
        Err(error) => app.status = format!("✗ {error}"),
    }
}

fn copy_previewed_ssh_key(app: &mut App) {
    let Some(preview) = &mut app.ssh_key_preview else {
        return;
    };
    match crate::clipboard::copy_to_clipboard(&preview.openssh) {
        Ok(()) => {
            let message = "✓ 完整 OpenSSH 公钥已复制到剪贴板".to_owned();
            preview.copy_message = Some(message.clone());
            app.status = message;
        }
        Err(error) => {
            let message = format!("✗ {error}");
            preview.copy_message = Some(message.clone());
            app.status = message;
        }
    }
}

fn preview_ssh_key(app: &mut App, credential: usize, account: usize, key_index: usize) {
    match ssh_key_public_info(app, credential, account, key_index) {
        Ok(info) => {
            app.ssh_key_preview = Some(SshKeyPreview {
                algorithm: info.algorithm,
                openssh: info.openssh,
                fingerprint: info.fingerprint,
                copy_message: None,
            });
        }
        Err(error) => app.status = format!("✗ {error}"),
    }
}

fn select_http_scheme(plugin: &mut PluginConfig, current: HttpAuthScheme, next: HttpAuthScheme) {
    let generated_header = match next {
        HttpAuthScheme::Basic | HttpAuthScheme::Bearer | HttpAuthScheme::Token => "authorization",
        HttpAuthScheme::LegacyScopedToken => "",
        HttpAuthScheme::XApiKey => "x-api-key",
        HttpAuthScheme::Cookie => "cookie",
        _ => "",
    };
    if !generated_header.is_empty() {
        remove_header_case_insensitive(&mut plugin.headers, generated_header);
    }
    let token_scheme = |scheme| {
        matches!(
            scheme,
            HttpAuthScheme::Bearer
                | HttpAuthScheme::Token
                | HttpAuthScheme::XApiKey
                | HttpAuthScheme::Cookie
                | HttpAuthScheme::QueryParameter
        )
    };
    let retained_secret = token_scheme(current)
        .then(|| plugin.secret.take())
        .flatten();
    plugin.username = None;
    plugin.password = None;
    plugin.secret = None;
    plugin.http_name = None;
    plugin.protocols = vec![PluginProtocol::Http];
    match next {
        HttpAuthScheme::Basic => plugin.username = Some(String::new()),
        HttpAuthScheme::Bearer | HttpAuthScheme::XApiKey => {
            plugin.secret = retained_secret;
        }
        HttpAuthScheme::Token => {
            plugin.username = Some(String::new());
            plugin.secret = retained_secret;
        }
        HttpAuthScheme::LegacyScopedToken => {}
        HttpAuthScheme::Cookie | HttpAuthScheme::QueryParameter => {
            plugin.secret = retained_secret;
            plugin.http_name = Some(String::new());
        }
        HttpAuthScheme::CustomHeaders => {}
    }
    plugin.http_scheme = Some(next);
}

fn edit_http_credential_field(app: &mut App, index: usize, field: usize) {
    let idx = credential_plugin_index(&app.config, index);
    let scheme = app.config.plugins[idx]
        .http_scheme
        .unwrap_or(HttpAuthScheme::CustomHeaders);
    match (scheme, field) {
        (HttpAuthScheme::Basic, 3) => open_text(
            app,
            "HTTP Basic 用户名",
            app.config.plugins[idx].username.clone().unwrap_or_default(),
            TextField::CredentialUsername(index),
        ),
        (HttpAuthScheme::Basic, 4) => open_secret(
            app,
            "HTTP Basic 密码",
            SecretField::CredentialPassword(index),
        ),
        (HttpAuthScheme::Basic, 5) => open_header(app, HeaderField::Credential(index)),
        (HttpAuthScheme::Token, 3) => open_text(
            app,
            "令牌用户名",
            app.config.plugins[idx].username.clone().unwrap_or_default(),
            TextField::CredentialUsername(index),
        ),
        (HttpAuthScheme::Token, 4) => {
            open_secret(app, "令牌", SecretField::CredentialHttpSecret(index))
        }
        (HttpAuthScheme::Token, 5) => open_header(app, HeaderField::Credential(index)),
        (HttpAuthScheme::CustomHeaders, 3) => open_header(app, HeaderField::Credential(index)),
        (HttpAuthScheme::Cookie | HttpAuthScheme::QueryParameter, 3) => open_text(
            app,
            if scheme == HttpAuthScheme::Cookie {
                "Cookie 名称"
            } else {
                "Query 参数名称"
            },
            app.config.plugins[idx]
                .http_name
                .clone()
                .unwrap_or_default(),
            TextField::CredentialHttpName(index),
        ),
        (HttpAuthScheme::Cookie | HttpAuthScheme::QueryParameter, 4) => {
            open_secret(app, "鉴权值", SecretField::CredentialHttpSecret(index))
        }
        (HttpAuthScheme::Cookie | HttpAuthScheme::QueryParameter, 5) => {
            open_header(app, HeaderField::Credential(index))
        }
        (HttpAuthScheme::Bearer | HttpAuthScheme::XApiKey, 3) => {
            open_secret(app, "鉴权值", SecretField::CredentialHttpSecret(index))
        }
        (HttpAuthScheme::Bearer | HttpAuthScheme::XApiKey, 4) => {
            open_header(app, HeaderField::Credential(index))
        }
        _ => app.status = "当前字段不可编辑".into(),
    }
}

fn has_protocol(plugin: &PluginConfig, protocol: PluginProtocol) -> bool {
    plugin.protocols.contains(&protocol)
}

fn toggle_protocol(plugin: &mut PluginConfig, protocol: PluginProtocol) {
    if let Some(position) = plugin.protocols.iter().position(|p| *p == protocol) {
        plugin.protocols.remove(position);
    } else {
        plugin.protocols.push(protocol);
    }
}

fn mark(value: bool) -> &'static str {
    if value {
        "[x]"
    } else {
        "[ ]"
    }
}

fn websocket_transcript_label(value: WebSocketCapture) -> &'static str {
    match value {
        WebSocketCapture::Off => "关闭",
        WebSocketCapture::Frames => "帧",
        WebSocketCapture::Messages => "消息",
    }
}

fn audit_protocol_label(value: PluginProtocol) -> &'static str {
    match value {
        PluginProtocol::Http => "HTTP",
        PluginProtocol::Ws => "WS",
        PluginProtocol::Git => "Git",
        PluginProtocol::Ssh => "SSH",
        PluginProtocol::Response => "Response",
        PluginProtocol::Message => "Message",
    }
}

fn audit_transcript_summary(profile: &PluginConfig) -> String {
    let mut enabled = Vec::new();
    if profile.http_transcript_enabled() {
        enabled.push("HTTP".to_string());
    }
    if profile.websocket_capture != WebSocketCapture::Off {
        enabled.push(format!(
            "WS:{}",
            websocket_transcript_label(profile.websocket_capture)
        ));
    }
    if profile.git_transcript_enabled() {
        enabled.push("Git".to_string());
    }
    if profile.ssh_transcript {
        enabled.push("SSH".to_string());
    }
    if enabled.is_empty() {
        "无".into()
    } else {
        enabled.join(",")
    }
}

fn ensure_transcript_direction(profile: &mut PluginConfig) {
    if !profile.transcript_client_upload && !profile.transcript_server_response {
        profile.transcript_client_upload = true;
        profile.transcript_server_response = true;
    }
}

fn transcript_direction_summary(profile: &PluginConfig) -> &'static str {
    match (
        profile.transcript_client_upload,
        profile.transcript_server_response,
    ) {
        (true, true) => "上传+响应",
        (true, false) => "上传",
        (false, true) => "响应",
        (false, false) => "无",
    }
}

fn edit_audit_field(app: &mut App, index: usize, field: usize) {
    let idx = audit_plugin_index(&app.config, index);
    match field {
        0 => open_text(
            app,
            "审计插件 ID",
            app.config.plugins[idx].id.clone(),
            TextField::AuditId(index),
        ),
        1 => {
            let disabling = has_protocol(&app.config.plugins[idx], PluginProtocol::Http);
            let http_transcript = app.config.plugins[idx].http_transcript_enabled();
            if app.config.plugins[idx].git_transcript.is_none() {
                let legacy = app.config.plugins[idx].git_transcript_enabled();
                app.config.plugins[idx].git_transcript = Some(legacy);
            }
            app.config.plugins[idx].capture_body = http_transcript;
            toggle_protocol(&mut app.config.plugins[idx], PluginProtocol::Http);
            if disabling {
                app.config.plugins[idx].capture_body = false;
            }
            changed(app);
        }
        2 => {
            if app.config.plugins[idx].git_transcript.is_none() {
                let legacy = app.config.plugins[idx].git_transcript_enabled();
                app.config.plugins[idx].git_transcript = Some(legacy);
            }
            app.config.plugins[idx].capture_body =
                !app.config.plugins[idx].http_transcript_enabled();
            if app.config.plugins[idx].capture_body
                && !has_protocol(&app.config.plugins[idx], PluginProtocol::Http)
            {
                app.config.plugins[idx].protocols.push(PluginProtocol::Http);
            }
            if app.config.plugins[idx].capture_body {
                ensure_transcript_direction(&mut app.config.plugins[idx]);
            }
            changed(app);
        }
        3 => {
            let disabling = has_protocol(&app.config.plugins[idx], PluginProtocol::Ws);
            toggle_protocol(&mut app.config.plugins[idx], PluginProtocol::Ws);
            if disabling {
                app.config.plugins[idx].websocket_capture = WebSocketCapture::Off;
            }
            changed(app);
        }
        4 => {
            app.config.plugins[idx].websocket_capture =
                match app.config.plugins[idx].websocket_capture {
                    WebSocketCapture::Off => WebSocketCapture::Frames,
                    WebSocketCapture::Frames => WebSocketCapture::Messages,
                    WebSocketCapture::Messages => WebSocketCapture::Off,
                };
            if app.config.plugins[idx].websocket_capture != WebSocketCapture::Off
                && !has_protocol(&app.config.plugins[idx], PluginProtocol::Ws)
            {
                app.config.plugins[idx].protocols.push(PluginProtocol::Ws);
            }
            if app.config.plugins[idx].websocket_capture != WebSocketCapture::Off {
                ensure_transcript_direction(&mut app.config.plugins[idx]);
            }
            changed(app);
        }
        5 => {
            let disabling = has_protocol(&app.config.plugins[idx], PluginProtocol::Git);
            if app.config.plugins[idx].git_transcript.is_none() {
                let legacy = app.config.plugins[idx].git_transcript_enabled();
                app.config.plugins[idx].git_transcript = Some(legacy);
            }
            toggle_protocol(&mut app.config.plugins[idx], PluginProtocol::Git);
            if disabling {
                app.config.plugins[idx].git_transcript = Some(false);
            }
            changed(app);
        }
        6 => {
            let enabled = !app.config.plugins[idx].git_transcript_enabled();
            app.config.plugins[idx].git_transcript = Some(enabled);
            if enabled && !has_protocol(&app.config.plugins[idx], PluginProtocol::Git) {
                app.config.plugins[idx].protocols.push(PluginProtocol::Git);
            }
            if enabled {
                ensure_transcript_direction(&mut app.config.plugins[idx]);
            }
            changed(app);
        }
        7 => {
            let disabling = has_protocol(&app.config.plugins[idx], PluginProtocol::Ssh);
            toggle_protocol(&mut app.config.plugins[idx], PluginProtocol::Ssh);
            if disabling {
                app.config.plugins[idx].ssh_transcript = false;
            }
            changed(app);
        }
        8 => {
            app.config.plugins[idx].ssh_transcript = !app.config.plugins[idx].ssh_transcript;
            if app.config.plugins[idx].ssh_transcript
                && !has_protocol(&app.config.plugins[idx], PluginProtocol::Ssh)
            {
                app.config.plugins[idx].protocols.push(PluginProtocol::Ssh);
            }
            if app.config.plugins[idx].ssh_transcript {
                ensure_transcript_direction(&mut app.config.plugins[idx]);
            }
            changed(app);
        }
        9 => {
            let disabling = app.config.plugins[idx].transcript_client_upload;
            if disabling
                && !app.config.plugins[idx].transcript_server_response
                && app.config.plugins[idx].content_transcript_enabled()
            {
                app.status = "内容转录已启用，至少保留一个转录方向".into();
                return;
            }
            app.config.plugins[idx].transcript_client_upload = !disabling;
            changed(app);
        }
        10 => {
            let disabling = app.config.plugins[idx].transcript_server_response;
            if disabling
                && !app.config.plugins[idx].transcript_client_upload
                && app.config.plugins[idx].content_transcript_enabled()
            {
                app.status = "内容转录已启用，至少保留一个转录方向".into();
                return;
            }
            app.config.plugins[idx].transcript_server_response = !disabling;
            changed(app);
        }
        11 => open_text(
            app,
            "单项转录上限（字节）",
            app.config.plugins[idx].body_limit.to_string(),
            TextField::AuditBodyLimit(index),
        ),
        _ => app.status = "当前字段不可编辑".into(),
    }
}

fn remove_header_case_insensitive(
    headers: &mut std::collections::HashMap<String, SecretValue>,
    name: &str,
) -> Option<SecretValue> {
    let key = headers
        .keys()
        .find(|key| key.eq_ignore_ascii_case(name))?
        .clone();
    headers.remove(&key)
}

fn add_default_http_header_removal(plugin: &mut PluginConfig) {
    if plugin
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case(DEFAULT_HTTP_HEADER_REMOVAL))
    {
        return;
    }
    plugin.headers.insert(
        DEFAULT_HTTP_HEADER_REMOVAL.into(),
        SecretValue::Inline {
            value: String::new(),
        },
    );
}

fn open_text(app: &mut App, title: &str, value: String, field: TextField) {
    open_input(app, title, &value, false, InputAction::Text(field));
}

fn open_secret(app: &mut App, title: &str, field: SecretField) {
    open_input(
        app,
        &format!("{title}：直接输入值；- 清除"),
        "",
        true,
        InputAction::Secret(field),
    );
}

fn open_header(app: &mut App, field: HeaderField) {
    app.header_editor = Some(HeaderEditor { field, selected: 0 });
    app.status = "Header 列表：[a]添加 [Enter/e]修改值 [d]删除 [Esc]返回".into();
}

fn open_target_editor(app: &mut App, route: usize) {
    open_list_editor(app, ListEditorKind::RouteTargets(route));
}

fn apply_protection_reference(app: &mut App, target: ReferenceTarget, selected: Option<String>) {
    match target {
        ReferenceTarget::DefaultRoute => app.config.default_route.protection = selected,
        ReferenceTarget::Route(index) => app.config.rules[index].protection = selected,
        ReferenceTarget::Firewall(index) => app.config.firewall.rules[index].protection = selected,
        ReferenceTarget::Process(index) => {
            app.config.sandbox.process.rules[index].protection = selected
        }
        ReferenceTarget::File(index) => app.config.sandbox.file.rules[index].protection = selected,
    }
}

fn protection_reference(app: &App, target: ReferenceTarget) -> Option<String> {
    match target {
        ReferenceTarget::DefaultRoute => app.config.default_route.protection.clone(),
        ReferenceTarget::Route(index) => app.config.rules[index].protection.clone(),
        ReferenceTarget::Firewall(index) => app.config.firewall.rules[index].protection.clone(),
        ReferenceTarget::Process(index) => {
            app.config.sandbox.process.rules[index].protection.clone()
        }
        ReferenceTarget::File(index) => app.config.sandbox.file.rules[index].protection.clone(),
    }
}

fn open_reference_picker(app: &mut App, target: ReferenceTarget, kind: ReferenceKind) {
    let target_kind = match kind {
        ReferenceKind::Credential => Some(PluginKind::Credential),
        ReferenceKind::Audit => Some(PluginKind::Audit),
        ReferenceKind::Proxy | ReferenceKind::Protection => None,
    };
    let current = match kind {
        ReferenceKind::Proxy => match target {
            ReferenceTarget::Route(route) => app.config.rules[route].upstream.clone(),
            _ => None,
        },
        ReferenceKind::Protection => protection_reference(app, target),
        ReferenceKind::Credential | ReferenceKind::Audit => {
            let plugins: &[String] = match target {
                ReferenceTarget::Route(route) => &app.config.rules[route].plugins,
                ReferenceTarget::DefaultRoute => &app.config.default_route.plugins,
                _ => &[],
            };
            plugins
                .iter()
                .find(|id| {
                    app.config
                        .plugin(id)
                        .is_some_and(|plugin| plugin.kind == target_kind.unwrap())
                })
                .cloned()
        }
    };
    let selected = current
        .as_deref()
        .and_then(|id| {
            (1..=reference_count(app, kind)).find(|selected| {
                reference_id(app, kind, *selected).is_some_and(|candidate| candidate == id)
            })
        })
        .unwrap_or(0);
    app.reference_picker = Some(ReferencePicker {
        target,
        kind,
        selected,
    });
    app.status = "↑↓ 选择，Enter 应用，Esc 取消；右侧为脱敏预览".into();
}

#[allow(dead_code)]
fn join_display<T: std::fmt::Display>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn input_chars(value: &str) -> Vec<char> {
    value.chars().collect()
}

fn input_replace_chars(value: &mut Zeroizing<String>, chars: Vec<char>) {
    value.clear();
    value.extend(chars);
}

fn input_insert(modal: &mut InputModal, value: char) {
    let mut chars = input_chars(&modal.value);
    let cursor = modal.cursor.min(chars.len());
    chars.insert(cursor, value);
    input_replace_chars(&mut modal.value, chars);
    modal.cursor = cursor + 1;
}

fn input_backspace(modal: &mut InputModal) {
    if modal.cursor == 0 {
        return;
    }
    let mut chars = input_chars(&modal.value);
    let cursor = modal.cursor.min(chars.len());
    chars.remove(cursor - 1);
    input_replace_chars(&mut modal.value, chars);
    modal.cursor = cursor - 1;
}

fn input_delete_at_cursor(modal: &mut InputModal) {
    let mut chars = input_chars(&modal.value);
    if modal.cursor >= chars.len() {
        return;
    }
    chars.remove(modal.cursor);
    input_replace_chars(&mut modal.value, chars);
}

fn input_line_start(value: &str, cursor: usize, multiline: bool) -> usize {
    if !multiline {
        return 0;
    }
    let chars = input_chars(value);
    let cursor = cursor.min(chars.len());
    chars[..cursor]
        .iter()
        .rposition(|value| *value == '\n')
        .map_or(0, |index| index + 1)
}

fn input_line_end(value: &str, cursor: usize, multiline: bool) -> usize {
    let chars = input_chars(value);
    let cursor = cursor.min(chars.len());
    if !multiline {
        return chars.len();
    }
    cursor
        + chars[cursor..]
            .iter()
            .position(|value| *value == '\n')
            .unwrap_or(chars.len() - cursor)
}

fn input_modal_view(
    modal: &InputModal,
    content_width: u16,
    visible_rows: u16,
) -> (String, (u16, u16)) {
    let width = content_width.max(1);
    let mut rows = vec!["> ".to_string()];
    let mut column = 2u16.min(width.saturating_sub(1));
    let mut cursor = None;
    for (index, value) in input_chars(&modal.value).into_iter().enumerate() {
        if index == modal.cursor {
            cursor = Some((column, rows.len() - 1));
        }
        if value == '\n' {
            rows.push(String::new());
            column = 0;
            continue;
        }
        let displayed = if modal.masked { '•' } else { value };
        let char_width = Line::from(displayed.to_string()).width() as u16;
        if column.saturating_add(char_width) > width {
            rows.push(String::new());
            column = 0;
        }
        rows.last_mut().unwrap().push(displayed);
        column = column.saturating_add(char_width);
        if column >= width {
            rows.push(String::new());
            column = 0;
        }
    }
    let (cursor_column, cursor_row) = cursor.unwrap_or((column, rows.len() - 1));
    let visible_rows = usize::from(visible_rows.max(1));
    let first_row = cursor_row.saturating_add(1).saturating_sub(visible_rows);
    let last_row = (first_row + visible_rows).min(rows.len());
    (
        rows[first_row..last_row].join("\n"),
        (cursor_column, (cursor_row - first_row) as u16),
    )
}

fn input_popup_text(value: &str, hint: &str) -> String {
    format!("{value}{hint}\n\n←→/Home/End 移动  Enter 确认  Esc 取消")
}

fn input_action_hint(action: &InputAction) -> Option<&'static str> {
    match action {
        InputAction::RouteTarget(_, _) => {
            Some("精确域名、*.通配域名、URL 路径、IP 或 CIDR；下一步输入端口")
        }
        InputAction::RoutePort(_, _, _) => Some("留空表示该目标的任意端口"),
        InputAction::FirewallTarget(_, _) => {
            Some("精确域名、*.通配域名、IP 或 CIDR；下一步输入绑定端口")
        }
        InputAction::FirewallPort(_, _, _) => Some("留空表示该目标的任意端口"),
        InputAction::FilePattern(_, _) => Some("输入 Rust regex，例：^C:/secret(?:/|$)"),
        InputAction::ProcessExecutable(_, _) => Some("输入 Rust regex；留空表示不限制可执行文件"),
        InputAction::ProcessCommandLine(_, _, _) => Some("输入 Rust regex；留空表示不限制命令行"),
        InputAction::ListValue(ListEditorKind::RouteTargets(_), _) => {
            Some("可输入：精确域名、*.通配域名、URL 路径、IP 或 CIDR；确认后输入端口\n例：example.com、*.example.com、*.example.com/api、10.0.0.0/8")
        }
        InputAction::ListValue(ListEditorKind::FirewallTargets(_), _) => Some(
            "可输入：精确域名、*.通配域名、IP 或 CIDR\n例：example.com、*.example.com、10.0.0.0/8（不支持 URL 路径）",
        ),
        InputAction::ListValue(ListEditorKind::FirewallPorts(_), _) => {
            Some("可输入：1-65535 的单个端口\n例：443")
        }
        InputAction::ListValue(ListEditorKind::FilePaths(_), _) => {
            Some("可输入：文件或目录路径\n例：C:\\Users\\me\\secret 或 /home/me/secret")
        }
        InputAction::ListValue(ListEditorKind::SandboxExecutables(_), _) => {
            Some("可输入：可执行文件名或完整路径\n例：git.exe 或 C:\\Tools\\git.exe")
        }
        InputAction::ListValue(ListEditorKind::SandboxCommandLines(_), _) => {
            Some("可输入：命令行子串（不区分大小写）\n例：--upload-secret")
        }
        _ => None,
    }
}

fn open_input(app: &mut App, title: &str, value: &str, masked: bool, action: InputAction) {
    app.modal = Some(InputModal {
        title: title.into(),
        value: Zeroizing::new(value.into()),
        cursor: value.chars().count(),
        masked,
        multiline: false,
        action,
    });
}

fn open_multiline(app: &mut App, title: &str, action: InputAction) {
    app.modal = Some(InputModal {
        title: title.into(),
        value: Zeroizing::new(String::new()),
        cursor: 0,
        masked: false,
        multiline: true,
        action,
    });
}

/// 解析 `host[:port]`，端口缺省时用 `default_port`。
fn parse_certificate_host(input: &str, default_port: u16) -> Result<(&str, u16), String> {
    let (host, port) = match input.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            (
                host,
                port.parse::<u16>()
                    .map_err(|_| format!("无效端口：{port}"))?,
            )
        }
        _ => (input, default_port),
    };
    if host.is_empty() {
        return Err("主机名不能为空".into());
    }
    Ok((host, port))
}

fn apply_input(app: &mut App, modal: InputModal) -> Result<(), String> {
    let value = Zeroizing::new(modal.value.to_string());
    match modal.action {
        InputAction::Text(field) => apply_text_field(app, field, value.as_str())?,
        InputAction::Secret(field) => {
            if value.is_empty() {
                app.status = "未修改 Secret".into();
                return Ok(());
            }
            apply_secret_field(app, field, value.as_str())?;
        }
        InputAction::HeaderName(field) => {
            if value.is_empty() {
                app.status = "未修改 Header".into();
                return Ok(());
            }
            let name = required(value.as_str(), "Header 名称")?;
            open_input(
                app,
                &format!("{name} 的值（留空表示删除客户端 Header）"),
                "",
                true,
                InputAction::HeaderValue(field, name, false),
            );
            return Ok(());
        }
        InputAction::HeaderValue(field, name, preserve_empty) => {
            if preserve_empty && value.is_empty() {
                app.status = "未修改 Header".into();
                return Ok(());
            }
            let value = if preserve_empty && value.as_str() == "-" {
                ""
            } else {
                value.as_str()
            };
            apply_header_field(app, field, &name, value)?;
        }
        InputAction::ListValue(kind, index) => {
            apply_list_value(app, kind, index, value.as_str())?;
        }
        InputAction::RouteTarget(route, index) => {
            let target = normalize_list_value(ListEditorKind::RouteTargets(route), value.as_str())?;
            let port = index
                .and_then(|i| app.config.rules[route].endpoints[i].port)
                .map(|port| port.to_string())
                .unwrap_or_default();
            open_input(
                app,
                "路由端口（留空表示任意端口）",
                &port,
                false,
                InputAction::RoutePort(route, index, target),
            );
            return Ok(());
        }
        InputAction::RoutePort(route, index, target) => {
            let port = optional_port(value.as_str())?;
            let endpoint = RouteEndpoint { target, port };
            match index {
                Some(index) => app.config.rules[route].endpoints[index] = endpoint,
                None => app.config.rules[route].endpoints.push(endpoint),
            }
            if let Some(editor) = &mut app.list_editor {
                editor.selected = index.unwrap_or(app.config.rules[route].endpoints.len() - 1);
            }
            changed(app);
        }
        InputAction::FirewallTarget(rule, index) => {
            let target =
                normalize_list_value(ListEditorKind::FirewallTargets(rule), value.as_str())?;
            let port = index
                .and_then(|i| app.config.firewall.rules[rule].endpoints[i].port)
                .map(|p| p.to_string())
                .unwrap_or_default();
            open_input(
                app,
                "端口（留空表示任意端口）",
                &port,
                false,
                InputAction::FirewallPort(rule, index, target),
            );
            return Ok(());
        }
        InputAction::FirewallPort(rule, index, target) => {
            let port = optional_port(value.as_str())?;
            let endpoint = FirewallEndpoint { target, port };
            match index {
                Some(index) => app.config.firewall.rules[rule].endpoints[index] = endpoint,
                None => app.config.firewall.rules[rule].endpoints.push(endpoint),
            }
            changed(app);
        }
        InputAction::FilePattern(rule, index) => {
            let pattern = required(value.as_str(), "路径正则")?;
            regex::Regex::new(&pattern).map_err(|error| format!("无效正则：{error}"))?;
            let enabled = index
                .map(|i| app.config.sandbox.file.rules[rule].patterns[i].enabled)
                .unwrap_or(true);
            let entry = FileSandboxPattern { enabled, pattern };
            match index {
                Some(index) => app.config.sandbox.file.rules[rule].patterns[index] = entry,
                None => app.config.sandbox.file.rules[rule].patterns.push(entry),
            }
            changed(app);
        }
        InputAction::ProcessExecutable(rule, index) => {
            let executable = value.trim().to_owned();
            if !executable.is_empty() {
                regex::Regex::new(&executable)
                    .map_err(|error| format!("无效可执行文件正则：{error}"))?;
            }
            let command_line = index
                .map(|i| {
                    app.config.sandbox.process.rules[rule].patterns[i]
                        .command_line
                        .clone()
                })
                .unwrap_or_default();
            open_input(
                app,
                "命令行正则（可留空）",
                &command_line,
                false,
                InputAction::ProcessCommandLine(rule, index, executable),
            );
            return Ok(());
        }
        InputAction::ProcessCommandLine(rule, index, executable) => {
            let command_line = value.trim().to_owned();
            if executable.is_empty() && command_line.is_empty() {
                return Err("可执行文件与命令行正则不能同时为空".into());
            }
            if !command_line.is_empty() {
                regex::Regex::new(&command_line)
                    .map_err(|error| format!("无效命令行正则：{error}"))?;
            }
            let enabled = index
                .map(|i| app.config.sandbox.process.rules[rule].patterns[i].enabled)
                .unwrap_or(true);
            let entry = ProcessSandboxPattern {
                enabled,
                executable,
                command_line,
            };
            match index {
                Some(index) => app.config.sandbox.process.rules[rule].patterns[index] = entry,
                None => app.config.sandbox.process.rules[rule].patterns.push(entry),
            }
            changed(app);
        }
        InputAction::EnvironmentName => {
            let name = normalize_environment_name(value.as_str())?;
            if app
                .config
                .environment
                .iter()
                .any(|variable| variable.name.eq_ignore_ascii_case(&name))
            {
                return Err(format!("环境变量 '{name}' 已存在"));
            }
            open_input(
                app,
                &format!("环境变量 {name} 的值"),
                "",
                true,
                InputAction::EnvironmentValue(None, name, false),
            );
            return Ok(());
        }
        InputAction::EnvironmentValue(index, name, preserve_empty) => {
            if preserve_empty && value.is_empty() {
                app.status = "未修改环境变量".into();
                return Ok(());
            }
            let cleared = value.trim() == "-";
            let cleared_status = cleared.then(|| format!("✓ 环境变量 {name} 已清空"));
            let variable = EnvironmentVariable {
                uuid: hyperhub_core::config::new_config_uuid(),
                name,
                value: SecretValue::Inline {
                    value: if cleared {
                        String::new()
                    } else {
                        value.to_string()
                    },
                },
            };
            if let Some(index) = index {
                app.config.environment[index] = variable;
            } else {
                app.config.environment.push(variable);
                app.field = app.config.environment.len() - 1;
            }
            changed(app);
            if let Some(status) = cleared_status {
                if app.status.starts_with('✓') {
                    app.status = status;
                }
            }
            return Ok(());
        }
        InputAction::ImportRootCertificate => {
            let input = value.trim();
            if let Some(rest) = input.strip_prefix("ssh://") {
                let (host, port) = parse_certificate_host(rest, 22)?;
                let (key_type, key_blob) =
                    hyperhub_core::certificate::fetch_ssh_host_key(host, port)
                        .map_err(|error| error.to_string())?;
                let entry_host = format!("{host}:{port}");
                if app
                    .config
                    .ssh_host_keys
                    .iter()
                    .any(|key| key.host == entry_host)
                {
                    app.status = "✓ 该 SSH 主机密钥已导入过".into();
                    return Ok(());
                }
                app.config.ssh_host_keys.push(SshHostKey {
                    uuid: hyperhub_core::config::new_config_uuid(),
                    host: entry_host,
                    key_type,
                    key_blob,
                    enabled: true,
                });
                changed(app);
                app.status = format!("✓ 已导入 SSH 主机密钥 {}", rest);
                return Ok(());
            }
            let (certificates, host_scope) = if let Some(rest) = input.strip_prefix("https://") {
                let (host, port) = parse_certificate_host(rest, 443)?;
                let certificate =
                    hyperhub_core::certificate::fetch_tls_peer_certificates(host, port)
                        .map_err(|error| error.to_string())?
                        .into_iter()
                        .next()
                        .ok_or("未捕获到 TLS 叶证书")?;
                (
                    vec![certificate],
                    Some(hyperhub_core::trust::trust_authority(host, port)),
                )
            } else {
                let path = PathBuf::from(required(input, "证书路径")?);
                if !path.is_file() {
                    return Err(format!("文件不存在或不可读：{}", path.display()));
                }
                (
                    hyperhub_core::certificate::load_root_certificates(&path)
                        .map_err(|error| error.to_string())?,
                    None,
                )
            };
            let imported = config_store::import_root_certificates_from_der(
                &app.path,
                app.password.as_bytes(),
                &certificates,
            )
            .map_err(|error| error.to_string())?;
            if imported.is_empty() {
                return Err("没有可解析的证书".into());
            }
            let mut added = 0usize;
            for item in imported {
                if app.config.root_certificates.iter().any(|certificate| {
                    certificate.fingerprint == item.fingerprint && certificate.host == host_scope
                }) {
                    continue;
                }
                app.config.root_certificates.push(RootCertificate {
                    uuid: hyperhub_core::config::new_config_uuid(),
                    fingerprint: item.fingerprint,
                    host: host_scope.clone(),
                    enabled: true,
                });
                added += 1;
            }
            if added == 0 {
                app.status = "✓ 该证书已导入过".into();
            } else {
                changed(app);
                app.status = format!("✓ 已导入 {added} 个证书");
            }
            refresh_root_certificate_cache(app);
            return Ok(());
        }
        InputAction::AddSshAccount(credential) => {
            let username = required(value.as_str(), "SSH 用户名")?;
            let idx = credential_plugin_index(&app.config, credential);
            if app.config.plugins[idx]
                .ssh_accounts
                .iter()
                .any(|account| account.username == username)
            {
                return Err(format!("SSH 用户名 '{username}' 已存在"));
            }
            app.config.plugins[idx].ssh_accounts.push(SshAccount {
                username,
                private_keys: Vec::new(),
                passwords: Vec::new(),
            });
            if let Some(editor) = &mut app.ssh_account_editor {
                editor.selected = app.config.plugins[idx].ssh_accounts.len() - 1;
            }
            app.status = "✓ 已添加 SSH 账号，请继续配置私钥或密码".into();
        }
        InputAction::ImportSshKeyPath(credential, account) => {
            import_ssh_key_path(app, credential, account, value.as_str())?;
            app.status = "✓ 已导入 SSH 私钥".into();
        }
        InputAction::AddSshKeyPaste(credential, account) => {
            add_ssh_key_pem(app, credential, account, value.as_str())?;
            app.status = "✓ 已添加 SSH 私钥".into();
        }
        InputAction::Search => {
            let needle = value.to_lowercase();
            app.editor = None;
            if let Some(category) = NAV_ITEMS.iter().find(|category| {
                category.label().to_lowercase().contains(&needle)
                    || category.breadcrumb().to_lowercase().contains(&needle)
            }) {
                app.category = *category;
                app.field = 0;
                app.focus = Focus::Detail;
                app.status = format!("✓ 已定位到 {}", category.breadcrumb());
                return Ok(());
            }
            for category in NAV_ITEMS {
                app.category = *category;
                if let Some(field) = detail_lines(app)
                    .iter()
                    .position(|line| line.to_lowercase().contains(&needle))
                {
                    app.field = field;
                    app.focus = Focus::Detail;
                    app.status = format!("✓ 已定位到 {}", category.breadcrumb());
                    return Ok(());
                }
            }
            return Err(format!("没有找到“{}”", value.as_str()));
        }
        InputAction::NewPassword => {
            if value.chars().count() < 8 {
                return Err("password must contain at least 8 characters".into());
            }
            open_input(
                app,
                "确认新密码",
                "",
                true,
                InputAction::ConfirmPassword(value),
            );
            return Ok(());
        }
        InputAction::ConfirmPassword(first) => {
            if first.as_str() != value.as_str() {
                return Err("password confirmation does not match".into());
            }
            if app.previous_password.is_none() {
                app.previous_password = Some(app.password.clone());
            }
            app.password = first;
            app.status = "✓ 主密码将在保存时更新".into();
            app.dirty = true;
            return Ok(());
        }
    }
    changed(app);
    Ok(())
}

fn apply_text_field(app: &mut App, field: TextField, value: &str) -> Result<(), String> {
    let optional = || (!value.trim().is_empty()).then(|| value.trim().to_owned());
    match field {
        TextField::SocksListen => app.config.listener.socks_listen = required(value, "监听地址")?,
        TextField::PendingTtl => {
            let ttl = value.parse().map_err(|_| "待激活会话有效期必须是正整数")?;
            if ttl == 0 {
                return Err("待激活会话有效期必须大于 0".into());
            }
            app.config.listener.pending_session_ttl_secs = ttl;
        }
        TextField::UpstreamId(index) => {
            let new_id = unique_id(
                value,
                "upstream",
                app.config
                    .upstreams
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != index)
                    .map(|(_, item)| item.id.as_str()),
            )?;
            let old_id = std::mem::replace(&mut app.config.upstreams[index].id, new_id.clone());
            for route in &mut app.config.rules {
                if route.upstream.as_deref() == Some(&old_id) {
                    route.upstream = Some(new_id.clone());
                }
            }
        }
        TextField::UpstreamAddress(index) => {
            app.config.upstreams[index].address = required(value, "上游地址")?
        }
        TextField::UpstreamTimeout(index) => {
            let timeout = value.parse().map_err(|_| "连接超时必须是正整数")?;
            if timeout == 0 {
                return Err("连接超时必须大于 0".into());
            }
            app.config.upstreams[index].timeout_ms = timeout;
        }
        TextField::CredentialId(index) => {
            let idx = credential_plugin_index(&app.config, index);
            let self_id = app.config.plugins[idx].id.clone();
            let new_id = unique_id(
                value,
                "credential",
                app.config
                    .plugins
                    .iter()
                    .filter(|plugin| plugin.kind == PluginKind::Credential && plugin.id != self_id)
                    .map(|plugin| plugin.id.as_str()),
            )?;
            let old_id = std::mem::replace(&mut app.config.plugins[idx].id, new_id.clone());
            for id in &mut app.config.default_route.plugins {
                if id == &old_id {
                    *id = new_id.clone();
                }
            }
            for route in &mut app.config.rules {
                for id in &mut route.plugins {
                    if id == &old_id {
                        *id = new_id.clone();
                    }
                }
            }
        }
        TextField::CredentialUsername(index) => {
            let idx = credential_plugin_index(&app.config, index);
            app.config.plugins[idx].username = optional();
        }
        TextField::CredentialHttpName(index) => {
            let idx = credential_plugin_index(&app.config, index);
            app.config.plugins[idx].http_name = optional();
        }
        TextField::SshAccountUsername(credential, account) => {
            let username = required(value, "SSH 用户名")?;
            let idx = credential_plugin_index(&app.config, credential);
            if app.config.plugins[idx]
                .ssh_accounts
                .iter()
                .enumerate()
                .any(|(other, candidate)| other != account && candidate.username == username)
            {
                return Err(format!("SSH 用户名 '{username}' 已存在"));
            }
            app.config.plugins[idx].ssh_accounts[account].username = username;
        }
        TextField::SshKeyName(credential, account, key_index) => {
            let idx = credential_plugin_index(&app.config, credential);
            app.config.plugins[idx].ssh_accounts[account].private_keys[key_index].name =
                required(value, "私钥名称")?;
        }
        TextField::AuditId(index) => {
            let idx = audit_plugin_index(&app.config, index);
            let self_id = app.config.plugins[idx].id.clone();
            let new_id = unique_id(
                value,
                "audit",
                app.config
                    .plugins
                    .iter()
                    .filter(|plugin| plugin.kind == PluginKind::Audit && plugin.id != self_id)
                    .map(|plugin| plugin.id.as_str()),
            )?;
            let old_id = std::mem::replace(&mut app.config.plugins[idx].id, new_id.clone());
            for id in &mut app.config.default_route.plugins {
                if id == &old_id {
                    *id = new_id.clone();
                }
            }
            for route in &mut app.config.rules {
                for id in &mut route.plugins {
                    if id == &old_id {
                        *id = new_id.clone();
                    }
                }
            }
        }
        TextField::AuditBodyLimit(index) => {
            let idx = audit_plugin_index(&app.config, index);
            app.config.plugins[idx].body_limit =
                value.parse().map_err(|_| "正文大小上限必须是非负整数")?;
        }
        TextField::AuditRetentionDays => {
            app.config.audit.retention_days =
                value.parse().map_err(|_| "保留天数必须是非负整数")?;
        }
        TextField::ProtectionId(index) => {
            let new_id = unique_id(
                value,
                "protection",
                app.config
                    .protections
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != index)
                    .map(|(_, item)| item.id.as_str()),
            )?;
            let old_id = std::mem::replace(&mut app.config.protections[index].id, new_id.clone());
            if app.config.default_route.protection.as_deref() == Some(&old_id) {
                app.config.default_route.protection = Some(new_id.clone());
            }
            for route in &mut app.config.rules {
                if route.protection.as_deref() == Some(&old_id) {
                    route.protection = Some(new_id.clone());
                }
            }
        }
        TextField::ProtectionMaxScanBytes(index) => {
            let parsed: usize = value.parse().map_err(|_| "最大扫描字节数必须是正整数")?;
            if parsed == 0 {
                return Err("最大扫描字节数必须大于 0".into());
            }
            app.config.protections[index].data.max_scan_bytes = parsed;
        }
        TextField::ProtectionTimeoutMs(index) => {
            let parsed: u64 = value.parse().map_err(|_| "超时必须是正整数")?;
            if parsed == 0 {
                return Err("超时必须大于 0".into());
            }
            app.config.protections[index].intelligence.timeout_ms = parsed;
        }
        TextField::ProtectionProvenanceWindow(index) => {
            let parsed: usize = value.parse().map_err(|_| "来源追踪窗口必须是正整数")?;
            app.config.protections[index].data.provenance_window_bytes = parsed;
        }
        TextField::ProtectionProvenanceMatches(index) => {
            let parsed: usize = value.parse().map_err(|_| "来源追踪命中阈值必须是正整数")?;
            app.config.protections[index].data.provenance_min_matches = parsed;
        }
        TextField::ProtectionMinConfidence(index) => {
            let parsed: f64 = value.parse().map_err(|_| "最低置信度必须是 0-1 数值")?;
            if !(0.0..=1.0).contains(&parsed) {
                return Err("最低置信度必须在 0-1 之间".into());
            }
            app.config.protections[index].intelligence.min_confidence = parsed;
        }
        TextField::ProtectionCacheTtlMs(index) => {
            app.config.protections[index].intelligence.cache_ttl_ms =
                value.parse().map_err(|_| "缓存时间必须是非负整数")?;
        }
        TextField::ProtectionProviderEndpoint(index) => {
            app.config.protections[index]
                .intelligence
                .provider
                .get_or_insert_with(default_intelligence_provider)
                .endpoint = optional();
        }
        TextField::ProtectionProviderModel(index) => {
            app.config.protections[index]
                .intelligence
                .provider
                .get_or_insert_with(default_intelligence_provider)
                .model = optional();
        }
        TextField::RouteId(index) => {
            app.config.rules[index].id = unique_id(
                value,
                "route",
                std::iter::once(DEFAULT_ROUTE_ID).chain(
                    app.config
                        .rules
                        .iter()
                        .enumerate()
                        .filter(|(other, _)| *other != index)
                        .map(|(_, item)| item.id.as_str()),
                ),
            )?;
        }
        TextField::RoutePriority(index) => {
            app.config.rules[index].priority = value.parse().map_err(|_| "优先级必须是整数")?
        }
        TextField::FirewallId(index) => {
            app.config.firewall.rules[index].id = unique_id(
                value,
                "firewall",
                app.config
                    .firewall
                    .rules
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != index)
                    .map(|(_, item)| item.id.as_str()),
            )?;
        }
        TextField::FirewallPriority(index) => {
            app.config.firewall.rules[index].priority =
                value.parse().map_err(|_| "优先级必须是整数")?;
        }
        TextField::SandboxProcessId(i) => {
            app.config.sandbox.process.rules[i].id = required(value, "规则 ID")?
        }
        TextField::SandboxProcessPriority(i) => {
            app.config.sandbox.process.rules[i].priority =
                value.parse().map_err(|_| "优先级必须是整数")?
        }
        TextField::FileSandboxId(i) => {
            app.config.sandbox.file.rules[i].id = required(value, "规则 ID")?
        }
        TextField::FileSandboxPriority(i) => {
            app.config.sandbox.file.rules[i].priority =
                value.parse().map_err(|_| "优先级必须是整数")?
        }
    }
    Ok(())
}

fn apply_secret_field(app: &mut App, field: SecretField, value: &str) -> Result<(), String> {
    let secret = if value.trim() == "-" {
        None
    } else {
        Some(SecretValue::Inline {
            value: value.to_owned(),
        })
    };
    match field {
        SecretField::UpstreamUsername(index) => app.config.upstreams[index].username = secret,
        SecretField::UpstreamPassword(index) => app.config.upstreams[index].password = secret,
        SecretField::CredentialPassword(index) => {
            let idx = credential_plugin_index(&app.config, index);
            app.config.plugins[idx].password = secret;
        }
        SecretField::CredentialHttpSecret(index) => {
            let idx = credential_plugin_index(&app.config, index);
            app.config.plugins[idx].secret = secret;
        }
        SecretField::ProtectionProviderApiKey(index) => {
            app.config.protections[index]
                .intelligence
                .provider
                .get_or_insert_with(default_intelligence_provider)
                .api_key = secret;
        }
        SecretField::SshPassword(credential, account, password_index) => {
            let idx = credential_plugin_index(&app.config, credential);
            let passwords = &mut app.config.plugins[idx].ssh_accounts[account].passwords;
            match password_index {
                Some(i) => match secret {
                    Some(value) => passwords[i] = value,
                    None => {
                        passwords.remove(i);
                    }
                },
                None => {
                    let value = secret.ok_or_else(|| "密码不能为空".to_string())?;
                    passwords.push(value);
                }
            }
        }
    }
    Ok(())
}

fn apply_header_field(
    app: &mut App,
    field: HeaderField,
    name: &str,
    value: &str,
) -> Result<(), String> {
    let name = required(name, "Header 名称")?;
    if let HeaderField::Credential(index) = field {
        let idx = credential_plugin_index(&app.config, index);
        let generated = match app.config.plugins[idx].http_scheme {
            Some(HttpAuthScheme::Basic | HttpAuthScheme::Bearer | HttpAuthScheme::Token) => {
                Some("Authorization")
            }
            Some(HttpAuthScheme::XApiKey) => Some("X-API-Key"),
            Some(HttpAuthScheme::Cookie) => Some("Cookie"),
            _ => None,
        };
        if generated.is_some_and(|generated| name.eq_ignore_ascii_case(generated)) {
            return Err(format!(
                "Header '{name}' 已由当前鉴权类型自动生成，无需重复配置"
            ));
        }
    }
    let headers = match field {
        HeaderField::Upstream(index) => &mut app.config.upstreams[index].headers,
        HeaderField::Credential(index) => {
            let idx = credential_plugin_index(&app.config, index);
            &mut app.config.plugins[idx].headers
        }
    };
    remove_header_case_insensitive(headers, &name);
    headers.insert(
        name.clone(),
        SecretValue::Inline {
            value: value.to_owned(),
        },
    );
    if app
        .header_editor
        .is_some_and(|editor| editor.field == field)
    {
        let selected = sorted_header_names(app, field)
            .iter()
            .position(|candidate| candidate == &name)
            .unwrap_or(0);
        if let Some(editor) = &mut app.header_editor {
            editor.selected = selected;
        }
    }
    Ok(())
}

fn apply_list_value(
    app: &mut App,
    kind: ListEditorKind,
    index: Option<usize>,
    value: &str,
) -> Result<(), String> {
    let normalized = normalize_list_value(kind, value)?;
    let selected = match kind {
        ListEditorKind::RouteTargets(route) => {
            let endpoint = RouteEndpoint {
                target: normalized,
                port: None,
            };
            match index {
                Some(index) => app.config.rules[route].endpoints[index] = endpoint,
                None => app.config.rules[route].endpoints.push(endpoint),
            }
            index.unwrap_or(app.config.rules[route].endpoints.len() - 1)
        }
        ListEditorKind::FirewallTargets(rule) => {
            let endpoint = FirewallEndpoint {
                target: normalized,
                port: None,
            };
            match index {
                Some(i) => app.config.firewall.rules[rule].endpoints[i] = endpoint,
                None => app.config.firewall.rules[rule].endpoints.push(endpoint),
            };
            index.unwrap_or(app.config.firewall.rules[rule].endpoints.len() - 1)
        }
        ListEditorKind::FirewallPorts(rule) => {
            let port = normalized
                .parse::<u16>()
                .map_err(|_| "端口必须是 1-65535 的数字".to_string())?;
            if port == 0 {
                return Err("端口不能为 0".into());
            }
            let i = index.unwrap_or(0);
            if let Some(endpoint) = app.config.firewall.rules[rule].endpoints.get_mut(i) {
                endpoint.port = Some(port);
            }
            i
        }
        ListEditorKind::FilePaths(rule) => {
            let entry = FileSandboxPattern {
                enabled: true,
                pattern: normalized,
            };
            match index {
                Some(i) => app.config.sandbox.file.rules[rule].patterns[i] = entry,
                None => app.config.sandbox.file.rules[rule].patterns.push(entry),
            };
            index.unwrap_or(app.config.sandbox.file.rules[rule].patterns.len() - 1)
        }
        ListEditorKind::SandboxExecutables(rule) => {
            let entry = ProcessSandboxPattern {
                enabled: true,
                executable: normalized,
                command_line: String::new(),
            };
            match index {
                Some(i) => app.config.sandbox.process.rules[rule].patterns[i] = entry,
                None => app.config.sandbox.process.rules[rule].patterns.push(entry),
            };
            index.unwrap_or(app.config.sandbox.process.rules[rule].patterns.len() - 1)
        }
        ListEditorKind::SandboxCommandLines(rule) => {
            let entry = ProcessSandboxPattern {
                enabled: true,
                executable: String::new(),
                command_line: normalized,
            };
            match index {
                Some(i) => app.config.sandbox.process.rules[rule].patterns[i] = entry,
                None => app.config.sandbox.process.rules[rule].patterns.push(entry),
            };
            index.unwrap_or(app.config.sandbox.process.rules[rule].patterns.len() - 1)
        }
    };
    if let Some(editor) = &mut app.list_editor {
        editor.selected = selected;
    }
    Ok(())
}

fn normalize_list_value(kind: ListEditorKind, value: &str) -> Result<String, String> {
    match kind {
        ListEditorKind::RouteTargets(_) => normalize_target(value),
        ListEditorKind::FirewallTargets(_) => {
            let target = normalize_target(value)?;
            let parsed = parse_route_target(&target)
                .map_err(|message| format!("网络目标无效（{message}）"))?;
            if matches!(
                parsed,
                RouteTarget::Domain {
                    path_prefix: Some(_),
                    ..
                }
            ) {
                return Err("网络目标不能包含 URL 路径".into());
            }
            Ok(target)
        }
        ListEditorKind::FirewallPorts(_) => required(value, "端口"),
        ListEditorKind::FilePaths(_) => required(value, "文件路径"),
        ListEditorKind::SandboxExecutables(_) => required(value, "可执行文件"),
        ListEditorKind::SandboxCommandLines(_) => required(value, "命令行"),
    }
}

#[allow(dead_code)]
fn replace_u16_list(
    list: &mut Vec<u16>,
    index: Option<usize>,
    value: u16,
    label: &str,
) -> Result<usize, String> {
    if list
        .iter()
        .enumerate()
        .any(|(candidate_index, candidate)| Some(candidate_index) != index && *candidate == value)
    {
        return Err(format!("{label} '{value}' 已存在"));
    }
    match index {
        Some(index) => {
            let Some(current) = list.get_mut(index) else {
                return Err("选中的条目已不存在".into());
            };
            *current = value;
            Ok(index)
        }
        None => {
            list.push(value);
            Ok(list.len() - 1)
        }
    }
}

fn normalize_target(value: &str) -> Result<String, String> {
    let value = required(value, "目标")?;
    match parse_route_target(&value)
        .map_err(|message| format!("目标必须是有效的域名、IP、CIDR 或 http(s) URL（{message}）"))?
    {
        RouteTarget::Network(network) => Ok(network.trunc().to_string()),
        RouteTarget::Ip(ip) => Ok(ip.to_string()),
        RouteTarget::Domain {
            host,
            wildcard,
            path_prefix,
        } => Ok(format!(
            "{}{}{}",
            if wildcard { "*." } else { "" },
            host,
            path_prefix.unwrap_or_default()
        )),
    }
}

fn normalize_environment_name(value: &str) -> Result<String, String> {
    let name = required(value, "环境变量名称")?;
    let mut bytes = name.bytes();
    let valid = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if !valid {
        return Err("环境变量名称只能包含字母、数字和下划线，且不能以数字开头".into());
    }
    if name.to_ascii_uppercase().starts_with("HYPERHUB_") {
        return Err("HYPERHUB_ 前缀由程序保留".into());
    }
    Ok(name)
}

fn remove_header(app: &mut App, field: HeaderField, name: &str) -> Result<(), String> {
    let name = required(name, "Header 名称")?;
    let removed = match field {
        HeaderField::Upstream(index) => {
            remove_header_case_insensitive(&mut app.config.upstreams[index].headers, &name)
        }
        HeaderField::Credential(index) => {
            let idx = credential_plugin_index(&app.config, index);
            remove_header_case_insensitive(&mut app.config.plugins[idx].headers, &name)
        }
    };
    if removed.is_none() {
        Err(format!("Header '{name}' 不存在"))
    } else {
        Ok(())
    }
}

fn required(value: &str, label: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        Err(format!("{label}不能为空"))
    } else {
        Ok(value.to_owned())
    }
}

fn optional_port(value: &str) -> Result<Option<u16>, String> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    let port = value
        .trim()
        .parse::<u16>()
        .map_err(|_| "端口必须是 1-65535 的数字".to_string())?;
    if port == 0 {
        return Err("端口不能为 0".into());
    }
    Ok(Some(port))
}

fn unique_id<'a>(
    value: &str,
    label: &str,
    existing: impl Iterator<Item = &'a str>,
) -> Result<String, String> {
    let value = required(value, label)?;
    if existing.into_iter().any(|id| id == value) {
        Err(format!("{label} ID '{value}' 已存在"))
    } else {
        Ok(value)
    }
}

fn changed(app: &mut App) {
    app.dirty = true;
    app.status = match app.config.validate() {
        Ok(()) => "✓ 配置有效，尚未保存".into(),
        Err(error) => format!("✗ {error}"),
    };
}

fn add_selected(app: &mut App) {
    match app.category {
        CATEGORY_PROXY => {
            let id = next_id(
                "upstream",
                app.config.upstreams.iter().map(|item| item.id.as_str()),
            );
            app.config.upstreams.push(Upstream {
                uuid: hyperhub_core::config::new_config_uuid(),
                id,
                kind: UpstreamKind::Socks5,
                address: "127.0.0.1:1080".into(),
                timeout_ms: 10_000,
                username: None,
                password: None,
                headers: Default::default(),
            });
            changed(app);
            enter_editor(app, ObjectEditor::Upstream(app.config.upstreams.len() - 1));
        }
        CATEGORY_CREDENTIAL => {
            let id = next_id(
                "credential",
                app.config
                    .plugins
                    .iter()
                    .filter(|plugin| plugin.kind == PluginKind::Credential)
                    .map(|plugin| plugin.id.as_str()),
            );
            app.config.plugins.push(PluginConfig {
                uuid: hyperhub_core::config::new_config_uuid(),
                id,
                kind: PluginKind::Credential,
                protocols: vec![PluginProtocol::Http],
                http_scheme: Some(HttpAuthScheme::Bearer),
                ..PluginConfig::default()
            });
            add_default_http_header_removal(app.config.plugins.last_mut().unwrap());
            let ordinal = credential_plugin_indices(&app.config).len() - 1;
            changed(app);
            enter_editor(app, ObjectEditor::Credential(ordinal));
        }
        CATEGORY_AUDIT => {
            let id = next_id(
                "audit",
                app.config
                    .plugins
                    .iter()
                    .filter(|plugin| plugin.kind == PluginKind::Audit)
                    .map(|plugin| plugin.id.as_str()),
            );
            app.config.plugins.push(PluginConfig {
                uuid: hyperhub_core::config::new_config_uuid(),
                id,
                kind: PluginKind::Audit,
                protocols: vec![PluginProtocol::Http, PluginProtocol::Ws],
                git_transcript: Some(false),
                ..PluginConfig::default()
            });
            let ordinal = audit_plugin_indices(&app.config).len() - 1;
            changed(app);
            enter_editor(app, ObjectEditor::AuditProfile(ordinal));
        }
        CATEGORY_PROTECTION => {
            let id = next_id(
                "protection",
                app.config.protections.iter().map(|item| item.id.as_str()),
            );
            app.config.protections.push(ProtectionProfile {
                uuid: hyperhub_core::config::new_config_uuid(),
                id,
                enabled: true,
                mode: ProtectionMode::Observe,
                data: DataProtectionConfig::default(),
                intelligence: IntelligenceProtectionConfig {
                    provider: Some(default_intelligence_provider()),
                    ..IntelligenceProtectionConfig::default()
                },
            });
            changed(app);
            enter_editor(
                app,
                ObjectEditor::Protection(app.config.protections.len() - 1),
            );
        }
        CATEGORY_FIREWALL => {
            let id = next_id(
                "firewall",
                app.config
                    .firewall
                    .rules
                    .iter()
                    .map(|item| item.id.as_str()),
            );
            app.config.firewall.rules.push(FirewallRule {
                uuid: hyperhub_core::config::new_config_uuid(),
                id,
                enabled: false,
                priority: 0,
                action: FirewallAction::Deny,
                endpoints: Vec::new(),
                legacy: Default::default(),
                protection: None,
            });
            changed(app);
            enter_editor(
                app,
                ObjectEditor::FirewallRule(app.config.firewall.rules.len() - 1),
            );
        }
        CATEGORY_SANDBOX_PROCESS => {
            let id = next_id(
                "process-sandbox",
                app.config
                    .sandbox
                    .process
                    .rules
                    .iter()
                    .map(|x| x.id.as_str()),
            );
            app.config.sandbox.process.rules.push(ProcessSandboxRule {
                uuid: hyperhub_core::config::new_config_uuid(),
                id,
                enabled: false,
                priority: 0,
                action: SandboxAction::Deny,
                patterns: Vec::new(),
                protection: None,
                legacy: Default::default(),
            });
            changed(app);
            enter_editor(
                app,
                ObjectEditor::SandboxProcessRule(app.config.sandbox.process.rules.len() - 1),
            );
        }
        CATEGORY_FILES => {
            let id = next_id(
                "file-sandbox",
                app.config.sandbox.file.rules.iter().map(|x| x.id.as_str()),
            );
            app.config.sandbox.file.rules.push(FileSandboxRule {
                uuid: hyperhub_core::config::new_config_uuid(),
                id,
                enabled: false,
                priority: 0,
                action: SandboxAction::Deny,
                patterns: Vec::new(),
                operations: vec![FileSandboxOperation::Read],
                protection: None,
                legacy: Default::default(),
            });
            changed(app);
            enter_editor(
                app,
                ObjectEditor::FileSandboxRule(app.config.sandbox.file.rules.len() - 1),
            );
        }
        CATEGORY_ROUTE => {
            let id = next_id(
                "route",
                app.config.rules.iter().map(|item| item.id.as_str()),
            );
            app.config.rules.push(RouteRule {
                uuid: hyperhub_core::config::new_config_uuid(),
                id,
                enabled: true,
                priority: 0,
                endpoints: Vec::new(),
                action: RuleAction::Pass,
                rewrite_host: None,
                rewrite_port: None,
                upstream: None,
                plugins: Vec::new(),
                legacy: Default::default(),
                protection: None,
                allow_sensitive_upload: false,
            });
            changed(app);
            enter_editor(app, ObjectEditor::Route(app.config.rules.len() - 1));
        }
        CATEGORY_CERTIFICATE => open_input(
            app,
            "证书文件路径、https://主机[:端口] 或 ssh://主机[:端口]",
            "",
            false,
            InputAction::ImportRootCertificate,
        ),
        CATEGORY_ENVIRONMENT => {
            open_input(app, "环境变量名称", "", false, InputAction::EnvironmentName)
        }
        _ => app.status = "当前分类不支持新增".into(),
    }
}

fn add_editor_pattern(app: &mut App) {
    match app.editor {
        Some(ObjectEditor::FirewallRule(rule)) => open_input(
            app,
            "目标（域名、IP 或 CIDR）",
            "",
            false,
            InputAction::FirewallTarget(rule, None),
        ),
        Some(ObjectEditor::FileSandboxRule(rule)) => open_input(
            app,
            "路径正则",
            "",
            false,
            InputAction::FilePattern(rule, None),
        ),
        Some(ObjectEditor::SandboxProcessRule(rule)) => open_input(
            app,
            "可执行文件正则（可留空）",
            "",
            false,
            InputAction::ProcessExecutable(rule, None),
        ),
        _ => app.status = "当前表单不支持添加子项".into(),
    }
}

fn delete_editor_pattern(app: &mut App) {
    match app.editor {
        Some(ObjectEditor::FirewallRule(rule)) if app.field >= 5 => {
            app.config.firewall.rules[rule]
                .endpoints
                .remove(app.field - 5);
            changed(app);
        }
        Some(ObjectEditor::SandboxProcessRule(rule)) if app.field >= 6 => {
            app.config.sandbox.process.rules[rule]
                .patterns
                .remove(app.field - 5);
            changed(app);
        }
        Some(ObjectEditor::FileSandboxRule(rule)) if app.field >= 11 => {
            app.config.sandbox.file.rules[rule]
                .patterns
                .remove(app.field - 10);
            changed(app);
        }
        _ => {
            app.status = "请选中要删除的子项".into();
            return;
        }
    }
    app.field = app.field.saturating_sub(1);
    app.status = "✓ 已删除子项".into();
}

fn delete_selected(app: &mut App) {
    let result = match app.category {
        CATEGORY_PROXY if app.field < app.config.upstreams.len() => {
            let id = &app.config.upstreams[app.field].id;
            if app
                .config
                .rules
                .iter()
                .any(|rule| rule.upstream.as_deref() == Some(id))
            {
                Err(format!("upstream '{id}' 仍被路由引用"))
            } else {
                app.config.upstreams.remove(app.field);
                Ok(())
            }
        }
        CATEGORY_CREDENTIAL if app.field < credential_plugin_indices(&app.config).len() => {
            let idx = credential_plugin_index(&app.config, app.field);
            let id = &app.config.plugins[idx].id;
            if app
                .config
                .default_route
                .plugins
                .iter()
                .any(|plugin| plugin == id)
                || app
                    .config
                    .rules
                    .iter()
                    .any(|rule| rule.plugins.iter().any(|plugin| plugin == id))
            {
                Err(format!("credential plugin '{id}' 仍被路由引用"))
            } else {
                app.config.plugins.remove(idx);
                Ok(())
            }
        }
        CATEGORY_PROTECTION if app.field < app.config.protections.len() => {
            let id = app.config.protections[app.field].id.clone();
            if app.config.default_route.protection.as_deref() == Some(&id)
                || app
                    .config
                    .rules
                    .iter()
                    .any(|rule| rule.protection.as_deref() == Some(&id))
            {
                Err(format!("protection '{id}' 仍被路由引用"))
            } else {
                app.config.protections.remove(app.field);
                Ok(())
            }
        }
        CATEGORY_AUDIT
            if app.field >= 1 && app.field - 1 < audit_plugin_indices(&app.config).len() =>
        {
            let index = app.field - 1;
            let idx = audit_plugin_index(&app.config, index);
            let id = &app.config.plugins[idx].id;
            if app
                .config
                .default_route
                .plugins
                .iter()
                .any(|plugin| plugin == id)
                || app
                    .config
                    .rules
                    .iter()
                    .any(|rule| rule.plugins.iter().any(|plugin| plugin == id))
            {
                Err(format!("audit plugin '{id}' 仍被路由引用"))
            } else {
                app.config.plugins.remove(idx);
                Ok(())
            }
        }
        CATEGORY_FIREWALL if app.field < 3 => {
            Err("网络沙盒启停、默认动作和出错动作是固定项，不能删除".into())
        }
        CATEGORY_FIREWALL if app.field - 3 < app.config.firewall.rules.len() => {
            app.config.firewall.rules.remove(app.field - 3);
            Ok(())
        }
        CATEGORY_SANDBOX_PROCESS if app.field < 3 => Err("固定项不能删除".into()),
        CATEGORY_SANDBOX_PROCESS if app.field - 3 < app.config.sandbox.process.rules.len() => {
            app.config.sandbox.process.rules.remove(app.field - 3);
            Ok(())
        }
        CATEGORY_FILES if app.field < 3 => Err("固定项不能删除".into()),
        CATEGORY_FILES if app.field - 3 < app.config.sandbox.file.rules.len() => {
            app.config.sandbox.file.rules.remove(app.field - 3);
            Ok(())
        }
        CATEGORY_ROUTE if app.field == 0 => Err("默认路由是内置兜底项，不能删除".into()),
        CATEGORY_ROUTE if app.field - 1 < app.config.rules.len() => {
            app.config.rules.remove(app.field - 1);
            Ok(())
        }
        CATEGORY_ENVIRONMENT if app.field < app.config.environment.len() => {
            app.config.environment.remove(app.field);
            Ok(())
        }
        CATEGORY_CERTIFICATE if app.field < app.config.root_certificates.len() => {
            let fingerprint = app.config.root_certificates[app.field].fingerprint.clone();
            app.config.root_certificates.remove(app.field);
            if app
                .config
                .root_certificates
                .iter()
                .any(|item| item.fingerprint == fingerprint)
            {
                refresh_root_certificate_cache(app);
                Ok(())
            } else {
                match config_store::delete_root_certificate(&app.path, &fingerprint) {
                    Ok(()) => {
                        refresh_root_certificate_cache(app);
                        Ok(())
                    }
                    Err(error) => Err(error.to_string()),
                }
            }
        }
        CATEGORY_CERTIFICATE
            if app.field >= app.config.root_certificates.len()
                && app.field
                    < app.config.root_certificates.len() + app.config.ssh_host_keys.len() =>
        {
            let key_index = app.field - app.config.root_certificates.len();
            app.config.ssh_host_keys.remove(key_index);
            Ok(())
        }
        _ => Err("当前项目不能删除".into()),
    };
    match result {
        Ok(()) => {
            changed(app);
            app.field = app.field.min(detail_lines(app).len().saturating_sub(1));
        }
        Err(error) => app.status = format!("✗ {error}"),
    }
}

fn next_id<'a>(prefix: &str, existing: impl Iterator<Item = &'a str>) -> String {
    let existing = existing.collect::<std::collections::HashSet<_>>();
    (1..)
        .map(|index| format!("{prefix}-{index}"))
        .find(|candidate| !existing.contains(candidate.as_str()))
        .unwrap()
}

fn save(app: &mut App) -> Result<(), String> {
    app.config.validate().map_err(|error| error.to_string())?;
    // 保存时重新探测 Serve，避免 TUI 早于 Serve 启动导致热更新被跳过。
    let live = app.live || crate::serve_is_running();
    // Serve 运行时复用现有 KDF descriptor，保证派生出的 session_auth_key 不变，
    // 热更新证明才能通过 serve 校验；非运行时每次保存轮换 descriptor。
    let descriptor = if live {
        config_store::read_descriptor(&app.path).unwrap_or_else(|_| config_store::new_descriptor())
    } else {
        config_store::new_descriptor()
    };
    if let Some(previous) = app.previous_password.take() {
        config_store::reencrypt_root_certificates(
            &app.path,
            previous.as_bytes(),
            app.password.as_bytes(),
            &descriptor,
        )
        .map_err(|error| error.to_string())?;
    }
    config_store::save_encrypted_with_descriptor(
        &app.path,
        &app.config,
        app.password.as_bytes(),
        &descriptor,
    )
    .map_err(|error| error.to_string())?;
    let _ = config_store::reconcile_root_certificates(
        &app.path,
        app.config
            .root_certificates
            .iter()
            .map(|certificate| certificate.fingerprint.as_str()),
    );
    app.dirty = false;
    app.saved = true;
    if live {
        match push_live_update(app) {
            Ok(()) => {
                app.status = format!("✓ 已保存并热更新到运行中的 Serve（{}）", app.path.display());
            }
            Err(error) => {
                app.status = format!(
                    "✓ 已保存到 {}；✗ 热更新失败：{error}（重启 Serve 后生效）",
                    app.path.display()
                );
            }
        }
    } else {
        app.status = format!("✓ 已加密保存到 {}", app.path.display());
    }
    Ok(())
}

/// 把已保存的配置推送给运行中的 Serve：用与 serve 相同的派生密钥对配置 JSON 做
/// HMAC 证明，serve 校验通过后经 `RuntimeState::apply` 热替换快照。
fn push_live_update(app: &App) -> Result<(), String> {
    let descriptor = config_store::read_descriptor(&app.path).map_err(|error| error.to_string())?;
    let key = config_store::derive_session_auth_key(app.password.as_bytes(), &descriptor)
        .map_err(|error| error.to_string())?;
    let config_json = serde_json::to_string(&app.config).map_err(|error| error.to_string())?;
    let proof = config_update_proof(&key, &config_json)?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let response = runtime
        .block_on(control_request(
            &discovery_control_endpoint(),
            &ControlRequest::UpdateConfig { proof, config_json },
        ))
        .map_err(|error| format!("无法连接运行中的 Serve：{error}"))?;
    match response {
        ControlResponse::Ok => Ok(()),
        ControlResponse::Error { message } => Err(message),
        _ => Err("Serve 返回了意外的响应".into()),
    }
}

/// 复用同一个 Tokio Runtime 执行控制面请求。每次刷新都执行
/// `Runtime::new()` 会反复创建线程池，是 TUI 空闲卡顿的主要来源之一。
fn control_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    static RUNTIME: std::sync::OnceLock<Result<tokio::runtime::Runtime, String>> =
        std::sync::OnceLock::new();
    RUNTIME
        .get_or_init(|| tokio::runtime::Runtime::new().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|error| error.clone())
}

fn query_managed_processes() -> Result<Vec<ManagedProcessView>, String> {
    let runtime = control_runtime()?;
    query_managed_processes_with(runtime)
}

fn query_managed_processes_with(
    runtime: &tokio::runtime::Runtime,
) -> Result<Vec<ManagedProcessView>, String> {
    let response = runtime
        .block_on(control_request(
            &discovery_control_endpoint(),
            &ControlRequest::GetStatus,
        ))
        .map_err(|error| error.to_string())?;
    let ControlResponse::Status { sessions, .. } = response else {
        return Err("Serve 返回了意外的状态响应".into());
    };
    let mut processes = sessions
        .into_iter()
        .flat_map(|session| {
            session
                .processes
                .into_iter()
                .map(move |process| ManagedProcessView {
                    session_id: session.session_id.clone(),
                    process,
                })
        })
        .collect::<Vec<_>>();
    processes.sort_by_key(|item| item.process.pid);
    Ok(processes)
}

fn refresh_managed_processes(app: &mut App) -> bool {
    // 直接复用同一 runtime 查询状态；Serve 离线时控制面请求快速失败，
    // 不再为 serve_is_running 重复新建 Runtime 并增加一次控制面往返。
    match query_managed_processes() {
        Ok(processes) => {
            app.live = true;
            app.managed_processes = processes;
            if app.category == CATEGORY_PROCESS {
                app.field = app.field.min(app.managed_processes.len().saturating_sub(1));
            }
            true
        }
        Err(_) => {
            app.live = false;
            app.managed_processes.clear();
            false
        }
    }
}

fn detail_lines(app: &App) -> Vec<String> {
    if let Some(editor) = app.list_editor {
        let values = list_values(app, editor.kind);
        return if values.is_empty() {
            vec![format!("（空，按 a 添加{}）", editor.kind.label())]
        } else {
            values
        };
    }
    if let Some(editor) = app.header_editor {
        let names = sorted_header_names(app, editor.field);
        return if names.is_empty() {
            vec!["（空，按 a 添加 Header）".into()]
        } else {
            names
                .into_iter()
                .map(|name| {
                    if matches!(
                        headers_for(app, editor.field).get(&name),
                        Some(SecretValue::Inline { value }) if value.is_empty()
                    ) {
                        format!("{name}: 删除客户端 Header")
                    } else {
                        format!("{name}: ••••••")
                    }
                })
                .collect()
        };
    }
    if let Some(editor) = app.ssh_key_editor {
        let idx = credential_plugin_index(&app.config, editor.credential);
        let keys = &app.config.plugins[idx].ssh_accounts[editor.account].private_keys;
        return if keys.is_empty() {
            vec!["（空，按 a 添加私钥）".into()]
        } else {
            keys.iter().map(|key| key.name.clone()).collect()
        };
    }
    if let Some(editor) = app.ssh_password_editor {
        let idx = credential_plugin_index(&app.config, editor.credential);
        let passwords = &app.config.plugins[idx].ssh_accounts[editor.account].passwords;
        return if passwords.is_empty() {
            vec!["（空，按 a 添加密码）".into()]
        } else {
            (0..passwords.len())
                .map(|index| format!("密码 {}: ••••••", index + 1))
                .collect()
        };
    }
    if let Some(detail) = app.ssh_account_detail {
        let idx = credential_plugin_index(&app.config, detail.credential);
        let account = &app.config.plugins[idx].ssh_accounts[detail.account];
        return vec![
            format!("用户名            {}", account.username),
            format!(
                "私钥              {} 个  （Enter 管理）",
                account.private_keys.len()
            ),
            format!(
                "密码              {} 个  （Enter 管理）",
                account.passwords.len()
            ),
        ];
    }
    if let Some(editor) = app.ssh_account_editor {
        let idx = credential_plugin_index(&app.config, editor.credential);
        let accounts = &app.config.plugins[idx].ssh_accounts;
        return if accounts.is_empty() {
            vec!["（空，按 a 添加 SSH 账号）".into()]
        } else {
            accounts
                .iter()
                .map(|account| {
                    format!(
                        "{}  {} 个私钥  {} 个密码",
                        account.username,
                        account.private_keys.len(),
                        account.passwords.len()
                    )
                })
                .collect()
        };
    }
    if let Some(editor) = app.editor {
        return editor_lines(app, editor);
    }
    match app.category {
        CATEGORY_GATEWAY => {
            let credentials = credential_plugin_indices(&app.config).len();
            let audits = audit_plugin_indices(&app.config).len();
            let routes = app.config.rules.len() + usize::from(app.config.default_route.enabled);
            let certificates = app.config.root_certificates.len() + app.config.ssh_host_keys.len();
            vec![
                format!(
                    "Serve             {}",
                    if app.live { "运行中" } else { "未运行" }
                ),
                format!(
                    "网关故障策略      {}",
                    enforcement_mode_label(app.config.mode)
                ),
                format!("SOCKS5            {}", app.config.listener.socks_listen),
                format!("代理              {} 个", app.config.upstreams.len()),
                format!("凭证              {credentials} 个"),
                format!("审计              {audits} 个"),
                format!("智能防护          {} 个", app.config.protections.len()),
                format!("路由              {routes} 条（含已启用默认路由）"),
                format!("证书              {certificates} 项"),
            ]
        }
        CATEGORY_BASIC => vec![
            format!(
                "网关故障策略      {}",
                enforcement_mode_label(app.config.mode)
            ),
            format!("SOCKS5            {}", app.config.listener.socks_listen),
            format!(
                "待激活会话有效期  {} 秒",
                app.config.listener.pending_session_ttl_secs
            ),
            format!(
                "调试事件          {}",
                if app.config.debug { "开启" } else { "关闭" }
            ),
        ],
        CATEGORY_PROXY => nonempty(
            app.config
                .upstreams
                .iter()
                .map(|item| format!("{}  {:?}  {}", item.id, item.kind, item.address))
                .collect(),
        ),
        CATEGORY_CREDENTIAL => nonempty(
            app.config
                .plugins
                .iter()
                .filter(|plugin| plugin.kind == PluginKind::Credential)
                .map(|item| {
                    if credential_carrier_is_http(item) {
                        let count = item.headers.len()
                            + usize::from(item.secret.is_some())
                            + usize::from(item.password.is_some())
                            + usize::from(item.username.is_some());
                        format!("{}  http  {} 个 Secret", item.id, count)
                    } else {
                        format!("{}  ssh  {} 个账号", item.id, item.ssh_accounts.len())
                    }
                })
                .collect(),
        ),
        CATEGORY_AUDIT => vec![format!(
            "审计保留天数      {}",
            if app.config.audit.retention_days == 0 {
                "永久".to_string()
            } else {
                app.config.audit.retention_days.to_string()
            }
        )]
        .into_iter()
        .chain(
            app.config
                .plugins
                .iter()
                .filter(|plugin| plugin.kind == PluginKind::Audit)
                .map(|item| {
                    format!(
                        "{}  事件={}  内容转录={}  方向={}",
                        item.id,
                        item.protocols
                            .iter()
                            .map(|protocol| audit_protocol_label(*protocol))
                            .collect::<Vec<_>>()
                            .join(","),
                        audit_transcript_summary(item),
                        transcript_direction_summary(item)
                    )
                }),
        )
        .chain(std::iter::once("提示：按 a 增加审计插件".into()))
        .collect(),
        CATEGORY_PROTECTION => nonempty(
            app.config
                .protections
                .iter()
                .map(|item| {
                    format!(
                        "{} {}  {}  本地检测={}  智能判断={}",
                        if item.enabled { "[x]" } else { "[ ]" },
                        item.id,
                        protection_mode_label(item.mode),
                        yes_no(item.data.enabled),
                        yes_no(item.intelligence.enabled),
                    )
                })
                .collect(),
        ),
        CATEGORY_ROUTE => std::iter::once(format!(
            "{} {}  内置兜底  {}  （不可删除）",
            if app.config.default_route.enabled {
                "[x]"
            } else {
                "[ ]"
            },
            DEFAULT_ROUTE_ID,
            rule_action_label(app.config.default_route.action, false)
        ))
        .chain(app.config.rules.iter().map(|item| {
            format!(
                "{} {}  优先级={}  {}",
                if item.enabled { "[x]" } else { "[ ]" },
                item.id,
                item.priority,
                rule_action_label(item.action, item.upstream.is_some())
            )
        }))
        .collect(),
        CATEGORY_FIREWALL => std::iter::once(format!(
            "网络沙盒          {}",
            if app.config.firewall.enabled {
                "启用"
            } else {
                "停用"
            }
        ))
        .chain(std::iter::once(format!(
            "默认动作          {}",
            firewall_default_label(app.config.firewall.default.as_ref())
        )))
        .chain(std::iter::once(format!(
            "出错动作          {}",
            firewall_action_label(app.config.firewall.error_action)
        )))
        .chain(app.config.firewall.rules.iter().map(|item| {
            format!(
                "{} {}  优先级={}  {}",
                if item.enabled { "[x]" } else { "[ ]" },
                item.id,
                item.priority,
                firewall_action_label(item.action)
            )
        }))
        .collect(),
        CATEGORY_SANDBOX => vec![
            format!(
                "网络沙盒        {}，{} 条规则",
                if app.config.firewall.enabled {
                    "启用"
                } else {
                    "停用"
                },
                app.config.firewall.rules.len()
            ),
            format!(
                "文件沙盒        {}，{} 条规则",
                if app.config.sandbox.file.enabled {
                    "启用"
                } else {
                    "停用"
                },
                app.config.sandbox.file.rules.len()
            ),
            format!(
                "子进程沙盒      {}，{} 条规则",
                if app.config.sandbox.process.enabled {
                    "启用"
                } else {
                    "停用"
                },
                app.config.sandbox.process.rules.len()
            ),
        ],
        CATEGORY_SANDBOX_PROCESS => std::iter::once(format!(
            "子进程沙盒      {}",
            if app.config.sandbox.process.enabled {
                "启用"
            } else {
                "停用"
            }
        ))
        .chain(std::iter::once(format!(
            "默认动作        {}",
            sandbox_action_label(app.config.sandbox.process.default.action)
        )))
        .chain(std::iter::once(format!(
            "出错动作        {}",
            sandbox_action_label(app.config.sandbox.process.error_action)
        )))
        .chain(app.config.sandbox.process.rules.iter().map(|r| {
            format!(
                "{} {}  优先级={}  {}",
                if r.enabled { "[x]" } else { "[ ]" },
                r.id,
                r.priority,
                sandbox_action_label(r.action)
            )
        }))
        .collect(),
        CATEGORY_FILES => std::iter::once(format!(
            "文件沙盒        {}",
            if app.config.sandbox.file.enabled {
                "启用"
            } else {
                "停用"
            }
        ))
        .chain(std::iter::once(format!(
            "默认动作        {}",
            sandbox_action_label(app.config.sandbox.file.default.action)
        )))
        .chain(std::iter::once(format!(
            "出错动作        {}",
            sandbox_action_label(app.config.sandbox.file.error_action)
        )))
        .chain(app.config.sandbox.file.rules.iter().map(|r| {
            format!(
                "{} {}  优先级={}  {}",
                if r.enabled { "[x]" } else { "[ ]" },
                r.id,
                r.priority,
                sandbox_action_label(r.action)
            )
        }))
        .collect(),
        CATEGORY_PROCESS => {
            if !app.live {
                vec!["Serve 未运行，暂无可观测的受管进程".into()]
            } else if app.managed_processes.is_empty() {
                vec!["暂无活跃的受管进程".into()]
            } else {
                app.managed_processes
                    .iter()
                    .map(|item| {
                        format!(
                            "PID {}  {}  hook={}  firewall=v{}  {}",
                            item.process.pid,
                            if item.process.root { "root" } else { "child" },
                            item.process.hook_status,
                            item.process.firewall_version,
                            item.process.executable
                        )
                    })
                    .collect()
            }
        }
        CATEGORY_ENVIRONMENT => nonempty(
            app.config
                .environment
                .iter()
                .map(|variable| {
                    let preview = environment_value_preview(variable);
                    if preview.is_empty() {
                        format!("{}: 空", variable.name)
                    } else {
                        format!("{}: {}", variable.name, preview)
                    }
                })
                .collect(),
        ),
        CATEGORY_CERTIFICATE => {
            let entries = app.root_certificate_cache.as_deref().unwrap_or_default();
            let mut lines = app
                .config
                .root_certificates
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let name = entries
                        .get(index)
                        .map(|entry| entry.name.clone())
                        .unwrap_or_else(|| {
                            hyperhub_core::certificate::short_fingerprint(&item.fingerprint)
                        });
                    let scope = item.host.as_deref().unwrap_or("全局根");
                    format!(
                        "{}  {}  {}",
                        name,
                        scope,
                        if item.enabled { "启用" } else { "停用" }
                    )
                })
                .collect::<Vec<_>>();
            lines.extend(app.config.ssh_host_keys.iter().map(|key| {
                format!(
                    "SSH  {}  {}  {}",
                    key.host,
                    key.key_type,
                    if key.enabled { "启用" } else { "停用" }
                )
            }));
            lines.push("提示：按 a 导入（证书文件 / https:// 主机 / ssh:// 主机）".into());
            nonempty(lines)
        }
    }
}

fn headers_for(app: &App, field: HeaderField) -> &std::collections::HashMap<String, SecretValue> {
    match field {
        HeaderField::Upstream(index) => &app.config.upstreams[index].headers,
        HeaderField::Credential(index) => {
            let idx = credential_plugin_index(&app.config, index);
            &app.config.plugins[idx].headers
        }
    }
}

fn sorted_header_names(app: &App, field: HeaderField) -> Vec<String> {
    let mut names = headers_for(app, field).keys().cloned().collect::<Vec<_>>();
    names.sort_by_key(|name| name.to_ascii_lowercase());
    names
}

fn nonempty(lines: Vec<String>) -> Vec<String> {
    if lines.is_empty() {
        vec!["（空，按 a 新增）".into()]
    } else {
        lines
    }
}

fn editor_lines(app: &App, editor: ObjectEditor) -> Vec<String> {
    match editor {
        ObjectEditor::DefaultRoute => vec![
            format!("ID                {}（内置，不可修改）", DEFAULT_ROUTE_ID),
            format!(
                "启用              {}",
                yes_no(app.config.default_route.enabled)
            ),
            format!(
                "动作              {}",
                rule_action_label(app.config.default_route.action, false)
            ),
            format!(
                "凭证              {}  （Enter 打开选择）",
                optional_summary(
                    default_plugin_id(
                        &app.config.default_route.plugins,
                        PluginKind::Credential,
                        &app.config,
                    )
                    .as_deref()
                )
            ),
            format!(
                "审计              {}  （Enter 打开选择）",
                optional_summary(
                    default_plugin_id(
                        &app.config.default_route.plugins,
                        PluginKind::Audit,
                        &app.config,
                    )
                    .as_deref()
                )
            ),
            format!(
                "智能防护          {}  （Enter 打开选择）",
                optional_summary(app.config.default_route.protection.as_deref())
            ),
        ],
        ObjectEditor::Upstream(index) => {
            let item = &app.config.upstreams[index];
            vec![
                format!("ID                {}", item.id),
                format!("代理类型          {:?}", item.kind),
                format!("地址              {}", item.address),
                format!("超时              {} ms", item.timeout_ms),
                format!(
                    "用户名            {}",
                    secret_summary(item.username.as_ref())
                ),
                format!(
                    "密码              {}",
                    secret_summary(item.password.as_ref())
                ),
                format!("CONNECT Headers   {}", header_summary(&item.headers)),
            ]
        }
        ObjectEditor::Credential(index) => {
            let item = &app.config.plugins[credential_plugin_index(&app.config, index)];
            let mut lines = vec![
                format!("ID                {}", item.id),
                format!(
                    "载体              {}",
                    if credential_carrier_is_http(item) {
                        "http"
                    } else {
                        "ssh"
                    }
                ),
            ];
            if credential_carrier_is_http(item) {
                let scheme = item.http_scheme.unwrap_or(HttpAuthScheme::CustomHeaders);
                lines.push(format!("鉴权方式          {}", http_scheme_name(scheme)));
                match scheme {
                    HttpAuthScheme::Basic => {
                        lines.push(format!(
                            "用户名            {}",
                            optional_summary(item.username.as_deref())
                        ));
                        lines.push(format!(
                            "密码              {}",
                            secret_summary(item.password.as_ref())
                        ));
                    }
                    HttpAuthScheme::Bearer | HttpAuthScheme::XApiKey => lines.push(format!(
                        "鉴权值            {}",
                        secret_summary(item.secret.as_ref())
                    )),
                    HttpAuthScheme::Token => {
                        lines.push(format!(
                            "令牌用户名        {}",
                            optional_summary(item.username.as_deref())
                        ));
                        lines.push(format!(
                            "令牌              {}",
                            secret_summary(item.secret.as_ref())
                        ));
                    }
                    HttpAuthScheme::LegacyScopedToken => {
                        lines.push("旧鉴权方式        已移除，请切换为令牌".into());
                    }
                    HttpAuthScheme::Cookie | HttpAuthScheme::QueryParameter => {
                        lines.push(format!(
                            "{}名称          {}",
                            if scheme == HttpAuthScheme::Cookie {
                                "Cookie"
                            } else {
                                "Query 参数"
                            },
                            optional_summary(item.http_name.as_deref())
                        ));
                        lines.push(format!(
                            "鉴权值            {}",
                            secret_summary(item.secret.as_ref())
                        ));
                    }
                    HttpAuthScheme::CustomHeaders => {}
                }
                if scheme != HttpAuthScheme::LegacyScopedToken {
                    lines.push(format!(
                        "自定义 Headers    {}  （Enter 添加/修改）",
                        header_summary(&item.headers)
                    ));
                }
            } else {
                lines.push(format!(
                    "SSH 账号          {} 个  （Enter 管理）",
                    item.ssh_accounts.len()
                ));
            }
            lines
        }
        ObjectEditor::AuditProfile(index) => {
            let item = &app.config.plugins[audit_plugin_index(&app.config, index)];
            vec![
                format!("ID                {}", item.id),
                format!(
                    "HTTP 事件审计      {}",
                    mark(has_protocol(item, PluginProtocol::Http))
                ),
                format!(
                    "HTTP 内容转录      {}",
                    mark(item.http_transcript_enabled())
                ),
                format!(
                    "WS 事件审计        {}",
                    mark(has_protocol(item, PluginProtocol::Ws))
                ),
                format!(
                    "WS 内容转录        {}",
                    websocket_transcript_label(item.websocket_capture)
                ),
                format!(
                    "Git 事件审计       {}",
                    mark(has_protocol(item, PluginProtocol::Git))
                ),
                format!("Git 内容转录       {}", mark(item.git_transcript_enabled())),
                format!(
                    "SSH 事件审计       {}",
                    mark(has_protocol(item, PluginProtocol::Ssh))
                ),
                format!("SSH 内容转录       {}", mark(item.ssh_transcript)),
                format!("转录客户端上传     {}", mark(item.transcript_client_upload)),
                format!(
                    "转录服务端响应     {}",
                    mark(item.transcript_server_response)
                ),
                format!("单项转录上限      {} 字节", item.body_limit),
            ]
        }
        ObjectEditor::Protection(index) => {
            let item = &app.config.protections[index];
            let scans = [
                item.data.detect_managed_secrets,
                item.data.detect_known_tokens,
                item.data.detect_private_keys,
                item.data.detect_prompt_injection,
            ]
            .into_iter()
            .filter(|enabled| *enabled)
            .count();
            let provider = item.intelligence.provider.as_ref();
            vec![
                format!("ID                {}", item.id),
                format!("总开关            {}", yes_no(item.enabled)),
                format!("执行策略          {}", protection_mode_label(item.mode)),
                format!(
                    "本地检测          {} · {scans}/4 扫描策略  （Enter 打开）",
                    if item.data.enabled {
                        "已开启"
                    } else {
                        "已关闭"
                    }
                ),
                format!(
                    "智能判断          {} · {}  （Enter 打开）",
                    if item.intelligence.enabled {
                        "已开启"
                    } else {
                        "已关闭"
                    },
                    provider
                        .map(|provider| format!(
                            "{:?} / {}",
                            provider.provider,
                            provider.model.as_deref().unwrap_or("官方默认")
                        ))
                        .unwrap_or_else(|| "未配置 Provider".into())
                ),
            ]
        }
        ObjectEditor::ProtectionLocal(index) => {
            let data = &app.config.protections[index].data;
            vec![
                format!("启用本地检测      {}", yes_no(data.enabled)),
                format!("最大扫描字节      {}", data.max_scan_bytes),
                format!("来源追踪窗口      {} 字节", data.provenance_window_bytes),
                format!("来源命中阈值      {}", data.provenance_min_matches),
                format!("{} 扫描托管 Secret", checkbox(data.detect_managed_secrets)),
                format!("{} 扫描常见 Token", checkbox(data.detect_known_tokens)),
                format!("{} 扫描私钥", checkbox(data.detect_private_keys)),
                format!("{} 扫描提示注入", checkbox(data.detect_prompt_injection)),
            ]
        }
        ObjectEditor::ProtectionIntelligence(index) => {
            let intelligence = &app.config.protections[index].intelligence;
            let provider = intelligence.provider.as_ref();
            vec![
                format!("启用智能判断      {}", yes_no(intelligence.enabled)),
                format!(
                    "Provider 类型     {:?}",
                    provider
                        .map(|p| p.provider)
                        .unwrap_or(IntelligenceProviderKind::Typesafe)
                ),
                format!(
                    "Endpoint          {}",
                    optional_summary(provider.and_then(|p| p.endpoint.as_deref()))
                ),
                format!(
                    "Model             {}",
                    optional_summary(provider.and_then(|p| p.model.as_deref()))
                ),
                format!(
                    "API Key           {}",
                    secret_summary(provider.and_then(|p| p.api_key.as_ref()))
                ),
                format!("判定超时          {} ms", intelligence.timeout_ms),
                format!("最低置信度        {:.2}", intelligence.min_confidence),
                format!("缓存时间          {} ms", intelligence.cache_ttl_ms),
                format!(
                    "服务异常时        {}",
                    protection_action_label(intelligence.error_action)
                ),
                format!(
                    "低置信度时        {}",
                    protection_action_label(intelligence.low_confidence_action)
                ),
            ]
        }
        ObjectEditor::Route(index) => {
            let item = &app.config.rules[index];
            vec![
                format!("ID                {}", item.id),
                format!("启用              {}", yes_no(item.enabled)),
                format!("优先级            {}", item.priority),
                format!("目标              {}", route_targets_summary(item)),
                format!(
                    "动作              {}",
                    rule_action_label(item.action, item.upstream.is_some())
                ),
                format!(
                    "代理              {}  （Enter 打开选择）",
                    optional_summary(item.upstream.as_deref())
                ),
                format!(
                    "凭证              {}  （Enter 打开选择）",
                    optional_summary(
                        item.plugins
                            .iter()
                            .find(|id| {
                                app.config
                                    .plugin(id)
                                    .is_some_and(|plugin| plugin.kind == PluginKind::Credential)
                            })
                            .map(|id| id.as_str())
                    )
                ),
                format!(
                    "审计              {}  （Enter 打开选择）",
                    optional_summary(
                        item.plugins
                            .iter()
                            .find(|id| {
                                app.config
                                    .plugin(id)
                                    .is_some_and(|plugin| plugin.kind == PluginKind::Audit)
                            })
                            .map(|id| id.as_str())
                    )
                ),
                format!(
                    "智能防护          {}  （Enter 打开选择）",
                    optional_summary(item.protection.as_deref())
                ),
                format!("允许敏感上传      {}", yes_no(item.allow_sensitive_upload)),
            ]
        }
        ObjectEditor::FirewallRule(index) => {
            let item = &app.config.firewall.rules[index];
            let mut lines = vec![
                format!("ID                {}", item.id),
                format!("启用              {}", yes_no(item.enabled)),
                format!("优先级            {}", item.priority),
                format!("动作              {}", firewall_action_label(item.action)),
                format!(
                    "智能防护          {}  （Enter 打开选择）",
                    optional_summary(item.protection.as_deref())
                ),
            ];
            lines.extend(item.endpoints.iter().map(|endpoint| {
                format!(
                    "绑定              {}:{}",
                    endpoint.target,
                    endpoint
                        .port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "*".into())
                )
            }));
            lines
        }
        ObjectEditor::SandboxProcessRule(i) => {
            let r = &app.config.sandbox.process.rules[i];
            let mut lines = vec![
                format!("ID                {}", r.id),
                format!("启用              {}", yes_no(r.enabled)),
                format!("优先级            {}", r.priority),
                format!("动作              {}", sandbox_action_label(r.action)),
                format!(
                    "智能防护          {}  （Enter 打开选择）",
                    optional_summary(r.protection.as_deref())
                ),
            ];
            lines.extend(r.patterns.iter().map(|p| {
                format!(
                    "{} 正则          exe={}  cmd={}",
                    if p.enabled { "[x]" } else { "[ ]" },
                    if p.executable.is_empty() {
                        "*"
                    } else {
                        &p.executable
                    },
                    if p.command_line.is_empty() {
                        "*"
                    } else {
                        &p.command_line
                    }
                )
            }));
            lines
        }
        ObjectEditor::FileSandboxRule(i) => {
            let r = &app.config.sandbox.file.rules[i];
            let has = |o| yes_no(r.operations.contains(&o));
            let mut lines = vec![
                format!("ID                {}", r.id),
                format!("启用              {}", yes_no(r.enabled)),
                format!("优先级            {}", r.priority),
                format!("动作              {}", sandbox_action_label(r.action)),
                format!("读取              {}", has(FileSandboxOperation::Read)),
                format!("写入              {}", has(FileSandboxOperation::Write)),
                format!("创建              {}", has(FileSandboxOperation::Create)),
                format!("删除              {}", has(FileSandboxOperation::Delete)),
                format!("重命名            {}", has(FileSandboxOperation::Rename)),
                format!(
                    "智能防护          {}  （Enter 打开选择）",
                    optional_summary(r.protection.as_deref())
                ),
            ];
            lines.extend(r.patterns.iter().map(|p| {
                format!(
                    "{} 路径正则      {}",
                    if p.enabled { "[x]" } else { "[ ]" },
                    p.pattern
                )
            }));
            lines
        }
        ObjectEditor::RootCertificate(index) => {
            let item = &app.config.root_certificates[index];
            let mut lines = vec![
                format!(
                    "信任范围          {}",
                    item.host.as_deref().unwrap_or("全局根证书")
                ),
                format!("指纹              {}", item.fingerprint),
                format!("启用              {}", yes_no(item.enabled)),
            ];
            match app
                .root_certificate_cache
                .as_deref()
                .and_then(|entries| entries.get(index))
            {
                Some(entry) => {
                    lines.push("── 证书信息 ────────────────".into());
                    lines.extend(entry.summary.lines().map(str::to_owned));
                }
                None => lines.push("证书信息        （无法读取）".into()),
            }
            lines
        }
    }
}

fn http_scheme_name(scheme: HttpAuthScheme) -> &'static str {
    match scheme {
        HttpAuthScheme::Basic => "Basic",
        HttpAuthScheme::Bearer => "Bearer",
        HttpAuthScheme::Token => "令牌（自动）",
        HttpAuthScheme::LegacyScopedToken => "已移除鉴权方式",
        HttpAuthScheme::XApiKey => "X-API-Key",
        HttpAuthScheme::Cookie => "Cookie",
        HttpAuthScheme::QueryParameter => "Query 参数",
        HttpAuthScheme::CustomHeaders => "仅自定义 Header",
    }
}

fn detail_title(app: &App) -> String {
    if let Some(editor) = app.list_editor {
        return match editor.kind {
            ListEditorKind::RouteTargets(route) => {
                format!("网关 / 路由 / {} / 目标", app.config.rules[route].id)
            }
            ListEditorKind::FirewallTargets(rule) => {
                format!(
                    "沙盒 / 网络 / {} / 目标",
                    app.config.firewall.rules[rule].id
                )
            }
            ListEditorKind::FirewallPorts(rule) => {
                format!(
                    "沙盒 / 网络 / {} / 端口",
                    app.config.firewall.rules[rule].id
                )
            }
            ListEditorKind::FilePaths(rule) => {
                format!(
                    "沙盒 / 文件 / {} / 路径",
                    app.config.sandbox.file.rules[rule].id
                )
            }
            ListEditorKind::SandboxExecutables(rule) => format!(
                "沙盒 / 子进程 / {} / 可执行文件",
                app.config.sandbox.process.rules[rule].id
            ),
            ListEditorKind::SandboxCommandLines(rule) => format!(
                "沙盒 / 子进程 / {} / 命令行",
                app.config.sandbox.process.rules[rule].id
            ),
        };
    }
    if let Some(editor) = app.header_editor {
        return match editor.field {
            HeaderField::Upstream(index) => {
                format!("网关 / 代理 / {} / Headers", app.config.upstreams[index].id)
            }
            HeaderField::Credential(index) => {
                let idx = credential_plugin_index(&app.config, index);
                format!("网关 / 凭证 / {} / Headers", app.config.plugins[idx].id)
            }
        };
    }
    if let Some(editor) = app.ssh_key_editor {
        let idx = credential_plugin_index(&app.config, editor.credential);
        let plugin = &app.config.plugins[idx];
        let username = &plugin.ssh_accounts[editor.account].username;
        return format!("网关 / 凭证 / {} / {} / 私钥", plugin.id, username);
    }
    if let Some(editor) = app.ssh_password_editor {
        let idx = credential_plugin_index(&app.config, editor.credential);
        let plugin = &app.config.plugins[idx];
        let username = &plugin.ssh_accounts[editor.account].username;
        return format!("网关 / 凭证 / {} / {} / 密码", plugin.id, username);
    }
    if let Some(detail) = app.ssh_account_detail {
        let idx = credential_plugin_index(&app.config, detail.credential);
        let plugin = &app.config.plugins[idx];
        let username = &plugin.ssh_accounts[detail.account].username;
        return format!("网关 / 凭证 / {} / {}", plugin.id, username);
    }
    if let Some(editor) = app.ssh_account_editor {
        let idx = credential_plugin_index(&app.config, editor.credential);
        return format!("网关 / 凭证 / {} / SSH 账号", app.config.plugins[idx].id);
    }
    match app.editor {
        Some(ObjectEditor::DefaultRoute) => {
            format!("网关 / 路由 / {}（内置兜底）", DEFAULT_ROUTE_ID)
        }
        Some(ObjectEditor::Upstream(index)) => {
            format!("网关 / 代理 / {}", app.config.upstreams[index].id)
        }
        Some(ObjectEditor::Credential(index)) => {
            let idx = credential_plugin_index(&app.config, index);
            format!("网关 / 凭证 / {}", app.config.plugins[idx].id)
        }
        Some(ObjectEditor::AuditProfile(index)) => {
            let idx = audit_plugin_index(&app.config, index);
            format!("网关 / 审计 / {}", app.config.plugins[idx].id)
        }
        Some(ObjectEditor::Protection(index)) => {
            format!("智能防护 / {}", app.config.protections[index].id)
        }
        Some(ObjectEditor::ProtectionLocal(index)) => {
            format!("智能防护 / {} / 本地检测", app.config.protections[index].id)
        }
        Some(ObjectEditor::ProtectionIntelligence(index)) => {
            format!("智能防护 / {} / 智能判断", app.config.protections[index].id)
        }
        Some(ObjectEditor::Route(index)) => {
            format!("网关 / 路由 / {}", app.config.rules[index].id)
        }
        Some(ObjectEditor::FirewallRule(index)) => {
            format!("沙盒 / 网络 / {}", app.config.firewall.rules[index].id)
        }
        Some(ObjectEditor::SandboxProcessRule(i)) => {
            format!("沙盒 / 子进程 / {}", app.config.sandbox.process.rules[i].id)
        }
        Some(ObjectEditor::FileSandboxRule(i)) => {
            format!("沙盒 / 文件 / {}", app.config.sandbox.file.rules[i].id)
        }
        Some(ObjectEditor::RootCertificate(index)) => {
            format!(
                "网关 / 证书 / {}",
                hyperhub_core::certificate::short_fingerprint(
                    &app.config.root_certificates[index].fingerprint
                )
            )
        }
        None => app.category.breadcrumb(),
    }
}

fn optional_summary(value: Option<&str>) -> &str {
    value.filter(|value| !value.is_empty()).unwrap_or("未设置")
}

fn firewall_action_label(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Pass => "放行",
        FirewallAction::Deny => "阻断",
        FirewallAction::Smart => "智能防护",
    }
}

fn firewall_default_label(default: Option<&FirewallDefaultRule>) -> &'static str {
    default
        .map(|rule| firewall_action_label(rule.action))
        .unwrap_or("放行")
}

fn sandbox_action_label(action: SandboxAction) -> &'static str {
    match action {
        SandboxAction::Pass => "放行",
        SandboxAction::Deny => "阻断",
        SandboxAction::Smart => "智能防护",
    }
}

fn enforcement_mode_label(mode: EnforcementMode) -> &'static str {
    match mode {
        EnforcementMode::Enforce => "失败关闭",
        EnforcementMode::Observe => "失败放行",
    }
}

fn protection_mode_label(mode: ProtectionMode) -> &'static str {
    match mode {
        ProtectionMode::Observe => "仅记录",
        ProtectionMode::Enforce => "自动阻断",
    }
}

fn protection_action_label(action: ProtectionAction) -> &'static str {
    match action {
        ProtectionAction::Pass => "放行",
        ProtectionAction::Deny => "阻断",
    }
}

fn opposite_protection_action(action: ProtectionAction) -> ProtectionAction {
    match action {
        ProtectionAction::Pass => ProtectionAction::Deny,
        ProtectionAction::Deny => ProtectionAction::Pass,
    }
}

fn checkbox(enabled: bool) -> &'static str {
    if enabled {
        "[x]"
    } else {
        "[ ]"
    }
}

fn rule_action_label(action: RuleAction, has_upstream: bool) -> &'static str {
    match action {
        RuleAction::Pass => {
            if has_upstream {
                "代理"
            } else {
                "放行"
            }
        }
        RuleAction::Deny => "阻断",
        RuleAction::Smart => "智能防护",
    }
}

fn cycle_rule_action(action: RuleAction) -> RuleAction {
    match action {
        RuleAction::Pass => RuleAction::Deny,
        RuleAction::Deny => RuleAction::Smart,
        RuleAction::Smart => RuleAction::Pass,
    }
}

fn opposite_sandbox_action(action: SandboxAction) -> SandboxAction {
    match action {
        SandboxAction::Deny => SandboxAction::Pass,
        _ => SandboxAction::Deny,
    }
}

fn cycle_sandbox_action(action: SandboxAction) -> SandboxAction {
    match action {
        SandboxAction::Pass => SandboxAction::Deny,
        SandboxAction::Deny => SandboxAction::Smart,
        SandboxAction::Smart => SandboxAction::Pass,
    }
}

fn opposite_firewall_action(action: FirewallAction) -> FirewallAction {
    match action {
        FirewallAction::Deny => FirewallAction::Pass,
        _ => FirewallAction::Deny,
    }
}

fn cycle_firewall_action(action: FirewallAction) -> FirewallAction {
    match action {
        FirewallAction::Pass => FirewallAction::Deny,
        FirewallAction::Deny => FirewallAction::Smart,
        FirewallAction::Smart => FirewallAction::Pass,
    }
}

fn cycle_firewall_default(default: &mut Option<FirewallDefaultRule>) {
    *default = Some(FirewallDefaultRule {
        action: match default.as_ref().map(|rule| rule.action) {
            Some(FirewallAction::Pass) | None => FirewallAction::Deny,
            Some(FirewallAction::Deny) | Some(FirewallAction::Smart) => FirewallAction::Pass,
        },
    });
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "是"
    } else {
        "否"
    }
}

fn route_targets_summary(route: &RouteRule) -> String {
    if !route.endpoints.is_empty() {
        return route
            .endpoints
            .iter()
            .map(|endpoint| match endpoint.port {
                Some(port) => format!("{}:{port}", endpoint.target),
                None => endpoint.target.clone(),
            })
            .collect::<Vec<_>>()
            .join(", ");
    }
    "不限".into()
}

#[allow(dead_code)]
fn join_or_none<T: std::fmt::Display>(values: &[T]) -> String {
    if values.is_empty() {
        "未设置".into()
    } else {
        join_display(values)
    }
}

fn secret_summary(secret: Option<&SecretValue>) -> String {
    match secret {
        None => "未设置".into(),
        Some(_) => "••••••（已设置）".into(),
    }
}

/// 环境变量值预览：空值显示为空，内联值掩码中间部分，引用值显示来源。
fn environment_value_preview(variable: &EnvironmentVariable) -> String {
    match &variable.value {
        SecretValue::Inline { value } => mask_middle(value),
        SecretValue::Env { env, .. } => format!("${{{env}}}"),
        SecretValue::File { file, .. } => format!("文件:{}", file.display()),
    }
}

/// 保留首尾少量字符，中间用 `••••••` 掩码；空值原样返回。
fn mask_middle(value: &str) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.is_empty() {
        return String::new();
    }
    let visible = if chars.len() <= 8 {
        (chars.len() / 3).clamp(1, 2)
    } else {
        4
    };
    let tail_len = visible.min(chars.len().saturating_sub(visible + 1));
    let head = chars[..visible].iter().collect::<String>();
    let tail = chars[chars.len() - tail_len..].iter().collect::<String>();
    format!("{head}••••••{tail}")
}

fn header_summary(headers: &std::collections::HashMap<String, SecretValue>) -> String {
    if headers.is_empty() {
        return "未设置".into();
    }
    let mut names = headers.keys().cloned().collect::<Vec<_>>();
    names.sort_unstable();
    names.join(", ")
}

fn object_editor_hint(editor: ObjectEditor) -> String {
    match editor {
        ObjectEditor::DefaultRoute => {
            "默认路由：内置兜底，配置启用状态、拒绝动作与直通".to_string()
        }
        ObjectEditor::Upstream(_) => "代理：配置 ID、类型、地址与超时".to_string(),
        ObjectEditor::Credential(_) => "凭证：配置 HTTP 认证或 SSH 账号".to_string(),
        ObjectEditor::AuditProfile(_) => "审计插件：配置事件范围与内容转录".to_string(),
        ObjectEditor::Protection(_) => {
            "智能防护概览：配置总开关、执行策略并进入功能模块".to_string()
        }
        ObjectEditor::ProtectionLocal(_) => {
            "本地检测：Space 启停扫描策略，Enter 编辑数值".to_string()
        }
        ObjectEditor::ProtectionIntelligence(_) => {
            "智能判断：配置单一 Provider、缓存和失败动作".to_string()
        }
        ObjectEditor::Route(_) => "路由：配置优先级、目标与动作".to_string(),
        ObjectEditor::FirewallRule(_) => "网络规则：配置优先级、动作、目标与端口".to_string(),
        ObjectEditor::SandboxProcessRule(_) => "子进程沙盒规则".into(),
        ObjectEditor::FileSandboxRule(_) => "文件沙盒规则与操作权限".into(),
        ObjectEditor::RootCertificate(_) => "证书：配置启用状态与指纹".to_string(),
    }
}

fn selection_hint(app: &App) -> Option<String> {
    if app.modal.is_some() || app.help || app.exit_prompt {
        return None;
    }

    if app.ssh_key_add_picker.is_some() {
        return Some("选择私钥导入方式".to_string());
    }
    if app.reference_picker.is_some() {
        return Some("选择引用目标".to_string());
    }
    if app.ssh_key_preview.is_some() {
        return Some("公钥预览".to_string());
    }
    if app.list_editor.is_some() {
        return Some("列表：a 添加，Enter/e 修改，d 删除，Esc 返回".to_string());
    }
    if app.header_editor.is_some() {
        return Some("Header 列表：添加、修改值或删除".to_string());
    }
    if app.ssh_key_editor.is_some() {
        return Some("私钥列表：预览、复制公钥、重命名或删除".to_string());
    }
    if app.ssh_password_editor.is_some() {
        return Some("密码列表：添加、修改或删除密码".to_string());
    }
    if app.ssh_account_detail.is_some() {
        return Some("SSH 账号详情：选择私钥或密码条目".to_string());
    }
    if app.ssh_account_editor.is_some() {
        return Some("SSH 账号列表：管理账号、私钥与密码".to_string());
    }
    if let Some(editor) = app.editor {
        return Some(object_editor_hint(editor));
    }

    if matches!(app.focus, Focus::Sidebar) {
        return Some(match app.category {
            CATEGORY_GATEWAY => "网关：代理、凭证、审计、路由和证书能力概览".to_string(),
            CATEGORY_BASIC => "基础：监听地址、网关故障策略与 Debug 热更新".to_string(),
            CATEGORY_PROXY => "代理：上游代理列表，供路由规则引用".to_string(),
            CATEGORY_CREDENTIAL => "凭证：HTTP 凭证与 SSH 账号、私钥、密码".to_string(),
            CATEGORY_AUDIT => "审计：保留策略与事件转录插件".to_string(),
            CATEGORY_PROTECTION => "智能防护：本地数据保护与 Jev 动作判定".to_string(),
            CATEGORY_ROUTE => "路由：默认路由与用户路由规则".to_string(),
            CATEGORY_FIREWALL => "沙盒 / 网络：Agent 出站域名、IP/CIDR 与端口规则".to_string(),
            CATEGORY_SANDBOX => "沙盒：网络、文件与子进程沙盒能力概览".to_string(),
            CATEGORY_SANDBOX_PROCESS => "沙盒 / 子进程：控制子程序创建".to_string(),
            CATEGORY_FILES => "沙盒 / 文件：控制文件访问权限".to_string(),
            CATEGORY_PROCESS => "进程：活跃受管进程观测".to_string(),
            CATEGORY_CERTIFICATE => "证书：根证书与 SSH 主机密钥".to_string(),
            CATEGORY_ENVIRONMENT => "环境变量：注入目标进程的环境变量".to_string(),
        });
    }

    match app.category {
        CATEGORY_GATEWAY => Some("网关概览：显示 Serve 与网关配置摘要".to_string()),
        CATEGORY_BASIC => match app.field {
            0 => Some(match app.config.mode {
                EnforcementMode::Enforce => "失败关闭：网关异常时拒绝".to_string(),
                EnforcementMode::Observe => "失败放行：网关异常时直连兜底".to_string(),
            }),
            1 => Some(format!(
                "SOCKS5 监听地址：{}",
                app.config.listener.socks_listen
            )),
            2 => Some(format!(
                "待激活会话有效期：{} 秒",
                app.config.listener.pending_session_ttl_secs
            )),
            3 => Some(format!(
                "调试事件：{}，保存后热更新运行中的 Serve",
                if app.config.debug { "开启" } else { "关闭" }
            )),
            _ => None,
        },
        CATEGORY_PROXY => {
            if app.field < app.config.upstreams.len() {
                let item = &app.config.upstreams[app.field];
                Some(format!(
                    "代理 {}（UUID={}）：{:?} {}，超时 {} ms",
                    item.id, item.uuid, item.kind, item.address, item.timeout_ms
                ))
            } else {
                Some("暂无代理，按 a 新增".to_string())
            }
        }
        CATEGORY_CREDENTIAL => {
            let indices = credential_plugin_indices(&app.config);
            if app.field < indices.len() {
                let idx = indices[app.field];
                let plugin = &app.config.plugins[idx];
                if credential_carrier_is_http(plugin) {
                    let count = plugin.headers.len()
                        + usize::from(plugin.secret.is_some())
                        + usize::from(plugin.password.is_some())
                        + usize::from(plugin.username.is_some());
                    Some(format!(
                        "HTTP 凭证 {}（UUID={}）：{} 个 Secret",
                        plugin.id, plugin.uuid, count
                    ))
                } else {
                    Some(format!(
                        "SSH 凭证 {}（UUID={}）：{} 个账号",
                        plugin.id,
                        plugin.uuid,
                        plugin.ssh_accounts.len()
                    ))
                }
            } else {
                Some("暂无凭证，按 a 新增".to_string())
            }
        }
        CATEGORY_AUDIT => {
            if app.field == 0 {
                let retention = if app.config.audit.retention_days == 0 {
                    "永久".to_string()
                } else {
                    app.config.audit.retention_days.to_string()
                };
                Some(format!("审计保留天数：{retention}"))
            } else {
                let indices = audit_plugin_indices(&app.config);
                let field = app.field - 1;
                if field < indices.len() {
                    let idx = indices[field];
                    let plugin = &app.config.plugins[idx];
                    let protocols = plugin
                        .protocols
                        .iter()
                        .map(|protocol| audit_protocol_label(*protocol))
                        .collect::<Vec<_>>()
                        .join(",");
                    Some(format!(
                        "审计插件 {}（UUID={}）：事件={protocols}，内容转录={}",
                        plugin.id,
                        plugin.uuid,
                        audit_transcript_summary(plugin)
                    ))
                } else {
                    Some("按 a 增加审计插件".to_string())
                }
            }
        }
        CATEGORY_PROTECTION => app
            .config
            .protections
            .get(app.field)
            .map(|item| {
                format!(
                    "智能防护 {}（UUID={}）：执行策略={}，本地检测={}，智能判断={}",
                    item.id,
                    item.uuid,
                    protection_mode_label(item.mode),
                    yes_no(item.data.enabled),
                    yes_no(item.intelligence.enabled)
                )
            })
            .or_else(|| Some("暂无智能防护，按 a 新增".to_string())),
        CATEGORY_ROUTE => {
            if app.field == 0 {
                let default = &app.config.default_route;
                Some(format!(
                    "默认路由 {}：内置兜底，{}",
                    DEFAULT_ROUTE_ID,
                    rule_action_label(default.action, false)
                ))
            } else {
                let field = app.field - 1;
                if field < app.config.rules.len() {
                    let rule = &app.config.rules[field];
                    let action = rule_action_label(rule.action, rule.upstream.is_some());
                    Some(format!(
                        "路由 {}（UUID={}）：优先级={}，{action}，目标={}",
                        rule.id,
                        rule.uuid,
                        rule.priority,
                        route_targets_summary(rule)
                    ))
                } else {
                    Some("暂无用户路由，按 a 新增".to_string())
                }
            }
        }
        CATEGORY_FIREWALL => {
            if app.field == 0 {
                Some(format!(
                    "网络沙盒：{}；未启用时全部放行",
                    if app.config.firewall.enabled {
                        "启用"
                    } else {
                        "停用"
                    }
                ))
            } else if app.field == 1 {
                Some(format!(
                    "默认动作：{}；未配置时为放行",
                    firewall_default_label(app.config.firewall.default.as_ref())
                ))
            } else if app.field == 2 {
                Some(format!(
                    "出错动作：{}",
                    firewall_action_label(app.config.firewall.error_action)
                ))
            } else {
                let index = app.field - 3;
                if let Some(rule) = app.config.firewall.rules.get(index) {
                    Some(format!(
                        "网络规则 {}（UUID={}）：优先级={}，{}，绑定={} 条",
                        rule.id,
                        rule.uuid,
                        rule.priority,
                        firewall_action_label(rule.action),
                        rule.endpoints.len()
                    ))
                } else {
                    Some("暂无网络规则，按 a 新增".to_string())
                }
            }
        }
        CATEGORY_SANDBOX => Some(format!(
            "沙盒概览：网络 {} 条、文件 {} 条、子进程 {} 条规则",
            app.config.firewall.rules.len(),
            app.config.sandbox.file.rules.len(),
            app.config.sandbox.process.rules.len()
        )),
        CATEGORY_SANDBOX_PROCESS => {
            if app.field == 0 {
                Some("子进程沙盒总开关".into())
            } else if app.field == 1 {
                Some(format!(
                    "默认动作：{}",
                    sandbox_action_label(app.config.sandbox.process.default.action)
                ))
            } else if app.field == 2 {
                Some(format!(
                    "出错动作：{}",
                    sandbox_action_label(app.config.sandbox.process.error_action)
                ))
            } else {
                app.config
                    .sandbox
                    .process
                    .rules
                    .get(app.field - 3)
                    .map(|r| {
                        format!(
                            "子进程规则 {}（UUID={}）：{}",
                            r.id,
                            r.uuid,
                            sandbox_action_label(r.action)
                        )
                    })
                    .or_else(|| Some("暂无规则，按 a 新增".into()))
            }
        }
        CATEGORY_FILES => {
            if app.field == 0 {
                Some("文件沙盒总开关".into())
            } else if app.field == 1 {
                Some(format!(
                    "默认动作：{}",
                    sandbox_action_label(app.config.sandbox.file.default.action)
                ))
            } else if app.field == 2 {
                Some(format!(
                    "出错动作：{}",
                    sandbox_action_label(app.config.sandbox.file.error_action)
                ))
            } else {
                app.config
                    .sandbox
                    .file
                    .rules
                    .get(app.field - 3)
                    .map(|r| {
                        format!(
                            "文件规则 {}（UUID={}）：{}",
                            r.id,
                            r.uuid,
                            sandbox_action_label(r.action)
                        )
                    })
                    .or_else(|| Some("暂无规则，按 a 新增".into()))
            }
        }
        CATEGORY_PROCESS => {
            if let Some(item) = app.managed_processes.get(app.field) {
                Some(format!(
                    "PID {}：{}，session={}，Hook={}，Firewall 快照版本={}",
                    item.process.pid,
                    if item.process.root {
                        "根进程"
                    } else {
                        "子进程"
                    },
                    item.session_id,
                    item.process.hook_status,
                    item.process.firewall_version
                ))
            } else if app.live {
                Some("暂无活跃的受管进程；列表每秒刷新".to_string())
            } else {
                Some("Serve 未运行".to_string())
            }
        }
        CATEGORY_CERTIFICATE => {
            let cert_count = app.config.root_certificates.len();
            if app.field < cert_count {
                let item = &app.config.root_certificates[app.field];
                let name = app
                    .root_certificate_cache
                    .as_deref()
                    .and_then(|entries| entries.get(app.field))
                    .map(|entry| entry.name.as_str())
                    .unwrap_or("证书");
                Some(format!(
                    "根证书 {name}（UUID={}）：{}",
                    item.uuid,
                    if item.enabled { "启用" } else { "停用" }
                ))
            } else {
                let key_index = app.field - cert_count;
                if key_index < app.config.ssh_host_keys.len() {
                    let key = &app.config.ssh_host_keys[key_index];
                    Some(format!(
                        "SSH 主机密钥 {}（UUID={}）：{} {}",
                        key.host,
                        key.uuid,
                        key.key_type,
                        if key.enabled { "启用" } else { "停用" }
                    ))
                } else {
                    Some("按 a 导入证书或 SSH 主机密钥".to_string())
                }
            }
        }
        CATEGORY_ENVIRONMENT => {
            if app.field < app.config.environment.len() {
                let variable = &app.config.environment[app.field];
                let preview = environment_value_preview(variable);
                Some(format!(
                    "环境变量 {}（UUID={}）：{}",
                    variable.name,
                    variable.uuid,
                    if preview.is_empty() {
                        "空".to_string()
                    } else {
                        preview
                    }
                ))
            } else {
                Some("暂无环境变量，按 a 新增".to_string())
            }
        }
    }
}
fn sidebar_node_style(node: NavNode) -> Style {
    if node.is_group() {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    }
}

fn shortcut_text(app: &App) -> &'static str {
    if app.reference_picker.is_some() {
        " [↑↓/jk]选择 [Enter/Space]应用 [Esc]取消 [?]帮助"
    } else if app.list_editor.is_some() {
        " [a]添加 [Enter/e]修改 [d]删除 [Esc]返回 [?]帮助"
    } else if app.header_editor.is_some() {
        " [a]添加 [Enter/e]修改值 [d]删除 [Esc]返回 [?]帮助"
    } else if app.ssh_key_editor.is_some() {
        " [a]添加 [Enter/e]预览 [c]复制公钥 [r]重命名 [d]删除 [Esc]返回 [?]帮助"
    } else if app.ssh_password_editor.is_some() {
        " [a]添加 [Enter/e]修改 [d]删除 [Esc]返回 [?]帮助"
    } else if app.ssh_account_detail.is_some() {
        " [↑↓/jk]选择 [Enter/e]编辑 [Esc]返回 [?]帮助"
    } else if app.ssh_account_editor.is_some() {
        " [a]添加 [Enter/e]详情 [r]改名 [d]删除 [Esc]返回 [?]帮助"
    } else if matches!(
        app.editor,
        Some(
            ObjectEditor::FirewallRule(_)
                | ObjectEditor::SandboxProcessRule(_)
                | ObjectEditor::FileSandboxRule(_)
        )
    ) {
        " [a]添加子项 [Space]启停 [Enter/e]编辑 [d]删除 [Esc]返回"
    } else if app.editor.is_some() {
        " [Enter/e]编辑或切换 [Space]切换 [Esc]返回 [Ctrl+S]保存 [?]帮助"
    } else if matches!(app.focus, Focus::Sidebar) {
        " [↑↓/jk]选择 [Tab]详情 [Esc/q]退出 [?]帮助"
    } else if app.category == CATEGORY_ROUTE && app.field == 0 {
        " [Space]启停 [Enter/e]编辑 [a]新增 [Esc]分类 [/]搜索 [?]帮助"
    } else if app.category == CATEGORY_ROUTE {
        " [Space]启停 [Enter/e]编辑 [a]新增 [d]删除 [Esc]分类 [/]搜索 [?]帮助"
    } else if app.category == CATEGORY_FIREWALL && app.field < 3 {
        " [Space]切换 [a]新增规则 [Esc]分类 [/]搜索 [?]帮助"
    } else if app.category == CATEGORY_FIREWALL {
        " [Space]启停 [Enter/e]编辑 [a]新增 [d]删除 [Esc]分类 [/]搜索 [?]帮助"
    } else if app.category == CATEGORY_PROCESS {
        " [r]刷新 [Esc]分类 [/]搜索 [?]帮助"
    } else if matches!(app.category, CATEGORY_FILES | CATEGORY_SANDBOX_PROCESS) && app.field < 3 {
        " [Space]切换 [a]新增规则 [Esc]分类 [/]搜索 [?]帮助"
    } else if matches!(app.category, CATEGORY_FILES | CATEGORY_SANDBOX_PROCESS) {
        " [Space]启停 [Enter/e]编辑 [a]新增 [d]删除 [Esc]分类 [/]搜索 [?]帮助"
    } else if matches!(app.category, CATEGORY_GATEWAY | CATEGORY_SANDBOX) {
        " [Esc]分类 [/]搜索 [?]帮助"
    } else {
        " [Space]切换 [a/e/d]增改删 [Esc]分类 [/]搜索 [p]密码 [?]帮助"
    }
}

fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    if area.width < 80 || area.height < 24 {
        frame.render_widget(
            Paragraph::new("终端过小，请调整到至少 80×24")
                .block(Block::bordered().title("HyperHub Config")),
            area,
        );
        return;
    }
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let accent = if no_color { Color::Reset } else { Color::Cyan };
    let status_color = if no_color {
        Color::Reset
    } else if app.status.starts_with('✓') {
        Color::Green
    } else if app.status.starts_with('✗') {
        Color::Red
    } else {
        Color::Yellow
    };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(area);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " HyperHub Config ",
                Style::default().fg(accent).add_modifier(Modifier::BOLD),
            ),
            Span::raw(if app.live {
                "[运行中 / 保存即热更新]"
            } else if app.dirty {
                "[已加密 / 未保存]"
            } else {
                "[已加密]"
            }),
        ])),
        rows[0],
    );
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(40)])
        .split(rows[1]);
    let items = NAV_ITEMS
        .iter()
        .map(|node| {
            ListItem::new(Line::styled(
                node.sidebar_label(),
                sidebar_node_style(*node),
            ))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.category.index()));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::bordered().title("分类"))
            .highlight_symbol("> ")
            .highlight_style(
                Style::default()
                    .fg(accent)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            ),
        columns[0],
        &mut state,
    );
    if let Some(editor) = app.list_editor {
        let items = detail_lines(app)
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>();
        let selected = (list_count(app, editor.kind) > 0).then_some(editor.selected);
        let mut state = ListState::default().with_selected(selected);
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::bordered().title(detail_title(app)))
                .highlight_symbol("> ")
                .highlight_style(
                    Style::default()
                        .fg(accent)
                        .add_modifier(Modifier::BOLD | Modifier::REVERSED),
                ),
            columns[1],
            &mut state,
        );
    } else if let Some(editor) = app.header_editor {
        let items = detail_lines(app)
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>();
        let selected = (!headers_for(app, editor.field).is_empty()).then_some(editor.selected);
        let mut state = ListState::default().with_selected(selected);
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::bordered().title(detail_title(app)))
                .highlight_symbol("> ")
                .highlight_style(
                    Style::default()
                        .fg(accent)
                        .add_modifier(Modifier::BOLD | Modifier::REVERSED),
                ),
            columns[1],
            &mut state,
        );
    } else if let Some(editor) = app.ssh_key_editor {
        let idx = credential_plugin_index(&app.config, editor.credential);
        let count = app.config.plugins[idx].ssh_accounts[editor.account]
            .private_keys
            .len();
        let items = detail_lines(app)
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>();
        let mut state = ListState::default().with_selected((count > 0).then_some(editor.selected));
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::bordered().title(detail_title(app)))
                .highlight_symbol("> ")
                .highlight_style(
                    Style::default()
                        .fg(accent)
                        .add_modifier(Modifier::BOLD | Modifier::REVERSED),
                ),
            columns[1],
            &mut state,
        );
    } else if let Some(editor) = app.ssh_password_editor {
        let idx = credential_plugin_index(&app.config, editor.credential);
        let count = app.config.plugins[idx].ssh_accounts[editor.account]
            .passwords
            .len();
        let items = detail_lines(app)
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>();
        let mut state = ListState::default().with_selected((count > 0).then_some(editor.selected));
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::bordered().title(detail_title(app)))
                .highlight_symbol("> ")
                .highlight_style(
                    Style::default()
                        .fg(accent)
                        .add_modifier(Modifier::BOLD | Modifier::REVERSED),
                ),
            columns[1],
            &mut state,
        );
    } else if let Some(detail) = app.ssh_account_detail {
        let items = detail_lines(app)
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>();
        let mut state = ListState::default().with_selected(Some(detail.field));
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::bordered().title(detail_title(app)))
                .highlight_symbol("> ")
                .highlight_style(
                    Style::default()
                        .fg(accent)
                        .add_modifier(Modifier::BOLD | Modifier::REVERSED),
                ),
            columns[1],
            &mut state,
        );
    } else if let Some(editor) = app.ssh_account_editor {
        let idx = credential_plugin_index(&app.config, editor.credential);
        let count = app.config.plugins[idx].ssh_accounts.len();
        let items = detail_lines(app)
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>();
        let mut state = ListState::default().with_selected((count > 0).then_some(editor.selected));
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::bordered().title(detail_title(app)))
                .highlight_symbol("> ")
                .highlight_style(
                    Style::default()
                        .fg(accent)
                        .add_modifier(Modifier::BOLD | Modifier::REVERSED),
                ),
            columns[1],
            &mut state,
        );
    } else {
        let lines = detail_lines(app)
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                if matches!(app.focus, Focus::Detail) && index == app.field {
                    Line::styled(
                        format!("> {value}"),
                        Style::default().fg(accent).add_modifier(Modifier::REVERSED),
                    )
                } else {
                    Line::raw(format!("  {value}"))
                }
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::bordered().title(detail_title(app)))
                .wrap(Wrap { trim: false }),
            columns[1],
        );
    }
    let shortcuts = shortcut_text(app);
    let status_line = if app.status.starts_with('✓')
        || app.status.starts_with('✗')
        || app.status.starts_with('⚠')
    {
        Line::from(vec![
            Span::styled(
                format!(" {} ", app.status),
                Style::default().fg(status_color),
            ),
            Span::raw(shortcuts),
        ])
    } else {
        Line::from(Span::raw(shortcuts))
    };
    let hint_line = selection_hint(app).map(|hint| {
        Line::from(Span::styled(
            format!(" › {hint}"),
            Style::default().fg(accent).add_modifier(Modifier::BOLD),
        ))
    });
    let bottom = match hint_line {
        Some(hint) => vec![hint, status_line],
        None => vec![status_line],
    };
    frame.render_widget(Paragraph::new(bottom), rows[2]);
    if let Some(picker) = app.reference_picker {
        draw_reference_picker(frame, area, app, picker, accent);
    }
    if let Some(picker) = app.ssh_key_add_picker {
        let width = area.width.saturating_sub(4).min(42);
        let height = 7u16.min(area.height.saturating_sub(2));
        let rect = Rect::new(
            area.x + (area.width - width) / 2,
            area.y + (area.height - height) / 2,
            width,
            height,
        );
        frame.render_widget(Clear, rect);
        let items = ["输入私钥路径导入", "自动生成 RSA", "直接粘贴 PEM"]
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>();
        let mut state = ListState::default().with_selected(Some(picker.selected));
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::bordered().title("导入私钥"))
                .highlight_symbol("> ")
                .highlight_style(
                    Style::default()
                        .fg(accent)
                        .add_modifier(Modifier::BOLD | Modifier::REVERSED),
                ),
            rect,
            &mut state,
        );
    }
    if app.help {
        let help = if app.reference_picker.is_some() {
            "↑↓/jk 选择已配置对象\n右侧实时显示脱敏配置预览\nEnter 或 Space 应用选择，Esc 取消"
        } else if app.list_editor.is_some() {
            "↑↓/jk 选择条目\na 添加，Enter/e 修改，d 删除，Esc 返回\n网络目标支持域名、IP 和 CIDR；端口为 1-65535"
        } else if app.header_editor.is_some() {
            "↑↓/jk 选择 Header\na 添加，Enter/e 修改选中值，d 删除\n值始终以掩码显示，Esc 返回凭证表单"
        } else {
            "↑↓/jk 导航，Tab 切换面板\nEnter/e 打开、编辑或切换选项，Space 专用于切换选项或启停路由\nEsc 按层返回：编辑器 → 右侧列表 → 左侧分类；分类中再次按 Esc 退出\na 新增，d 删除，/ 搜索，p 修改密码\n规则内目标/端口/路径/命令均使用列表管理：a 添加，Enter/e 修改，d 删除\n路由目标支持域名、URL 路径、IP 与 CIDR；网络/文件/子进程规则不再限制进程\n进程页面显示当前活跃受管进程，包括 ptrace 与 Gum 后端\n沙盒/文件控制读写、创建、删除、重命名；沙盒/子进程按可执行文件与命令行控制\n网关故障策略：失败关闭=异常时拒绝，失败放行=异常时直连兜底\nCtrl+S 校验并保存，Q 强制放弃修改"
        };
        popup(frame, area, "帮助", help, false);
    }
    if let Some(preview) = &app.ssh_key_preview {
        draw_ssh_key_preview(frame, area, preview, accent);
    }
    if let Some(modal) = &app.modal {
        let popup_area = popup_rect(area);
        let hint_text = input_action_hint(&modal.action);
        let reserved_rows = hint_text.map_or(2, |hint| 3 + hint.lines().count() as u16);
        let input_rows = popup_area
            .height
            .saturating_sub(2)
            .saturating_sub(reserved_rows)
            .max(1);
        let (value, (column, row)) =
            input_modal_view(modal, popup_area.width.saturating_sub(2), input_rows);
        let hint = hint_text
            .map(|hint| format!("\n\n{hint}"))
            .unwrap_or_default();
        popup(
            frame,
            area,
            &modal.title,
            &input_popup_text(&value, &hint),
            true,
        );
        frame.set_cursor_position((popup_area.x + 1 + column, popup_area.y + 1 + row));
    }
    if app.exit_prompt {
        popup(
            frame,
            area,
            "未保存修改",
            "[s] 保存并退出\n[d] 放弃修改\n[c/Esc] 取消",
            true,
        );
    }
}

fn draw_ssh_key_preview(frame: &mut Frame, area: Rect, preview: &SshKeyPreview, accent: Color) {
    let width = area.width.saturating_sub(4).min(120);
    let height = area.height.saturating_sub(4).min(20);
    let popup = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    let block = Block::bordered()
        .title("SSH 公钥信息")
        .border_style(Style::default().fg(accent));
    let inner = block.inner(popup);
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(inner);
    let content = format!(
        "算法：{}\n\nOpenSSH 公钥：\n{}\n\n指纹：{}",
        preview.algorithm, preview.openssh, preview.fingerprint
    );
    let instruction = preview
        .copy_message
        .as_deref()
        .unwrap_or("按 Enter / c / Ctrl+C 复制完整公钥（不要用鼠标框选）");

    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);
    frame.render_widget(
        Paragraph::new(content).wrap(Wrap { trim: false }),
        sections[0],
    );
    frame.render_widget(
        Paragraph::new(format!("{instruction}\n不要用鼠标框选 · [Esc/q] 返回"))
            .style(Style::default().fg(accent).add_modifier(Modifier::BOLD)),
        sections[1],
    );
}

fn draw_reference_picker(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    picker: ReferencePicker,
    accent: Color,
) {
    let width = area.width.saturating_sub(4).min(92);
    let height = area.height.saturating_sub(4).min(20);
    let popup = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, popup);
    let title = format!("选择{}", reference_kind_name(picker.kind));
    frame.render_widget(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(accent)),
        popup,
    );
    let inner = Rect::new(popup.x + 1, popup.y + 1, popup.width - 2, popup.height - 2);
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(inner);
    let mut options = vec![ListItem::new("不使用")];
    options.extend(
        (1..=reference_count(app, picker.kind)).filter_map(|selected| {
            reference_id(app, picker.kind, selected).map(|id| ListItem::new(id.to_owned()))
        }),
    );
    let mut state = ListState::default().with_selected(Some(picker.selected));
    frame.render_stateful_widget(
        List::new(options)
            .block(Block::bordered().title("已配置"))
            .highlight_symbol("> ")
            .highlight_style(
                Style::default()
                    .fg(accent)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            ),
        columns[0],
        &mut state,
    );
    frame.render_widget(
        Paragraph::new(reference_preview(app, picker))
            .block(Block::bordered().title("配置预览（Secret 已隐藏）"))
            .wrap(Wrap { trim: false }),
        columns[1],
    );
}

fn credential_plugin_indices(config: &Config) -> Vec<usize> {
    config
        .plugins
        .iter()
        .enumerate()
        .filter(|(_, plugin)| plugin.kind == PluginKind::Credential)
        .map(|(index, _)| index)
        .collect()
}

fn audit_plugin_indices(config: &Config) -> Vec<usize> {
    config
        .plugins
        .iter()
        .enumerate()
        .filter(|(_, plugin)| plugin.kind == PluginKind::Audit)
        .map(|(index, _)| index)
        .collect()
}

fn credential_plugin_index(config: &Config, index: usize) -> usize {
    credential_plugin_indices(config)[index]
}

fn audit_plugin_index(config: &Config, index: usize) -> usize {
    audit_plugin_indices(config)[index]
}

fn credential_carrier_is_http(plugin: &PluginConfig) -> bool {
    plugin.protocols.contains(&PluginProtocol::Http)
}

fn default_plugin_id(plugins: &[String], kind: PluginKind, config: &Config) -> Option<String> {
    plugins
        .iter()
        .find(|id| config.plugin(id).is_some_and(|plugin| plugin.kind == kind))
        .cloned()
}

fn reference_kind_name(kind: ReferenceKind) -> &'static str {
    match kind {
        ReferenceKind::Proxy => "代理",
        ReferenceKind::Credential => "凭证",
        ReferenceKind::Audit => "审计",
        ReferenceKind::Protection => "智能防护",
    }
}

fn reference_preview(app: &App, picker: ReferencePicker) -> String {
    let Some(index) = picker.selected.checked_sub(1) else {
        return format!(
            "不关联{}。\n\n以后可随时重新选择。",
            reference_kind_name(picker.kind)
        );
    };
    let lines = match picker.kind {
        ReferenceKind::Proxy if index < app.config.upstreams.len() => {
            editor_lines(app, ObjectEditor::Upstream(index))
        }
        ReferenceKind::Credential if index < credential_plugin_indices(&app.config).len() => {
            editor_lines(app, ObjectEditor::Credential(index))
        }
        ReferenceKind::Audit if index < audit_plugin_indices(&app.config).len() => {
            editor_lines(app, ObjectEditor::AuditProfile(index))
        }
        ReferenceKind::Protection if index < app.config.protections.len() => {
            editor_lines(app, ObjectEditor::Protection(index))
        }
        _ => vec!["配置不存在".into()],
    };
    lines.join("\n")
}

fn popup(frame: &mut Frame, area: Rect, title: &str, text: &str, focused: bool) {
    let popup = popup_rect(area);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .title(title)
                    .border_style(if focused {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default()
                    }),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn popup_rect(area: Rect) -> Rect {
    let width = area.width.min(64);
    let height = area.height.min(10);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn renders_at_supported_terminal_sizes() {
        for (width, height) in [(80, 24), (120, 40), (200, 60)] {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            let app = App {
                config: Config::default(),
                password: Zeroizing::new("password".into()),
                previous_password: None,
                path: "config.bin".into(),
                root_certificate_cache: None,
                category: CATEGORY_GATEWAY,
                field: 0,
                editor: None,
                focus: Focus::Sidebar,
                dirty: false,
                help: false,
                exit_prompt: false,
                modal: None,
                header_editor: None,
                list_editor: None,
                ssh_account_editor: None,
                ssh_account_detail: None,
                ssh_key_editor: None,
                ssh_password_editor: None,
                ssh_key_add_picker: None,
                reference_picker: None,
                ssh_key_preview: None,
                managed_processes: Vec::new(),
                status: "✓ 配置有效".into(),
                saved: false,
                discarded: false,
                live: false,
            };
            terminal.draw(|frame| draw(frame, &app)).unwrap();
        }
    }

    #[test]
    fn release_events_do_not_modify_modal_input() {
        let mut app = App {
            config: Config::default(),
            password: Zeroizing::new("password".into()),
            previous_password: None,
            path: "config.bin".into(),
            root_certificate_cache: None,
            category: CATEGORY_GATEWAY,
            field: 0,
            editor: None,
            focus: Focus::Sidebar,
            dirty: false,
            help: false,
            exit_prompt: false,
            modal: Some(InputModal {
                title: "input".into(),
                value: Zeroizing::new(String::new()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::Search,
            }),
            header_editor: None,
            list_editor: None,
            ssh_account_editor: None,
            ssh_account_detail: None,
            ssh_key_editor: None,
            ssh_password_editor: None,
            ssh_key_add_picker: None,
            reference_picker: None,
            ssh_key_preview: None,
            managed_processes: Vec::new(),
            status: String::new(),
            saved: false,
            discarded: false,
            live: false,
        };
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('x'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert!(!handle_key(&mut app, release).unwrap());
        assert_eq!(app.modal.as_ref().unwrap().value.as_str(), "");

        let press = KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE);
        assert!(!handle_key(&mut app, press).unwrap());
        assert_eq!(app.modal.as_ref().unwrap().value.as_str(), "x");
    }

    #[test]
    fn navigation_tree_is_stable_and_defaults_to_gateway() {
        let app = test_app();
        assert_eq!(app.category, CATEGORY_GATEWAY);
        assert_eq!(
            NAV_ITEMS
                .iter()
                .map(|node| node.sidebar_label())
                .collect::<Vec<_>>(),
            [
                "进程",
                "网关",
                "  基础",
                "  代理",
                "  凭证",
                "  审计",
                "  路由",
                "  证书",
                "沙盒",
                "  网络",
                "  文件",
                "  子进程",
                "智能防护",
                "环境变量",
            ]
        );
        assert!(CATEGORY_GATEWAY.is_group());
        assert!(CATEGORY_SANDBOX.is_group());
        assert!(!CATEGORY_PROCESS.is_group());
        assert_eq!(CATEGORY_ROUTE.breadcrumb(), "网关 / 路由");
        assert_eq!(CATEGORY_FIREWALL.breadcrumb(), "沙盒 / 网络");
        assert_eq!(CATEGORY_PROCESS.breadcrumb(), "进程");
        assert_eq!(CATEGORY_PROTECTION.breadcrumb(), "智能防护");
    }

    #[test]
    fn file_navigation_uses_the_normal_editable_style() {
        assert_eq!(sidebar_node_style(CATEGORY_FILES), Style::default());
        assert_ne!(
            sidebar_node_style(CATEGORY_FILES),
            Style::default().fg(Color::DarkGray)
        );
    }

    #[test]
    fn sandbox_rules_start_with_empty_inline_patterns() {
        let mut app = test_app();
        app.category = CATEGORY_FIREWALL;
        add_selected(&mut app);
        assert!(app.config.firewall.rules[0].endpoints.is_empty());

        app.category = CATEGORY_FILES;
        add_selected(&mut app);
        assert!(app.config.sandbox.file.rules[0].patterns.is_empty());

        app.category = CATEGORY_SANDBOX_PROCESS;
        add_selected(&mut app);
        assert!(app.config.sandbox.process.rules[0].patterns.is_empty());
    }

    #[test]
    fn gateway_overview_summarizes_current_configuration() {
        let mut app = test_app();
        app.live = true;
        app.config.upstreams.push(Upstream {
            uuid: hyperhub_core::config::new_config_uuid(),
            id: "proxy".into(),
            kind: UpstreamKind::Socks5,
            address: "127.0.0.1:1080".into(),
            timeout_ms: 10_000,
            username: None,
            password: None,
            headers: Default::default(),
        });
        let lines = detail_lines(&app);
        assert_eq!(detail_title(&app), "网关");
        assert!(lines
            .iter()
            .any(|line| line.contains("Serve") && line.contains("运行中")));
        assert!(lines
            .iter()
            .any(|line| line.contains("代理") && line.contains("1 个")));
        assert!(lines
            .iter()
            .any(|line| line.contains("路由") && line.contains("1 条")));
    }

    #[test]
    fn file_sandbox_page_is_editable_and_searchable() {
        let mut app = test_app();
        app.category = CATEGORY_FILES;
        app.focus = Focus::Detail;
        let lines = detail_lines(&app);
        assert_eq!(detail_title(&app), "沙盒 / 文件");
        assert!(lines[0].contains("文件沙盒"));
        add_selected(&mut app);
        assert_eq!(app.config.sandbox.file.rules.len(), 1);
        assert!(matches!(app.editor, Some(ObjectEditor::FileSandboxRule(0))));
        app.editor = None;
        apply_input(
            &mut app,
            InputModal {
                title: "search".into(),
                value: Zeroizing::new("文件".into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::Search,
            },
        )
        .unwrap();
        assert_eq!(app.category, CATEGORY_FILES);
    }

    #[test]
    fn sidebar_navigation_walks_parent_and_child_nodes() {
        let mut app = test_app();
        move_selection(&mut app, -1);
        assert_eq!(app.category, CATEGORY_PROCESS);
        move_selection(&mut app, 1);
        assert_eq!(app.category, CATEGORY_GATEWAY);
        app.category = CATEGORY_ENVIRONMENT;
        move_selection(&mut app, 1);
        assert_eq!(app.category, CATEGORY_ENVIRONMENT);
    }

    #[test]
    fn basic_category_contains_listener_settings() {
        assert_eq!(
            NAV_ITEMS,
            &[
                CATEGORY_PROCESS,
                CATEGORY_GATEWAY,
                CATEGORY_BASIC,
                CATEGORY_PROXY,
                CATEGORY_CREDENTIAL,
                CATEGORY_AUDIT,
                CATEGORY_ROUTE,
                CATEGORY_CERTIFICATE,
                CATEGORY_SANDBOX,
                CATEGORY_FIREWALL,
                CATEGORY_FILES,
                CATEGORY_SANDBOX_PROCESS,
                CATEGORY_PROTECTION,
                CATEGORY_ENVIRONMENT,
            ]
        );
        let mut app = test_app();
        app.category = CATEGORY_BASIC;
        app.focus = Focus::Detail;

        let lines = detail_lines(&app);
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("网关故障策略"));
        assert!(lines[1].contains("SOCKS5"));
        assert!(lines[2].contains("待激活会话有效期"));
        assert!(lines[3].contains("调试事件"));

        let enforce = matches!(app.config.mode, EnforcementMode::Enforce);
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        )
        .unwrap();
        assert_ne!(matches!(app.config.mode, EnforcementMode::Enforce), enforce);
        handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)).unwrap();
        assert_eq!(matches!(app.config.mode, EnforcementMode::Enforce), enforce);

        app.field = 1;
        edit_selected(&mut app);
        assert!(matches!(
            app.modal.as_ref().map(|modal| &modal.action),
            Some(InputAction::Text(TextField::SocksListen))
        ));

        app.modal = None;
        app.field = 2;
        edit_selected(&mut app);
        assert!(matches!(
            app.modal.as_ref().map(|modal| &modal.action),
            Some(InputAction::Text(TextField::PendingTtl))
        ));

        app.modal = None;
        app.field = 3;
        assert!(!app.config.debug);
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        )
        .unwrap();
        assert!(app.config.debug);
        assert!(app.status.contains("保存后立即热更新"));
    }

    #[test]
    fn text_input_supports_middle_cursor_editing() {
        let mut app = test_app();
        open_input(&mut app, "输入", "abcd", false, InputAction::Search);
        handle_key(&mut app, KeyEvent::new(KeyCode::Left, KeyModifiers::NONE)).unwrap();
        handle_key(&mut app, KeyEvent::new(KeyCode::Left, KeyModifiers::NONE)).unwrap();
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('X'), KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(app.modal.as_ref().unwrap().value.as_str(), "abXcd");
        handle_key(&mut app, KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE)).unwrap();
        assert_eq!(app.modal.as_ref().unwrap().value.as_str(), "abXd");
    }

    #[test]
    fn input_cursor_does_not_add_or_shift_display_characters() {
        let mut app = test_app();
        open_input(&mut app, "输入", "ab中d", false, InputAction::Search);
        let modal = app.modal.as_mut().unwrap();
        modal.cursor = 3;
        assert_eq!(input_modal_view(modal, 62, 4), ("> ab中d".into(), (6, 0)));
        assert!(input_popup_text("> ab中d", "").starts_with("> ab中d\n"));
        assert!(!input_popup_text("> ab中d", "").starts_with("> > "));

        modal.masked = true;
        assert_eq!(input_modal_view(modal, 62, 4), ("> ••••".into(), (5, 0)));
    }

    #[test]
    fn input_cursor_scrolls_with_long_and_multiline_content() {
        let mut app = test_app();
        open_input(
            &mut app,
            "输入",
            "abcdef\nghijkl",
            false,
            InputAction::Search,
        );
        let modal = app.modal.as_mut().unwrap();
        modal.multiline = true;
        let (view, cursor) = input_modal_view(modal, 4, 2);
        assert_eq!(view, "ghij\nkl");
        assert_eq!(cursor, (2, 1));
        assert!(cursor.0 < 4);
        assert!(cursor.1 < 2);
    }

    #[test]
    fn process_page_is_readonly_monitor() {
        let mut app = test_app();
        app.category = CATEGORY_PROCESS;
        app.focus = Focus::Detail;
        assert_eq!(detail_title(&app), "进程");
        add_selected(&mut app);
        assert!(app.status.contains("不支持新增"));
    }

    #[test]
    fn sandbox_overview_matches_network_file_and_child_process_order() {
        let mut app = test_app();
        app.category = CATEGORY_SANDBOX;
        app.focus = Focus::Detail;
        let lines = detail_lines(&app);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("网络沙盒"));
        assert!(lines[1].contains("文件沙盒"));
        assert!(lines[2].contains("子进程沙盒"));
        assert!(!lines.iter().any(|line| line.contains("PID")));
    }

    #[test]
    fn process_overview_lists_managed_processes() {
        let mut app = test_app();
        app.live = true;
        app.category = CATEGORY_PROCESS;
        app.focus = Focus::Detail;
        app.managed_processes.push(ManagedProcessView {
            session_id: "session-1".into(),
            process: InjectedProcessSnapshot {
                pid: 42,
                executable: r"C:\tools\client.exe".into(),
                root: true,
                last_seen_ms: 100,
                firewall_version: 7,
                hook_status: "hook".into(),
                process_policy_version: 9,
                process_rule_id: Some("client-only".into()),
                process_decision_source: "rule".into(),
            },
        });

        let lines = detail_lines(&app);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("PID 42"));
        assert!(lines[0].contains("firewall=v7"));
        assert!(selection_hint(&app).unwrap().contains("session=session-1"));
    }

    #[test]
    fn firewall_category_manages_defaults_and_rules() {
        let mut app = test_app();
        app.category = CATEGORY_FIREWALL;
        app.focus = Focus::Detail;

        let lines = detail_lines(&app);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("网络沙盒"));
        assert!(!lines[0].contains("[ ]"));
        assert!(lines[0].contains("停用"));
        app.field = 0;
        assert!(!selected_is_toggle(&app));
        assert!(lines[1].contains("放行"));
        assert!(!lines[1].contains("未配置"));
        assert!(lines[2].contains("放行"));

        app.field = 0;
        toggle_selected(&mut app);
        assert!(app.config.firewall.enabled);
        assert_eq!(
            app.config.firewall.default.as_ref().map(|rule| rule.action),
            Some(FirewallAction::Pass)
        );

        app.field = 1;
        toggle_selected(&mut app);
        assert_eq!(
            app.config.firewall.default.as_ref().map(|rule| rule.action),
            Some(FirewallAction::Deny)
        );

        app.field = 2;
        toggle_selected(&mut app);
        assert_eq!(app.config.firewall.error_action, FirewallAction::Deny);
        toggle_selected(&mut app);
        assert_eq!(app.config.firewall.error_action, FirewallAction::Pass);
        app.field = 1;
        toggle_selected(&mut app);
        assert_eq!(
            app.config.firewall.default.as_ref().map(|rule| rule.action),
            Some(FirewallAction::Pass)
        );
        toggle_selected(&mut app);
        assert_eq!(
            app.config.firewall.default.as_ref().map(|rule| rule.action),
            Some(FirewallAction::Deny)
        );

        add_selected(&mut app);
        assert_eq!(app.config.firewall.rules.len(), 1);
        assert!(!app.config.firewall.rules[0].enabled);
        assert!(matches!(app.editor, Some(ObjectEditor::FirewallRule(0))));
        assert_eq!(editor_lines(&app, ObjectEditor::FirewallRule(0)).len(), 5);

        app.field = 3;
        edit_object_field(&mut app, ObjectEditor::FirewallRule(0));
        assert_eq!(app.config.firewall.rules[0].action, FirewallAction::Smart);

        app.editor = None;
        app.field = 3;
        edit_selected(&mut app);
        assert!(matches!(app.editor, Some(ObjectEditor::FirewallRule(0))));
        app.editor = None;
        app.field = 3;
        toggle_selected(&mut app);
        assert!(app.config.firewall.rules[0].enabled);

        delete_selected(&mut app);
        assert!(app.config.firewall.rules.is_empty());
    }

    #[test]
    fn firewall_rule_editor_updates_targets_and_ports() {
        let mut app = test_app();
        app.config.firewall.rules.push(FirewallRule {
            uuid: hyperhub_core::config::new_config_uuid(),
            id: "firewall-1".into(),
            enabled: false,
            priority: 0,
            action: FirewallAction::Deny,
            endpoints: Vec::new(),
            legacy: Default::default(),
            protection: None,
        });

        apply_list_value(
            &mut app,
            ListEditorKind::FirewallTargets(0),
            None,
            "example.com",
        )
        .unwrap();
        apply_list_value(
            &mut app,
            ListEditorKind::FirewallTargets(0),
            None,
            "10.0.0.0/8",
        )
        .unwrap();
        let rule = &app.config.firewall.rules[0];
        assert_eq!(rule.endpoints.len(), 2);
        assert_eq!(rule.endpoints[0].target, "example.com");
        assert!(apply_list_value(
            &mut app,
            ListEditorKind::FirewallTargets(0),
            None,
            "https://example.com/private",
        )
        .is_err());
        assert!(apply_list_value(&mut app, ListEditorKind::FirewallPorts(0), None, "0",).is_err());
    }

    #[test]
    fn audit_category_hides_managed_storage_paths() {
        let mut app = test_app();
        app.category = CATEGORY_AUDIT;
        app.focus = Focus::Detail;

        let lines = detail_lines(&app);
        assert!(lines[0].contains("审计保留天数"));
        assert!(lines.iter().all(|line| !line.contains("事件日志路径")));
        assert!(lines.iter().all(|line| !line.contains("内容转录目录")));

        app.field = 0;
        edit_selected(&mut app);
        assert!(matches!(
            app.modal.as_ref().map(|modal| &modal.action),
            Some(InputAction::Text(TextField::AuditRetentionDays))
        ));
    }

    #[test]
    fn escape_returns_from_detail_to_sidebar_before_exiting() {
        let mut app = test_app();
        app.category = CATEGORY_ROUTE;
        app.field = 3;
        app.focus = Focus::Detail;

        let exited = handle_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)).unwrap();
        assert!(!exited);
        assert!(matches!(app.focus, Focus::Sidebar));
        assert_eq!(app.field, 3);
        assert!(app.status.contains("分类列表"));

        let exited = handle_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)).unwrap();
        assert!(exited);
    }

    #[test]
    fn default_route_is_the_fixed_first_route_and_cannot_be_deleted() {
        let mut app = test_app();
        app.category = CATEGORY_ROUTE;
        app.field = 0;

        let routes = detail_lines(&app);
        assert_eq!(routes.len(), 1);
        assert!(routes[0].contains(DEFAULT_ROUTE_ID));
        assert!(routes[0].contains("内置兜底"));
        assert!(routes[0].contains("不可删除"));

        edit_selected(&mut app);
        assert!(matches!(app.editor, Some(ObjectEditor::DefaultRoute)));
        let form = editor_lines(&app, ObjectEditor::DefaultRoute);
        assert_eq!(form.len(), 6);
        assert!(form[0].contains("不可修改"));

        app.field = 1;
        let enabled = app.config.default_route.enabled;
        edit_selected(&mut app);
        assert_eq!(app.config.default_route.enabled, !enabled);

        app.editor = None;
        app.field = 0;
        delete_selected(&mut app);
        assert!(app.config.rules.is_empty());
        assert!(app.status.contains("不能删除"));
    }

    #[test]
    fn user_routes_follow_the_default_route_in_the_route_list() {
        let mut app = test_app();
        app.category = CATEGORY_ROUTE;
        add_selected(&mut app);
        assert!(matches!(app.editor, Some(ObjectEditor::Route(0))));

        app.editor = None;
        app.field = 1;
        edit_selected(&mut app);
        assert!(matches!(app.editor, Some(ObjectEditor::Route(0))));

        app.editor = None;
        app.field = 1;
        delete_selected(&mut app);
        assert!(app.config.rules.is_empty());
        assert_eq!(app.field, 0);
    }

    #[test]
    fn default_route_plugin_references_follow_renames_and_block_deletion() {
        let mut app = test_app();
        app.category = CATEGORY_CREDENTIAL;
        add_selected(&mut app);
        let original = app.config.plugins[credential_plugin_index(&app.config, 0)]
            .id
            .clone();
        app.config.default_route.plugins.push(original);

        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new("renamed-credential".into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::Text(TextField::CredentialId(0)),
            },
        )
        .unwrap();
        assert_eq!(
            app.config.default_route.plugins,
            ["renamed-credential".to_string()]
        );

        app.editor = None;
        app.field = 0;
        delete_selected(&mut app);
        assert_eq!(credential_plugin_indices(&app.config).len(), 1);
        assert!(app.status.contains("仍被路由引用"));
    }

    #[test]
    fn route_editor_updates_all_route_fields() {
        let mut app = test_app();
        app.category = CATEGORY_ROUTE;
        add_selected(&mut app);
        assert!(matches!(app.editor, Some(ObjectEditor::Route(0))));

        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new("42".into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::Text(TextField::RoutePriority(0)),
            },
        )
        .unwrap();
        assert_eq!(app.config.rules[0].priority, 42);
        let lines = editor_lines(&app, ObjectEditor::Route(0));
        assert_eq!(lines.len(), 10);
        assert!(lines[0].starts_with("ID"));
        assert!(lines[1].starts_with("启用"));
        assert!(lines[7].starts_with("审计"));
        assert!(lines[8].starts_with("智能防护"));
        app.field = 1;
        let enabled = app.config.rules[0].enabled;
        toggle_selected(&mut app);
        assert_ne!(app.config.rules[0].enabled, enabled);
        let rendered = lines.join("\n");
        assert!(!rendered.contains("进程正则"));
        assert!(!rendered.contains("端口"));
    }

    #[test]
    fn route_target_input_continues_with_bound_port() {
        let mut app = test_app();
        app.category = CATEGORY_ROUTE;
        add_selected(&mut app);
        open_target_editor(&mut app, 0);
        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new("example.com".into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::RouteTarget(0, None),
            },
        )
        .unwrap();
        let modal = app.modal.take().unwrap();
        assert!(matches!(modal.action, InputAction::RoutePort(0, None, _)));
        apply_input(
            &mut app,
            InputModal {
                title: modal.title,
                value: Zeroizing::new("443".into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: modal.action,
            },
        )
        .unwrap();
        assert_eq!(
            app.config.rules[0].endpoints,
            vec![RouteEndpoint {
                target: "example.com".into(),
                port: Some(443),
            }]
        );
    }

    #[test]
    fn route_references_are_selected_from_configured_objects_with_preview() {
        let mut app = test_app();
        app.config.upstreams.push(Upstream {
            uuid: hyperhub_core::config::new_config_uuid(),
            id: "office-proxy".into(),
            kind: UpstreamKind::HttpConnect,
            address: "127.0.0.1:7890".into(),
            timeout_ms: 10_000,
            username: None,
            password: Some(SecretValue::Inline {
                value: "hidden".into(),
            }),
            headers: Default::default(),
        });
        app.category = CATEGORY_ROUTE;
        add_selected(&mut app);
        open_reference_picker(&mut app, ReferenceTarget::Route(0), ReferenceKind::Proxy);
        handle_reference_picker_key(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        let picker = app.reference_picker.unwrap();
        let preview = reference_preview(&app, picker);
        assert!(preview.contains("127.0.0.1:7890"));
        assert!(!preview.contains("hidden"));
        handle_reference_picker_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.reference_picker.is_none());
        assert_eq!(
            app.config.rules[0].upstream.as_deref(),
            Some("office-proxy")
        );

        app.config.rules[0].upstream = None;
        open_reference_picker(&mut app, ReferenceTarget::Route(0), ReferenceKind::Proxy);
        handle_reference_picker_key(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        handle_reference_picker_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        );
        assert_eq!(
            app.config.rules[0].upstream.as_deref(),
            Some("office-proxy")
        );
    }

    #[test]
    fn space_toggles_routes_while_enter_only_opens_the_editor() {
        let mut app = test_app();
        app.category = CATEGORY_ROUTE;
        app.field = 0;

        let default_enabled = app.config.default_route.enabled;
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(app.config.default_route.enabled, !default_enabled);
        assert!(app.editor.is_none());

        handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)).unwrap();
        assert!(matches!(app.editor, Some(ObjectEditor::DefaultRoute)));

        app.editor = None;
        add_selected(&mut app);
        app.editor = None;
        app.field = 1;
        let route_enabled = app.config.rules[0].enabled;
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(app.config.rules[0].enabled, !route_enabled);

        handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)).unwrap();
        assert!(matches!(app.editor, Some(ObjectEditor::Route(0))));
    }

    #[test]
    fn enter_and_space_both_toggle_editor_options() {
        let mut app = test_app();
        app.editor = Some(ObjectEditor::DefaultRoute);
        app.field = 2;
        let deny = app.config.default_route.action == RuleAction::Deny;

        handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)).unwrap();
        assert_eq!(app.config.default_route.action == RuleAction::Deny, !deny);

        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(app.config.default_route.action == RuleAction::Deny, deny);
    }

    #[test]
    fn ssh_transcript_can_be_enabled_without_http_body() {
        let mut app = test_app();
        app.category = CATEGORY_AUDIT;
        add_selected(&mut app);
        assert!(matches!(app.editor, Some(ObjectEditor::AuditProfile(0))));
        assert_eq!(editor_lines(&app, ObjectEditor::AuditProfile(0)).len(), 12);

        app.field = 8;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(profile.ssh_transcript);
        assert!(profile.protocols.contains(&PluginProtocol::Ssh));
        assert!(!profile.capture_body);
        assert_eq!(profile.websocket_capture, WebSocketCapture::Off);

        app.field = 7;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(!profile.protocols.contains(&PluginProtocol::Ssh));
        assert!(!profile.ssh_transcript);

        app.field = 8;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(profile.protocols.contains(&PluginProtocol::Ssh));
        assert!(profile.ssh_transcript);

        app.field = 8;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(!profile.ssh_transcript);
        assert!(!profile.capture_body);
    }

    #[test]
    fn http_body_capture_toggles_independently() {
        let mut app = test_app();
        app.category = CATEGORY_AUDIT;
        add_selected(&mut app);
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(!profile.capture_body);
        assert!(!profile.ssh_transcript);
        assert_eq!(profile.websocket_capture, WebSocketCapture::Off);

        app.field = 2;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(profile.capture_body);
        assert!(!profile.ssh_transcript);
        assert_eq!(profile.websocket_capture, WebSocketCapture::Off);
        assert!(editor_lines(&app, ObjectEditor::AuditProfile(0))
            .contains(&"HTTP 内容转录      [x]".to_string()));

        app.field = 2;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(!profile.capture_body);
        assert!(!profile.ssh_transcript);
        assert_eq!(profile.websocket_capture, WebSocketCapture::Off);
    }

    #[test]
    fn git_transcript_is_independent_from_http_content() {
        let mut app = test_app();
        app.category = CATEGORY_AUDIT;
        add_selected(&mut app);

        app.field = 6;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(profile.protocols.contains(&PluginProtocol::Git));
        assert!(profile.git_transcript_enabled());
        assert!(!profile.http_transcript_enabled());

        app.field = 2;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(profile.git_transcript_enabled());
        assert!(profile.http_transcript_enabled());

        app.field = 2;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(profile.git_transcript_enabled());
        assert!(!profile.http_transcript_enabled());
    }

    #[test]
    fn legacy_git_capture_does_not_enable_http_content_when_http_events_are_added() {
        let mut app = test_app();
        app.category = CATEGORY_AUDIT;
        add_selected(&mut app);
        let idx = audit_plugin_index(&app.config, 0);
        app.config.plugins[idx].protocols = vec![PluginProtocol::Git];
        app.config.plugins[idx].capture_body = true;
        app.config.plugins[idx].git_transcript = None;

        app.field = 1;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[idx];
        assert!(profile.protocols.contains(&PluginProtocol::Http));
        assert!(profile.git_transcript_enabled());
        assert!(!profile.http_transcript_enabled());
    }

    #[test]
    fn space_toggles_new_audit_fields_without_uneditable_status() {
        for field in [6, 9, 10] {
            let mut app = test_app();
            app.category = CATEGORY_AUDIT;
            add_selected(&mut app);
            let idx = audit_plugin_index(&app.config, 0);
            app.field = field;
            handle_key(
                &mut app,
                KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
            )
            .unwrap();
            assert!(
                !app.status.contains("不可切换"),
                "field {field} must be toggleable"
            );
            match field {
                6 => assert!(app.config.plugins[idx].git_transcript_enabled()),
                9 => assert!(!app.config.plugins[idx].transcript_client_upload),
                10 => assert!(!app.config.plugins[idx].transcript_server_response),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn transcript_directions_are_independent_but_keep_one_when_content_is_enabled() {
        let mut app = test_app();
        app.category = CATEGORY_AUDIT;
        add_selected(&mut app);
        let idx = audit_plugin_index(&app.config, 0);

        app.field = 2;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        app.field = 9;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        assert!(!app.config.plugins[idx].transcript_client_upload);
        assert!(app.config.plugins[idx].transcript_server_response);

        app.field = 10;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        assert!(app.config.plugins[idx].transcript_server_response);
        assert!(app.status.contains("至少保留一个"));

        app.field = 9;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        app.field = 10;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        assert!(app.config.plugins[idx].transcript_client_upload);
        assert!(!app.config.plugins[idx].transcript_server_response);

        app.field = 2;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        app.field = 9;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        assert!(!app.config.plugins[idx].transcript_client_upload);
        assert!(!app.config.plugins[idx].transcript_server_response);

        app.field = 6;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        assert!(app.config.plugins[idx].transcript_client_upload);
        assert!(app.config.plugins[idx].transcript_server_response);
    }

    #[test]
    fn audit_protocol_toggles_add_and_remove_protocols() {
        let mut app = test_app();
        app.category = CATEGORY_AUDIT;
        add_selected(&mut app);
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(profile.protocols.contains(&PluginProtocol::Http));
        assert!(profile.protocols.contains(&PluginProtocol::Ws));
        assert!(!profile.protocols.contains(&PluginProtocol::Ssh));

        app.field = 7;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(profile.protocols.contains(&PluginProtocol::Ssh));

        app.field = 1;
        edit_object_field(&mut app, ObjectEditor::AuditProfile(0));
        let profile = &app.config.plugins[audit_plugin_index(&app.config, 0)];
        assert!(!profile.protocols.contains(&PluginProtocol::Http));
    }

    #[test]
    fn inline_secrets_are_never_rendered() {
        let secret = SecretValue::Inline {
            value: "do-not-display".into(),
        };
        let rendered = secret_summary(Some(&secret));
        assert!(!rendered.contains("do-not-display"));
        assert!(rendered.contains("已设置"));
    }

    #[test]
    fn credential_editor_only_shows_selected_type_fields() {
        let mut app = test_app();
        app.category = CATEGORY_CREDENTIAL;
        add_selected(&mut app);

        let http = editor_lines(&app, ObjectEditor::Credential(0)).join("\n");
        assert!(http.contains("Bearer"));
        assert!(http.contains("自定义 Headers"));
        assert!(matches!(
            app.config.plugins[credential_plugin_index(&app.config, 0)]
                .headers
                .get(DEFAULT_HTTP_HEADER_REMOVAL),
            Some(SecretValue::Inline { value }) if value.is_empty()
        ));
        assert!(!http.contains("目标用户名"));
        assert!(!http.contains("私钥"));

        edit_credential_field(&mut app, 0, 1);
        let ssh = editor_lines(&app, ObjectEditor::Credential(0)).join("\n");
        assert!(ssh.contains("SSH 账号"));
        assert!(!ssh.contains("自定义 Headers"));
        assert!(app.config.plugins[credential_plugin_index(&app.config, 0)]
            .secret
            .is_none());
        assert!(app.config.plugins[credential_plugin_index(&app.config, 0)]
            .headers
            .is_empty());

        edit_credential_field(&mut app, 0, 1);
        assert!(matches!(
            app.config.plugins[credential_plugin_index(&app.config, 0)]
                .headers
                .get(DEFAULT_HTTP_HEADER_REMOVAL),
            Some(SecretValue::Inline { value }) if value.is_empty()
        ));
    }

    #[test]
    fn http_credential_editor_adapts_to_every_authentication_type() {
        let mut app = test_app();
        app.category = CATEGORY_CREDENTIAL;
        add_selected(&mut app);

        let idx = credential_plugin_index(&app.config, 0);
        let credential = &mut app.config.plugins[idx];
        select_http_scheme(credential, HttpAuthScheme::Bearer, HttpAuthScheme::Basic);
        let basic = editor_lines(&app, ObjectEditor::Credential(0)).join("\n");
        assert!(basic.contains("Basic"));
        assert!(basic.contains("用户名"));
        assert!(basic.contains("密码"));
        assert!(!basic.contains("Cookie名称"));

        {
            let idx = credential_plugin_index(&app.config, 0);
            select_http_scheme(
                &mut app.config.plugins[idx],
                HttpAuthScheme::Basic,
                HttpAuthScheme::Cookie,
            );
        }
        let cookie = editor_lines(&app, ObjectEditor::Credential(0)).join("\n");
        assert!(cookie.contains("Cookie名称"));
        assert!(!cookie.contains("用户名"));

        {
            let idx = credential_plugin_index(&app.config, 0);
            select_http_scheme(
                &mut app.config.plugins[idx],
                HttpAuthScheme::Cookie,
                HttpAuthScheme::QueryParameter,
            );
        }
        let query = editor_lines(&app, ObjectEditor::Credential(0)).join("\n");
        assert!(query.contains("Query 参数名称"));
        assert!(!query.contains("Cookie名称"));

        {
            let idx = credential_plugin_index(&app.config, 0);
            select_http_scheme(
                &mut app.config.plugins[idx],
                HttpAuthScheme::QueryParameter,
                HttpAuthScheme::CustomHeaders,
            );
        }
        let custom = editor_lines(&app, ObjectEditor::Credential(0)).join("\n");
        assert!(custom.contains("仅自定义 Header"));
        assert!(!custom.contains("鉴权值"));
    }

    #[test]
    fn credential_values_are_stored_inline_without_env_syntax() {
        let mut app = test_app();
        app.category = CATEGORY_CREDENTIAL;
        add_selected(&mut app);

        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new("token-value".into()),
                cursor: 0,
                masked: true,
                multiline: false,
                action: InputAction::Secret(SecretField::CredentialHttpSecret(0)),
            },
        )
        .unwrap();
        assert_eq!(
            app.config.plugins[credential_plugin_index(&app.config, 0)].secret,
            Some(SecretValue::Inline {
                value: "token-value".into()
            })
        );

        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new("X-Tenant".into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::HeaderName(HeaderField::Credential(0)),
            },
        )
        .unwrap();
        let modal = app.modal.take().unwrap();
        assert!(modal.masked);
        apply_input(
            &mut app,
            InputModal {
                title: modal.title,
                value: Zeroizing::new("tenant-1".into()),
                cursor: 0,
                masked: modal.masked,
                multiline: modal.multiline,
                action: modal.action,
            },
        )
        .unwrap();
        assert_eq!(
            app.config.plugins[credential_plugin_index(&app.config, 0)].headers["X-Tenant"],
            SecretValue::Inline {
                value: "tenant-1".into()
            }
        );
        assert!(apply_header_field(
            &mut app,
            HeaderField::Credential(0),
            "Authorization",
            "duplicate"
        )
        .unwrap_err()
        .contains("自动生成"));

        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new("-".into()),
                cursor: 0,
                masked: true,
                multiline: false,
                action: InputAction::HeaderValue(
                    HeaderField::Credential(0),
                    "X-Tenant".into(),
                    true,
                ),
            },
        )
        .unwrap();
        assert!(matches!(
            app.config.plugins[credential_plugin_index(&app.config, 0)]
                .headers
                .get("X-Tenant"),
            Some(SecretValue::Inline { value }) if value.is_empty()
        ));
        open_header(&mut app, HeaderField::Credential(0));
        assert!(detail_lines(&app)
            .iter()
            .any(|line| line == "X-Tenant: 删除客户端 Header"));
        remove_header(
            &mut app,
            HeaderField::Credential(0),
            DEFAULT_HTTP_HEADER_REMOVAL,
        )
        .unwrap();
        assert!(!app.config.plugins[credential_plugin_index(&app.config, 0)]
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case(DEFAULT_HTTP_HEADER_REMOVAL)));

        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new("X-Remove".into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::HeaderName(HeaderField::Credential(0)),
            },
        )
        .unwrap();
        let modal = app.modal.take().unwrap();
        apply_input(
            &mut app,
            InputModal {
                value: Zeroizing::new(String::new()),
                ..modal
            },
        )
        .unwrap();
        assert!(matches!(
            app.config.plugins[credential_plugin_index(&app.config, 0)]
                .headers
                .get("X-Remove"),
            Some(SecretValue::Inline { value }) if value.is_empty()
        ));
    }

    #[test]
    fn token_editor_is_protocol_aware_without_credential_path_lists() {
        let mut app = test_app();
        app.category = CATEGORY_CREDENTIAL;
        add_selected(&mut app);
        let plugin = credential_plugin_index(&app.config, 0);
        select_http_scheme(
            &mut app.config.plugins[plugin],
            HttpAuthScheme::Bearer,
            HttpAuthScheme::Token,
        );

        let rendered = editor_lines(&app, ObjectEditor::Credential(0)).join("\n");
        assert!(rendered.contains("令牌（自动）"));
        assert!(rendered.contains("令牌              未设置"));
        assert!(!rendered.contains("REST Bearer 路径"));
        assert!(!rendered.contains("Git/LFS 路径"));
        assert!(rendered.contains("自定义 Headers"));
        assert_eq!(
            app.config.plugins[plugin].protocols,
            vec![PluginProtocol::Http]
        );

        edit_http_credential_field(&mut app, 0, 4);
        assert!(app.modal.as_ref().is_some_and(|modal| modal.masked));
        app.modal = None;
        edit_http_credential_field(&mut app, 0, 5);
        assert!(app.header_editor.is_some());
        assert!(detail_lines(&app)
            .iter()
            .any(|line| line == "PRIVATE-TOKEN: 删除客户端 Header"));
    }

    #[test]
    fn list_editor_adds_edits_and_deletes_unbounded_entries() {
        let mut app = test_app();
        app.category = CATEGORY_ROUTE;
        add_selected(&mut app);
        open_target_editor(&mut app, 0);
        for index in 0..128 {
            apply_input(
                &mut app,
                InputModal {
                    title: String::new(),
                    value: Zeroizing::new(format!("host-{index}.example.com")),
                    cursor: 0,
                    masked: false,
                    multiline: false,
                    action: InputAction::ListValue(ListEditorKind::RouteTargets(0), None),
                },
            )
            .unwrap();
        }
        assert_eq!(detail_lines(&app).len(), 128);
        assert_eq!(app.list_editor.unwrap().selected, 127);

        app.list_editor.as_mut().unwrap().selected = 0;
        handle_key(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)).unwrap();
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        )
        .unwrap();
        assert!(!app.config.rules[0]
            .endpoints
            .iter()
            .any(|endpoint| endpoint.target == "host-1.example.com"));
        assert_eq!(app.config.rules[0].endpoints.len(), 127);

        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
        )
        .unwrap();
        assert!(matches!(
            app.modal.as_ref().map(|modal| &modal.action),
            Some(InputAction::RouteTarget(0, None))
        ));
        assert!(normalize_target("invalid target").is_err());
        assert_eq!(normalize_target("10.0.0.1/8").unwrap(), "10.0.0.0/8");
        assert_eq!(
            normalize_target("HTTPS://*.Example.COM/api/").unwrap(),
            "*.example.com/api"
        );
        assert!(normalize_target("api.*.example.com").is_err());
    }

    #[test]
    fn list_input_modals_explain_accepted_values() {
        let cases = [
            (ListEditorKind::RouteTargets(0), "*.通配域名"),
            (ListEditorKind::FirewallTargets(0), "不支持 URL 路径"),
            (ListEditorKind::FirewallPorts(0), "1-65535"),
            (ListEditorKind::FilePaths(0), "文件或目录路径"),
            (
                ListEditorKind::SandboxExecutables(0),
                "可执行文件名或完整路径",
            ),
            (ListEditorKind::SandboxCommandLines(0), "命令行子串"),
        ];
        for (kind, expected) in cases {
            let action = InputAction::ListValue(kind, None);
            assert!(input_action_hint(&action).unwrap().contains(expected));
        }

        let mut app = test_app();
        app.modal = Some(InputModal {
            title: "添加路由目标".into(),
            value: Zeroizing::new(String::new()),
            cursor: 0,
            masked: false,
            multiline: false,
            action: InputAction::ListValue(ListEditorKind::RouteTargets(0), None),
        });
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("example.com"));
        assert!(rendered.contains("CIDR"));
    }

    #[test]
    fn environment_variables_are_managed_as_a_masked_list() {
        let mut app = test_app();
        app.category = CATEGORY_ENVIRONMENT;
        add_selected(&mut app);
        let name_modal = app.modal.take().unwrap();
        apply_input(
            &mut app,
            InputModal {
                value: Zeroizing::new("GH_TOKEN".into()),
                ..name_modal
            },
        )
        .unwrap();
        let value_modal = app.modal.take().unwrap();
        assert!(value_modal.masked);
        apply_input(
            &mut app,
            InputModal {
                value: Zeroizing::new("never-render-this".into()),
                ..value_modal
            },
        )
        .unwrap();
        let rendered = detail_lines(&app).join("\n");
        assert!(rendered.contains("GH_TOKEN: neve••••••this"));
        assert!(!rendered.contains("never-render-this"));

        app.field = 0;
        delete_selected(&mut app);
        assert!(app.config.environment.is_empty());
        assert!(normalize_environment_name("HYPERHUB_SESSION_ID").is_err());
    }

    #[test]
    fn environment_value_preview_masks_middle_and_shows_empty() {
        assert_eq!(mask_middle(""), "");
        assert_eq!(mask_middle("a"), "a••••••");
        assert_eq!(mask_middle("ab"), "a••••••");
        assert_eq!(mask_middle("abc"), "a••••••c");
        assert_eq!(mask_middle("abcdef"), "ab••••••ef");
        assert_eq!(mask_middle("ghp_1234567890abcdef"), "ghp_••••••cdef");

        let variable = EnvironmentVariable {
            uuid: hyperhub_core::config::new_config_uuid(),
            name: "GITLAB_HOST".into(),
            value: SecretValue::Inline {
                value: String::new(),
            },
        };
        assert_eq!(environment_value_preview(&variable), "");

        let mut app = test_app();
        app.config.environment.push(variable);
        app.category = CATEGORY_ENVIRONMENT;
        assert!(detail_lines(&app).join("\n").contains("GITLAB_HOST: 空"));
    }

    #[test]
    fn environment_value_can_be_cleared_with_dash() {
        let mut app = test_app();
        app.category = CATEGORY_ENVIRONMENT;
        app.config.environment.push(EnvironmentVariable {
            uuid: hyperhub_core::config::new_config_uuid(),
            name: "GITLAB_HOST".into(),
            value: SecretValue::Inline {
                value: "gitlab.example.com".into(),
            },
        });
        app.field = 0;

        edit_selected(&mut app);
        let modal = app.modal.take().unwrap();
        assert!(modal.title.contains("- 清空"));
        apply_input(
            &mut app,
            InputModal {
                value: Zeroizing::new("-".into()),
                ..modal
            },
        )
        .unwrap();

        match &app.config.environment[0].value {
            SecretValue::Inline { value } => assert!(value.is_empty()),
            _ => panic!("environment value should remain inline"),
        }
        assert!(app.status.contains("已清空"));
        assert!(app.dirty);
    }

    #[test]
    fn header_editor_lists_adds_edits_and_deletes_unbounded_entries() {
        let mut app = test_app();
        app.category = CATEGORY_CREDENTIAL;
        add_selected(&mut app);
        for index in 0..128 {
            apply_header_field(
                &mut app,
                HeaderField::Credential(0),
                &format!("X-Test-{index:03}"),
                &format!("secret-{index}"),
            )
            .unwrap();
        }
        open_header(&mut app, HeaderField::Credential(0));
        let lines = detail_lines(&app);
        assert_eq!(lines.len(), 129);
        assert!(lines
            .iter()
            .any(|line| line == "PRIVATE-TOKEN: 删除客户端 Header"));
        assert!(lines.iter().any(|line| line.starts_with("X-Test-000: ")));
        assert!(!lines.join("\n").contains("secret-0"));

        let selected = sorted_header_names(&app, HeaderField::Credential(0))
            .iter()
            .position(|name| name == "X-Test-001")
            .unwrap();
        app.header_editor.as_mut().unwrap().selected = selected;
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        )
        .unwrap();
        assert!(!app.config.plugins[credential_plugin_index(&app.config, 0)]
            .headers
            .contains_key("X-Test-001"));
        assert_eq!(
            app.config.plugins[credential_plugin_index(&app.config, 0)]
                .headers
                .len(),
            128
        );

        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
        )
        .unwrap();
        assert!(matches!(
            app.modal.as_ref().map(|modal| &modal.action),
            Some(InputAction::HeaderName(HeaderField::Credential(0)))
        ));
    }

    fn test_root_certificate() -> (rcgen::Certificate, std::path::PathBuf) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "HyperHub TUI Root");
        let certificate = params.self_signed(&key).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "hyperhub-tui-cert-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("ca.pem");
        std::fs::write(&source, certificate.pem()).unwrap();
        (certificate, source)
    }

    #[test]
    fn root_certificate_category_imports_toggles_and_previews() {
        let (certificate, source) = test_root_certificate();
        let mut app = test_app();
        app.path = source.parent().unwrap().join("config.bin");
        config_store::save_encrypted(&app.path, &app.config, b"password").unwrap();
        app.category = CATEGORY_CERTIFICATE;

        add_selected(&mut app);
        assert!(matches!(
            app.modal.as_ref().map(|modal| &modal.action),
            Some(InputAction::ImportRootCertificate)
        ));
        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new(source.display().to_string().into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::ImportRootCertificate,
            },
        )
        .unwrap();
        assert_eq!(app.config.root_certificates.len(), 1);
        assert!(app.config.root_certificates[0].enabled);
        let fingerprint = app.config.root_certificates[0].fingerprint.clone();
        assert_eq!(fingerprint.len(), 64);

        let lines = editor_lines(&app, ObjectEditor::RootCertificate(0));
        let joined = lines.join("\n");
        assert!(lines.len() > 3);
        assert!(joined.contains("HyperHub TUI Root"));
        assert!(joined.contains("主体"));
        assert!(joined.contains("SHA-256"));
        assert!(!joined.contains(source.display().to_string().as_str()));

        let list = detail_lines(&app);
        assert!(list[0].contains("HyperHub TUI Root"));
        assert!(list[0].contains("启用"));

        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new(source.display().to_string().into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::ImportRootCertificate,
            },
        )
        .unwrap();
        assert_eq!(app.config.root_certificates.len(), 1);
        assert!(app.status.contains("已导入过"));

        app.field = 1;
        edit_object_field(&mut app, ObjectEditor::RootCertificate(0));
        assert!(!app.config.root_certificates[0].enabled);

        app.field = 0;
        let summary = app
            .root_certificate_cache
            .as_deref()
            .unwrap()
            .first()
            .unwrap()
            .summary
            .clone();
        assert!(summary.contains("HyperHub TUI Root"));
        assert!(summary.contains("SHA-256"));
        assert_eq!(
            certificate.der().as_ref(),
            config_store::read_root_certificate(&app.path, b"password", &fingerprint)
                .unwrap()
                .as_ref()
        );

        app.config.root_certificates.push(RootCertificate {
            uuid: hyperhub_core::config::new_config_uuid(),
            fingerprint: fingerprint.clone(),
            host: Some("localhost:443".into()),
            enabled: true,
        });
        refresh_root_certificate_cache(&mut app);
        delete_selected(&mut app);
        assert_eq!(app.config.root_certificates.len(), 1);
        assert_eq!(
            app.config.root_certificates[0].host.as_deref(),
            Some("localhost:443")
        );
        assert!(config_store::root_certificates_dir(&app.path)
            .join(format!("{fingerprint}.bin"))
            .exists());

        app.field = 0;
        delete_selected(&mut app);
        assert!(app.config.root_certificates.is_empty());
        assert!(!config_store::root_certificates_dir(&app.path)
            .join(format!("{fingerprint}.bin"))
            .exists());
        std::fs::remove_dir_all(source.parent().unwrap()).ok();
    }

    #[test]
    fn root_certificate_list_renders_state_and_preview_popup() {
        let mut app = test_app();
        app.category = CATEGORY_CERTIFICATE;
        let fingerprint =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned();
        app.config.root_certificates.push(RootCertificate {
            uuid: hyperhub_core::config::new_config_uuid(),
            fingerprint: fingerprint.clone(),
            host: None,
            enabled: true,
        });
        app.root_certificate_cache = Some(vec![RootCertificateView {
            fingerprint: fingerprint.clone(),
            name: "Corp Root CA".into(),
            summary: "主体              CN=Corp Root\n签发者            CN=Corp Root".into(),
        }]);
        app.field = 0;
        let lines = detail_lines(&app);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Corp Root CA"));
        assert!(lines[0].contains("启用"));
        assert!(!lines[0].contains('\\'));
        assert!(!lines[0].contains(&fingerprint));

        let editor = editor_lines(&app, ObjectEditor::RootCertificate(0)).join("\n");
        assert!(editor.contains("信任范围          全局根证书"));
        assert!(editor.contains("指纹"));
        assert!(editor.contains("主体              CN=Corp Root"));

        app.config.root_certificates[0].host = Some("example.test:443".into());
        let editor = editor_lines(&app, ObjectEditor::RootCertificate(0)).join("\n");
        assert!(editor.contains("信任范围          example.test:443"));
        assert!(detail_lines(&app)[0].contains("example.test:443"));

        app.root_certificate_cache = None;
        let lines = detail_lines(&app);
        assert!(lines[0].contains("01:23:45:67:89:ab:cd:ef…"));

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
    }

    #[test]
    fn root_certificate_space_toggles_on_homepage_and_enter_opens_details() {
        let mut app = test_app();
        app.category = CATEGORY_CERTIFICATE;
        let fingerprint =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned();
        app.config.root_certificates.push(RootCertificate {
            uuid: hyperhub_core::config::new_config_uuid(),
            fingerprint: fingerprint.clone(),
            host: None,
            enabled: true,
        });
        app.root_certificate_cache = Some(vec![RootCertificateView {
            fingerprint: fingerprint.clone(),
            name: "Corp Root CA".into(),
            summary: "主体              CN=Corp Root".into(),
        }]);
        app.field = 0;

        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        )
        .unwrap();
        assert!(!app.config.root_certificates[0].enabled);
        assert!(app.editor.is_none());

        handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)).unwrap();
        assert!(matches!(app.editor, Some(ObjectEditor::RootCertificate(0))));
    }

    #[test]
    fn ssh_key_preview_renders_copy_instruction_inside_popup() {
        let preview = SshKeyPreview {
            algorithm: "ssh-rsa".into(),
            openssh: format!("ssh-rsa {} gitlab", "A".repeat(600)),
            fingerprint: "SHA256:test-fingerprint".into(),
            copy_message: None,
        };
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw_ssh_key_preview(frame, frame.area(), &preview, Color::Cyan))
            .unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("SHA256:test-fingerprint"));
        assert!(rendered.contains("Enter / c / Ctrl+C"));
        assert!(rendered.contains("Esc/q"));
    }

    #[test]
    fn ssh_credential_editor_exposes_account_list() {
        let mut app = test_app();
        app.category = CATEGORY_CREDENTIAL;
        add_selected(&mut app);
        edit_credential_field(&mut app, 0, 1);

        let editor = editor_lines(&app, ObjectEditor::Credential(0)).join("\n");
        assert!(editor.contains("SSH 账号"));

        edit_credential_field(&mut app, 0, 2);
        assert!(app.ssh_account_editor.is_some());
    }

    #[test]
    fn ssh_account_can_be_added_and_opened() {
        let mut app = ssh_account_app("ubuntu");
        let idx = credential_plugin_index(&app.config, 0);
        assert_eq!(app.config.plugins[idx].ssh_accounts[0].username, "ubuntu");

        handle_ssh_account_editor_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.ssh_account_detail.is_some());
        let detail = detail_lines(&app).join("\n");
        assert!(detail.contains("ubuntu"));
        assert!(detail.contains("私钥"));
        assert!(detail.contains("密码"));
    }

    #[test]
    fn ssh_account_rejects_duplicate_username() {
        let mut app = ssh_account_app("ubuntu");
        let result = apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new("ubuntu".into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::AddSshAccount(0),
            },
        );
        assert!(result.unwrap_err().contains("已存在"));
    }

    #[test]
    fn ssh_key_editor_add_picker_opens_path_import() {
        let mut app = ssh_account_app("ubuntu");
        app.ssh_account_detail = Some(SshAccountDetail {
            credential: 0,
            account: 0,
            field: 1,
        });
        handle_ssh_account_detail_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        handle_ssh_key_editor_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
        );
        assert!(app.ssh_key_add_picker.is_some());
        handle_ssh_key_add_picker_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            app.modal.as_ref().map(|modal| &modal.action),
            Some(InputAction::ImportSshKeyPath(0, 0))
        ));
    }

    #[test]
    fn ssh_password_editor_adds_and_edits_passwords() {
        let mut app = ssh_account_app("ubuntu");
        app.ssh_account_detail = Some(SshAccountDetail {
            credential: 0,
            account: 0,
            field: 2,
        });
        handle_ssh_account_detail_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.ssh_password_editor.is_some());

        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new("s3cret".into()),
                cursor: 0,
                masked: true,
                multiline: false,
                action: InputAction::Secret(SecretField::SshPassword(0, 0, None)),
            },
        )
        .unwrap();
        let idx = credential_plugin_index(&app.config, 0);
        assert_eq!(app.config.plugins[idx].ssh_accounts[0].passwords.len(), 1);
    }

    #[test]
    fn ssh_private_key_import_rejects_missing_file() {
        let mut app = ssh_account_app("ubuntu");
        let result = apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new("E:\\no\\such\\id_rsa".into()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::ImportSshKeyPath(0, 0),
            },
        );
        let error = result.unwrap_err();
        assert!(error.contains("文件不存在或不可读"));
    }

    fn ssh_account_app(username: &str) -> App {
        let mut app = test_app();
        app.category = CATEGORY_CREDENTIAL;
        add_selected(&mut app);
        edit_credential_field(&mut app, 0, 1);
        edit_credential_field(&mut app, 0, 2);
        apply_input(
            &mut app,
            InputModal {
                title: String::new(),
                value: Zeroizing::new(username.to_owned()),
                cursor: 0,
                masked: false,
                multiline: false,
                action: InputAction::AddSshAccount(0),
            },
        )
        .unwrap();
        app
    }

    #[test]
    fn selection_hint_describes_sidebar_category() {
        let mut app = test_app();
        app.focus = Focus::Sidebar;
        app.category = CATEGORY_BASIC;
        assert_eq!(
            selection_hint(&app).unwrap(),
            "基础：监听地址、网关故障策略与 Debug 热更新"
        );
        app.category = CATEGORY_ROUTE;
        assert_eq!(
            selection_hint(&app).unwrap(),
            "路由：默认路由与用户路由规则"
        );
    }

    #[test]
    fn selection_hint_describes_selected_basic_field() {
        let mut app = test_app();
        app.focus = Focus::Detail;
        app.category = CATEGORY_BASIC;
        app.field = 0;
        assert_eq!(selection_hint(&app).unwrap(), "失败关闭：网关异常时拒绝");
        app.config.mode = EnforcementMode::Observe;
        assert_eq!(
            selection_hint(&app).unwrap(),
            "失败放行：网关异常时直连兜底"
        );

        app.field = 3;
        assert_eq!(
            selection_hint(&app).unwrap(),
            "调试事件：关闭，保存后热更新运行中的 Serve"
        );
    }

    #[test]
    fn selection_hint_handles_empty_lists_and_editors() {
        let mut app = test_app();
        app.focus = Focus::Detail;
        app.category = CATEGORY_PROXY;
        app.field = 0;
        assert_eq!(selection_hint(&app).unwrap(), "暂无代理，按 a 新增");

        app.editor = Some(ObjectEditor::DefaultRoute);
        assert_eq!(
            selection_hint(&app).unwrap(),
            "默认路由：内置兜底，配置启用状态、拒绝动作与直通"
        );
    }

    #[test]
    fn bottom_bar_shows_selection_hint_in_lists_and_editors() {
        let mut app = test_app();
        app.focus = Focus::Detail;
        app.category = CATEGORY_BASIC;
        app.field = 0;

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains(" › "));

        app.editor = Some(ObjectEditor::DefaultRoute);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains(" › "));
    }
    fn test_app() -> App {
        App {
            config: Config::default(),
            password: Zeroizing::new("password".into()),
            previous_password: None,
            path: "config.bin".into(),
            root_certificate_cache: None,
            category: CATEGORY_GATEWAY,
            field: 0,
            editor: None,
            focus: Focus::Sidebar,
            dirty: false,
            help: false,
            exit_prompt: false,
            modal: None,
            header_editor: None,
            list_editor: None,
            ssh_account_editor: None,
            ssh_account_detail: None,
            ssh_key_editor: None,
            ssh_password_editor: None,
            ssh_key_add_picker: None,
            reference_picker: None,
            ssh_key_preview: None,
            managed_processes: Vec::new(),
            status: String::new(),
            saved: false,
            discarded: false,
            live: false,
        }
    }

    #[test]
    fn protection_category_creates_and_binds_profiles() {
        let mut app = test_app();
        app.category = CATEGORY_PROTECTION;
        add_selected(&mut app);
        assert_eq!(app.config.protections.len(), 1);
        assert!(matches!(app.editor, Some(ObjectEditor::Protection(0))));
        assert!(!app.config.protections[0].data.enabled);
        app.editor = None;
        app.field = 0;
        let enabled = app.config.protections[0].enabled;
        handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)).unwrap();
        assert!(matches!(app.editor, Some(ObjectEditor::Protection(0))));
        assert_eq!(app.config.protections[0].enabled, enabled);
        app.editor = None;
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(app.config.protections[0].enabled, !enabled);
        app.editor = None;
        app.category = CATEGORY_ROUTE;
        add_selected(&mut app);
        app.editor = Some(ObjectEditor::Route(0));
        app.field = 8;
        edit_selected(&mut app);
        assert!(matches!(
            app.reference_picker,
            Some(ReferencePicker {
                kind: ReferenceKind::Protection,
                ..
            })
        ));
    }

    #[test]
    fn protection_editor_uses_overview_and_two_subpages() {
        let mut app = test_app();
        app.category = CATEGORY_PROTECTION;
        add_selected(&mut app);
        let overview = editor_lines(&app, ObjectEditor::Protection(0));
        assert_eq!(overview.len(), 5);
        assert!(overview[2].contains("仅记录"));
        assert!(overview[3].contains("本地检测"));
        assert!(overview[4].contains("智能判断"));

        app.field = 3;
        edit_selected(&mut app);
        assert!(matches!(app.editor, Some(ObjectEditor::ProtectionLocal(0))));
        let local = editor_lines(&app, ObjectEditor::ProtectionLocal(0));
        assert_eq!(local.len(), 8);
        assert!(local[4].contains("扫描托管 Secret"));
        assert!(local[6].contains("扫描私钥"));
        assert!(local[7].contains("扫描提示注入"));

        handle_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)).unwrap();
        assert!(matches!(app.editor, Some(ObjectEditor::Protection(0))));
        app.field = 4;
        edit_selected(&mut app);
        assert!(matches!(
            app.editor,
            Some(ObjectEditor::ProtectionIntelligence(0))
        ));
        assert_eq!(
            editor_lines(&app, ObjectEditor::ProtectionIntelligence(0)).len(),
            10
        );
    }

    #[test]
    fn protection_scan_checkboxes_toggle_only_with_space() {
        let mut app = test_app();
        app.category = CATEGORY_PROTECTION;
        add_selected(&mut app);
        app.editor = Some(ObjectEditor::ProtectionLocal(0));
        app.field = 6;
        let enabled = app.config.protections[0].data.detect_private_keys;
        handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)).unwrap();
        assert_eq!(app.config.protections[0].data.detect_private_keys, enabled);
        assert!(app.status.contains("Space"));
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(app.config.protections[0].data.detect_private_keys, !enabled);
    }
}

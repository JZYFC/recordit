use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap};

use super::command_line::tokenize_command;
use super::term::{TuiTerminal, centered_rect, restore_terminal, setup_terminal};
use super::viewport::Viewport;

const LOG_PREVIEW_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone)]
struct ExecutionInfo {
    command: Vec<String>,
    cwd: String,
    success: bool,
    exit_code: Option<i64>,
    detail: Option<String>,
}

#[derive(Debug, Clone)]
struct SessionInfo {
    name: String,
    path: PathBuf,
    message: Option<String>,
    execution: Option<ExecutionInfo>,
}

impl SessionInfo {
    fn status_label(&self) -> String {
        match &self.execution {
            Some(exec) if exec.success => "ok".to_string(),
            Some(exec) => match (exec.exit_code, &exec.detail) {
                (Some(code), _) => format!("exit {code}"),
                (None, Some(detail)) => detail.clone(),
                (None, None) => "fail".to_string(),
            },
            None => "no-meta".to_string(),
        }
    }

    fn command_label(&self) -> String {
        match &self.execution {
            Some(exec) if !exec.command.is_empty() => {
                let joined = exec.command.join(" ");
                if joined.chars().count() > 42 {
                    let truncated: String = joined.chars().take(39).collect();
                    format!("{truncated}…")
                } else {
                    joined
                }
            }
            _ => "—".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    Overview,
    Files,
    Stdout,
    Stderr,
    Stdin,
}

impl DetailTab {
    const ALL: [DetailTab; 5] = [
        DetailTab::Overview,
        DetailTab::Files,
        DetailTab::Stdout,
        DetailTab::Stderr,
        DetailTab::Stdin,
    ];

    fn title(self) -> &'static str {
        match self {
            DetailTab::Overview => "Overview",
            DetailTab::Files => "Files",
            DetailTab::Stdout => "stdout",
            DetailTab::Stderr => "stderr",
            DetailTab::Stdin => "stdin",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    fn previous(self) -> Self {
        let idx = self.index();
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

struct SessionCache {
    name: String,
    files: Vec<String>,
    stdout: String,
    stderr: String,
    stdin: String,
}

enum PromptMode {
    None,
    Command,
}

enum BrowserAction {
    None,
    Quit,
    LaunchRun(crate::RunArgs),
}

struct App {
    cwd: PathBuf,
    record_base_arg: PathBuf,
    sessions: Vec<SessionInfo>,
    list_state: ListState,
    detail_tab: DetailTab,
    detail_view: Viewport,
    show_help: bool,
    status: String,
    cache: Option<SessionCache>,
    prompt: PromptMode,
    prompt_input: String,
    prompt_error: String,
}

impl App {
    fn new(cwd: PathBuf, record_base_arg: PathBuf, sessions: Vec<SessionInfo>) -> Self {
        let mut list_state = ListState::default();
        if !sessions.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            cwd,
            record_base_arg,
            sessions,
            list_state,
            detail_tab: DetailTab::Overview,
            detail_view: Viewport::default(),
            show_help: false,
            status: String::new(),
            cache: None,
            prompt: PromptMode::None,
            prompt_input: String::new(),
            prompt_error: String::new(),
        }
    }

    fn reset_detail_scroll(&mut self) {
        self.detail_view.y = 0;
        self.detail_view.x = 0;
    }

    fn selected_index(&self) -> Option<usize> {
        self.list_state.selected()
    }

    fn selected_session(&self) -> Option<&SessionInfo> {
        self.selected_index().and_then(|idx| self.sessions.get(idx))
    }

    fn select_next(&mut self) {
        if self.sessions.is_empty() {
            return;
        }
        let next = match self.list_state.selected() {
            Some(idx) if idx + 1 < self.sessions.len() => idx + 1,
            Some(_) => 0,
            None => 0,
        };
        self.list_state.select(Some(next));
        self.invalidate_cache();
    }

    fn select_previous(&mut self) {
        if self.sessions.is_empty() {
            return;
        }
        let prev = match self.list_state.selected() {
            Some(0) | None => self.sessions.len() - 1,
            Some(idx) => idx - 1,
        };
        self.list_state.select(Some(prev));
        self.invalidate_cache();
    }

    fn invalidate_cache(&mut self) {
        self.cache = None;
        self.reset_detail_scroll();
    }

    fn refresh_sessions(&mut self, record_base: &Path) -> Result<()> {
        let sessions = load_sessions(record_base)?;
        let previous = self
            .selected_session()
            .map(|s| s.name.clone())
            .unwrap_or_default();
        self.sessions = sessions;
        if self.sessions.is_empty() {
            self.list_state.select(None);
            self.cache = None;
            self.status = "No sessions found".to_string();
            return Ok(());
        }
        let restored = self
            .sessions
            .iter()
            .position(|s| s.name == previous)
            .unwrap_or(0);
        self.list_state.select(Some(restored));
        self.invalidate_cache();
        self.status = format!("Loaded {} session(s)", self.sessions.len());
        Ok(())
    }

    fn ensure_cache(&mut self) {
        let Some(session) = self.selected_session().cloned() else {
            self.cache = None;
            return;
        };
        if let Some(cache) = &self.cache
            && cache.name == session.name
        {
            return;
        }
        self.cache = Some(load_session_cache(&session));
        self.reset_detail_scroll();
    }

    fn current_body_lines(&mut self) -> Vec<Line<'static>> {
        self.ensure_cache();
        let Some(session) = self.selected_session().cloned() else {
            return vec![Line::from("No session selected")];
        };
        let Some(cache) = self.cache.as_ref() else {
            return vec![Line::from("Failed to load session details")];
        };

        match self.detail_tab {
            DetailTab::Overview => overview_lines(&session),
            DetailTab::Files => {
                if cache.files.is_empty() {
                    vec![Line::from("(no recorded files)")]
                } else {
                    cache.files.iter().map(|f| Line::from(f.clone())).collect()
                }
            }
            DetailTab::Stdout => text_lines(&cache.stdout, "(empty stdout)"),
            DetailTab::Stderr => text_lines(&cache.stderr, "(empty stderr)"),
            DetailTab::Stdin => text_lines(&cache.stdin, "(empty stdin)"),
        }
    }

    fn open_command_prompt(&mut self) {
        self.prompt = PromptMode::Command;
        self.prompt_input.clear();
        self.prompt_error.clear();
    }

    fn try_launch_from_prompt(&mut self) -> Result<BrowserAction> {
        let cmd = match tokenize_command(self.prompt_input.trim()) {
            Ok(cmd) => cmd,
            Err(err) => {
                self.prompt_error = err.to_string();
                return Ok(BrowserAction::None);
            }
        };
        let version_name = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
        Ok(BrowserAction::LaunchRun(crate::RunArgs {
            cwd: self.cwd.clone(),
            record_base: self.record_base_arg.clone(),
            version_name,
            message: String::new(),
            record: Vec::new(),
            stdin: None,
            use_pty: false,
            cmd,
        }))
    }
}

pub(crate) async fn run_browser(cwd: PathBuf, record_base_arg: PathBuf) -> Result<()> {
    let mut context = crate::Context {
        git_root: None,
        session_dir: None,
    };
    let record_base = crate::resolve_record_base(&cwd, &record_base_arg, &mut context);

    let sessions = if record_base.exists() {
        load_sessions(&record_base)?
    } else {
        Vec::new()
    };
    let mut app = App::new(cwd, record_base_arg, sessions);
    if record_base.exists() {
        app.status = format!("Base: {}", record_base.display());
    } else {
        app.status = format!(
            "No recordings at {} — press R to run a command",
            record_base.display()
        );
    }

    let mut terminal = setup_terminal()?;
    let result = event_loop(&mut terminal, &mut app, &record_base).await;
    let restore_result = restore_terminal(&mut terminal);
    result.and(restore_result)
}

async fn event_loop(terminal: &mut TuiTerminal, app: &mut App, record_base: &Path) -> Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;

        if !event::poll(std::time::Duration::from_millis(50))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }

        match handle_key(app, key, record_base)? {
            BrowserAction::None => {}
            BrowserAction::Quit => return Ok(()),
            BrowserAction::LaunchRun(args) => {
                // Leave browser terminal, run live monitor, then return to browser.
                restore_terminal(terminal)?;
                let run_result = super::run::run_live(args).await;
                *terminal = setup_terminal()?;
                match run_result {
                    Ok(()) => {
                        let sessions = if record_base.exists() {
                            load_sessions(record_base)?
                        } else {
                            Vec::new()
                        };
                        app.sessions = sessions;
                        if !app.sessions.is_empty() {
                            app.list_state.select(Some(0));
                        }
                        app.invalidate_cache();
                        app.status = "Returned from run".into();
                    }
                    Err(err) => {
                        app.status = format!("Run failed: {err}");
                    }
                }
            }
        }
    }
}

fn handle_key(app: &mut App, key: KeyEvent, record_base: &Path) -> Result<BrowserAction> {
    if app.show_help {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter => {
                app.show_help = false;
            }
            _ => {}
        }
        return Ok(BrowserAction::None);
    }

    if matches!(app.prompt, PromptMode::Command) {
        return handle_prompt_key(app, key);
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return Ok(BrowserAction::Quit),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return Ok(BrowserAction::Quit);
        }
        KeyCode::Char('?') => app.show_help = true,
        KeyCode::Char('R') => app.open_command_prompt(),
        KeyCode::Char('r') => app.refresh_sessions(record_base)?,
        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
        KeyCode::Up | KeyCode::Char('k') => app.select_previous(),
        KeyCode::PageDown => {
            for _ in 0..10 {
                app.select_next();
            }
        }
        KeyCode::PageUp => {
            for _ in 0..10 {
                app.select_previous();
            }
        }
        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.detail_view.y = app.detail_view.y.saturating_add(10);
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.detail_view.y = app.detail_view.y.saturating_sub(10);
        }
        KeyCode::Char('J') => app.detail_view.y = app.detail_view.y.saturating_add(1),
        KeyCode::Char('K') => app.detail_view.y = app.detail_view.y.saturating_sub(1),
        KeyCode::Char('g') => app.detail_view.y = 0,
        KeyCode::Char('G') => app.detail_view.y = u16::MAX,
        KeyCode::Home => {
            if !app.sessions.is_empty() {
                app.list_state.select(Some(0));
                app.invalidate_cache();
            }
        }
        KeyCode::End => {
            if !app.sessions.is_empty() {
                app.list_state.select(Some(app.sessions.len() - 1));
                app.invalidate_cache();
            }
        }
        // Tab switching: Tab / Shift-Tab / 1-5 only (arrows pan horizontally).
        KeyCode::Tab => {
            app.detail_tab = app.detail_tab.next();
            app.reset_detail_scroll();
        }
        KeyCode::BackTab => {
            app.detail_tab = app.detail_tab.previous();
            app.reset_detail_scroll();
        }
        KeyCode::Left => {
            app.detail_view.scroll_x(-4);
        }
        KeyCode::Right => {
            if app.detail_tab != DetailTab::Overview {
                app.detail_view.scroll_x(4);
            }
        }
        KeyCode::Char('1') => {
            app.detail_tab = DetailTab::Overview;
            app.reset_detail_scroll();
        }
        KeyCode::Char('2') => {
            app.detail_tab = DetailTab::Files;
            app.reset_detail_scroll();
        }
        KeyCode::Char('3') => {
            app.detail_tab = DetailTab::Stdout;
            app.reset_detail_scroll();
        }
        KeyCode::Char('4') => {
            app.detail_tab = DetailTab::Stderr;
            app.reset_detail_scroll();
        }
        KeyCode::Char('5') => {
            app.detail_tab = DetailTab::Stdin;
            app.reset_detail_scroll();
        }
        _ => {}
    }
    Ok(BrowserAction::None)
}

fn handle_prompt_key(app: &mut App, key: KeyEvent) -> Result<BrowserAction> {
    match key.code {
        KeyCode::Esc => {
            app.prompt = PromptMode::None;
            app.prompt_input.clear();
            app.prompt_error.clear();
        }
        KeyCode::Enter => {
            let action = app.try_launch_from_prompt()?;
            if matches!(action, BrowserAction::LaunchRun(_)) {
                app.prompt = PromptMode::None;
                app.prompt_input.clear();
                app.prompt_error.clear();
                return Ok(action);
            }
        }
        KeyCode::Backspace => {
            app.prompt_input.pop();
            app.prompt_error.clear();
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.prompt_input.push(c);
            app.prompt_error.clear();
        }
        _ => {}
    }
    Ok(BrowserAction::None)
}

fn draw(frame: &mut ratatui::Frame, app: &mut App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    draw_title(frame, app, chunks[0]);
    draw_main(frame, app, chunks[1]);
    draw_footer(frame, app, chunks[2]);

    if app.show_help {
        draw_help(frame, area);
    }
    if matches!(app.prompt, PromptMode::Command) {
        draw_command_prompt(frame, area, app);
    }
}

fn draw_title(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let total = app.sessions.len();
    let selected = app.selected_index().map(|i| i + 1).unwrap_or(0);
    let title = Line::from(vec![
        Span::styled(
            " recordit ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" sessions "),
        Span::styled(
            format!("{selected}/{total}"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("  "),
        Span::styled("R run", Style::default().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled("? help", Style::default().fg(Color::DarkGray)),
    ]);
    frame.render_widget(Paragraph::new(title), area);
}

fn draw_main(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    draw_session_list(frame, app, chunks[0]);
    draw_detail(frame, app, chunks[1]);
}

fn draw_session_list(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Sessions ")
        .border_style(Style::default().fg(Color::DarkGray));

    if app.sessions.is_empty() {
        let empty = Paragraph::new(
            "No sessions found.\n\nPress R to run a command,\nor: recordit tui run -- <cmd>",
        )
        .style(Style::default().fg(Color::DarkGray))
        .wrap(Wrap { trim: false })
        .block(block);
        frame.render_widget(empty, area);
        return;
    }

    let items: Vec<ListItem> = app
        .sessions
        .iter()
        .map(|session| {
            let marker = if session.message.is_some() { "·" } else { " " };
            let status = session.status_label();
            let status_color = match status.as_str() {
                "ok" => Color::Green,
                "no-meta" => Color::DarkGray,
                _ => Color::Red,
            };
            let line = Line::from(vec![
                Span::raw(format!("{marker} ")),
                Span::styled(session.name.clone(), Style::default()),
                Span::raw("  "),
                Span::styled(status, Style::default().fg(status_color)),
            ]);
            let cmd_line = Line::from(Span::styled(
                format!("    {}", session.command_label()),
                Style::default().fg(Color::DarkGray),
            ));
            ListItem::new(vec![line, cmd_line])
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Cyan)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_detail(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let Some(session) = app.selected_session().cloned() else {
        let empty = Paragraph::new("Select a session to inspect\n\nPress R to run a new command")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Detail ")
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
        frame.render_widget(empty, area);
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let titles: Vec<Line> = DetailTab::ALL
        .iter()
        .map(|tab| Line::from(tab.title()))
        .collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", session.name))
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .select(app.detail_tab.index())
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, chunks[0]);

    let body = app.current_body_lines();
    let body_area = chunks[1];
    let view_h = body_area.height.saturating_sub(2) as usize;
    let view_w = body_area.width.saturating_sub(2) as usize;

    let wrap = app.detail_tab == DetailTab::Overview;
    let max_w = if wrap {
        view_w
    } else {
        body.iter().map(Line::width).max().unwrap_or(0).max(view_w)
    };
    app.detail_view
        .update(body.len(), max_w, view_h, view_w, wrap, false);
    let (scroll_y, scroll_x) = app.detail_view.offset();
    let indicators = app.detail_view.indicators(wrap);
    let title = format!(" {}{} ", session.name, indicators);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::DarkGray));

    let paragraph = Paragraph::new(body)
        .block(block)
        .scroll((scroll_y, scroll_x));
    if wrap {
        frame.render_widget(paragraph.wrap(Wrap { trim: false }), body_area);
    } else {
        frame.render_widget(paragraph, body_area);
    }
}

fn draw_footer(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let hints = " j/k select · Tab pane · ←→ hscroll · R run · r refresh · ? help · q quit ";
    let text = if app.status.is_empty() {
        Line::from(hints).style(Style::default().fg(Color::DarkGray))
    } else {
        Line::from(vec![
            Span::styled(app.status.clone(), Style::default().fg(Color::Yellow)),
            Span::raw("  "),
            Span::styled(hints, Style::default().fg(Color::DarkGray)),
        ])
    };
    frame.render_widget(Paragraph::new(text), area);
}

fn draw_command_prompt(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup = centered_rect(72, 28, area);
    frame.render_widget(Clear, popup);

    let mut lines = vec![
        Line::from(Span::styled(
            "Run command",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("> {}_", app.prompt_input),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
    ];
    if !app.prompt_error.is_empty() {
        lines.push(Line::from(Span::styled(
            app.prompt_error.clone(),
            Style::default().fg(Color::Red),
        )));
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        "Enter to launch · Esc to cancel",
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" New run ")
                    .border_style(Style::default().fg(Color::Cyan))
                    .style(Style::default().bg(Color::Black)),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_help(frame: &mut ratatui::Frame, area: Rect) {
    let popup = centered_rect(70, 70, area);
    frame.render_widget(Clear, popup);

    let help = vec![
        Line::from(Span::styled(
            "Keyboard shortcuts",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  R              open command prompt and run"),
        Line::from("  j / ↓          next session"),
        Line::from("  k / ↑          previous session"),
        Line::from("  PgUp / PgDn    jump 10 sessions"),
        Line::from("  Home / End     first / last session"),
        Line::from("  Tab / Shift-Tab  next / previous detail pane"),
        Line::from("  1-5            Overview/Files/stdout/stderr/stdin"),
        Line::from("  ← / →          horizontal scroll in detail body"),
        Line::from("  g / G          scroll detail to top / bottom"),
        Line::from("  J / K          scroll detail down / up"),
        Line::from("  r              refresh session list"),
        Line::from("  q / Esc        quit"),
        Line::from(""),
        Line::from(Span::styled(
            "Press ? or Esc to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    frame.render_widget(
        Paragraph::new(help)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Help ")
                    .border_style(Style::default().fg(Color::Cyan))
                    .style(Style::default().bg(Color::Black)),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn overview_lines(session: &SessionInfo) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("Session   ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            session.name.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Path      ", Style::default().fg(Color::DarkGray)),
        Span::raw(session.path.display().to_string()),
    ]));

    let message = session
        .message
        .clone()
        .unwrap_or_else(|| "(none)".to_string());
    lines.push(Line::from(vec![
        Span::styled("Message   ", Style::default().fg(Color::DarkGray)),
        Span::raw(message),
    ]));

    match &session.execution {
        Some(exec) => {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Execution",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(vec![
                Span::styled("Command   ", Style::default().fg(Color::DarkGray)),
                Span::raw(exec.command.join(" ")),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Cwd       ", Style::default().fg(Color::DarkGray)),
                Span::raw(exec.cwd.clone()),
            ]));
            let (status_text, status_color) = if exec.success {
                ("success".to_string(), Color::Green)
            } else {
                let label = match (exec.exit_code, &exec.detail) {
                    (Some(code), _) => format!("failed (exit {code})"),
                    (None, Some(detail)) => format!("failed ({detail})"),
                    (None, None) => "failed".to_string(),
                };
                (label, Color::Red)
            };
            lines.push(Line::from(vec![
                Span::styled("Status    ", Style::default().fg(Color::DarkGray)),
                Span::styled(status_text, Style::default().fg(status_color)),
            ]));
            if let Some(detail) = &exec.detail {
                lines.push(Line::from(vec![
                    Span::styled("Detail    ", Style::default().fg(Color::DarkGray)),
                    Span::raw(detail.clone()),
                ]));
            }
        }
        None => {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "No execution.toml found (session may be incomplete).",
                Style::default().fg(Color::Yellow),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Tip: use the Files / stdout / stderr / stdin tabs for full content.",
        Style::default().fg(Color::DarkGray),
    )));
    lines
}

fn text_lines(content: &str, empty_placeholder: &'static str) -> Vec<Line<'static>> {
    if content.is_empty() {
        return vec![Line::from(Span::styled(
            empty_placeholder,
            Style::default().fg(Color::DarkGray),
        ))];
    }
    content.lines().map(|l| Line::from(l.to_string())).collect()
}

fn load_session_cache(session: &SessionInfo) -> SessionCache {
    SessionCache {
        name: session.name.clone(),
        files: list_session_files(&session.path),
        stdout: read_log_preview(&session.path.join("io").join("stdout.log")),
        stderr: read_log_preview(&session.path.join("io").join("stderr.log")),
        stdin: read_log_preview(&session.path.join("io").join("stdin.log")),
    }
}

fn list_session_files(session_path: &Path) -> Vec<String> {
    let files_dir = session_path.join("files");
    let mut entries = Vec::new();
    collect_relative_files(&files_dir, Path::new(""), &mut entries);
    entries.sort();
    entries
}

fn collect_relative_files(root: &Path, relative: &Path, out: &mut Vec<String>) {
    let Ok(read_dir) = fs::read_dir(root) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let rel = relative.join(&name);
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_relative_files(&path, &rel, out);
        } else {
            let label = rel.to_string_lossy().replace('\\', "/");
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push(format!("{label}  ({})", human_size(size)));
        }
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0usize;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

fn read_log_preview(path: &Path) -> String {
    let Ok(bytes) = fs::read(path) else {
        return String::new();
    };
    if bytes.len() <= LOG_PREVIEW_BYTES {
        return String::from_utf8_lossy(&bytes).into_owned();
    }
    let start = bytes.len() - LOG_PREVIEW_BYTES;
    let mut slice = &bytes[start..];
    while !slice.is_empty() && (slice[0] & 0xC0) == 0x80 {
        slice = &slice[1..];
    }
    format!(
        "[truncated: showing last {} of {} bytes]\n{}",
        human_size(LOG_PREVIEW_BYTES as u64),
        human_size(bytes.len() as u64),
        String::from_utf8_lossy(slice)
    )
}

fn load_sessions(record_base: &Path) -> Result<Vec<SessionInfo>> {
    let mut sessions = Vec::new();
    let Ok(read_dir) = fs::read_dir(record_base) else {
        return Ok(sessions);
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let message_path = path.join("MESSAGE.txt");
        let message = fs::read_to_string(&message_path)
            .ok()
            .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
            .filter(|s| !s.trim().is_empty());
        let execution = load_execution(&path.join("execution.toml"));
        sessions.push(SessionInfo {
            name,
            path,
            message,
            execution,
        });
    }

    sessions.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(sessions)
}

fn load_execution(path: &Path) -> Option<ExecutionInfo> {
    let content = fs::read_to_string(path).ok()?;
    let value: toml::Value = toml::from_str(&content).ok()?;

    let command = value
        .get("command")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let cwd = value
        .get("cwd")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let status = value.get("status")?;
    let success = status
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let exit_code = status.get("code").and_then(|v| v.as_integer());
    let detail = status
        .get("detail")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    Some(ExecutionInfo {
        command,
        cwd,
        success,
        exit_code,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_sample_session(base: &Path, name: &str, message: Option<&str>, success: bool) {
        let session = base.join(name);
        fs::create_dir_all(session.join("files").join("src")).unwrap();
        fs::create_dir_all(session.join("io")).unwrap();
        if let Some(msg) = message {
            fs::write(session.join("MESSAGE.txt"), msg).unwrap();
        }
        fs::write(
            session.join("files").join("src").join("main.rs"),
            b"fn main() {}",
        )
        .unwrap();
        fs::write(session.join("io").join("stdout.log"), b"hello stdout").unwrap();
        fs::write(session.join("io").join("stderr.log"), b"").unwrap();
        let code = if success { 0 } else { 1 };
        let toml = format!(
            r#"
command = ["cargo", "test"]
cwd = "C:/project"

[status]
success = {success}
code = {code}
"#
        );
        fs::write(session.join("execution.toml"), toml).unwrap();
    }

    #[test]
    fn load_sessions_reads_message_and_execution() {
        let temp = TempDir::new().unwrap();
        write_sample_session(temp.path(), "20240101-120000-note", Some("hello"), true);
        write_sample_session(temp.path(), "20240102-130000", None, false);

        let sessions = load_sessions(temp.path()).unwrap();
        assert_eq!(sessions.len(), 2);

        assert_eq!(sessions[0].name, "20240102-130000");
        assert!(sessions[0].message.is_none());
        let exec0 = sessions[0].execution.as_ref().unwrap();
        assert!(!exec0.success);
        assert_eq!(exec0.exit_code, Some(1));

        assert_eq!(sessions[1].name, "20240101-120000-note");
        assert_eq!(sessions[1].message.as_deref(), Some("hello"));
        let exec1 = sessions[1].execution.as_ref().unwrap();
        assert!(exec1.success);
        assert_eq!(exec1.command, vec!["cargo", "test"]);
    }

    #[test]
    fn list_session_files_includes_nested_paths() {
        let temp = TempDir::new().unwrap();
        write_sample_session(temp.path(), "s1", None, true);
        let files = list_session_files(&temp.path().join("s1"));
        assert!(files.iter().any(|f| f.starts_with("src/main.rs")));
    }

    #[test]
    fn human_size_formats_reasonably() {
        assert_eq!(human_size(10), "10 B");
        assert_eq!(human_size(2048), "2.0 KB");
    }
}

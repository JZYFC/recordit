mod view;

use std::path::PathBuf;
use view::draw;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::runner::{IoLine, LiveProcess, RunEvent, StreamKind};
use super::term::{TuiTerminal, restore_terminal, setup_terminal};
use super::viewport::Viewport;

const MAX_LINES_PER_STREAM: usize = 8_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Files,
    Env,
    Stdin,
    Stdout,
    Stderr,
}

impl Focus {
    fn all(interleaved: bool) -> &'static [Focus] {
        if interleaved {
            &[
                Focus::Files,
                Focus::Env,
                Focus::Stdin,
                Focus::Stdout, // combined
            ]
        } else {
            &[
                Focus::Files,
                Focus::Env,
                Focus::Stdin,
                Focus::Stdout,
                Focus::Stderr,
            ]
        }
    }

    fn next(self, interleaved: bool) -> Self {
        let items = Self::all(interleaved);
        let idx = items.iter().position(|f| *f == self).unwrap_or(0);
        items[(idx + 1) % items.len()]
    }

    fn previous(self, interleaved: bool) -> Self {
        let items = Self::all(interleaved);
        let idx = items.iter().position(|f| *f == self).unwrap_or(0);
        items[(idx + items.len() - 1) % items.len()]
    }

    fn title(self) -> &'static str {
        match self {
            Focus::Files => "Files",
            Focus::Env => "Env",
            Focus::Stdin => "stdin",
            Focus::Stdout => "stdout",
            Focus::Stderr => "stderr",
        }
    }
}

enum ProcessState {
    Running,
    Exited { success: bool, code: Option<i32> },
}

struct RunApp {
    command_label: String,
    files: Vec<String>,
    env: Vec<(String, String)>,
    stdout_lines: Vec<IoLine>,
    stderr_lines: Vec<IoLine>,
    stdin_history: Vec<IoLine>,
    /// Partial stdin line shown while typing (line mode draft or raw-mode echo).
    stdin_draft: String,
    stdin_history_idx: Option<usize>,
    /// True when keystrokes are consumed by the stdin panel.
    stdin_typing: bool,
    stdin_from_file: bool,
    /// Line-buffered: send on Enter. Raw: send every key immediately.
    line_buffered: bool,
    focus: Focus,
    wrap_streams: bool,
    interleave: bool,
    state: ProcessState,
    status: String,
    show_help: bool,
    show_command: bool,
    auto_follow: bool,
    files_view: Viewport,
    env_view: Viewport,
    stdin_view: Viewport,
    stdout_view: Viewport,
    stderr_view: Viewport,
    combined_view: Viewport,
}

impl RunApp {
    fn new(command_label: String, files: Vec<String>, env: Vec<(String, String)>) -> Self {
        Self {
            command_label,
            files,
            env,
            stdout_lines: Vec::new(),
            stderr_lines: Vec::new(),
            stdin_history: Vec::new(),
            stdin_draft: String::new(),
            stdin_history_idx: None,
            stdin_typing: false,
            stdin_from_file: false,
            line_buffered: true,
            focus: Focus::Stdout,
            wrap_streams: true,
            interleave: false,
            state: ProcessState::Running,
            status: String::new(),
            show_help: false,
            show_command: false,
            auto_follow: true,
            files_view: Viewport::default(),
            env_view: Viewport::default(),
            stdin_view: Viewport::default(),
            stdout_view: Viewport::default(),
            stderr_view: Viewport::default(),
            combined_view: Viewport::default(),
        }
    }

    fn process_running(&self) -> bool {
        matches!(self.state, ProcessState::Running)
    }

    fn viewport_mut(&mut self, focus: Focus) -> &mut Viewport {
        match focus {
            Focus::Files => &mut self.files_view,
            Focus::Env => &mut self.env_view,
            Focus::Stdin => &mut self.stdin_view,
            Focus::Stdout if self.interleave => &mut self.combined_view,
            Focus::Stdout => &mut self.stdout_view,
            Focus::Stderr => &mut self.stderr_view,
        }
    }

    fn lines_mut(&mut self, stream: StreamKind) -> &mut Vec<IoLine> {
        match stream {
            StreamKind::Stdin => &mut self.stdin_history,
            StreamKind::Stdout => &mut self.stdout_lines,
            StreamKind::Stderr => &mut self.stderr_lines,
        }
    }

    fn push_line(&mut self, line: IoLine) {
        push_capped(self.lines_mut(line.stream), line);
    }

    fn apply_event(&mut self, event: RunEvent) {
        match event {
            RunEvent::Line(line) => self.push_line(line),
            RunEvent::ReplaceLine(line) => {
                let lines = self.lines_mut(line.stream);
                if let Some(last) = lines.last_mut() {
                    *last = line;
                } else {
                    push_capped(lines, line);
                }
            }
            RunEvent::Error(message) => self.status = message,
        }
    }

    fn follow_bottom(&mut self) {
        self.stdout_view.follow_bottom();
        self.stderr_view.follow_bottom();
        self.stdin_view.follow_bottom();
        self.combined_view.follow_bottom();
    }

    fn combined_lines(&self) -> Vec<IoLine> {
        let mut all: Vec<IoLine> = self
            .stdout_lines
            .iter()
            .chain(self.stderr_lines.iter())
            .cloned()
            .collect();
        all.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.stream.tag().cmp(b.stream.tag()))
        });
        all
    }

    fn record_stdin_display(&mut self, text: &str) {
        let line = IoLine {
            stream: StreamKind::Stdin,
            timestamp: chrono::Local::now(),
            text: text.to_string(),
        };
        self.push_line(line);
        self.stdin_view.follow_bottom();
    }
}

fn push_capped(buf: &mut Vec<IoLine>, line: IoLine) {
    buf.push(line);
    if buf.len() > MAX_LINES_PER_STREAM {
        let overflow = buf.len() - MAX_LINES_PER_STREAM;
        buf.drain(0..overflow);
    }
}

pub(crate) async fn run_live(mut args: crate::RunArgs) -> Result<()> {
    // TUI owns the terminal — never use PTY here.
    args.use_pty = false;

    let mut context = crate::Context {
        git_root: None,
        session_dir: None,
    };
    let record_base = crate::resolve_record_base(&args.cwd, &args.record_base, &mut context);
    crate::ensure_record_base(&record_base).await?;
    args.record_base = record_base;

    crate::recorder::record_files(&args, &mut context).await?;
    let session_dir = context
        .session_dir
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Recording session directory was not captured"))?;

    let command_label = args.cmd.join(" ");
    let mut terminal = setup_terminal()?;
    let mut process = super::runner::start_live_process(&args, session_dir.clone()).await?;
    let result = event_loop(
        &mut terminal,
        &mut process,
        command_label,
        session_dir.clone(),
        &args,
    )
    .await;
    let cleanup_result = finish_run(process, &session_dir, &args).await;
    let restore_result = restore_terminal(&mut terminal);
    result.and(cleanup_result).and(restore_result)
}

pub(super) async fn finish_run(
    process: LiveProcess,
    session_dir: &std::path::Path,
    args: &crate::RunArgs,
) -> Result<()> {
    let status = process.shutdown().await?;
    crate::executor::write_execution_toml(session_dir, args, status.success(), status.code()).await
}

async fn event_loop(
    terminal: &mut TuiTerminal,
    process: &mut LiveProcess,
    command_label: String,
    session_dir: PathBuf,
    args: &crate::RunArgs,
) -> Result<()> {
    let mut app = RunApp::new(command_label, process.files.clone(), process.env.clone());
    app.stdin_from_file = args.stdin.is_some();
    let mut wrote_toml = false;

    loop {
        // Drain process events first.
        while let Ok(event) = process.events.try_recv() {
            app.apply_event(event);
        }

        if let Some(status) = process.poll_exit()? {
            if matches!(app.state, ProcessState::Running) {
                app.state = ProcessState::Exited {
                    success: status.success(),
                    code: status.code(),
                };
                app.status = if status.success() {
                    "process exited successfully".to_string()
                } else {
                    format!(
                        "process exited ({})",
                        status
                            .code()
                            .map(|c| format!("code {c}"))
                            .unwrap_or_else(|| "signal".into())
                    )
                };
            }
            if !wrote_toml {
                if let Err(err) = crate::executor::write_execution_toml(
                    &session_dir,
                    args,
                    status.success(),
                    status.code(),
                )
                .await
                {
                    app.status = format!("failed to write execution.toml: {err}");
                } else {
                    wrote_toml = true;
                }
            }
        }

        terminal.draw(|frame| draw(frame, &mut app))?;

        // Poll terminal input with a short timeout so IO stays live.
        if event::poll(std::time::Duration::from_millis(30))?
            && let Event::Key(key) = event::read()?
            && key.kind != KeyEventKind::Release
            && handle_key(&mut app, key, process)?
        {
            break;
        }
    }

    Ok(())
}

/// Returns true to quit.
fn handle_key(app: &mut RunApp, key: KeyEvent, process: &mut LiveProcess) -> Result<bool> {
    if app.show_help {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter => {
                app.show_help = false;
            }
            _ => {}
        }
        return Ok(false);
    }
    if app.show_command {
        if key.code == KeyCode::Esc {
            app.show_command = false;
        }
        return Ok(false);
    }

    // Always-available bindings (work even while typing stdin).
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Ok(true);
    }
    match key.code {
        KeyCode::Tab => {
            app.focus = app.focus.next(app.interleave);
            app.stdin_typing = false;
            return Ok(false);
        }
        KeyCode::BackTab => {
            app.focus = app.focus.previous(app.interleave);
            app.stdin_typing = false;
            return Ok(false);
        }
        _ => {}
    }

    // Stdin typing: only when focused, typing, and process still running.
    if app.focus == Focus::Stdin && app.stdin_typing {
        return handle_stdin_typing(app, key, process);
    }

    match key.code {
        KeyCode::Char('q') => return Ok(true),
        KeyCode::Char('?') => app.show_help = true,
        KeyCode::Char('c') => app.show_command = true,
        KeyCode::Char('w') => {
            app.wrap_streams = !app.wrap_streams;
            // Horizontal offsets are only meaningful without wrap.
            if app.wrap_streams {
                app.stdout_view.x = 0;
                app.stderr_view.x = 0;
                app.combined_view.x = 0;
                app.stdin_view.x = 0;
            }
            if app.auto_follow {
                app.follow_bottom();
            }
            app.status = if app.wrap_streams {
                "wrap:on".into()
            } else {
                "wrap:off".into()
            };
        }
        KeyCode::Char('b') => {
            app.line_buffered = !app.line_buffered;
            app.status = if app.line_buffered {
                "stdin: line-buffered (Enter to send)".into()
            } else {
                "stdin: raw (each key sent immediately)".into()
            };
        }
        KeyCode::Char('x') => {
            app.interleave = !app.interleave;
            if app.interleave && app.focus == Focus::Stderr {
                app.focus = Focus::Stdout;
            }
            if app.auto_follow {
                app.follow_bottom();
            }
            app.status = if app.interleave {
                "stdout/stderr: interleaved by time".into()
            } else {
                "stdout/stderr: split columns".into()
            };
        }
        KeyCode::Char('t') => {
            app.auto_follow = !app.auto_follow;
            if app.auto_follow {
                app.follow_bottom();
            }
        }
        KeyCode::Char('i') => {
            app.focus = Focus::Stdin;
            if app.stdin_from_file {
                app.status = "stdin is supplied by --stdin".into();
            } else if app.process_running() {
                app.stdin_typing = true;
            } else {
                app.status = "process already exited; stdin is closed".into();
            }
        }
        KeyCode::Char('1') => app.focus = Focus::Files,
        KeyCode::Char('2') => app.focus = Focus::Env,
        KeyCode::Char('3') => app.focus = Focus::Stdin,
        KeyCode::Char('4') => app.focus = Focus::Stdout,
        KeyCode::Char('5') if !app.interleave => app.focus = Focus::Stderr,
        KeyCode::Enter if app.focus == Focus::Stdin => {
            if app.stdin_from_file {
                app.status = "stdin is supplied by --stdin".into();
            } else if app.process_running() {
                app.stdin_typing = true;
            } else {
                app.status = "process already exited; stdin is closed".into();
            }
        }
        KeyCode::Down | KeyCode::Char('j') => scroll_by(app, 1),
        KeyCode::Up | KeyCode::Char('k') => scroll_by(app, -1),
        KeyCode::PageDown => scroll_by(app, 10),
        KeyCode::PageUp => scroll_by(app, -10),
        KeyCode::Left => scroll_x_by(app, -4),
        KeyCode::Right => scroll_x_by(app, 4),
        KeyCode::Char('g') => scroll_to(app, 0),
        KeyCode::Char('G') => {
            app.auto_follow = true;
            app.files_view.y = u16::MAX;
            app.env_view.y = u16::MAX;
            app.stdin_view.y = u16::MAX;
            app.stdout_view.y = u16::MAX;
            app.stderr_view.y = u16::MAX;
            app.follow_bottom();
        }
        KeyCode::Esc => {
            if app.focus == Focus::Stdin {
                app.stdin_typing = false;
            } else if app.process_running() {
                process.try_kill();
                app.status = "sent kill signal".into();
            } else {
                return Ok(true);
            }
        }
        _ => {}
    }
    Ok(false)
}

fn handle_stdin_typing(app: &mut RunApp, key: KeyEvent, process: &mut LiveProcess) -> Result<bool> {
    if !app.process_running() {
        app.stdin_typing = false;
        app.status = "process already exited; stdin is closed".into();
        return Ok(false);
    }

    match key.code {
        KeyCode::Esc => {
            app.stdin_typing = false;
        }
        KeyCode::Enter => {
            if app.line_buffered {
                let line = std::mem::take(&mut app.stdin_draft);
                app.stdin_history_idx = None;
                let payload = format!("{line}\n");
                let _ = process.stdin_tx.send(payload.into_bytes());
                app.record_stdin_display(&line);
            } else {
                let _ = process.stdin_tx.send(b"\r".to_vec());
                app.record_stdin_display(&app.stdin_draft.clone());
                app.stdin_draft.clear();
            }
        }
        KeyCode::Backspace => {
            if app.line_buffered {
                app.stdin_draft.pop();
            } else {
                // Send DEL; also reflect locally.
                let _ = process.stdin_tx.send(vec![0x7f]);
                app.stdin_draft.pop();
            }
        }
        KeyCode::Up if app.line_buffered => {
            if !app.stdin_history.is_empty() {
                let idx = match app.stdin_history_idx {
                    None => app.stdin_history.len() - 1,
                    Some(0) => 0,
                    Some(i) => i - 1,
                };
                app.stdin_history_idx = Some(idx);
                app.stdin_draft = app.stdin_history[idx].text.clone();
            }
        }
        KeyCode::Down if app.line_buffered => {
            if let Some(i) = app.stdin_history_idx {
                if i + 1 < app.stdin_history.len() {
                    app.stdin_history_idx = Some(i + 1);
                    app.stdin_draft = app.stdin_history[i + 1].text.clone();
                } else {
                    app.stdin_history_idx = None;
                    app.stdin_draft.clear();
                }
            }
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if app.line_buffered {
                app.stdin_draft.push(c);
            } else {
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                let _ = process.stdin_tx.send(s.as_bytes().to_vec());
                if c == '\n' || c == '\r' {
                    app.record_stdin_display(&app.stdin_draft.clone());
                    app.stdin_draft.clear();
                } else {
                    app.stdin_draft.push(c);
                }
            }
        }
        _ => {}
    }
    Ok(false)
}

fn scroll_by(app: &mut RunApp, delta: i32) {
    app.auto_follow = false;
    app.viewport_mut(app.focus).scroll_y(delta);
}

fn scroll_x_by(app: &mut RunApp, delta: i32) {
    if matches!(app.focus, Focus::Files | Focus::Env) || !app.wrap_streams {
        app.viewport_mut(app.focus).scroll_x(delta);
    }
}

fn scroll_to(app: &mut RunApp, value: u16) {
    app.auto_follow = false;
    let view = app.viewport_mut(app.focus);
    view.y = value.min(view.max_y());
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Local};

    #[test]
    fn partial_events_replace_only_their_own_stream() {
        let mut app = RunApp::new("cmd".into(), vec![], vec![]);
        let line = |stream, text: &str| IoLine {
            stream,
            timestamp: Local::now(),
            text: text.into(),
        };
        app.apply_event(RunEvent::Line(line(StreamKind::Stdout, "pro")));
        app.apply_event(RunEvent::Line(line(StreamKind::Stderr, "warning")));
        app.apply_event(RunEvent::ReplaceLine(line(StreamKind::Stdout, "prompt")));
        app.apply_event(RunEvent::Line(line(StreamKind::Stdout, "next")));
        assert_eq!(
            app.stdout_lines
                .iter()
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>(),
            ["prompt", "next"]
        );
        assert_eq!(app.stderr_lines[0].text, "warning");
        app.apply_event(RunEvent::Error("read failed".into()));
        assert_eq!(app.status, "read failed");
    }

    #[test]
    fn scrolling_combined_output_preserves_split_pane_positions() {
        let mut app = RunApp::new("cmd".into(), vec![], vec![]);
        app.stdout_view.update(100, 100, 10, 20, false, false);
        app.stderr_view.update(100, 100, 10, 20, false, false);
        app.combined_view.update(200, 100, 10, 40, false, false);
        app.stdout_view.y = 3;
        app.stderr_view.y = 7;
        app.interleave = true;
        app.wrap_streams = false;
        app.focus = Focus::Stdout;
        scroll_by(&mut app, 5);
        scroll_x_by(&mut app, 4);
        assert_eq!(app.combined_view.offset(), (5, 4));
        assert_eq!(app.stdout_view.offset(), (3, 0));
        assert_eq!(app.stderr_view.offset(), (7, 0));
    }

    #[test]
    fn combined_lines_sorted_by_time() {
        let mut app = RunApp::new("cmd".into(), vec![], vec![]);
        let base = Local::now();
        app.push_line(IoLine {
            stream: StreamKind::Stdout,
            timestamp: base + Duration::milliseconds(20),
            text: "later".into(),
        });
        app.push_line(IoLine {
            stream: StreamKind::Stderr,
            timestamp: base,
            text: "earlier".into(),
        });
        let combined = app.combined_lines();
        assert_eq!(combined[0].text, "earlier");
        assert_eq!(combined[1].text, "later");
    }

    #[test]
    fn scroll_by_clamps_to_viewport() {
        let mut app = RunApp::new("cmd".into(), vec![], vec![]);
        app.stdout_view.rows = 5;
        app.stdout_view.height = 2;
        app.focus = Focus::Stdout;
        scroll_by(&mut app, 100);
        assert_eq!(app.stdout_view.y, 3); // 5 - 2
        scroll_by(&mut app, -100);
        assert_eq!(app.stdout_view.y, 0);
        assert!(!app.auto_follow);
    }
}

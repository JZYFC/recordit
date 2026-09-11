use std::io::{self, Stdout, Write};
use std::ops::{Deref, DerefMut};

use anyhow::{Context as _, Result};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Owns the terminal modes as well as the renderer. Explicit restoration reports
/// errors; Drop is the fallback for early returns, cancellation, and unwinding.
pub(crate) struct TuiTerminal {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    active: bool,
}

impl Deref for TuiTerminal {
    type Target = Terminal<CrosstermBackend<Stdout>>;

    fn deref(&self) -> &Self::Target {
        &self.terminal
    }
}

impl DerefMut for TuiTerminal {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.terminal
    }
}

impl Drop for TuiTerminal {
    fn drop(&mut self) {
        let _ = restore_terminal(self);
    }
}

pub(crate) fn setup_terminal() -> Result<TuiTerminal> {
    enable_raw_mode().context("Failed to enable raw mode")?;
    let result = (|| {
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen).context("Failed to enter alternate screen")?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).context("Failed to create terminal")?;
        Ok(TuiTerminal {
            terminal,
            active: true,
        })
    })();
    if result.is_err() {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
    result
}

pub(crate) fn restore_terminal(terminal: &mut TuiTerminal) -> Result<()> {
    if !terminal.active {
        return Ok(());
    }
    let raw_result = disable_raw_mode().context("Failed to disable raw mode");
    let screen_result = execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("Failed to leave alternate screen");
    let cursor_result = terminal.show_cursor().context("Failed to show cursor");
    io::stdout().flush().ok();
    let result = raw_result.and(screen_result).and(cursor_result);
    if result.is_ok() {
        terminal.active = false;
    }
    result
}

pub(crate) fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

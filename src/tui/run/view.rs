//! Rendering and display-width calculations for the live monitor.
use super::super::term::centered_rect;
use super::{Focus, IoLine, ProcessState, RunApp, StreamKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/// Display width of an IO line including timestamp and tag prefix.
fn io_line_display_width(line: &IoLine) -> usize {
    io_line_spans(line, true).width()
}

fn max_io_width(lines: &[IoLine]) -> usize {
    lines.iter().map(io_line_display_width).max().unwrap_or(0)
}

/// Build display lines for a stream, optionally wrapping long lines.
/// Scroll is always in visual (display) rows so wrap toggles stay consistent.
fn stream_display_lines(lines: &[IoLine], wrap: bool, width: u16) -> Vec<Line<'static>> {
    let width = width.max(1) as usize;
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        let ts = format!("[{}] ", line.format_timestamp());
        let tag = format!("{} ", line.stream.tag());
        let prefix_len = ts.width() + tag.width();
        if !wrap || line.text.width() + prefix_len <= width {
            out.push(io_line_spans(line, true));
            continue;
        }
        // Wrap styled grapheme clusters using terminal columns, including the
        // prefix so even narrow panes do not silently clip it or the body.
        let styled = io_line_spans(line, true);
        let mut row = Line::default();
        let mut used = 0;
        for span in styled.spans {
            for grapheme in span.content.graphemes(true) {
                let columns = grapheme.width();
                if used + columns > width && !row.spans.is_empty() {
                    out.push(row);
                    row = Line::default();
                    used = 0;
                }
                // A two-column grapheme cannot fit in a one-column pane.
                let content = if columns > width { "�" } else { grapheme };
                if let Some(last) = row.spans.last_mut().filter(|last| last.style == span.style) {
                    last.content.to_mut().push_str(content);
                } else {
                    row.spans
                        .push(Span::styled(content.to_string(), span.style));
                }
                used += content.width();
            }
        }
        if !row.spans.is_empty() {
            out.push(row);
        }
    }
    out
}

pub(super) fn draw(frame: &mut ratatui::Frame, app: &mut RunApp) {
    let area = frame.area();
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);

    draw_status(frame, app, root[0]);
    draw_body(frame, app, root[1]);
    draw_footer(frame, app, root[2]);

    if app.show_help {
        draw_help(frame, area);
    }
    if app.show_command {
        draw_command_popup(frame, area, &app.command_label);
    }
}

fn draw_status(frame: &mut ratatui::Frame, app: &RunApp, area: Rect) {
    let state_span = match &app.state {
        ProcessState::Running => Span::styled(
            " RUNNING ",
            Style::default().fg(Color::Black).bg(Color::Green),
        ),
        ProcessState::Exited { success, code } => {
            let text = if *success {
                " EXIT OK ".to_string()
            } else if let Some(c) = code {
                format!(" EXIT {c} ")
            } else {
                " EXIT ".to_string()
            };
            let style = if *success {
                Style::default().fg(Color::Black).bg(Color::Green)
            } else {
                Style::default().fg(Color::White).bg(Color::Red)
            };
            Span::styled(text, style)
        }
    };

    let wrap = if app.wrap_streams {
        "wrap:on"
    } else {
        "wrap:off"
    };
    let mode = if app.interleave {
        "time-order:on"
    } else {
        "time-order:off"
    };
    let follow = if app.auto_follow { "follow" } else { "paused" };

    let line = Line::from(vec![
        Span::styled(
            " recordit run ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        state_span,
        Span::raw("  "),
        Span::styled(app.command_label.clone(), Style::default().fg(Color::White)),
        Span::raw("  "),
        Span::styled(wrap, Style::default().fg(Color::DarkGray)),
        Span::raw(" "),
        Span::styled(mode, Style::default().fg(Color::DarkGray)),
        Span::raw(" "),
        Span::styled(follow, Style::default().fg(Color::DarkGray)),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_body(frame: &mut ratatui::Frame, app: &mut RunApp, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(36),
            Constraint::Percentage(36),
        ])
        .split(area);

    // Left column: files / env / stdin
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(36),
            Constraint::Percentage(36),
        ])
        .split(cols[0]);

    draw_files(frame, app, left[0]);
    draw_env(frame, app, left[1]);
    draw_stdin(frame, app, left[2]);

    if app.interleave {
        // Merge middle+right into one chronological pane.
        let wide = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
            .split(area);
        draw_combined(frame, app, wide[1]);
    } else {
        draw_stdout(frame, app, cols[1]);
        draw_stderr(frame, app, cols[2]);
    }
}

fn focused_block<'a>(app: &RunApp, focus: Focus, title: &'a str) -> Block<'a> {
    let is_focus = app.focus == focus
        || (app.interleave
            && focus == Focus::Stdout
            && matches!(app.focus, Focus::Stdout | Focus::Stderr));
    let style = if is_focus {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(style)
}

fn draw_files(frame: &mut ratatui::Frame, app: &mut RunApp, area: Rect) {
    let view_h = area.height.saturating_sub(2) as usize;
    let view_w = area.width.saturating_sub(2) as usize;
    if app.files.is_empty() {
        app.files_view.update(1, 0, view_h, view_w, false, false);
        let title = format!(" {} ", Focus::Files.title());
        frame.render_widget(
            Paragraph::new("(no files recorded)")
                .style(Style::default().fg(Color::DarkGray))
                .block(focused_block(app, Focus::Files, &title)),
            area,
        );
        return;
    }

    let lines: Vec<Line> = app.files.iter().map(|f| Line::from(f.as_str())).collect();
    let max_w = app.files.iter().map(|f| f.width()).max().unwrap_or(0);
    app.files_view
        .update(lines.len(), max_w, view_h, view_w, false, false);
    let indicators = app.files_view.indicators(false);
    let title = format!(" Files ({}){indicators}", app.files.len());
    frame.render_widget(
        Paragraph::new(lines)
            .block(focused_block(app, Focus::Files, &title))
            .scroll(app.files_view.offset()),
        area,
    );
}

fn draw_env(frame: &mut ratatui::Frame, app: &mut RunApp, area: Rect) {
    let view_h = area.height.saturating_sub(2) as usize;
    let view_w = area.width.saturating_sub(2) as usize;

    // Full KEY=VALUE; horizontal pan instead of truncation.
    let lines: Vec<Line> = app
        .env
        .iter()
        .map(|(k, v)| {
            Line::from(Span::styled(
                format!("{k}={v}"),
                Style::default().fg(Color::Gray),
            ))
        })
        .collect();
    let max_w = lines.iter().map(Line::width).max().unwrap_or(0);
    app.env_view
        .update(lines.len(), max_w, view_h, view_w, false, false);
    let indicators = app.env_view.indicators(false);
    let title = format!(" Env ({} vars){indicators}", app.env.len());
    frame.render_widget(
        Paragraph::new(lines)
            .block(focused_block(app, Focus::Env, &title))
            .scroll(app.env_view.offset()),
        area,
    );
}

fn draw_stdin(frame: &mut ratatui::Frame, app: &mut RunApp, area: Rect) {
    let mode = if !app.process_running() {
        "[closed]"
    } else if app.stdin_from_file {
        "[file]"
    } else if app.stdin_typing {
        if app.line_buffered { "[line]" } else { "[raw]" }
    } else {
        "[i/Enter]"
    };
    let inner_width = area.width.saturating_sub(2) as usize;
    let inner_height = area.height.saturating_sub(2) as usize;

    // History pane leaves the last row for the draft prompt.
    let history_h = inner_height.saturating_sub(1).max(1);
    let history = stream_display_lines(&app.stdin_history, app.wrap_streams, inner_width as u16);

    let max_w = if app.wrap_streams {
        inner_width
    } else {
        max_io_width(&app.stdin_history).max(inner_width)
    };
    app.stdin_view.update(
        history.len(),
        max_w,
        history_h,
        inner_width,
        app.wrap_streams,
        app.auto_follow,
    );
    let (scroll_y, scroll_x) = app.stdin_view.offset();
    let indicators = app.stdin_view.indicators(app.wrap_streams);
    let title = format!(" {} {}{indicators}", Focus::Stdin.title(), mode);
    let block = focused_block(app, Focus::Stdin, &title);

    // Split: history (rest) + draft line (1 row).
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 {
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    frame.render_widget(
        Paragraph::new(history).scroll((scroll_y, scroll_x)),
        rows[0],
    );

    let draft_style = if app.stdin_typing {
        Style::default().fg(Color::Yellow)
    } else if !app.process_running() {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::Gray)
    };
    let prompt = if !app.process_running() {
        "> (closed)".to_string()
    } else if app.stdin_from_file {
        "> (input from file)".to_string()
    } else if app.line_buffered {
        format!("> {}_", app.stdin_draft)
    } else {
        format!("* {}_", app.stdin_draft)
    };
    // Horizontal-pan the draft with the same scroll_x when not wrapping.
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(prompt, draft_style))).scroll((0, scroll_x)),
        rows[1],
    );
}

/// Shared drawer for stdout / stderr / combined stream panes.
fn draw_stream_pane(
    frame: &mut ratatui::Frame,
    app: &mut RunApp,
    area: Rect,
    focus: Focus,
    logical: &[IoLine],
    is_combined: bool,
) {
    let inner_h = area.height.saturating_sub(2) as usize;
    let inner_w = area.width.saturating_sub(2) as usize;

    let lines = stream_display_lines(logical, app.wrap_streams, inner_w as u16);
    let total = lines.len();
    let max_w = if app.wrap_streams {
        inner_w
    } else {
        max_io_width(logical).max(inner_w)
    };

    // Combined output is one viewport; split panes retain their own state.
    let wrap = app.wrap_streams;
    let follow = app.auto_follow;
    let view = if is_combined {
        &mut app.combined_view
    } else {
        app.viewport_mut(focus)
    };
    view.update(total, max_w, inner_h, inner_w, wrap, follow);
    let (scroll_y, scroll_x) = view.offset();
    let indicators = view.indicators(wrap);
    let title = if is_combined {
        format!(" stdout+stderr by time ({}){indicators}", logical.len())
    } else if focus == Focus::Stdout {
        format!(" stdout ({}){indicators}", logical.len())
    } else {
        format!(" stderr ({}){indicators}", logical.len())
    };

    let block = if is_combined {
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Color::Cyan))
    } else {
        focused_block(app, focus, &title)
    };

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((scroll_y, scroll_x)),
        area,
    );
}

fn draw_stdout(frame: &mut ratatui::Frame, app: &mut RunApp, area: Rect) {
    let logical = app.stdout_lines.clone();
    draw_stream_pane(frame, app, area, Focus::Stdout, &logical, false);
}

fn draw_stderr(frame: &mut ratatui::Frame, app: &mut RunApp, area: Rect) {
    let logical = app.stderr_lines.clone();
    draw_stream_pane(frame, app, area, Focus::Stderr, &logical, false);
}

fn draw_combined(frame: &mut ratatui::Frame, app: &mut RunApp, area: Rect) {
    let combined = app.combined_lines();
    draw_stream_pane(frame, app, area, Focus::Stdout, &combined, true);
}

fn io_line_spans(line: &IoLine, show_ts: bool) -> Line<'static> {
    let mut spans = Vec::new();
    if show_ts {
        spans.push(Span::styled(
            format!("[{}] ", line.format_timestamp()),
            Style::default().fg(Color::DarkGray),
        ));
    }
    let tag_color = match line.stream {
        StreamKind::Stdin => Color::Yellow,
        StreamKind::Stdout => Color::Cyan,
        StreamKind::Stderr => Color::Magenta,
    };
    spans.push(Span::styled(
        format!("{} ", line.stream.tag()),
        Style::default().fg(tag_color),
    ));
    spans.push(Span::raw(line.text.clone()));
    Line::from(spans)
}

fn draw_footer(frame: &mut ratatui::Frame, app: &RunApp, area: Rect) {
    let hints = " Tab focus · i/Enter stdin · b buffer · j/k scroll · ←→ hscroll · w wrap · x time · t follow · ? help · q quit ";
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

fn draw_help(frame: &mut ratatui::Frame, area: Rect) {
    let popup = centered_rect(72, 72, area);
    frame.render_widget(Clear, popup);
    let help = vec![
        Line::from(Span::styled(
            "Run monitor shortcuts",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  Tab / 1-5      focus pane (Files/Env/stdin/stdout/stderr)"),
        Line::from("  i / Enter      focus stdin and start typing"),
        Line::from("  Esc            leave stdin typing (or kill process)"),
        Line::from("  b              toggle stdin line-buffer vs raw mode"),
        Line::from("  Enter          send stdin line (line mode) / CR (raw)"),
        Line::from("  Backspace      edit draft (line) or send DEL (raw)"),
        Line::from("  ↑ / ↓          stdin history (line mode)"),
        Line::from("  j/k / PgUp/Dn  scroll focused pane vertically"),
        Line::from("  ← / →          horizontal scroll (files/env always; streams when wrap off)"),
        Line::from("  g / G          scroll top / bottom"),
        Line::from("  w              toggle word wrap"),
        Line::from("  x              toggle stdout+stderr time-order merge"),
        Line::from("  t              toggle auto-follow latest output"),
        Line::from("  c              show command"),
        Line::from("  q              quit"),
        Line::from(""),
        Line::from(Span::styled(
            "Timestamps are local HH:MM:SS.mmm; wrap scroll uses visual rows",
            Style::default().fg(Color::DarkGray),
        )),
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

fn draw_command_popup(frame: &mut ratatui::Frame, area: Rect, command: &str) {
    let popup = centered_rect(70, 30, area);
    frame.render_widget(Clear, popup);
    let text = vec![
        Line::from(Span::styled(
            "Command",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(command.to_string()),
        Line::from(""),
        Line::from(Span::styled(
            "Esc to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Command ")
                    .border_style(Style::default().fg(Color::Cyan))
                    .style(Style::default().bg(Color::Black)),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Local;

    #[test]
    fn unicode_output_wraps_without_losing_graphemes() {
        let line = IoLine {
            stream: StreamKind::Stdout,
            timestamp: Local::now(),
            text: "中文输出👩‍💻e\u{301}".repeat(8),
        };
        let expected = io_line_spans(&line, true).to_string();
        for width in [2, 10, 20, 40] {
            let rows = stream_display_lines(std::slice::from_ref(&line), true, width);
            assert!(rows.iter().all(|row| row.width() <= width as usize));
            let actual: String = rows.iter().map(|row| row.to_string()).collect();
            assert_eq!(actual, expected);
        }
        assert_eq!(max_io_width(&[line]), Line::from(expected).width());
    }

    #[test]
    fn stream_display_lines_wraps_long_content() {
        let line = IoLine {
            stream: StreamKind::Stdout,
            timestamp: Local::now(),
            text: "x".repeat(80),
        };
        let unwrapped = stream_display_lines(std::slice::from_ref(&line), false, 40);
        assert_eq!(unwrapped.len(), 1);
        let wrapped = stream_display_lines(&[line], true, 40);
        assert!(wrapped.len() > 1, "expected wrap, got {}", wrapped.len());
    }
}

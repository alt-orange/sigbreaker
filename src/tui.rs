//! Interactive front end for the same options and pipeline used by the CLI.

use std::io::{self, IsTerminal};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, List, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use sigbraker::{
    cli::Cli,
    pipeline,
    report::{self, LineKind},
};

pub(crate) fn run() -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("--tui requires an interactive terminal");
    }
    let mut app = App::new();
    let result = (|| {
        let mut terminal = ratatui::try_init().context("could not initialize terminal")?;
        execute!(io::stdout(), EnableBracketedPaste)?;
        app.event_loop(&mut terminal)
    })();
    let paste = execute!(io::stdout(), DisableBracketedPaste);
    let restore = ratatui::try_restore();
    if let Some(job) = app.job {
        // Let an in-flight write finish even if the terminal disconnects.
        let _ = job.handle.join();
    }
    result.and(paste.and(restore).context("could not restore terminal"))
}

#[derive(Default)]
struct Editor {
    text: String,
    cursor: usize,
}

fn tail_start(text: &str, width: usize) -> usize {
    let mut start = text.len();
    let mut used = 0;
    for (index, ch) in text.char_indices().rev() {
        used += Span::raw(&text[index..index + ch.len_utf8()]).width();
        if used > width {
            break;
        }
        start = index;
    }
    start
}

impl Editor {
    fn insert(&mut self, value: &str) {
        let value: String = value.chars().filter(|ch| !ch.is_control()).collect();
        self.text.insert_str(self.cursor, &value);
        self.cursor += value.len();
    }

    fn key(&mut self, key: KeyEvent) {
        let previous = self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(index, _)| index);
        let next = self.cursor
            + self.text[self.cursor..]
                .chars()
                .next()
                .map_or(0, char::len_utf8);
        match (key.code, key.modifiers) {
            (KeyCode::Char('u'), KeyModifiers::CONTROL) => *self = Self::default(),
            (_, modifiers) if modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {}
            (KeyCode::Char(ch), _) if !ch.is_control() => {
                self.text.insert(self.cursor, ch);
                self.cursor += ch.len_utf8();
            }
            (KeyCode::Home, _) => self.cursor = 0,
            (KeyCode::End, _) => self.cursor = self.text.len(),
            (KeyCode::Left, _) => self.cursor = previous,
            (KeyCode::Right, _) => self.cursor = next,
            (KeyCode::Backspace, _) => {
                self.text.drain(previous..self.cursor);
                self.cursor = previous;
            }
            (KeyCode::Delete, _) => {
                self.text.drain(self.cursor..next);
            }
            _ => {}
        }
    }

    fn visible(&self, width: usize) -> [Span<'_>; 3] {
        let rest = &self.text[self.cursor..];
        let head_len = rest.chars().next().map_or(0, char::len_utf8);
        let (head, tail) = rest.split_at(head_len);
        let caret = Span::raw(if head.is_empty() { " " } else { head }).reversed();
        let budget = width.saturating_sub(caret.width());
        let start = tail_start(&self.text[..self.cursor], budget);
        [
            Span::raw(&self.text[start..self.cursor]),
            caret,
            Span::raw(tail),
        ]
    }
}

enum Value {
    Text { editor: Editor, hint: &'static str },
    Toggle { enabled: bool, default: bool },
}

struct Field {
    label: &'static str,
    flag: &'static str,
    value: Value,
}

impl Field {
    fn text(label: &'static str, flag: &'static str, hint: &'static str) -> Self {
        Self {
            label,
            flag,
            value: Value::Text {
                editor: Editor::default(),
                hint,
            },
        }
    }

    fn toggle(label: &'static str, flag: &'static str, default: bool) -> Self {
        Self {
            label,
            flag,
            value: Value::Toggle {
                enabled: default,
                default,
            },
        }
    }

    fn arg(&self) -> Option<String> {
        match &self.value {
            Value::Text { editor, .. } => {
                let text = editor.text.trim();
                let text = text
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(text);
                if text.is_empty() {
                    None
                } else if self.flag.is_empty() {
                    Some(text.to_owned())
                } else {
                    Some(format!("{}={text}", self.flag))
                }
            }
            Value::Toggle { enabled, default } => {
                (enabled != default).then(|| self.flag.to_owned())
            }
        }
    }

    fn line(&self, selected: bool, width: usize) -> Line<'_> {
        let label_width = (width / 2).clamp(1, 19);
        let value_width = width.saturating_sub(label_width + 1);
        let label = &self.label[..label_width.min(self.label.len())];
        let mut spans = vec![Span::raw(format!("{label:label_width$} ")).fg(Color::Cyan)];
        match &self.value {
            Value::Text { editor, hint } if selected => {
                spans.extend(editor.visible(value_width));
                if editor.text.is_empty() {
                    spans.push(Span::raw(*hint).dim());
                }
            }
            Value::Text { editor, hint } if editor.text.is_empty() => {
                spans.push(Span::raw(*hint).dim())
            }
            Value::Text { editor, .. } => {
                if Span::raw(&editor.text).width() > value_width {
                    let start = tail_start(&editor.text, value_width.saturating_sub(1));
                    spans.push(Span::raw("…").dim());
                    spans.push(Span::raw(&editor.text[start..]));
                } else {
                    spans.push(Span::raw(&editor.text));
                }
            }
            Value::Toggle { enabled: true, .. } => spans.push(Span::raw("On").fg(Color::Green)),
            Value::Toggle { enabled: false, .. } => spans.push(Span::raw("Off").dim()),
        }
        Line::from(spans)
    }
}

#[derive(Clone, Copy)]
enum Status {
    Ready,
    Running,
    Done,
    Failed,
}

enum Update {
    Stage(String),
    Finished(Result<String>),
}

struct Job {
    updates: Receiver<Update>,
    handle: JoinHandle<()>,
}

struct App {
    fields: Vec<Field>,
    focus: ListState,
    report: String,
    report_offset: u16,
    report_height: u16,
    report_expanded: bool,
    follow: bool,
    status: Status,
    job: Option<Job>,
}

impl App {
    fn new() -> Self {
        Self {
            fields: vec![
                Field::text("Input PE", "", "Path to an EXE or DLL"),
                Field::text("Output PE", "--output", "Automatic"),
                Field::text("Seed", "--seed", "Default seed"),
                Field::text("Global map", "--global-map", "Optional"),
                Field::text("Global slot", "--global-slot", "Derived from seed"),
                Field::text("Handler map", "--handler-map", "Optional"),
                Field::toggle("Auto globals", "--auto-globals", false),
                Field::toggle("Segment injection", "--no-seg-inject", true),
                Field::toggle("Grow segments", "--no-grow-segments", true),
                Field::toggle("Opcode aliasing", "--no-alias", true),
                Field::toggle("Instruction order", "--no-reorder", true),
                Field::toggle("Block shuffle", "--no-shuffle", true),
                Field::toggle("Wipe old code", "--keep-original", true),
                Field::toggle("Compress section", "--compress-section", false),
                Field::toggle("Verify output", "--no-verify", true),
                Field::text("Segments", "--segments", "es,cs,ss,ds"),
                Field::text("Segment chance", "--seg-prob", "1.0"),
                Field::text("Alias chance", "--alias-prob", "1.0"),
                Field::text("Reorder chance", "--reorder-prob", "1.0"),
                Field::text("Shuffle chance", "--shuffle-prob", "1.0"),
                Field::text("Junk chance", "--junk-prob", "1.0"),
            ],
            focus: ListState::default().with_selected(Some(0)),
            report: "Enter the input PE path, then press F2 to inspect it or F5 to process it."
                .to_owned(),
            report_offset: 0,
            report_height: 1,
            report_expanded: false,
            follow: false,
            status: Status::Ready,
            job: None,
        }
    }

    fn args(&self, info: bool) -> Result<Cli> {
        let input = self.fields[0].arg().context("Enter an input PE path.")?;
        let mut args = vec!["sigbraker".to_owned()];
        if info {
            args.push("--info".to_owned());
        }
        args.extend(
            self.fields[1..]
                .iter()
                .filter(|field| !info || field.flag == "--handler-map")
                .filter_map(Field::arg),
        );
        args.extend(["--".to_owned(), input]);
        Ok(Cli::try_parse_from(args)?)
    }

    fn start(&mut self, info: bool) {
        self.report_offset = 0;
        self.report.clear();
        match self.spawn(info) {
            Ok(job) => {
                self.report.push_str("Progress\n\n");
                self.job = Some(job);
                self.status = Status::Running;
                self.follow = true;
            }
            Err(err) => {
                self.status = Status::Failed;
                self.report = format!("{err:#}");
            }
        }
    }

    fn spawn(&self, info: bool) -> Result<Job> {
        let cli = self.args(info)?;
        let (sender, updates) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("sigbraker-pipeline".into())
            .spawn(move || {
                let result = pipeline::run_with_progress(&cli, |stage| {
                    let _ = sender.send(Update::Stage(stage.to_owned()));
                });
                let _ = sender.send(Update::Finished(result));
            })?;
        Ok(Job { updates, handle })
    }

    fn receive_updates(&mut self) -> Result<bool> {
        let mut changed = false;
        while let Some(job) = &self.job {
            match job.updates.try_recv() {
                Ok(Update::Stage(stage)) => {
                    self.report.push_str("  > ");
                    self.report.push_str(&stage);
                    self.report.push('\n');
                }
                Ok(Update::Finished(result)) => {
                    match result {
                        Ok(report) => {
                            self.status = Status::Done;
                            self.report = report;
                        }
                        Err(err) => {
                            self.status = Status::Failed;
                            self.report = format!("{err:#}");
                        }
                    }
                    self.report_offset = 0;
                    let _ = self.job.take().unwrap().handle.join();
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => bail!("pipeline worker exited unexpectedly"),
            }
            changed = true;
        }
        Ok(changed)
    }

    fn selected(&self) -> usize {
        self.focus.selected().unwrap_or(0)
    }

    fn event_loop(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        let mut redraw = true;
        loop {
            if self.receive_updates()? || redraw {
                terminal.draw(|frame| self.draw(frame))?;
                redraw = false;
            }
            if !event::poll(Duration::from_millis(100))? {
                continue;
            }
            redraw = true;
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if self.key(key) {
                        return Ok(());
                    }
                }
                Event::Paste(text) if self.job.is_none() => {
                    let selected = self.selected();
                    if let Value::Text { editor, .. } = &mut self.fields[selected].value {
                        editor.insert(&text);
                    }
                }
                _ => {}
            }
        }
    }

    fn key(&mut self, key: KeyEvent) -> bool {
        if key.code == KeyCode::F(6) {
            self.report_expanded = !self.report_expanded;
            return false;
        }
        let page = self.report_height.saturating_sub(1).max(1);
        if matches!(key.code, KeyCode::PageUp | KeyCode::PageDown) {
            self.follow = false;
            self.report_offset = if key.code == KeyCode::PageUp {
                self.report_offset.saturating_sub(page)
            } else {
                self.report_offset.saturating_add(page)
            };
            return false;
        }
        if self.job.is_some() {
            return false;
        }
        let selected = self.selected();
        match (key.code, key.modifiers) {
            (KeyCode::Esc, _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => return true,
            (KeyCode::F(2), _) => self.start(true),
            (KeyCode::F(5), _) => self.start(false),
            (KeyCode::Tab, KeyModifiers::SHIFT) | (KeyCode::BackTab | KeyCode::Up, _)
                if !self.report_expanded =>
            {
                self.focus
                    .select(Some((selected + self.fields.len() - 1) % self.fields.len()));
            }
            (KeyCode::Tab | KeyCode::Down, _) if !self.report_expanded => {
                self.focus.select(Some((selected + 1) % self.fields.len()));
            }
            _ if !self.report_expanded => match &mut self.fields[selected].value {
                Value::Text { editor, .. } => editor.key(key),
                Value::Toggle { enabled, .. }
                    if matches!(key.code, KeyCode::Char(' ') | KeyCode::Enter) =>
                {
                    *enabled = !*enabled;
                }
                _ => {}
            },
            _ => {}
        }
        false
    }

    fn draw(&mut self, frame: &mut Frame<'_>) {
        let area = frame.area();
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(2),
        ])
        .areas(area);
        let (status, color) = match self.status {
            Status::Ready => ("Ready", Color::Cyan),
            Status::Running => ("Running", Color::Yellow),
            Status::Done => ("Complete", Color::Green),
            Status::Failed => ("Error", Color::Red),
        };
        frame.render_widget(
            Line::from(vec![
                Span::raw(" SigBreaker ").bold(),
                Span::raw(" / PE32+ diversification    ").dim(),
                Span::raw(status).fg(color).bold(),
            ]),
            header,
        );
        if self.report_expanded {
            self.draw_report(frame, body, color);
        } else {
            let [config, report] = if area.width >= 110 {
                Layout::horizontal([Constraint::Length(40), Constraint::Fill(1)]).areas(body)
            } else {
                Layout::vertical([Constraint::Percentage(40), Constraint::Fill(1)]).areas(body)
            };
            self.draw_config(frame, config);
            self.draw_report(frame, report, color);
        }
        let keys = if self.job.is_some() {
            " Processing the current configuration"
        } else if self.report_expanded {
            " F2 inspect   F5 process   Esc quit"
        } else {
            " Tab/↑↓ select   Space toggle   F2 inspect   F5 process   Esc quit"
        };
        let view = if self.report_expanded {
            "configuration"
        } else {
            "expand report"
        };
        let edit = if self.report_expanded || self.job.is_some() {
            ""
        } else {
            "   Ctrl+U clear field"
        };
        let keys = format!("{keys}\n PgUp/PgDn scroll   F6 {view}{edit}");
        frame.render_widget(Paragraph::new(keys).dim(), footer);
    }

    fn draw_config(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let focused = self.selected();
        let width = usize::from(area.width.saturating_sub(4));
        let rows = self
            .fields
            .iter()
            .enumerate()
            .map(|(index, field)| field.line(index == focused && self.job.is_none(), width));
        let border = Block::bordered()
            .title(" Configuration ")
            .border_style(Style::new().fg(Color::Cyan));
        let list = List::new(rows)
            .block(border)
            .highlight_symbol("› ")
            .highlight_spacing(ratatui::widgets::HighlightSpacing::Always)
            .highlight_style(Style::new().fg(Color::White).bg(Color::Indexed(236)))
            .scroll_padding(1);
        frame.render_stateful_widget(list, area, &mut self.focus);
    }

    fn draw_report(&mut self, frame: &mut Frame<'_>, area: Rect, color: Color) {
        let mut block = Block::bordered()
            .title(" Report ")
            .border_style(Style::new().fg(color));
        let body = block.inner(area);
        if body.is_empty() {
            frame.render_widget(block, area);
            return;
        }
        self.report_height = body.height;
        let safe: String = self
            .report
            .chars()
            .filter(|&ch| ch == '\n' || !ch.is_control())
            .collect();
        let lines = safe
            .lines()
            .map(|line| {
                if matches!(self.status, Status::Failed) {
                    Line::styled(line, Style::new().fg(Color::Red))
                } else {
                    report_line(line)
                }
            })
            .collect::<Vec<_>>();
        let report = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false });
        let line_count = report.line_count(body.width);
        let max_offset = line_count.saturating_sub(usize::from(body.height));
        let max_offset = u16::try_from(max_offset).unwrap_or(u16::MAX);
        self.report_offset = if self.job.is_some() && self.follow {
            max_offset
        } else {
            self.report_offset.min(max_offset)
        };
        let first = (usize::from(self.report_offset) + 1).min(line_count);
        let last = (usize::from(self.report_offset) + usize::from(body.height)).min(line_count);
        block =
            block.title_bottom(Line::from(format!(" {first}-{last} / {line_count} lines ")).dim());
        frame.render_widget(block, area);
        frame.render_widget(report.scroll((self.report_offset, 0)), body);
    }
}

fn report_line(line: &str) -> Line<'_> {
    let style = match report::line_kind(line) {
        LineKind::Heading => Style::new().fg(Color::Cyan).bold(),
        LineKind::Subheading => Style::new().fg(Color::White).bold(),
        LineKind::Success => Style::new().fg(Color::Green),
        LineKind::Warning => Style::new().fg(Color::Yellow),
        LineKind::Text => Style::new().fg(Color::White),
    };
    if let Some(value) = report::value_start(line) {
        Line::from(vec![
            Span::styled(&line[..value], Style::new().fg(Color::Gray)),
            Span::styled(&line[value..], style),
        ])
    } else {
        Line::styled(line, style)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiping_defaults_on_and_can_be_disabled() {
        let mut app = App::new();
        if let Value::Text { editor, .. } = &mut app.fields[0].value {
            editor.text = "input.exe".to_owned();
        }
        let defaults = app.args(false).unwrap();
        assert!(defaults.wipe_original);
        assert!(!defaults.keep_original);

        let field = app
            .fields
            .iter_mut()
            .find(|f| f.flag == "--keep-original")
            .unwrap();
        if let Value::Toggle { enabled, .. } = &mut field.value {
            *enabled = false;
        }
        assert!(app.args(false).unwrap().keep_original);
    }
}

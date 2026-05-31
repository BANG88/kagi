use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Row, Table};
use std::io;

use super::layout;
use super::theme::Theme;

struct AuditItem {
    timestamp: String,
    event_type: String,
    project_id: String,
    actor: String,
    metadata: String,
}

struct App {
    events: Vec<AuditItem>,
    selected: usize,
    filtered: Vec<usize>,
    show_search: bool,
    search_query: String,
}

impl App {
    fn filter_events(&mut self) {
        if self.search_query.is_empty() {
            self.filtered = (0..self.events.len()).collect();
            return;
        }
        let q = self.search_query.to_lowercase();
        self.filtered = self
            .events
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.event_type.to_lowercase().contains(&q)
                    || e.project_id.to_lowercase().contains(&q)
                    || e.actor.to_lowercase().contains(&q)
                    || e.metadata.to_lowercase().contains(&q)
            })
            .map(|(i, _)| i)
            .collect();
        if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len().saturating_sub(1);
        }
    }

    fn current_event_index(&self) -> usize {
        self.filtered.get(self.selected).copied().unwrap_or(0)
    }
}

pub fn run_tui_audit_log(events: Vec<serde_json::Value>) -> anyhow::Result<()> {
    let mut app = App {
        events: events
            .into_iter()
            .map(|e| AuditItem {
                timestamp: e["created_at"].as_str().unwrap_or("?").to_string(),
                event_type: e["event_type"].as_str().unwrap_or("?").to_string(),
                project_id: e["project_id"].as_str().unwrap_or("-").to_string(),
                actor: e["actor_token_id"].as_str().unwrap_or("-").to_string(),
                metadata: e["metadata_json"].as_str().unwrap_or("").to_string(),
            })
            .collect(),
        selected: 0,
        filtered: Vec::new(),
        show_search: false,
        search_query: String::new(),
    };
    app.filter_events();

    let theme = Theme::default();
    layout::run_tui(|terminal| run_app(terminal, &mut app, &theme))
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    theme: &Theme,
) -> io::Result<()> {
    let mut last_tick = std::time::Instant::now();
    let tick_rate = std::time::Duration::from_millis(250);

    loop {
        terminal.draw(|f| draw_ui(f, app, theme))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if crossterm::event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if app.show_search {
                match key.code {
                    KeyCode::Esc => {
                        app.show_search = false;
                        app.search_query.clear();
                        app.filter_events();
                    }
                    KeyCode::Enter => {
                        app.show_search = false;
                        app.filter_events();
                    }
                    KeyCode::Backspace => {
                        app.search_query.pop();
                    }
                    KeyCode::Char(c) => {
                        app.search_query.push(c);
                    }
                    _ => {}
                }
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('/') => {
                    app.show_search = true;
                }
                KeyCode::Down | KeyCode::Char('j') if app.selected + 1 < app.filtered.len() => {
                    app.selected += 1;
                }
                KeyCode::Up | KeyCode::Char('k') if app.selected > 0 => {
                    app.selected -= 1;
                }
                _ => {}
            }
        }
        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
        }
    }
}

fn draw_ui(f: &mut ratatui::Frame, app: &App, theme: &Theme) {
    let title = if app.show_search {
        format!("Audit Log (filter: {})", app.search_query)
    } else {
        format!("Audit Log ({} / {})", app.filtered.len(), app.events.len())
    };

    let idx = app.current_event_index();
    let footer = if app.show_search {
        "Enter=confirm  Esc=clear".to_string()
    } else {
        let hints = "j/k=navigate  /=search  q=quit";
        if let Some(e) = app.events.get(idx) {
            format!("{} | {}  {hints}", e.event_type, e.project_id)
        } else {
            hints.to_string()
        }
    };

    let content = layout::draw_frame(f, theme, &title, &footer);

    let rows: Vec<Row> = app
        .filtered
        .iter()
        .enumerate()
        .map(|(i, &fi)| {
            let e = &app.events[fi];
            let row_style = if i == app.selected {
                theme.highlight_style()
            } else {
                Style::default()
            };
            Row::new(vec![
                Span::styled(&e.timestamp, theme.muted_style()),
                Span::styled(&e.event_type, theme.key_hint_style()),
                Span::styled(&e.project_id, theme.title_style()),
                Span::styled(&e.actor, theme.muted_style()),
                Span::styled(&e.metadata, theme.muted_style()),
            ])
            .style(row_style)
            .height(1)
        })
        .collect();

    let header = Row::new(vec!["Timestamp", "Event", "Project", "Actor", "Metadata"])
        .style(theme.header_style())
        .height(1);

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(20),
            Constraint::Percentage(15),
            Constraint::Percentage(20),
            Constraint::Percentage(15),
            Constraint::Percentage(30),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Events")
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(table, content);

    // Search modal
    if app.show_search {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Search")
            .title_style(theme.header_style())
            .border_style(theme.block_style());
        let paragraph = Paragraph::new(app.search_query.clone()).block(block);
        let area = layout::centered_rect(40, 10, f.area());
        f.render_widget(Clear, area);
        f.render_widget(paragraph, area);
    }
}

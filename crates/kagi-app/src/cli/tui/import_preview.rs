use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use std::io;

use super::layout;
use super::theme::Theme;

struct ImportItem {
    key: String,
    is_overwritten: bool,
}

struct App {
    items: Vec<ImportItem>,
    selected: usize,
    scope: String,
    file: String,
    confirmed: Option<bool>,
}

pub fn run_tui_import(
    imported: Vec<String>,
    overwritten: Vec<String>,
    scope: String,
    file: String,
) -> anyhow::Result<bool> {
    let mut items = Vec::new();
    for key in &imported {
        let is_overwritten = overwritten.contains(key);
        items.push(ImportItem {
            key: key.clone(),
            is_overwritten,
        });
    }

    let mut app = App {
        items,
        selected: 0,
        scope,
        file,
        confirmed: None,
    };

    let theme = Theme::default();
    layout::run_tui(|terminal| run_app(terminal, &mut app, &theme))?;
    Ok(app.confirmed == Some(true))
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    theme: &Theme,
) -> io::Result<()> {
    let tick_rate = std::time::Duration::from_millis(250);
    let mut last_tick = std::time::Instant::now();

    loop {
        terminal.draw(|f| draw_ui(f, app, theme))?;

        if app.confirmed.is_some() {
            return Ok(());
        }

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if crossterm::event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    app.confirmed = Some(false);
                    return Ok(());
                }
                KeyCode::Char('y') => {
                    app.confirmed = Some(true);
                    return Ok(());
                }
                KeyCode::Char('n') => {
                    app.confirmed = Some(false);
                    return Ok(());
                }
                KeyCode::Down if app.selected + 1 < app.items.len() => {
                    app.selected += 1;
                }
                KeyCode::Up if app.selected > 0 => {
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
    let overwritten_count = app.items.iter().filter(|i| i.is_overwritten).count();
    let title = if overwritten_count > 0 {
        format!(
            "Import Preview — {} ({} overwritten)",
            app.scope, overwritten_count
        )
    } else {
        format!("Import Preview — {}", app.scope)
    };

    let content = layout::draw_frame(f, theme, &title, "y=confirm  n=cancel  q=quit  ↑↓=navigate");

    let header = Row::new(vec!["Key", "Status"])
        .style(theme.header_style())
        .height(1);

    let rows: Vec<Row> = app
        .items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let style = if i == app.selected {
                theme.highlight_style()
            } else {
                Style::default()
            };
            let status = if item.is_overwritten {
                Span::styled("overwrite", theme.warning_style())
            } else {
                Span::styled("new", theme.success_style())
            };
            Row::new(vec![
                Cell::new(Span::styled(&item.key, theme.key_hint_style())).style(style),
                Cell::new(status).style(style),
            ])
            .height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Percentage(50), Constraint::Percentage(50)],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Keys from {} ({})", app.file, app.items.len()))
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(table, content);
}

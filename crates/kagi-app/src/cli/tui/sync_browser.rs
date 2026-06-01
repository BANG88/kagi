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

struct SyncItem {
    env_name: String,
    added: usize,
    commented: usize,
    skipped: usize,
}

struct App {
    items: Vec<SyncItem>,
    selected: usize,
}

use crate::application::sync_service::EnvSyncReport;

pub fn run_tui_sync(env_reports: Vec<(String, EnvSyncReport)>) -> anyhow::Result<()> {
    if env_reports.is_empty() {
        println!("kagi: no environments to sync.");
        return Ok(());
    }

    let items: Vec<SyncItem> = env_reports
        .into_iter()
        .map(|(env_name, report)| SyncItem {
            env_name,
            added: report.added.len(),
            commented: report.commented.len(),
            skipped: report.skipped.len(),
        })
        .collect();

    let mut app = App { items, selected: 0 };

    let theme = Theme::default();
    layout::run_tui(|terminal| run_app(terminal, &mut app, &theme))
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

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if crossterm::event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
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
    let content = layout::draw_frame(f, theme, "Sync Results", "↑↓=navigate  q=quit");

    let header = Row::new(vec!["Environment", "Added", "Commented", "Skipped"])
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
            Row::new(vec![
                Cell::new(Span::styled(&item.env_name, theme.key_hint_style())).style(style),
                Cell::new(Span::styled(
                    if item.added > 0 {
                        format!("+{}", item.added)
                    } else {
                        "-".to_string()
                    },
                    theme.success_style(),
                ))
                .style(style),
                Cell::new(Span::styled(
                    if item.commented > 0 {
                        format!("#{}", item.commented)
                    } else {
                        "-".to_string()
                    },
                    theme.warning_style(),
                ))
                .style(style),
                Cell::new(Span::styled(
                    if item.skipped > 0 {
                        format!("-{}", item.skipped)
                    } else {
                        "-".to_string()
                    },
                    theme.muted_style(),
                ))
                .style(style),
            ])
            .height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Environments ({})", app.items.len()))
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(table, content);
}

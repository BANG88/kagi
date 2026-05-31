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

struct TokenItem {
    id: String,
    status: String,
    member: String,
    capabilities: String,
    created: String,
}

struct App {
    items: Vec<TokenItem>,
    selected: usize,
}

pub fn run_tui_token_list(tokens: Vec<serde_json::Value>) -> anyhow::Result<()> {
    if tokens.is_empty() {
        println!("kagi: no tokens found.");
        return Ok(());
    }

    let items: Vec<TokenItem> = tokens
        .into_iter()
        .map(|t| TokenItem {
            id: t["token_id"].as_str().unwrap_or("?").to_string(),
            status: t["status"].as_str().unwrap_or("?").to_string(),
            member: t["member_id"].as_str().unwrap_or("?").to_string(),
            capabilities: t["capabilities"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default(),
            created: t["created_at"].as_str().unwrap_or("?").to_string(),
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
    let content = layout::draw_frame(f, theme, "Token List", "↑↓=navigate  q=quit");

    let header = Row::new(vec![
        "Token ID",
        "Status",
        "Member",
        "Capabilities",
        "Created",
    ])
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
                Cell::new(Span::styled(&item.id, theme.key_hint_style())).style(style),
                Cell::new(Span::styled(
                    &item.status,
                    if item.status == "active" {
                        theme.success_style()
                    } else {
                        theme.warning_style()
                    },
                ))
                .style(style),
                Cell::new(Span::styled(&item.member, theme.title_style())).style(style),
                Cell::new(Span::styled(&item.capabilities, theme.info_style())).style(style),
                Cell::new(Span::styled(&item.created, theme.muted_style())).style(style),
            ])
            .height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(12),
            Constraint::Percentage(20),
            Constraint::Percentage(23),
            Constraint::Percentage(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Tokens ({})", app.items.len()))
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(table, content);
}

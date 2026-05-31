use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use kagi_store::fs_store::FileStore;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};
use std::io;

use super::layout;
use super::theme::Theme;

struct SearchItem {
    scope: String,
    key: String,
    description: Option<String>,
    value: Option<String>,
}

struct App {
    items: Vec<SearchItem>,
    selected: usize,
    query: String,
    revealed: std::collections::HashSet<usize>,
    show_confirm: bool,
    confirmed_reveal: bool,
    show_value: bool,
}

pub fn run_tui_search(store: FileStore, query: String, show_values: bool) -> anyhow::Result<()> {
    let search_service = crate::application::search_secrets::SearchSecretsService::new(store);
    let results = if show_values {
        search_service.search_values(&query)?
    } else {
        search_service.search_keys(&query)?
    };

    let items: Vec<SearchItem> = results
        .into_iter()
        .map(|r| SearchItem {
            scope: r.scope,
            key: r.key,
            description: r.description,
            value: r.value,
        })
        .collect();

    if items.is_empty() {
        println!("kagi: no matches for '{query}'.");
        return Ok(());
    }

    let mut app = App {
        items,
        selected: 0,
        query,
        revealed: std::collections::HashSet::new(),
        show_confirm: false,
        confirmed_reveal: false,
        show_value: false,
    };

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
            if app.show_confirm {
                app.show_confirm = false;
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        app.confirmed_reveal = true;
                        app.revealed.insert(app.selected);
                        app.show_value = true;
                    }
                    _ => {
                        app.show_value = false;
                    }
                }
                continue;
            }
            if app.show_value {
                app.show_value = false;
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('s') | KeyCode::Enter => {
                    if app.revealed.contains(&app.selected) {
                        app.revealed.remove(&app.selected);
                    } else {
                        let has_value = app
                            .items
                            .get(app.selected)
                            .map(|i| i.value.is_some())
                            .unwrap_or(false);
                        if has_value {
                            if app.confirmed_reveal {
                                app.revealed.insert(app.selected);
                            } else {
                                app.show_confirm = true;
                            }
                        }
                    }
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
    let title = if app.show_confirm {
        format!("Search: {} (confirm reveal)", app.query)
    } else {
        format!("Search: {}", app.query)
    };
    let footer = if app.show_confirm {
        "y=confirm reveal  any other key=cancel".to_string()
    } else {
        "s/Enter=reveal value  ↑↓=navigate  q=quit".to_string()
    };

    let content = layout::draw_frame(f, theme, &title, &footer);

    let header = Row::new(vec!["Scope", "Key", "Value", "Description"])
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
            let value_display = if app.revealed.contains(&i) {
                item.value.as_deref().unwrap_or("********")
            } else {
                "********"
            };
            Row::new(vec![
                Cell::new(Span::styled(
                    &item.scope,
                    Style::default().fg(theme.accent()),
                ))
                .style(style),
                Cell::new(Span::styled(&item.key, theme.key_hint_style())).style(style),
                Cell::new(Span::styled(
                    value_display,
                    if app.revealed.contains(&i) {
                        Style::default().fg(theme.success())
                    } else {
                        Style::default().fg(theme.muted())
                    },
                ))
                .style(style),
                Cell::new(Span::styled(
                    item.description.as_deref().unwrap_or(""),
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
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Results ({})", app.items.len()))
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(table, content);

    // Confirm modal
    if app.show_confirm {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Confirm Reveal")
            .title_style(theme.warning_style())
            .border_style(theme.block_style());
        let paragraph = Paragraph::new("Reveal decrypted value? (y/N)").block(block);
        let area = layout::centered_rect(40, 10, f.area());
        f.render_widget(Clear, area);
        f.render_widget(paragraph, area);
    }

    // Value display modal
    if app.show_value {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Value")
            .title_style(theme.header_style())
            .border_style(theme.block_style());
        let value_text = app
            .items
            .get(app.selected)
            .and_then(|i| i.value.as_deref())
            .unwrap_or("");
        let paragraph = Paragraph::new(value_text).block(block);
        let area = layout::centered_rect(60, 20, f.area());
        f.render_widget(Clear, area);
        f.render_widget(paragraph, area);
    }
}

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

struct ProjectItem {
    id: String,
    revision: String,
    created: String,
    is_pending: bool,
    requester_name: String,
}

struct App {
    items: Vec<ProjectItem>,
    selected: usize,
    active_tab: usize,
}

pub fn run_tui_project_list(
    requests: Vec<serde_json::Value>,
    projects: Vec<serde_json::Value>,
) -> anyhow::Result<()> {
    if requests.is_empty() && projects.is_empty() {
        println!("kagi: no projects or pending requests found.");
        return Ok(());
    }

    let mut items: Vec<ProjectItem> = requests
        .into_iter()
        .map(|r| ProjectItem {
            id: r["project_id"].as_str().unwrap_or("unknown").to_string(),
            revision: "-".to_string(),
            created: r["created_at"].as_str().unwrap_or("").to_string(),
            is_pending: true,
            requester_name: r["requester_name"].as_str().unwrap_or("").to_string(),
        })
        .collect();

    items.extend(projects.into_iter().map(|p| ProjectItem {
        id: p["project_id"].as_str().unwrap_or("unknown").to_string(),
        revision: p["revision"].as_i64().unwrap_or(0).to_string(),
        created: p["created_at"].as_str().unwrap_or("").to_string(),
        is_pending: false,
        requester_name: String::new(),
    }));

    let mut app = App {
        items,
        selected: 0,
        active_tab: 0,
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
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Down if app.selected + 1 < app.items.len() => {
                    app.selected += 1;
                }
                KeyCode::Up if app.selected > 0 => {
                    app.selected -= 1;
                }
                KeyCode::Tab => {
                    app.active_tab = (app.active_tab + 1) % 2;
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
    let content = layout::draw_frame(
        f,
        theme,
        "Project List",
        "↑↓=navigate  Tab=switch tab  q=quit",
    );

    let body = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(content);

    let pending_items: Vec<_> = app.items.iter().filter(|i| i.is_pending).collect();
    let active_items: Vec<_> = app.items.iter().filter(|i| !i.is_pending).collect();

    // Pending requests
    let pending_rows: Vec<Row> = pending_items
        .iter()
        .map(|item| {
            let is_selected = app.active_tab == 0
                && app.selected == app.items.iter().position(|x| x.id == item.id).unwrap_or(0);
            let style = if is_selected {
                theme.highlight_style()
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::new(Span::styled(&item.id, theme.key_hint_style())).style(style),
                Cell::new(Span::styled(
                    if item.requester_name.is_empty() {
                        "-"
                    } else {
                        &item.requester_name
                    },
                    theme.title_style(),
                ))
                .style(style),
                Cell::new(Span::styled(&item.created, theme.muted_style())).style(style),
            ])
            .height(1)
        })
        .collect();

    let pending_table = Table::new(
        pending_rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ],
    )
    .header(
        Row::new(vec!["ID", "Requester", "Created"])
            .style(theme.header_style())
            .height(1),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Pending ({})", pending_items.len()))
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(pending_table, body[0]);

    // Active projects
    let active_rows: Vec<Row> = active_items
        .iter()
        .map(|item| {
            let is_selected = app.active_tab == 1
                && app.selected == app.items.iter().position(|x| x.id == item.id).unwrap_or(0);
            let style = if is_selected {
                theme.highlight_style()
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::new(Span::styled(&item.id, theme.key_hint_style())).style(style),
                Cell::new(Span::styled(&item.revision, theme.info_style())).style(style),
                Cell::new(Span::styled(&item.created, theme.muted_style())).style(style),
            ])
            .height(1)
        })
        .collect();

    let active_table = Table::new(
        active_rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ],
    )
    .header(
        Row::new(vec!["ID", "Revision", "Created"])
            .style(theme.header_style())
            .height(1),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Active ({})", active_items.len()))
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(active_table, body[1]);
}

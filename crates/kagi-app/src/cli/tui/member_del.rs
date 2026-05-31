use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use kagi_store::key_manager::KeyManager;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use std::io;
use std::path::PathBuf;

use super::layout;
use super::theme::Theme;

struct Member {
    member_id: String,
    name: String,
    status: String,
}

struct App {
    members: Vec<Member>,
    selected: usize,
    removed: Option<String>,
}

pub fn run_tui_member_del(base_path: PathBuf) -> anyhow::Result<Option<String>> {
    let key_manager = KeyManager::new(base_path);
    let local_members = key_manager.list_members()?;

    let members: Vec<Member> = local_members
        .into_iter()
        .filter(|m| m.status == "active")
        .map(|m| Member {
            member_id: m.member_id,
            name: m.name,
            status: m.status,
        })
        .collect();

    if members.is_empty() {
        println!("kagi: no active members to remove.");
        return Ok(None);
    }

    let mut app = App {
        members,
        selected: 0,
        removed: None,
    };

    let theme = Theme::default();
    layout::run_tui(|terminal| run_app(terminal, &mut app, &theme))?;
    Ok(app.removed)
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

        if app.removed.is_some() {
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
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Enter => {
                    if let Some(m) = app.members.get(app.selected) {
                        app.removed = Some(m.member_id.clone());
                        return Ok(());
                    }
                }
                KeyCode::Down if app.selected + 1 < app.members.len() => {
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
    let content = layout::draw_frame(
        f,
        theme,
        "Remove Member",
        "↑↓=navigate  Enter=select to remove  q=quit",
    );

    let header = Row::new(vec!["Member ID", "Name", "Status"])
        .style(theme.header_style())
        .height(1);

    let rows: Vec<Row> = app
        .members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let style = if i == app.selected {
                theme.highlight_style()
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::new(Span::styled(&m.member_id, theme.key_hint_style())).style(style),
                Cell::new(Span::styled(&m.name, theme.title_style())).style(style),
                Cell::new(Span::styled(&m.status, theme.success_style())).style(style),
            ])
            .height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(40),
            Constraint::Percentage(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Active Members ({})", app.members.len()))
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(table, content);
}

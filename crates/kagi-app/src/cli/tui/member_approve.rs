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

struct PendingMember {
    member_id: String,
    name: String,
}

struct App {
    members: Vec<PendingMember>,
    selected: usize,
    approved: Option<String>,
}

pub fn run_tui_member_approve(base_path: PathBuf) -> anyhow::Result<Option<String>> {
    let key_manager = KeyManager::new(base_path);
    let requests = key_manager.list_join_requests()?;

    let members: Vec<PendingMember> = requests
        .into_iter()
        .map(|r| PendingMember {
            member_id: r.member_id,
            name: r.name,
        })
        .collect();

    if members.is_empty() {
        println!("kagi: no pending join requests.");
        return Ok(None);
    }

    let mut app = App {
        members,
        selected: 0,
        approved: None,
    };

    let theme = Theme::default();
    layout::run_tui(|terminal| run_app(terminal, &mut app, &theme))?;
    Ok(app.approved)
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

        if app.approved.is_some() {
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
                        app.approved = Some(m.member_id.clone());
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
        "Member Approval",
        "↑↓=navigate  Enter=approve  q=quit",
    );

    let header = Row::new(vec!["Member ID", "Name"])
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
            ])
            .height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Percentage(40), Constraint::Percentage(60)],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Pending ({})", app.members.len()))
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(table, content);
}

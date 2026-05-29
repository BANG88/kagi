use crate::infrastructure::key_manager::KeyManager;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use std::io;
use std::path::PathBuf;

struct MemberItem {
    id: String,
    name: String,
    status: String,
    is_pending: bool,
}

struct App {
    members: Vec<MemberItem>,
    selected: usize,
    active_tab: usize, // 0 = active, 1 = pending
}

pub fn run_tui_member_list() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let base = find_kagi_base(&cwd)?;
    let key_manager = KeyManager::new(base.clone());
    let local_members = key_manager.list_members()?;
    let local_requests = key_manager.list_join_requests()?;

    let mut members: Vec<MemberItem> = local_members
        .into_iter()
        .map(|m| MemberItem {
            id: m.member_id,
            name: m.name,
            status: m.status,
            is_pending: false,
        })
        .collect();

    let mut requests: Vec<MemberItem> = local_requests
        .into_iter()
        .map(|r| MemberItem {
            id: r.member_id,
            name: r.name,
            status: "pending".to_string(),
            is_pending: true,
        })
        .collect();

    members.sort_by(|a, b| a.id.cmp(&b.id));
    requests.sort_by(|a, b| a.id.cmp(&b.id));

    let mut app = App {
        members: requests.into_iter().chain(members).collect(),
        selected: 0,
        active_tab: 0,
    };

    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, &mut app);

    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = res {
        return Err(anyhow::anyhow!("TUI error: {}", e));
    }
    Ok(())
}

fn find_kagi_base(cwd: &std::path::Path) -> anyhow::Result<PathBuf> {
    let mut current = cwd;
    loop {
        let local = current.join(".kagi");
        if local.is_dir() {
            return Ok(local);
        }
        match current.parent() {
            Some(p) => current = p,
            None => break,
        }
    }
    Err(anyhow::anyhow!(
        "No .kagi directory found in current or parent directories."
    ))
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> io::Result<()> {
    let mut last_tick = std::time::Instant::now();
    let tick_rate = std::time::Duration::from_millis(250);

    loop {
        terminal.draw(|f| draw_ui(f, app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if crossterm::event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Down if app.selected + 1 < app.members.len() => {
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

fn draw_ui(f: &mut ratatui::Frame, app: &App) {
    let header_style = Style::default()
        .fg(Color::Rgb(35, 82, 133))
        .add_modifier(Modifier::BOLD);
    let success_style = Style::default()
        .fg(Color::Rgb(72, 121, 78))
        .add_modifier(Modifier::BOLD);
    let warning_style = Style::default().fg(Color::Rgb(188, 111, 35));
    let key_style = Style::default().fg(Color::Rgb(164, 74, 61));

    let active_members: Vec<_> = app.members.iter().filter(|m| !m.is_pending).collect();
    let pending_members: Vec<_> = app.members.iter().filter(|m| m.is_pending).collect();

    let body_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(f.area());

    // Active members
    let active_rows: Vec<Row> = active_members
        .iter()
        .map(|m| {
            let is_selected = app.active_tab == 0
                && app.selected == app.members.iter().position(|x| x.id == m.id).unwrap_or(0);
            let style = if is_selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(Span::styled(&m.id, key_style)).style(style),
                Cell::from(Span::styled(&m.name, style.fg(Color::White))).style(style),
                Cell::from(Span::styled(&m.status, success_style)).style(style),
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
        Row::new(vec!["ID", "Name", "Status"])
            .style(header_style)
            .height(1),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Active ({})", active_members.len()))
            .title_style(header_style),
    );
    f.render_widget(active_table, body_layout[0]);

    // Pending members
    let pending_rows: Vec<Row> = pending_members
        .iter()
        .map(|m| {
            let is_selected = app.active_tab == 1
                && app.selected == app.members.iter().position(|x| x.id == m.id).unwrap_or(0);
            let style = if is_selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(Span::styled(&m.id, key_style)).style(style),
                Cell::from(Span::styled(&m.name, style.fg(Color::White))).style(style),
                Cell::from(Span::styled(&m.status, warning_style)).style(style),
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
        Row::new(vec!["ID", "Name", "Status"])
            .style(header_style)
            .height(1),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Pending ({})", pending_members.len()))
            .title_style(header_style),
    );
    f.render_widget(pending_table, body_layout[1]);
}

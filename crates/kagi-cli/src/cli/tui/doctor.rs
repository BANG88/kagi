use crate::cli::commands::{DoctorCheck, collect_doctor_checks};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use std::io;
use std::io::IsTerminal;
use std::path::Path;

struct App {
    checks: Vec<DoctorCheck>,
    warnings: usize,
    errors: usize,
    selected: usize,
    show_detail: bool,
}

pub fn run_tui_doctor(base_path: &Path, fix: bool) -> anyhow::Result<()> {
    let (mut checks, mut warnings, mut errors) = collect_doctor_checks(base_path)?;
    if checks.is_empty() {
        println!("kagi: no checks to run.");
        return Ok(());
    }

    // Handle --fix before TUI if rotation journal exists
    if fix {
        let journal_path = base_path.join("rotation.journal.json");
        if journal_path.exists() {
            if !std::io::stdin().is_terminal() {
                return Err(anyhow::anyhow!(
                    "kagi doctor --fix requires an interactive terminal."
                ));
            }
            eprint!("recover pending rotation journal? [y/N]: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().eq_ignore_ascii_case("y") {
                let recovered = crate::cli::commands::recover_pending_rotation(base_path)?;
                if recovered {
                    println!("recovered pending rotation.");
                } else {
                    println!("no pending rotation to recover.");
                }
                // Recompute status after fix
                let (c, w, e) = collect_doctor_checks(base_path)?;
                checks = c;
                warnings = w;
                errors = e;
            }
        }
    }

    let mut app = App {
        checks,
        warnings,
        errors,
        selected: 0,
        show_detail: false,
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
                KeyCode::Down if app.selected + 1 < app.checks.len() => {
                    app.selected += 1;
                }
                KeyCode::Up if app.selected > 0 => {
                    app.selected -= 1;
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    app.show_detail = !app.show_detail;
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
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(f.area());

    let header_style = Style::default()
        .fg(Color::Rgb(35, 82, 133))
        .add_modifier(Modifier::BOLD);
    let success_style = Style::default()
        .fg(Color::Rgb(72, 121, 78))
        .add_modifier(Modifier::BOLD);
    let error_style = Style::default().fg(Color::Rgb(190, 55, 43));
    let warning_style = Style::default().fg(Color::Rgb(188, 111, 35));
    let muted_style = Style::default().fg(Color::Rgb(140, 140, 140));

    let summary = if app.errors > 0 {
        format!("{} error(s), {} warning(s)", app.errors, app.warnings)
    } else if app.warnings > 0 {
        format!("{} warning(s)", app.warnings)
    } else {
        "all checks passed".to_string()
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled("Kagi Doctor", header_style),
        Span::raw("  "),
        Span::styled(
            &summary,
            if app.errors > 0 {
                error_style
            } else if app.warnings > 0 {
                warning_style
            } else {
                success_style
            },
        ),
    ]));
    f.render_widget(header, main_layout[1]);

    let rows: Vec<Row> = app
        .checks
        .iter()
        .enumerate()
        .map(|(i, check)| {
            let is_selected = i == app.selected;
            let icon = if check.ok { "✓" } else { "✗" };
            let icon_style = if check.ok { success_style } else { error_style };
            let style = if is_selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            let cells = vec![
                Cell::from(Span::styled(icon, icon_style)).style(style),
                Cell::from(Span::styled(check.name, style.fg(Color::Rgb(35, 82, 133)))),
                Cell::from(Span::styled(&check.detail, muted_style)).style(style),
            ];
            Row::new(cells).height(1)
        })
        .collect();

    let header_row = Row::new(vec!["", "Check", "Detail"])
        .style(header_style)
        .height(1);

    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Percentage(30),
            Constraint::Percentage(70),
        ],
    )
    .header(header_row)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Checks")
            .title_style(header_style),
    );
    f.render_widget(table, main_layout[0]);

    // Detail panel
    if app.show_detail {
        let check = &app.checks[app.selected];
        let detail_text = format!("{}\n{}", check.name, check.detail);
        let detail_block = Block::default()
            .borders(Borders::ALL)
            .title("Detail")
            .title_style(header_style);
        let detail = Paragraph::new(detail_text).block(detail_block);
        let area = centered_rect(60, 40, f.area());
        f.render_widget(ratatui::widgets::Clear, area);
        f.render_widget(detail, area);
    }
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

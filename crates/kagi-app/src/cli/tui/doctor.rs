use crate::cli::commands::{DoctorCheck, collect_doctor_checks};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use std::io;
use std::io::IsTerminal;
use std::path::Path;

use super::layout;
use super::theme::Theme;

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

fn draw_ui(f: &mut ratatui::Frame, app: &App, theme: &Theme) {
    let summary = if app.errors > 0 {
        format!("{} error(s), {} warning(s)", app.errors, app.warnings)
    } else if app.warnings > 0 {
        format!("{} warning(s)", app.warnings)
    } else {
        "all checks passed".to_string()
    };

    let content = layout::draw_frame(
        f,
        theme,
        &format!("Doctor — {summary}"),
        "↑↓=navigate  Enter=details  q=quit",
    );

    let rows: Vec<Row> = app
        .checks
        .iter()
        .enumerate()
        .map(|(i, check)| {
            let is_selected = i == app.selected;
            let icon = if check.ok { "✓" } else { "✗" };
            let icon_style = if check.ok {
                theme.success_style()
            } else {
                theme.error_style()
            };
            let style = if is_selected {
                theme.highlight_style()
            } else {
                Style::default()
            };
            let cells = vec![
                Cell::new(Span::styled(icon, icon_style)).style(style),
                Cell::new(Span::styled(check.name, theme.title_style())).style(style),
                Cell::new(Span::styled(&check.detail, theme.muted_style())).style(style),
            ];
            Row::new(cells).height(1)
        })
        .collect();

    let header_row = Row::new(vec!["", "Check", "Detail"])
        .style(theme.header_style())
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
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(table, content);

    // Detail modal
    if app.show_detail {
        let check = &app.checks[app.selected];
        let detail_text = check.detail.to_string();
        layout::draw_modal(f, theme, check.name, &detail_text, (60, 40));
    }
}

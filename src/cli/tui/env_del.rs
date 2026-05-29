use crate::domain::repository::secret_repo::SecretRepository;
use crate::infrastructure::fs_store::FileStore;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use std::io;

struct App {
    env: String,
    affected: Vec<String>,
    confirm_input: String,
    confirmed: Option<bool>,
}

pub fn run_tui_env_del(store: &FileStore, env: &str) -> anyhow::Result<bool> {
    let all_services = store.list_services()?;
    let prefix = format!("/{}", env);
    let affected: Vec<String> = all_services
        .into_iter()
        .filter(|s| s.ends_with(&prefix))
        .collect();

    let mut app = App {
        env: env.to_string(),
        affected,
        confirm_input: String::new(),
        confirmed: None,
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

    Ok(app.confirmed == Some(true))
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> io::Result<()> {
    let tick_rate = std::time::Duration::from_millis(250);
    let mut last_tick = std::time::Instant::now();

    loop {
        terminal.draw(|f| draw_ui(f, app))?;

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
                KeyCode::Esc => {
                    app.confirmed = Some(false);
                    return Ok(());
                }
                KeyCode::Enter if app.confirm_input == app.env => {
                    app.confirmed = Some(true);
                    return Ok(());
                }
                KeyCode::Backspace => {
                    app.confirm_input.pop();
                }
                KeyCode::Char(c) => {
                    app.confirm_input.push(c);
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
    let error_style = Style::default()
        .fg(Color::Rgb(190, 55, 43))
        .add_modifier(Modifier::BOLD);
    let warning_style = Style::default().fg(Color::Rgb(188, 111, 35));
    let muted_style = Style::default().fg(Color::Rgb(140, 140, 140));
    let white_style = Style::default().fg(Color::White);

    let area = centered_rect(60, 50, f.area());

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Delete Environment")
        .title_style(error_style);

    let mut lines: Vec<Line> = Vec::new();
    let warning_text = format!(
        "This will delete '{}' from the following services:",
        app.env
    );
    lines.push(Line::from(vec![
        Span::styled("WARNING: ", error_style),
        Span::styled(&warning_text, warning_style),
    ]));
    lines.push(Line::from(""));

    if app.affected.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "No services currently have this environment.",
            muted_style,
        )]));
    } else {
        for scope in &app.affected {
            lines.push(Line::from(vec![
                Span::styled("  • ", muted_style),
                Span::styled(scope, white_style),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Type ", muted_style),
        Span::styled(&app.env, error_style),
        Span::styled(" to confirm deletion, or Esc to cancel.", muted_style),
    ]));
    lines.push(Line::from(""));
    let input_display = format!(
        "> {}{}",
        app.confirm_input,
        if app.confirm_input.is_empty() {
            " "
        } else {
            ""
        }
    );
    let input_style = if app.confirm_input == app.env {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        white_style
    };
    lines.push(Line::from(vec![Span::styled(&input_display, input_style)]));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });

    f.render_widget(Clear, area);
    f.render_widget(paragraph, area);
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

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use kagi_domain::repository::secret_repo::SecretRepository;
use kagi_store::fs_store::FileStore;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use std::io;

use super::layout;
use super::theme::Theme;

struct App {
    env: String,
    affected: Vec<String>,
    confirm_input: String,
    confirmed: Option<bool>,
}

pub fn run_tui_env_del(store: &FileStore, env: &str) -> anyhow::Result<bool> {
    let all_services = store.list_services()?;
    let prefix = format!("/{env}");
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

    let theme = Theme::default();
    layout::run_tui(|terminal| run_app(terminal, &mut app, &theme))?;
    Ok(app.confirmed == Some(true))
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

fn draw_ui(f: &mut ratatui::Frame, app: &App, theme: &Theme) {
    let content = layout::draw_frame(f, theme, "Delete Environment", "Esc=cancel  Enter=confirm");

    let error_style = theme.error_style();
    let warning_style = theme.warning_style();
    let muted_style = theme.muted_style();
    let white_style = Style::default().fg(theme.text());

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Confirm")
        .title_style(error_style)
        .border_style(theme.block_style());

    let mut lines: Vec<Line> = Vec::new();
    let warning_text = format!(
        "This will delete '{}' from the following services:",
        app.env
    );
    lines.push(Line::from(vec![
        Span::styled("WARNING: ", error_style),
        Span::styled(warning_text, warning_style),
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
            .fg(theme.success())
            .add_modifier(Modifier::BOLD)
    } else {
        white_style
    };
    lines.push(Line::from(vec![Span::styled(input_display, input_style)]));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });

    f.render_widget(Clear, content);
    f.render_widget(paragraph, content);
}

use crate::application::export_env::ExportEnvService;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use kagi_domain::repository::secret_repo::SecretRepository;
use kagi_store::fs_store::FileStore;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use std::io;
use std::path::Path;

use super::layout;
use super::theme::Theme;

struct ScopePreview {
    scope: String,
    content: String,
    path: String,
}

struct App {
    scopes: Vec<ScopePreview>,
    out_dir: Option<String>,
    selected: usize,
    confirmed: Option<bool>,
}

pub fn run_tui_export(
    store: FileStore,
    scopes: Vec<String>,
    out: Option<String>,
) -> anyhow::Result<()> {
    let mut previews = Vec::new();
    for scope in &scopes {
        let service = store.load(scope)?;
        let mut secrets: Vec<_> = service.secrets.values().collect();
        secrets.sort_by(|a, b| a.key.cmp(&b.key));
        let mut lines = Vec::new();
        for s in secrets {
            if let Some(desc) = &s.description {
                lines.push(format!("# {desc}"));
            }
            lines.push(format!("{}={}", s.key, s.value));
        }
        let content = lines.join("\n");
        let path = if let Some(ref out) = out {
            let env = scope.split_once('/').map_or(scope.as_str(), |(_, e)| e);
            format!("{out}/.env.{env}")
        } else {
            "(stdout)".to_string()
        };
        previews.push(ScopePreview {
            scope: scope.clone(),
            content,
            path,
        });
    }

    let mut app = App {
        scopes: previews,
        out_dir: out,
        selected: 0,
        confirmed: None,
    };

    let theme = Theme::default();
    layout::run_tui(|terminal| run_app(terminal, &mut app, &theme))?;

    if app.confirmed != Some(true) {
        return Ok(());
    }

    let export_service = ExportEnvService::new(store);
    for preview in &app.scopes {
        let output = export_service.execute(&preview.scope)?;
        if let Some(ref out) = app.out_dir {
            let out_dir = Path::new(out);
            std::fs::create_dir_all(out_dir)?;
            let env = preview
                .scope
                .split_once('/')
                .map_or(preview.scope.as_str(), |(_, e)| e);
            let path = out_dir.join(format!(".env.{env}"));
            std::fs::write(&path, output)?;
        } else {
            println!("{output}");
        }
    }

    Ok(())
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
                KeyCode::Char('q') | KeyCode::Esc => {
                    app.confirmed = Some(false);
                    return Ok(());
                }
                KeyCode::Char('y') => {
                    app.confirmed = Some(true);
                    return Ok(());
                }
                KeyCode::Char('n') => {
                    app.confirmed = Some(false);
                    return Ok(());
                }
                KeyCode::Down if app.selected + 1 < app.scopes.len() => {
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
    let out_label = app.out_dir.as_deref().unwrap_or("stdout");
    let content = layout::draw_frame(
        f,
        theme,
        &format!("Export Preview — {out_label}"),
        "y=confirm  n=cancel  q=quit  ↑↓=navigate",
    );

    let body = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(content);

    let left = body[0];
    let right = body[1];

    // Left: preview table
    let header = Row::new(vec!["Scope", "Destination"])
        .style(theme.header_style())
        .height(1);
    let rows: Vec<Row> = app
        .scopes
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let style = if i == app.selected {
                theme.highlight_style()
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::new(Span::styled(&p.scope, theme.title_style())).style(style),
                Cell::new(Span::styled(&p.path, theme.muted_style())).style(style),
            ])
            .height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Percentage(50), Constraint::Percentage(50)],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Scopes")
            .title_style(theme.header_style())
            .border_style(theme.block_style()),
    );
    f.render_widget(table, left);

    // Right: content preview
    let preview = app
        .scopes
        .get(app.selected)
        .map(|p| p.content.as_str())
        .unwrap_or("");
    let right_block = Block::default()
        .borders(Borders::ALL)
        .title("Content")
        .title_style(theme.header_style())
        .border_style(theme.block_style());
    let right_paragraph = Paragraph::new(preview)
        .block(right_block)
        .wrap(Wrap { trim: false });
    f.render_widget(right_paragraph, right);
}

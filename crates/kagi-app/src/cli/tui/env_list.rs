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

struct App {
    items: Vec<String>,
    selected: usize,
}

pub fn run_tui_env_list(envs: Vec<String>) -> anyhow::Result<()> {
    if envs.is_empty() {
        println!("kagi: no environments configured.");
        return Ok(());
    }

    let mut app = App {
        items: envs,
        selected: 0,
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
                _ => {}
            }
        }
        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
        }
    }
}

fn draw_ui(f: &mut ratatui::Frame, app: &App, theme: &Theme) {
    let content = layout::draw_frame(f, theme, "Environments", "↑↓=navigate  q=quit");

    let header = Row::new(vec!["Environment"])
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
            Row::new(vec![
                Cell::new(Span::styled(item, theme.key_hint_style())).style(style),
            ])
            .height(1)
        })
        .collect();

    let table = Table::new(rows, [Constraint::Percentage(100)])
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Results ({})", app.items.len()))
                .title_style(theme.header_style())
                .border_style(theme.block_style()),
        );
    f.render_widget(table, content);
}

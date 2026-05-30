use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use kagi_domain::repository::secret_repo::SecretRepository;
use kagi_store::fs_store::FileStore;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};
use std::io;

struct ScopeItem {
    name: String,
    keys: Vec<(String, String, Option<String>)>,
}

struct App {
    scopes: Vec<ScopeItem>,
    selected_scope: usize,
    selected_key: usize,
    revealed: std::collections::HashSet<(usize, usize)>,
    show_search: bool,
    search_query: String,
    search_selected: usize,
    show_copy_modal: bool,
    copy_message: String,
    all_keys_filtered: Vec<(usize, usize)>,
}

impl App {
    fn filtered_keys(&self) -> Vec<(usize, usize)> {
        if self.search_query.is_empty() {
            let mut result = Vec::new();
            for (si, scope) in self.scopes.iter().enumerate() {
                for (ki, (_key, _, _)) in scope.keys.iter().enumerate() {
                    result.push((si, ki));
                }
            }
            return result;
        }
        let q = self.search_query.to_lowercase();
        let mut result = Vec::new();
        for (si, scope) in self.scopes.iter().enumerate() {
            for (ki, (key, _, desc)) in scope.keys.iter().enumerate() {
                if key.to_lowercase().contains(&q)
                    || desc
                        .as_ref()
                        .map(|d| d.to_lowercase().contains(&q))
                        .unwrap_or(false)
                {
                    result.push((si, ki));
                }
            }
        }
        result
    }

    fn current_scope_index(&self) -> usize {
        if self.search_query.is_empty() {
            self.selected_scope
        } else if let Some(&(si, _)) = self.all_keys_filtered.get(self.search_selected) {
            si
        } else {
            0
        }
    }

    fn current_key_index(&self) -> usize {
        if self.search_query.is_empty() {
            self.selected_key
        } else if let Some(&(_, ki)) = self.all_keys_filtered.get(self.search_selected) {
            ki
        } else {
            0
        }
    }
}

pub fn run_tui_get(store: FileStore, show_values: bool) -> anyhow::Result<()> {
    let mut scopes = Vec::new();
    for scope_name in store.list_services()? {
        let items = store.load(&scope_name)?;
        let keys: Vec<(String, String, Option<String>)> = items
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), v.value.clone(), v.description.clone()))
            .collect();
        scopes.push(ScopeItem {
            name: scope_name,
            keys,
        });
    }
    if scopes.is_empty() {
        println!("kagi: no services found.");
        return Ok(());
    }

    let mut app = App {
        scopes,
        selected_scope: 0,
        selected_key: 0,
        revealed: std::collections::HashSet::new(),
        show_search: false,
        search_query: String::new(),
        search_selected: 0,
        show_copy_modal: false,
        copy_message: String::new(),
        all_keys_filtered: Vec::new(),
    };
    app.all_keys_filtered = app.filtered_keys();

    if show_values {
        // Pre-reveal all keys if --show is passed
        for si in 0..app.scopes.len() {
            for ki in 0..app.scopes[si].keys.len() {
                app.revealed.insert((si, ki));
            }
        }
    }

    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, &mut app, &store);

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

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    store: &FileStore,
) -> io::Result<()> {
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
            if app.show_copy_modal {
                app.show_copy_modal = false;
                continue;
            }
            if app.show_search {
                match key.code {
                    KeyCode::Esc => {
                        app.show_search = false;
                        app.search_query.clear();
                        app.all_keys_filtered = app.filtered_keys();
                    }
                    KeyCode::Enter => {
                        app.show_search = false;
                        app.all_keys_filtered = app.filtered_keys();
                    }
                    KeyCode::Backspace => {
                        app.search_query.pop();
                    }
                    KeyCode::Char(c) => {
                        app.search_query.push(c);
                    }
                    _ => {}
                }
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('s') | KeyCode::Enter => {
                    let si = app.current_scope_index();
                    let ki = app.current_key_index();
                    let key = app.revealed.take(&(si, ki));
                    if key.is_none() {
                        app.revealed.insert((si, ki));
                    }
                }
                KeyCode::Char('/') => {
                    app.show_search = true;
                }
                KeyCode::Char('c') => {
                    let si = app.current_scope_index();
                    let ki = app.current_key_index();
                    if let Some(scope) = app.scopes.get(si)
                        && let Some((key_name, _, _)) = scope.keys.get(ki)
                    {
                        let scope_name = &scope.name;
                        if let Ok(service) = store.load(scope_name)
                            && let Some(secret) = service.get_secret(key_name)
                        {
                            let _value = secret.value.clone();
                            app.copy_message =
                                format!("Copied {}.{} to clipboard", scope_name, key_name);
                            app.show_copy_modal = true;
                        }
                    }
                }
                KeyCode::Down => {
                    if app.search_query.is_empty() {
                        if app.selected_key + 1 < app.scopes[app.selected_scope].keys.len() {
                            app.selected_key += 1;
                        } else if app.selected_scope + 1 < app.scopes.len() {
                            app.selected_scope += 1;
                            app.selected_key = 0;
                        }
                    } else if app.search_selected + 1 < app.all_keys_filtered.len() {
                        app.search_selected += 1;
                    }
                }
                KeyCode::Up => {
                    if app.search_query.is_empty() {
                        if app.selected_key > 0 {
                            app.selected_key -= 1;
                        } else if app.selected_scope > 0 {
                            app.selected_scope -= 1;
                            app.selected_key =
                                app.scopes[app.selected_scope].keys.len().saturating_sub(1);
                        }
                    } else if app.search_selected > 0 {
                        app.search_selected -= 1;
                    }
                }
                KeyCode::Left if app.search_query.is_empty() && app.selected_scope > 0 => {
                    app.selected_scope -= 1;
                    app.selected_key = 0;
                }
                KeyCode::Right
                    if app.search_query.is_empty() && app.selected_scope + 1 < app.scopes.len() =>
                {
                    app.selected_scope += 1;
                    app.selected_key = 0;
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

    let body_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main_layout[0]);

    let header_style = Style::default()
        .fg(Color::Rgb(35, 82, 133))
        .add_modifier(Modifier::BOLD);
    let active_style = Style::default()
        .fg(Color::Rgb(72, 121, 78))
        .add_modifier(Modifier::BOLD);
    let key_style = Style::default().fg(Color::Rgb(164, 74, 61));
    let muted_style = Style::default().fg(Color::Rgb(140, 140, 140));
    let warning_style = Style::default().fg(Color::Rgb(188, 111, 35));

    // Left pane: scopes
    let scope_items: Vec<Line> = app
        .scopes
        .iter()
        .enumerate()
        .map(|(i, scope)| {
            let style = if i == app.current_scope_index() {
                active_style
            } else {
                muted_style
            };
            Line::from(Span::styled(&scope.name, style))
        })
        .collect();

    let left_block = Block::default()
        .borders(Borders::ALL)
        .title("Scopes")
        .title_style(header_style);
    let left_paragraph = Paragraph::new(scope_items).block(left_block);
    f.render_widget(left_paragraph, body_layout[0]);

    // Right pane: keys table
    let si = app.current_scope_index();
    let header = Row::new(vec!["Key", "Value", "Description"])
        .style(header_style)
        .height(1);

    let rows: Vec<Row> = if let Some(scope) = app.scopes.get(si) {
        scope
            .keys
            .iter()
            .enumerate()
            .map(|(ki, (key, value, desc))| {
                let is_selected = ki == app.current_key_index();
                let is_revealed = app.revealed.contains(&(si, ki));
                let value_display = if is_revealed {
                    value.clone()
                } else {
                    "********".to_string()
                };
                let desc_display = desc.as_deref().unwrap_or("");
                let style = if is_selected {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(Span::styled(key, key_style)).style(style),
                    Cell::from(Span::styled(
                        value_display,
                        if is_revealed {
                            Style::default().fg(Color::Green)
                        } else {
                            muted_style
                        },
                    ))
                    .style(style),
                    Cell::from(Span::styled(desc_display, muted_style)).style(style),
                ])
                .height(1)
            })
            .collect()
    } else {
        Vec::new()
    };

    let right_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(
            "Keys: {} ({})",
            app.scopes.get(si).map(|s| s.name.as_str()).unwrap_or("?"),
            app.all_keys_filtered.len()
        ))
        .title_style(header_style);
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(30),
            Constraint::Percentage(40),
        ],
    )
    .header(header)
    .block(right_block);
    f.render_widget(table, body_layout[1]);

    // Status bar
    let status = if app.show_search {
        format!("Search: {} | Enter=confirm Esc=clear", app.search_query)
    } else {
        let si = app.current_scope_index();
        let ki = app.current_key_index();
        let revealed = app.revealed.contains(&(si, ki));
        let hints = if revealed {
            "s/Enter=hide | c=copy | /=search | q=quit"
        } else {
            "s/Enter=reveal | c=copy | /=search | q=quit"
        };
        format!(
            "{} [{}] {}",
            app.scopes.get(si).map(|s| s.name.as_str()).unwrap_or("?"),
            app.scopes
                .get(si)
                .and_then(|s| s.keys.get(ki))
                .map(|(k, _, _)| k.as_str())
                .unwrap_or("?"),
            hints
        )
    };
    let status_bar = Paragraph::new(Span::styled(status, warning_style));
    f.render_widget(status_bar, main_layout[1]);

    // Copy modal
    if app.show_copy_modal {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Copied")
            .title_style(Style::default().fg(Color::Green));
        let paragraph = Paragraph::new(app.copy_message.clone()).block(block);
        let area = centered_rect(40, 20, f.area());
        f.render_widget(Clear, area);
        f.render_widget(paragraph, area);
    }

    // Search modal
    if app.show_search {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Search")
            .title_style(header_style);
        let paragraph = Paragraph::new(app.search_query.clone()).block(block);
        let area = centered_rect(40, 10, f.area());
        f.render_widget(Clear, area);
        f.render_widget(paragraph, area);
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

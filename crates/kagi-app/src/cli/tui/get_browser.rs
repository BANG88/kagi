use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use kagi_domain::repository::secret_repo::SecretRepository;
use kagi_store::fs_store::FileStore;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table};
use std::io::{self, Write};
use std::process::{Command, Stdio};

use super::layout;
use super::theme::Theme;

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
    copy_error: bool,
    copy_message: String,
    all_keys_filtered: Vec<(usize, usize)>,
    show_confirm: bool,
    confirmed_reveal: bool,
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

pub fn run_tui_get(store: FileStore, _show_values: bool) -> anyhow::Result<()> {
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
        copy_error: false,
        copy_message: String::new(),
        all_keys_filtered: Vec::new(),
        show_confirm: false,
        confirmed_reveal: _show_values,
    };
    app.all_keys_filtered = app.filtered_keys();

    let theme = Theme::default();
    layout::run_tui(|terminal| run_app(terminal, &mut app, &store, &theme))
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    store: &FileStore,
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
            if app.show_copy_modal {
                app.show_copy_modal = false;
                continue;
            }
            if app.show_confirm {
                app.show_confirm = false;
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        app.confirmed_reveal = true;
                    }
                    _ => {}
                }
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
                    if app.revealed.contains(&(si, ki)) {
                        app.revealed.remove(&(si, ki));
                    } else if app.confirmed_reveal {
                        app.revealed.insert((si, ki));
                    } else {
                        app.show_confirm = true;
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
                            match copy_to_clipboard(&secret.value) {
                                Ok(()) => {
                                    app.copy_error = false;
                                    app.copy_message =
                                        format!("Copied {scope_name}.{key_name} to clipboard");
                                }
                                Err(error) => {
                                    app.copy_error = true;
                                    app.copy_message = format!("Copy failed: {error}");
                                }
                            }
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
                KeyCode::BackTab if app.search_query.is_empty() && app.selected_scope > 0 => {
                    app.selected_scope -= 1;
                    app.selected_key = 0;
                }
                KeyCode::Right
                    if app.search_query.is_empty() && app.selected_scope + 1 < app.scopes.len() =>
                {
                    app.selected_scope += 1;
                    app.selected_key = 0;
                }
                KeyCode::Tab
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

struct ClipboardCommand<'a> {
    program: &'a str,
    args: &'a [&'a str],
}

fn copy_to_clipboard(value: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let commands = [ClipboardCommand {
        program: "pbcopy",
        args: &[],
    }];

    #[cfg(windows)]
    let commands = [ClipboardCommand {
        program: "clip",
        args: &[],
    }];

    #[cfg(all(unix, not(target_os = "macos")))]
    let commands = [
        ClipboardCommand {
            program: "wl-copy",
            args: &[],
        },
        ClipboardCommand {
            program: "xclip",
            args: &["-selection", "clipboard"],
        },
        ClipboardCommand {
            program: "xsel",
            args: &["--clipboard", "--input"],
        },
    ];

    copy_to_clipboard_with_commands(value, &commands)
}

fn copy_to_clipboard_with_commands(
    value: &str,
    commands: &[ClipboardCommand<'_>],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for command in commands {
        match copy_with_command(command, value) {
            Ok(()) => return Ok(()),
            Err(error) => errors.push(error),
        }
    }

    if errors.is_empty() {
        Err("no clipboard command configured".to_string())
    } else {
        Err(errors.join("; "))
    }
}

fn copy_with_command(command: &ClipboardCommand<'_>, value: &str) -> Result<(), String> {
    let mut child = Command::new(command.program)
        .args(command.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{}: {e}", command.program))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("{}: stdin unavailable", command.program))?;
        stdin
            .write_all(value.as_bytes())
            .map_err(|e| format!("{}: {e}", command.program))?;
    }

    let status = child
        .wait()
        .map_err(|e| format!("{}: {e}", command.program))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{}: exited with {status}", command.program))
    }
}

fn draw_ui(f: &mut ratatui::Frame, app: &App, theme: &Theme) {
    let content = layout::draw_frame(
        f,
        theme,
        "Secret Browser",
        "Tab=scope  s/Enter=reveal all  c=copy  /=search  q=quit",
    );

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(content);

    let left = body[0];
    let right = body[1];

    // Left: scope list using List widget
    let scope_items: Vec<ListItem> = app
        .scopes
        .iter()
        .enumerate()
        .map(|(i, scope)| {
            let style = if i == app.current_scope_index() {
                theme.highlight_style()
            } else {
                Style::default().fg(theme.muted())
            };
            ListItem::new(Line::from(Span::styled(&scope.name, style)))
        })
        .collect();

    let list = List::new(scope_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Scopes")
                .title_style(theme.header_style())
                .border_style(theme.block_style()),
        )
        .highlight_style(theme.highlight_style());
    f.render_widget(list, left);

    // Right: keys table
    let si = app.current_scope_index();
    let header = Row::new(vec!["Key", "Value", "Description"])
        .style(theme.header_style())
        .height(1);

    let rows: Vec<Row> = if let Some(scope) = app.scopes.get(si) {
        scope
            .keys
            .iter()
            .enumerate()
            .map(|(ki, (key, value, desc))| {
                let is_selected = ki == app.current_key_index();
                let is_revealed = app.revealed.contains(&(si, ki));
                let is_revealed = app.confirmed_reveal || is_revealed;
                let value_display = if is_revealed {
                    value.clone()
                } else {
                    "********".to_string()
                };
                let desc_display = desc.as_deref().unwrap_or("");
                let style = if is_selected {
                    theme.highlight_style()
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::new(Span::styled(key, theme.key_hint_style())).style(style),
                    Cell::new(Span::styled(
                        value_display,
                        if is_revealed {
                            Style::default().fg(theme.success())
                        } else {
                            Style::default().fg(theme.muted())
                        },
                    ))
                    .style(style),
                    Cell::new(Span::styled(desc_display, theme.muted_style())).style(style),
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
        .title_style(theme.header_style())
        .border_style(theme.block_style());
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
    f.render_widget(table, right);

    // Confirm modal
    if app.show_confirm {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Confirm Reveal")
            .title_style(theme.warning_style())
            .border_style(theme.block_style());
        let paragraph = Paragraph::new("Reveal decrypted value? (y/N)").block(block);
        let area = layout::centered_rect(40, 10, f.area());
        f.render_widget(Clear, area);
        f.render_widget(paragraph, area);
    }

    // Copy modal
    if app.show_copy_modal {
        let title = if app.copy_error {
            "Copy Failed"
        } else {
            "Copied"
        };
        let title_style = if app.copy_error {
            theme.error_style()
        } else {
            theme.success_style()
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_style(title_style)
            .border_style(theme.block_style());
        let paragraph = Paragraph::new(app.copy_message.clone()).block(block);
        let area = layout::centered_rect(40, 20, f.area());
        f.render_widget(Clear, area);
        f.render_widget(paragraph, area);
    }

    // Search modal
    if app.show_search {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Search")
            .title_style(theme.header_style())
            .border_style(theme.block_style());
        let paragraph = Paragraph::new(app.search_query.clone()).block(block);
        let area = layout::centered_rect(40, 10, f.area());
        f.render_widget(Clear, area);
        f.render_widget(paragraph, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn copy_to_clipboard_command_writes_value_to_stdin() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let script = dir.path().join("copy.sh");
        let output = dir.path().join("clipboard.txt");
        std::fs::write(&script, "#!/bin/sh\ncat > \"$1\"\n").unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&script, permissions).unwrap();

        let output_arg = output.to_str().unwrap().to_string();
        let args = [output_arg.as_str()];
        let commands = [ClipboardCommand {
            program: script.to_str().unwrap(),
            args: &args,
        }];

        copy_to_clipboard_with_commands("secret-value", &commands).unwrap();

        assert_eq!(std::fs::read_to_string(output).unwrap(), "secret-value");
    }
}

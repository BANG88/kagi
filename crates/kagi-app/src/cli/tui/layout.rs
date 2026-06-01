use super::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

pub fn draw_frame(frame: &mut Frame, theme: &Theme, title: &str, footer: &str) -> Rect {
    let full = frame.area();

    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(0),    // content
            Constraint::Length(1), // footer
        ])
        .split(full);

    let header = main[0];
    let content = main[1];
    let footer_area = main[2];

    // Header
    let header_block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(theme.block_style());
    let header_text = Line::from(vec![
        Span::styled("  KAGI  ", theme.logo_style()),
        Span::styled("  ", Style::default()),
        Span::styled(title, theme.title_style()),
    ]);
    let header_paragraph = Paragraph::new(header_text).block(header_block);
    frame.render_widget(header_paragraph, header);

    // Footer
    let footer_paragraph = Paragraph::new(Span::styled(footer, theme.footer_style()));
    frame.render_widget(footer_paragraph, footer_area);

    // Content area with padding
    content.inner(Margin::new(1, 0))
}

pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup = Layout::default()
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
        .split(popup[1])[1]
}

pub fn draw_modal(frame: &mut Frame, theme: &Theme, title: &str, text: &str, percent: (u16, u16)) {
    let area = centered_rect(percent.0, percent.1, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(theme.header_style())
        .border_style(theme.block_style());
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

/// Run a TUI application with proper terminal setup and teardown.
/// Accepts a closure that receives the terminal and runs the application loop.
/// The closure should return an `io::Result` which is converted to an `anyhow::Result`.
pub fn run_tui<F, T>(f: F) -> anyhow::Result<T>
where
    F: FnOnce(
        &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    ) -> std::io::Result<T>,
{
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let result = f(&mut terminal);

    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result.map_err(|e| anyhow::anyhow!("TUI error: {e}"))
}

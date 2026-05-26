use owo_colors::OwoColorize;

/// Japanese-inspired terminal styles with high-contrast colors.
pub fn kagi_styles() -> clap::builder::styling::Styles {
    use clap::builder::styling::{Color, RgbColor, Style, Styles};
    Styles::styled()
        .header(
            Style::new()
                .bold()
                .fg_color(Some(Color::Rgb(RgbColor(188, 111, 35)))),
        )
        .usage(
            Style::new()
                .bold()
                .fg_color(Some(Color::Rgb(RgbColor(45, 93, 145)))),
        )
        .literal(Style::new().fg_color(Some(Color::Rgb(RgbColor(72, 121, 78)))))
        .placeholder(Style::new().fg_color(Some(Color::Rgb(RgbColor(164, 74, 61)))))
        .error(
            Style::new()
                .bold()
                .fg_color(Some(Color::Rgb(RgbColor(190, 55, 43)))),
        )
        .valid(Style::new().fg_color(Some(Color::Rgb(RgbColor(72, 121, 78)))))
        .invalid(Style::new().fg_color(Some(Color::Rgb(RgbColor(190, 55, 43)))))
}

/// Low-saturation Japanese color palette for Kagi CLI.
pub struct Palette {
    tty: bool,
}

impl Palette {
    pub fn new(tty: bool) -> Self {
        Self { tty }
    }

    fn apply(&self, text: &str, rgb: (u8, u8, u8)) -> String {
        if self.tty {
            text.truecolor(rgb.0, rgb.1, rgb.2).bold().to_string()
        } else {
            text.to_string()
        }
    }

    fn plain(&self, text: &str) -> String {
        text.to_string()
    }

    /// Log prefix for human-facing status lines.
    pub fn prefix(&self) -> String {
        self.apply("kagi:", (35, 82, 133))
    }

    /// Success / done — matcha green.
    pub fn success(&self, text: &str) -> String {
        self.apply(text, (72, 121, 78))
    }

    /// Info / normal messages — muted indigo.
    pub fn info(&self, text: &str) -> String {
        self.plain(text)
    }

    /// Warning / overwrite — old gold.
    pub fn warning(&self, text: &str) -> String {
        self.apply(text, (188, 111, 35))
    }

    /// Error / abort — vermilion.
    pub fn error(&self, text: &str) -> String {
        self.apply(text, (190, 55, 43))
    }

    /// Accent / scope names — indigo.
    pub fn accent(&self, text: &str) -> String {
        self.apply(text, (35, 82, 133))
    }

    /// Secret key names — sakura clay.
    pub fn key(&self, text: &str) -> String {
        self.apply(text, (164, 74, 61))
    }

    /// Interactive prompt — warm gold.
    pub fn prompt(&self, text: &str) -> String {
        self.apply(text, (176, 105, 31))
    }

    /// Muted / secondary — sumi gray.
    pub fn muted(&self, text: &str) -> String {
        self.plain(text)
    }

    /// Commented / needs value — soft sakura.
    pub fn commented(&self, text: &str) -> String {
        self.apply(text, (150, 82, 86))
    }
}

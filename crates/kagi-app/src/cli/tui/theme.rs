use ratatui::style::{Color, Modifier, Style};

/// Theme system with Dark/Light variants.
/// Inspired by Japanese minimalism: clean palettes, subtle contrast,
/// with cherry blossom (sakura) accents.
#[derive(Clone, Debug)]
pub enum Theme {
    Dark,
    Light,
}

impl Default for Theme {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Theme {
    /// Detect theme preference from environment.
    /// Checks `KAGI_THEME` env var, then falls back to terminal hints.
    pub fn from_env() -> Self {
        if let Ok(val) = std::env::var("KAGI_THEME") {
            match val.to_lowercase().as_str() {
                "light" => return Theme::Light,
                "dark" => return Theme::Dark,
                _ => {}
            }
        }
        // Some terminals export background color via COLORFGBG
        if let Ok(val) = std::env::var("COLORFGBG") {
            // COLORFGBG format: "fg;bg" or "fg:bg"
            let bg = val.split([';', ':']).nth(1);
            if let Some(bg) = bg
                && let Ok(bg_num) = bg.parse::<u8>()
                && ((7..=15).contains(&bg_num) || (230..=255).contains(&bg_num))
            {
                return Theme::Light;
            }
        }
        Theme::Dark
    }

    // === Dark palette: midnight indigo with sakura accents ===
    pub fn base(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(26, 27, 38),     // midnight indigo
            Theme::Light => Color::Rgb(250, 248, 245), // warm paper white
        }
    }

    pub fn surface(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(35, 38, 52),     // deep panel
            Theme::Light => Color::Rgb(240, 237, 232), // light panel
        }
    }

    pub fn overlay(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(84, 88, 108),    // subtle border
            Theme::Light => Color::Rgb(180, 175, 168), // light border
        }
    }

    pub fn text(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(211, 213, 225), // soft moonlight
            Theme::Light => Color::Rgb(45, 45, 55),   // ink black
        }
    }

    pub fn muted(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(130, 135, 155),  // distant star
            Theme::Light => Color::Rgb(130, 128, 122), // warm gray
        }
    }

    pub fn accent(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(180, 142, 173), // sakura pink
            Theme::Light => Color::Rgb(140, 90, 120), // deep sakura
        }
    }

    pub fn success(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(158, 206, 168), // bamboo green
            Theme::Light => Color::Rgb(80, 140, 100), // forest green
        }
    }

    pub fn warning(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(235, 195, 140), // warm amber
            Theme::Light => Color::Rgb(180, 130, 60), // dark amber
        }
    }

    pub fn error(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(230, 126, 126), // coral red
            Theme::Light => Color::Rgb(190, 70, 70),  // crimson
        }
    }

    pub fn info(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(140, 170, 210), // sky blue
            Theme::Light => Color::Rgb(80, 120, 170), // steel blue
        }
    }

    pub fn highlight_bg(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(45, 48, 65),     // deep highlight
            Theme::Light => Color::Rgb(225, 220, 212), // warm highlight
        }
    }

    pub fn border(&self) -> Color {
        match self {
            Theme::Dark => Color::Rgb(55, 58, 75),     // subtle border
            Theme::Light => Color::Rgb(200, 195, 188), // light border
        }
    }

    // === Style helpers ===

    pub fn header_style(&self) -> Style {
        Style::default()
            .fg(self.accent())
            .add_modifier(Modifier::BOLD)
    }

    pub fn title_style(&self) -> Style {
        Style::default()
            .fg(self.text())
            .add_modifier(Modifier::BOLD)
    }

    pub fn muted_style(&self) -> Style {
        Style::default().fg(self.muted())
    }

    pub fn success_style(&self) -> Style {
        Style::default()
            .fg(self.success())
            .add_modifier(Modifier::BOLD)
    }

    pub fn warning_style(&self) -> Style {
        Style::default()
            .fg(self.warning())
            .add_modifier(Modifier::BOLD)
    }

    pub fn error_style(&self) -> Style {
        Style::default()
            .fg(self.error())
            .add_modifier(Modifier::BOLD)
    }

    pub fn info_style(&self) -> Style {
        Style::default()
            .fg(self.info())
            .add_modifier(Modifier::BOLD)
    }

    pub fn highlight_style(&self) -> Style {
        Style::default().bg(self.highlight_bg()).fg(self.text())
    }

    pub fn block_style(&self) -> Style {
        Style::default().fg(self.border())
    }

    pub fn logo_style(&self) -> Style {
        Style::default()
            .fg(self.accent())
            .add_modifier(Modifier::BOLD)
    }

    pub fn key_hint_style(&self) -> Style {
        Style::default()
            .fg(self.accent())
            .add_modifier(Modifier::BOLD)
    }

    pub fn key_desc_style(&self) -> Style {
        Style::default().fg(self.muted())
    }

    pub fn footer_style(&self) -> Style {
        Style::default().bg(self.surface()).fg(self.muted())
    }

    pub fn bg_style(&self) -> Style {
        Style::default().bg(self.base())
    }
}

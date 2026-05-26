use owo_colors::OwoColorize;

/// Japanese kawaii pastel color palette for Kagi CLI.
/// All colors are soft, warm, and easy on the eyes.
pub struct Palette {
    tty: bool,
}

impl Palette {
    pub fn new(tty: bool) -> Self {
        Self { tty }
    }

    fn apply(&self, text: &str, rgb: (u8, u8, u8)) -> String {
        if self.tty {
            text.truecolor(rgb.0, rgb.1, rgb.2).to_string()
        } else {
            text.to_string()
        }
    }

    /// Success / done — pastel mint green (パステルミント)
    pub fn success(&self, text: &str) -> String {
        self.apply(text, (152, 251, 152))
    }

    /// Info / normal messages — powder blue (パウダーブルー)
    pub fn info(&self, text: &str) -> String {
        self.apply(text, (176, 224, 230))
    }

    /// Warning / overwrite — peach puff (ピーチパフ)
    pub fn warning(&self, text: &str) -> String {
        self.apply(text, (255, 218, 185))
    }

    /// Error / abort — sakura pink (桜色)
    pub fn error(&self, text: &str) -> String {
        self.apply(text, (255, 183, 197))
    }

    /// Accent / service names — light sky blue (ライトスカイブルー)
    pub fn accent(&self, text: &str) -> String {
        self.apply(text, (135, 206, 250))
    }

    /// Secret key names — lavender (ラベンダー)
    pub fn key(&self, text: &str) -> String {
        self.apply(text, (230, 230, 250))
    }

    /// Interactive prompt — lemon chiffon (レモンシフォン)
    pub fn prompt(&self, text: &str) -> String {
        self.apply(text, (255, 250, 205))
    }

    /// Muted / secondary — thistle (シスル)
    pub fn muted(&self, text: &str) -> String {
        self.apply(text, (216, 191, 216))
    }

    /// Commented / needs value — light pink (ライトピンク)
    pub fn commented(&self, text: &str) -> String {
        self.apply(text, (255, 182, 193))
    }
}

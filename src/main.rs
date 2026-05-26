use std::io::IsTerminal;
use clap::{CommandFactory, FromArgMatches};

mod application;
mod cli;
mod domain;
mod infrastructure;

fn main() {
    let mut cmd = cli::args::Cli::command();
    cmd = cmd.styles(cli::style::kagi_styles());
    cmd = cmd.help_template("{before-help}\n{usage-heading} {usage}\n\n{all-args}");

    let tty = std::io::stdout().is_terminal();
    let c = cli::style::Palette::new(tty);
    let logo = format!(
        "{}\n{}\n{}\n{}\n{}",
        c.accent("    ╭────────────────────────────╮"),
        c.accent("    │      🔑  Kagi 鍵           │"),
        c.accent("    │   Encrypted Env Manager    │"),
        c.accent("    ╰────────────────────────────╯"),
        c.muted("    Manage encrypted environment variables"),
    );
    cmd = cmd.before_help(logo);

    let matches = cmd.get_matches();
    let cli = match cli::args::Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    if let Err(e) = cli::commands::run(cli) {
        let tty = std::io::stdout().is_terminal();
        let c = cli::style::Palette::new(tty);
        eprintln!("{} {}", c.error("Error:"), c.error(&e.to_string()));
        std::process::exit(1);
    }
}

use std::io::IsTerminal;
use clap::Parser;

mod application;
mod cli;
mod domain;
mod infrastructure;

fn main() {
    let cli = cli::args::Cli::parse();
    if let Err(e) = cli::commands::run(cli) {
        let tty = std::io::stdout().is_terminal();
        let c = cli::style::Palette::new(tty);
        eprintln!("{} {}", c.error("Error:"), c.error(&e.to_string()));
        std::process::exit(1);
    }
}

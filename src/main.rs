use clap::Parser;

mod application;
mod cli;
mod domain;
mod infrastructure;

fn main() -> anyhow::Result<()> {
    let cli = cli::args::Cli::parse();
    cli::commands::run(cli)
}

use clap::{CommandFactory, FromArgMatches};
use std::io::IsTerminal;

mod application;
mod cli;
mod domain;
mod infrastructure;

fn main() {
    let mut cmd = cli::args::Cli::command();
    cmd = cmd.styles(cli::style::kagi_styles());

    let tty = std::io::stdout().is_terminal();
    let c = cli::style::Palette::new(tty);
    let cmd_ref = format!(
        "{}\n{}\n{}\n{}\n\n{}\n  {}  {}\n  {}  {}\n\n{}\n  {} {} {} {}\n      {}\n  {} {} {} {} {}\n      {}\n  {} {} {} {} {}\n      {}\n  {} {} {} {} {}\n      {}\n  {} {} {} {}\n      {}\n  {} {} {} {} {}\n      {}\n  {} {} {} {}\n      {}\n  {} {} {} {} {}\n      {}\n\n{}\n  {}\n  {}\n  {}\n  {}\n\n{}\n  {}",
        c.accent("◜ kagi  鍵 ◞"),
        c.warning("────────────o╼"),
        c.info("A small Rust CLI for encrypted environment variables."),
        c.info("日々の開発に、静かな鍵を。"),
        c.warning("Usage"),
        c.accent("kagi"),
        c.key("<command>"),
        c.accent("kagi"),
        c.key("<command> --help"),
        c.warning("Commands"),
        c.accent("init"),
        c.info("[--envs <envs>]"),
        c.info("[--nested]"),
        c.info("[--force]"),
        c.info("Create .kagi/ and the local master key"),
        c.accent("set"),
        c.info("[--service <service>]"),
        c.info("[env]"),
        c.key("<key>"),
        c.key("<value>"),
        c.info("Store one encrypted value"),
        c.accent("get"),
        c.info("[--service <service>]"),
        c.info("[--allow-non-interactive]"),
        c.info("[env]"),
        c.key("<key>"),
        c.info("Print one decrypted value"),
        c.accent("run"),
        c.info("[--service <service>]"),
        c.info("[env]"),
        c.key("<command>"),
        c.muted("..."),
        c.info("Run a child process with injected env vars"),
        c.accent("export"),
        c.info("[--service <service>]"),
        c.info("[--allow-non-interactive]"),
        c.key("[env]"),
        c.info("Write KEY=value lines"),
        c.accent("import"),
        c.info("[--service <service>]"),
        c.key("[env]"),
        c.info("[--file <path>]"),
        c.info("[--force]"),
        c.info("Import values from a .env file"),
        c.accent("list"),
        c.info("[--service <service>]"),
        c.info("[--show-values]"),
        c.key("[env]"),
        c.info("List scopes or masked keys"),
        c.accent("sync"),
        c.info("[--service <service>]"),
        c.info("[--example <path>]"),
        c.info("[--sources <files>]"),
        c.info("[--envs <envs>]"),
        c.info("Sync keys from .env.example"),
        c.warning("Examples"),
        c.muted("kagi init --envs dev,prod"),
        c.muted("kagi set dev DATABASE_URL postgres://localhost/dev"),
        c.muted("kagi run bun dev"),
        c.muted("kagi set --service api prod API_KEY fake_api_key"),
        c.warning("Note"),
        c.muted("Use kagi run for scripts; get/export need explicit non-interactive opt-in."),
    );
    cmd = cmd.before_help(cmd_ref);
    cmd = cmd.help_template("{before-help}");

    if std::env::args_os().len() == 1 {
        if let Err(e) = cmd.print_help() {
            eprintln!("{}", e);
            std::process::exit(1);
        }
        println!();
        return;
    }

    let matches = cmd.get_matches();
    let cli = match cli::args::Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    if let Err(e) = cli::commands::run(cli) {
        let tty = std::io::stdout().is_terminal();
        let c = cli::style::Palette::new(tty);
        eprintln!("{} {}", c.prefix(), c.error(&format!("error: {}", e)));
        std::process::exit(1);
    }
}

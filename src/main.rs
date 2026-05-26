use clap::{CommandFactory, FromArgMatches};
use std::io::IsTerminal;

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
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        c.accent(" _  __    _    ____  ____"),
        c.accent("| |/ /   / \\  / ___|| __ )"),
        c.accent("| ' /   / _ \\ | |  _|  _ \\"),
        c.accent("| . \\  / ___ \\| |_| | |_) |"),
        c.accent("|_|\\_\\/_/   \\_\\____|____/"),
        c.muted(""),
        c.muted("Manage encrypted environment variables"),
    );
    cmd = cmd.before_help(logo);

    let cmd_ref = format!(
        "{}\n  {} {} {}\n    {}\n  {} {} {} {}\n    {}\n  {} {} {}\n    {}\n  {} {} {} {}\n    {}\n  {} {}\n    {}\n  {} {} {} {}\n    {}\n  {} {}\n    {}\n  {} {} {} {}\n    {}",
        c.info("Command Reference:"),
        c.accent("init"),
        c.info("[--envs <envs>]"),
        c.info("[--force]"),
        c.muted("Initialize a new kagi repository in the current directory"),
        c.accent("set"),
        c.info("[service]"),
        c.key("<key>"),
        c.key("<value>"),
        c.muted("Store an encrypted secret for a service"),
        c.accent("get"),
        c.info("[service]"),
        c.key("<key>"),
        c.muted("Retrieve and decrypt a secret value"),
        c.accent("run"),
        c.info("[service]"),
        c.key("<command>"),
        c.muted("..."),
        c.muted("Run a command with injected environment variables"),
        c.accent("export"),
        c.key("<service>"),
        c.muted("Export secrets as KEY=value lines (suitable for shell sourcing)"),
        c.accent("import"),
        c.key("<service>"),
        c.info("[--file <path>]"),
        c.info("[--force]"),
        c.muted("Import secrets from a .env file"),
        c.accent("list"),
        c.key("[service]"),
        c.muted("List all services or secrets within a service"),
        c.accent("sync"),
        c.info("[--example <path>]"),
        c.info("[--sources <files>]"),
        c.info("[--envs <envs>]"),
        c.muted("Synchronize keys from .env.example across environments"),
    );
    cmd = cmd.after_help(cmd_ref);
    cmd = cmd.help_template("{before-help}\n{usage-heading} {usage}\n{after-help}");

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

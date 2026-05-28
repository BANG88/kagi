use clap::{CommandFactory, FromArgMatches};
use std::io::IsTerminal;

mod application;
mod cli;
mod domain;
mod infrastructure;
#[cfg(feature = "server")]
mod server;

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let mut cmd = cli::args::Cli::command();
    cmd = cmd.styles(cli::style::kagi_styles());

    let tty = std::io::stdout().is_terminal();
    let c = cli::style::Palette::new(tty);
    let logo = c.accent(
        r#"  _              _
 | | ____ _  __ _(_)
 | |/ / _` |/ _` | |
 |   < (_| | (_| | |
 |_|\_\__,_|\__, |_|
            |___/   鍵"#,
    );
    #[cfg(not(feature = "server"))]
    let cmd_lines: Vec<(&str, &str)> = vec![
        ("init", "create a team-ready encrypted project"),
        ("set", "store one encrypted value"),
        ("run", "start a process with injected env vars"),
        (
            "get",
            "show service/env keys or print one value after confirmation",
        ),
        ("export", "print KEY=value lines after confirmation"),
        ("import", "import values from a .env file"),
        ("sync", "sync keys from .env.example"),
        ("env", "manage default environments"),
        ("member", "list, approve, or remove members"),
    ];
    #[cfg(feature = "server")]
    let cmd_lines: Vec<(&str, &str)> = vec![
        ("init", "create a team-ready encrypted project"),
        ("set", "store one encrypted value"),
        ("run", "start a process with injected env vars"),
        (
            "get",
            "show service/env keys or print one value after confirmation",
        ),
        ("export", "print KEY=value lines after confirmation"),
        ("import", "import values from a .env file"),
        ("sync", "sync keys from .env.example"),
        ("env", "manage default environments"),
        ("member", "list, approve, or remove members"),
        ("serve", "start the remote sync server"),
        ("push", "upload project state to remote server"),
        ("pull", "download project state from remote server"),
        ("status", "compare local and remote revisions"),
        ("project", "manage remote projects"),
        ("remote", "manage remote server credentials"),
    ];
    let max_cmd = cmd_lines.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    let cmd_list = cmd_lines
        .iter()
        .map(|(name, desc)| {
            let pad = " ".repeat(max_cmd.saturating_sub(name.len()));
            format!("  {}{} {}", c.accent(name), pad, c.muted(desc))
        })
        .collect::<Vec<_>>()
        .join("\n");

    let flow_lines: Vec<(&str, &str)> = vec![
        ("init", "--envs development,production"),
        ("set", "api DATABASE_URL '<value>'"),
        ("run", "api bun dev"),
    ];
    let max_flow = flow_lines.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    let flow_list = flow_lines
        .iter()
        .map(|(name, args)| {
            let pad = " ".repeat(max_flow.saturating_sub(name.len()));
            format!(
                "  {} {}{} {}",
                c.accent("kagi"),
                c.accent(name),
                pad,
                c.muted(args)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let cmd_ref = format!(
        "{logo}\n{rule}\n{tagline}\n{jp}\n\n{usage}\n  {kagi} {command}\n  {kagi} {command_help}\n\n{flow}\n{flow_list}\n\n{commands}\n{cmd_list}\n\n{security}\n  {security_note}",
        rule = c.warning("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"),
        tagline = c.muted("Encrypted envs, scoped safely."),
        jp = c.muted("日々の開発に、静かな鍵を。"),
        usage = c.warning("Usage"),
        kagi = c.accent("kagi"),
        command = c.key("<command>"),
        command_help = c.key("<command> --help"),
        flow = c.warning("Core Flow"),
        flow_list = flow_list,
        commands = c.warning("Commands"),
        cmd_list = cmd_list,
        security = c.warning("Security"),
        security_note =
            c.muted("Use kagi run for scripts. get --show/export require a terminal prompt."),
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
    if let Err(e) = cli::commands::run(cli).await {
        let tty = std::io::stdout().is_terminal();
        let c = cli::style::Palette::new(tty);
        eprintln!("{} {}", c.prefix(), c.error(&format!("error: {}", e)));
        std::process::exit(1);
    }
}

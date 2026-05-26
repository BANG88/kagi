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
    let logo = c.accent(
        r#"  _              _
 | | ____ _  __ _(_)
 | |/ / _` |/ _` | |
 |   < (_| | (_| | |
 |_|\_\__,_|\__, |_|
            |___/   鍵"#,
    );
    let cmd_ref = format!(
        "{logo}\n{rule}\n{tagline}\n{jp}\n\n{usage}\n  {kagi} {command}\n  {kagi} {command_help}\n\n{flow}\n  {init_cmd}\n  {set_cmd}\n  {run_cmd}\n\n{commands}\n  {init:<10} {init_desc}\n  {set:<10} {set_desc}\n  {run:<10} {run_desc}\n  {get:<10} {get_desc}\n  {export:<10} {export_desc}\n  {import:<10} {import_desc}\n  {list:<10} {list_desc}\n  {sync:<10} {sync_desc}\n\n{security}\n  {security_note}",
        rule = c.warning("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"),
        tagline = c.info("Encrypted envs, scoped safely."),
        jp = c.info("日々の開発に、静かな鍵を。"),
        usage = c.warning("Usage"),
        kagi = c.accent("kagi"),
        command = c.key("<command>"),
        command_help = c.key("<command> --help"),
        flow = c.warning("Core Flow"),
        init_cmd = c.muted("kagi init --envs dev,prod"),
        set_cmd = c.muted("kagi set dev DATABASE_URL '<value>'"),
        run_cmd = c.muted("kagi run dev bun dev"),
        commands = c.warning("Commands"),
        init = c.accent("init"),
        init_desc = c.info("create .kagi/ and the local master key"),
        set = c.accent("set"),
        set_desc = c.info("store one encrypted value"),
        run = c.accent("run"),
        run_desc = c.info("start a process with injected env vars"),
        get = c.accent("get"),
        get_desc = c.info("print one value after interactive confirmation"),
        export = c.accent("export"),
        export_desc = c.info("print KEY=value lines after confirmation"),
        import = c.accent("import"),
        import_desc = c.info("import values from a .env file"),
        list = c.accent("list"),
        list_desc = c.info("list scopes or masked keys"),
        sync = c.accent("sync"),
        sync_desc = c.info("sync keys from .env.example"),
        security = c.warning("Security"),
        security_note =
            c.muted("Use kagi run for scripts. get/export/list values require a terminal prompt."),
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

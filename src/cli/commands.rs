use crate::application::export_env::ExportEnvService;
use crate::application::get_secret::GetSecretService;
use crate::application::init_service::InitService;
use crate::application::list_services::ListServicesService;
use crate::application::run_command::RunCommandService;
use crate::application::set_secret::SetSecretService;
use crate::application::sync_service::SyncService;
use crate::cli::args::{Cli, Commands};
use crate::cli::style::Palette;
use crate::domain::config::KagiConfig;
use crate::domain::entity::service::Service;
use crate::domain::error::DomainError;
use crate::domain::repository::secret_repo::SecretRepository;
use crate::domain::runner::CommandRunner;
use crate::infrastructure::env_injector::SystemCommandRunner;
use crate::infrastructure::fs_store::FileStore;
use crate::infrastructure::key_manager::KeyManager;
use crate::infrastructure::xchacha_crypto::XChaChaEncryptor;
use anyhow::Context;
use std::io::{self, IsTerminal};
use std::path::PathBuf;

fn draw_key_table(items: &[(String, String)], show_values: bool, c: &Palette) {
    let max_key = items.iter().map(|(k, _)| k.len()).max().unwrap_or(0).max(3);
    let max_val = items
        .iter()
        .map(|(_, v)| {
            if show_values {
                if v.is_empty() { 7 } else { v.len() }
            } else {
                8
            }
        })
        .max()
        .unwrap_or(0)
        .max(5);

    let border = format!(
        "┌─{:─<width1$}─┬─{:─<width2$}─┐",
        "",
        "",
        width1 = max_key,
        width2 = max_val
    );
    println!("{}", c.muted(&border));

    let header = format!(
        "│ {: <width1$} │ {: <width2$} │",
        "Key",
        "Value",
        width1 = max_key,
        width2 = max_val
    );
    println!("{}", c.info(&header));

    let sep = format!(
        "├─{:─<width1$}─┼─{:─<width2$}─┤",
        "",
        "",
        width1 = max_key,
        width2 = max_val
    );
    println!("{}", c.muted(&sep));

    for (key, value) in items {
        let left = format!("│ {: <width1$} │ ", key, width1 = max_key);
        print!("{}", c.muted(&left));
        if !show_values {
            print!("{}", c.muted("********"));
            let padding = max_val.saturating_sub(8);
            if padding > 0 {
                print!("{}", c.muted(&" ".repeat(padding)));
            }
            println!("{}", c.muted(" │"));
        } else if value.is_empty() {
            print!("{}", c.commented("(empty)"));
            let padding = max_val.saturating_sub(7);
            if padding > 0 {
                print!("{}", c.muted(&" ".repeat(padding)));
            }
            println!("{}", c.muted(" │"));
        } else {
            print!("{}", c.success(value));
            let padding = max_val.saturating_sub(value.len());
            if padding > 0 {
                print!("{}", c.muted(&" ".repeat(padding)));
            }
            println!("{}", c.muted(" │"));
        }
    }

    let bottom = format!(
        "└─{:─<width1$}─┴─{:─<width2$}─┘",
        "",
        "",
        width1 = max_key,
        width2 = max_val
    );
    println!("{}", c.muted(&bottom));
}

fn scope_name(service: Option<&str>, env: &str) -> String {
    match service {
        Some(service) => format!("{}/{}", service, env),
        None => env.to_string(),
    }
}

fn parse_secret_target(
    inferred_service: Option<String>,
    service_flag: Option<String>,
    first: Option<String>,
    second: Option<String>,
    third: Option<String>,
    usage: &str,
) -> anyhow::Result<(String, String, String)> {
    match (service_flag, inferred_service, first, second, third) {
        (Some(service), _, Some(env), Some(key), Some(value)) => {
            Ok((scope_name(Some(&service), &env), key, value))
        }
        (Some(service), _, Some(key), Some(value), None) => Ok((service, key, value)),
        (None, Some(service), Some(env_or_key), Some(key_or_value), Some(value)) => {
            Ok((scope_name(Some(&service), &env_or_key), key_or_value, value))
        }
        (None, Some(service), Some(key), Some(value), None) => Ok((service, key, value)),
        (None, None, Some(env), Some(key), Some(value)) => Ok((scope_name(None, &env), key, value)),
        _ => Err(anyhow::anyhow!(usage.to_string())),
    }
}

fn parse_key_target(
    inferred_service: Option<String>,
    service_flag: Option<String>,
    first: Option<String>,
    second: Option<String>,
    usage: &str,
) -> anyhow::Result<(String, String)> {
    match (service_flag, inferred_service, first, second) {
        (Some(service), _, Some(env), Some(key)) => Ok((scope_name(Some(&service), &env), key)),
        (Some(service), _, Some(key), None) => Ok((service, key)),
        (None, Some(service), Some(env_or_key), Some(key)) => {
            Ok((scope_name(Some(&service), &env_or_key), key))
        }
        (None, Some(service), Some(key), None) => Ok((service, key)),
        (None, None, Some(env), Some(key)) => Ok((scope_name(None, &env), key)),
        _ => Err(anyhow::anyhow!(usage.to_string())),
    }
}

fn parse_scope_target(
    inferred_service: Option<String>,
    service_flag: Option<String>,
    env: Option<String>,
) -> anyhow::Result<String> {
    match (service_flag, inferred_service, env) {
        (Some(service), _, Some(env)) => Ok(scope_name(Some(&service), &env)),
        (Some(service), _, None) => Ok(service),
        (None, Some(service), Some(env)) => Ok(scope_name(Some(&service), &env)),
        (None, Some(service), None) => Ok(service),
        (None, None, Some(env)) => Ok(scope_name(None, &env)),
        _ => Err(anyhow::anyhow!(
            "No environment specified. Provide an environment name or run from a nested service directory."
        )),
    }
}

fn require_interactive_read(tty: bool, operation: &str) -> anyhow::Result<()> {
    if tty {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "{} prints decrypted secrets and requires an interactive TTY. Use `kagi run` for scripts that need secrets injected into a child process.",
        operation
    ))
}

fn resolve_kagi_base() -> anyhow::Result<(PathBuf, Option<String>)> {
    let cwd = std::env::current_dir()?;

    let local = cwd.join(".kagi");
    if local.is_dir() {
        return Ok((local, None));
    }

    let mut current = cwd.as_path();
    loop {
        let kagi = current.join(".kagi");
        if kagi.is_dir() {
            let config_path = kagi.join(crate::domain::config::KAGI_CONFIG_FILE);
            let relative = cwd
                .strip_prefix(current)
                .unwrap_or(std::path::Path::new(""));
            let rel_str = relative.to_string_lossy();
            let inferred = if let Ok(content) = std::fs::read_to_string(&config_path)
                && let Ok(config) = serde_json::from_str::<KagiConfig>(&content)
                && config.settings.nested.is_allowed(&rel_str)
            {
                relative
                    .components()
                    .next()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
            } else {
                None
            };
            return Ok((kagi, inferred));
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }

    Err(anyhow::anyhow!(
        "No .kagi directory found in current or parent directories. Run `kagi init` to create one."
    ))
}

fn resolve_store() -> anyhow::Result<(FileStore, Option<String>)> {
    let (base_path, inferred_service) = resolve_kagi_base()?;

    let config_path = base_path.join(crate::domain::config::KAGI_CONFIG_FILE);
    if !config_path.exists() {
        return Err(anyhow::anyhow!(
            "Found .kagi at {} but {} is missing. \
             This may be an old repository or it was created manually. \
             Run `kagi init` to create a proper repository.",
            base_path.display(),
            crate::domain::config::KAGI_CONFIG_FILE
        ));
    }

    let key_manager = KeyManager::new(base_path.clone());
    let master_key = key_manager.load().context(
        "Failed to load master key. \
         Did you run `kagi init`? \
         If this is a shared repository, ask the owner for the master key or set KAGI_MASTER_KEY.",
    )?;
    let key_array: [u8; 32] = master_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
    let encryptor = XChaChaEncryptor::new(&key_array);
    let store = FileStore::new(base_path, Box::new(encryptor));
    Ok((store, inferred_service))
}

pub fn run(cli: Cli) -> anyhow::Result<()> {
    let tty = io::stdout().is_terminal();
    let c = Palette::new(tty);
    match cli.command {
        Commands::Init {
            envs,
            nested,
            force,
        } => {
            let cwd = std::env::current_dir()?;
            let local = cwd.join(".kagi");
            if local.is_dir() && !force {
                return Err(anyhow::anyhow!(
                    ".kagi/ already exists in this directory. Use --force to overwrite."
                ));
            }
            if local.is_dir() && force {
                let services_dir = local.join("services");
                if services_dir.is_dir() {
                    let has_enc = std::fs::read_dir(&services_dir)?
                        .filter_map(|e| e.ok())
                        .any(|e| e.path().extension().is_some_and(|ext| ext == "enc"));
                    if has_enc {
                        eprintln!(
                            "{} {}",
                            c.prefix(),
                            c.warning(
                                "warning: overwriting existing .kagi/ will delete all stored secrets."
                            )
                        );
                    }
                }
                std::fs::remove_dir_all(&local)?;
            }
            let service = if nested {
                InitService::with_nested(local.clone(), true)
            } else {
                InitService::new(local.clone())
            };
            service.execute()?;

            if !envs.is_empty() {
                let key_manager = KeyManager::new(local.clone());
                let master_key = key_manager.load()?;
                let key_array: [u8; 32] = master_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
                let encryptor = XChaChaEncryptor::new(&key_array);
                let store = FileStore::new(local, Box::new(encryptor));
                for env_name in &envs {
                    let svc = Service::new(env_name);
                    store
                        .save(&svc)
                        .context(format!("Failed to create '{}' environment", env_name))?;
                }
                println!(
                    "{} {} {} {}",
                    c.prefix(),
                    c.success("Initialized .kagi/"),
                    c.muted("with"),
                    c.accent(&envs.join(", "))
                );
            } else {
                println!("{} {}", c.prefix(), c.success("Initialized .kagi/"));
            }
            println!(
                "{} {}",
                c.prefix(),
                c.muted("Keep .kagi/ out of version control.")
            );
        }
        Commands::Set {
            service: service_name,
            env,
            key,
            value,
        } => {
            let (store, inferred) = resolve_store()?;
            let (scope, key, value) = parse_secret_target(
                inferred,
                service_name,
                env,
                key,
                value,
                "Usage: kagi set [--service <service>] [env] <key> <value>",
            )?;
            let set_service = SetSecretService::new(store);
            set_service.execute(&scope, &key, &value)?;
            println!(
                "{} {} {}.{}",
                c.prefix(),
                c.info("set"),
                c.accent(&scope),
                c.key(&key)
            );
        }
        Commands::Get {
            service: service_name,
            allow_non_interactive,
            env,
            key,
        } => {
            if !allow_non_interactive {
                require_interactive_read(tty, "kagi get")?;
            }
            let (store, inferred) = resolve_store()?;
            let (scope, key) = parse_key_target(
                inferred,
                service_name,
                env,
                key,
                "Usage: kagi get [--allow-non-interactive] [--service <service>] [env] <key>",
            )?;
            let get_service = GetSecretService::new(store);
            let value = get_service.execute(&scope, &key)?;
            println!("{}", value);
        }
        Commands::Run {
            service: service_name,
            args,
        } => {
            if args.is_empty() {
                return Err(anyhow::anyhow!("No command provided"));
            }
            let (store, inferred) = resolve_store()?;
            let services = store
                .list_services()
                .map_err(|e| anyhow::anyhow!("Failed to list services: {}", e))?;
            let (scope, cmd, run_args, allow_empty_inferred_scope) =
                if let Some(service) = service_name {
                    if args.len() < 2 {
                        return Err(anyhow::anyhow!("No command provided"));
                    }
                    (
                        scope_name(Some(&service), &args[0]),
                        args[1].clone(),
                        args[2..].to_vec(),
                        false,
                    )
                } else if let Some(service) = inferred {
                    let env_scope = scope_name(Some(&service), &args[0]);
                    if services.contains(&env_scope) && args.len() >= 2 {
                        (env_scope, args[1].clone(), args[2..].to_vec(), false)
                    } else {
                        (service, args[0].clone(), args[1..].to_vec(), true)
                    }
                } else if services.contains(&args[0]) {
                    if args.len() < 2 {
                        return Err(anyhow::anyhow!("No command provided"));
                    }
                    (args[0].clone(), args[1].clone(), args[2..].to_vec(), false)
                } else {
                    (String::new(), args[0].clone(), args[1..].to_vec(), true)
                };
            let runner = SystemCommandRunner::new();
            if allow_empty_inferred_scope && (scope.is_empty() || !services.contains(&scope)) {
                if scope.is_empty() {
                    eprintln!(
                        "{} {} {}",
                        c.prefix(),
                        c.warning("notice:"),
                        c.info("no environment or service scope specified")
                    );
                } else {
                    eprintln!(
                        "{} {} {} {}",
                        c.prefix(),
                        c.warning("notice:"),
                        c.info("no secrets found for inferred scope"),
                        c.accent(&scope)
                    );
                }
                eprintln!(
                    "{} {}",
                    c.prefix(),
                    c.info("Running command without injected environment variables.")
                );
                let exit_code = runner.run(&[], &cmd, &run_args)?;
                std::process::exit(exit_code);
            }
            let run_service = RunCommandService::new(store, runner);
            let exit_code = run_service.execute(&scope, &cmd, &run_args)?;
            std::process::exit(exit_code);
        }
        Commands::Export {
            service: service_name,
            allow_non_interactive,
            env,
        } => {
            if !allow_non_interactive {
                require_interactive_read(tty, "kagi export")?;
            }
            let (store, inferred) = resolve_store()?;
            let service_name = parse_scope_target(inferred, service_name, env)?;
            let export_service = ExportEnvService::new(store);
            let output = export_service.execute(&service_name)?;
            println!("{}", output);
        }
        Commands::Import {
            service: service_name,
            env,
            file,
            force,
        } => {
            let (store, inferred) = resolve_store()?;
            let service_name = parse_scope_target(inferred, service_name, env)?;
            let import_service =
                crate::application::import_env_file::ImportEnvFileService::new(store);

            let preview = import_service.execute(&service_name, &file, false)?;

            if !preview.overwritten.is_empty() && !force {
                eprintln!(
                    "{} {} the following keys already exist in {} and will be overwritten:",
                    c.prefix(),
                    c.warning("warning:"),
                    c.accent(&service_name)
                );
                for key in &preview.overwritten {
                    eprintln!("  {} {}", c.error("-"), c.error(key));
                }
                eprint!("{} {} [y/N]: ", c.prefix(), c.prompt("continue?"));
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("{} {}", c.prefix(), c.error("aborted."));
                    return Ok(());
                }
            }

            let report = if preview.overwritten.is_empty() {
                preview
            } else {
                import_service.execute(&service_name, &file, true)?
            };

            println!(
                "{} {} {} keys from {}",
                c.prefix(),
                c.success("Imported"),
                c.success(&report.imported.len().to_string()),
                c.accent(&file)
            );
            if !report.overwritten.is_empty() {
                println!(
                    "{} {} {} keys overwritten",
                    c.prefix(),
                    c.warning("warning:"),
                    c.warning(&report.overwritten.len().to_string())
                );
            }
            for key in report.imported {
                let overwritten_marker = if report.overwritten.contains(&key) {
                    c.warning(" (overwritten)")
                } else {
                    String::new()
                };
                println!(
                    "  {}.{}{}",
                    c.accent(&service_name),
                    c.key(&key),
                    overwritten_marker
                );
            }
        }
        Commands::List {
            service: service_name,
            show_values,
            env,
        } => {
            if show_values {
                require_interactive_read(tty, "kagi list --show-values")?;
            }
            let (store, inferred) = resolve_store()?;
            let list_service = ListServicesService::new(store);
            let (resolved_name, items) = match (service_name, env) {
                (Some(service), Some(env)) => {
                    let scope = scope_name(Some(&service), &env);
                    (Some(scope.clone()), list_service.execute(Some(&scope))?)
                }
                (None, Some(env)) => match inferred {
                    Some(service) => {
                        let scope = scope_name(Some(&service), &env);
                        (Some(scope.clone()), list_service.execute(Some(&scope))?)
                    }
                    None => (Some(env.clone()), list_service.execute(Some(&env))?),
                },
                (Some(service), None) => {
                    (Some(service.clone()), list_service.execute(Some(&service))?)
                }
                (None, None) => match inferred {
                    Some(name) => match list_service.execute(Some(&name)) {
                        Ok(items) => (Some(name), items),
                        Err(DomainError::ServiceNotFound(_)) => (None, list_service.execute(None)?),
                        Err(e) => return Err(e.into()),
                    },
                    None => (None, list_service.execute(None)?),
                },
            };
            if let Some(name) = resolved_name {
                if items.is_empty() {
                    draw_key_table(&[], show_values, &c);
                    println!(
                        "{} {}",
                        c.prefix(),
                        c.muted(&format!("no secrets in {}", name))
                    );
                } else {
                    draw_key_table(&items, show_values, &c);
                }
            } else {
                if items.is_empty() {
                    println!("{} {}", c.prefix(), c.muted("no services found"));
                } else {
                    for (name, _) in items {
                        println!("{}", c.accent(&name));
                    }
                }
            }
        }
        Commands::Sync {
            service: service_name,
            example,
            sources,
            envs,
        } => {
            let (store, inferred) = resolve_store()?;
            let sync_service = SyncService::new(store);
            let scoped_envs: Vec<String> = match service_name.or(inferred) {
                Some(service) => envs
                    .iter()
                    .map(|env| scope_name(Some(&service), env))
                    .collect(),
                None => envs,
            };
            let report = sync_service.execute(&example, &sources, &scoped_envs)?;

            for (env_name, env_report) in &report.env_reports {
                println!(
                    "{} {} {}",
                    c.prefix(),
                    c.success("synced"),
                    c.accent(env_name)
                );
                if !env_report.added.is_empty() {
                    println!(
                        "  {} {} keys added",
                        c.success("+"),
                        c.success(&env_report.added.len().to_string())
                    );
                    for key in &env_report.added {
                        println!("    {} = {}", c.key(key), c.muted("(from example)"));
                    }
                }
                if !env_report.commented.is_empty() {
                    println!(
                        "  {} {} keys added (commented)",
                        c.commented("#"),
                        c.commented(&env_report.commented.len().to_string())
                    );
                    for key in &env_report.commented {
                        println!("    {} {}", c.key(key), c.commented("(needs value)"));
                    }
                }
                if !env_report.skipped.is_empty() {
                    println!(
                        "  {} {} keys skipped (already exist)",
                        c.muted("-"),
                        c.muted(&env_report.skipped.len().to_string())
                    );
                }
            }
        }
    }
    Ok(())
}

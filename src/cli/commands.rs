use crate::application::export_env::ExportEnvService;
use crate::application::get_secret::GetSecretService;
use crate::application::init_service::InitService;
use crate::application::list_services::ListServicesService;
use crate::application::run_command::RunCommandService;
use crate::application::set_secret::SetSecretService;
use crate::application::sync_service::SyncService;
use crate::cli::args::{Cli, Commands, EnvCommands};
use crate::cli::style::Palette;
use crate::domain::config::{DEFAULT_ENV_NAME, KagiConfig};
use crate::domain::repository::secret_repo::SecretRepository;
use crate::domain::runner::CommandRunner;
use crate::infrastructure::env_injector::SystemCommandRunner;
use crate::infrastructure::fs_store::FileStore;
use crate::infrastructure::key_manager::KeyManager;
use crate::infrastructure::xchacha_crypto::XChaChaEncryptor;
use anyhow::Context;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

fn draw_key_table(items: &[(String, String)], show_values: bool, c: &Palette) {
    draw_key_table_with_indent(items, show_values, c, "");
}

fn draw_key_table_with_indent(
    items: &[(String, String)],
    show_values: bool,
    c: &Palette,
    indent: &str,
) {
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
    println!("{}{}", indent, c.accent(&border));

    print!("{}{}", indent, c.accent("│ "));
    print!("{}", c.prompt("Key"));
    print!("{}", " ".repeat(max_key.saturating_sub(3)));
    print!("{}", c.accent(" │ "));
    print!("{}", c.prompt("Value"));
    print!("{}", " ".repeat(max_val.saturating_sub(5)));
    println!("{}", c.accent(" │"));

    let sep = format!(
        "├─{:─<width1$}─┼─{:─<width2$}─┤",
        "",
        "",
        width1 = max_key,
        width2 = max_val
    );
    println!("{}{}", indent, c.accent(&sep));

    for (key, value) in items {
        print!("{}{}", indent, c.accent("│ "));
        print!("{}", c.key(key));
        let key_padding = max_key.saturating_sub(key.len());
        if key_padding > 0 {
            print!("{}", " ".repeat(key_padding));
        }
        print!("{}", c.accent(" │ "));
        if !show_values {
            print!("{}", c.muted("********"));
            let padding = max_val.saturating_sub(8);
            if padding > 0 {
                print!("{}", c.muted(&" ".repeat(padding)));
            }
            println!("{}", c.accent(" │"));
        } else if value.is_empty() {
            print!("{}", c.commented("(empty)"));
            let padding = max_val.saturating_sub(7);
            if padding > 0 {
                print!("{}", c.muted(&" ".repeat(padding)));
            }
            println!("{}", c.accent(" │"));
        } else {
            print!("{}", c.success(value));
            let padding = max_val.saturating_sub(value.len());
            if padding > 0 {
                print!("{}", c.muted(&" ".repeat(padding)));
            }
            println!("{}", c.accent(" │"));
        }
    }

    let bottom = format!(
        "└─{:─<width1$}─┴─{:─<width2$}─┘",
        "",
        "",
        width1 = max_key,
        width2 = max_val
    );
    println!("{}{}", indent, c.accent(&bottom));
}

fn list_service_scopes(
    list_service: &ListServicesService<FileStore>,
    service: &str,
) -> anyhow::Result<Vec<String>> {
    let prefix = format!("{}/", service);
    let mut scopes: Vec<String> = list_service
        .execute(None)?
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name.starts_with(&prefix))
        .collect();
    scopes.sort();
    Ok(scopes)
}

fn draw_service_envs(
    list_service: &ListServicesService<FileStore>,
    service: &str,
    show_values: bool,
    c: &Palette,
) -> anyhow::Result<()> {
    let scopes = list_service_scopes(list_service, service)?;
    if scopes.is_empty() {
        println!("{} {}", c.prefix(), c.muted("no services found"));
        return Ok(());
    }

    println!("{}", c.accent(service));
    for scope in scopes {
        let env = scope.split_once('/').map_or(scope.as_str(), |(_, env)| env);
        println!("  {}", c.accent(env));
        let items = list_service.execute(Some(&scope))?;
        if items.is_empty() {
            println!(
                "    {} {}",
                c.prefix(),
                c.muted(&format!("no secrets in {}", env))
            );
        } else {
            draw_key_table_with_indent(&items, show_values, c, "    ");
        }
    }
    Ok(())
}

fn draw_all_service_envs(
    list_service: &ListServicesService<FileStore>,
    show_values: bool,
    c: &Palette,
) -> anyhow::Result<()> {
    let mut scopes: Vec<String> = list_service
        .execute(None)?
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    scopes.sort();

    if scopes.is_empty() {
        println!("{} {}", c.prefix(), c.muted("no services found"));
        return Ok(());
    }

    let mut current_service: Option<String> = None;
    for scope in scopes {
        let (service, env) = scope
            .split_once('/')
            .map_or(("(root)", scope.as_str()), |(service, env)| (service, env));
        if current_service.as_deref() != Some(service) {
            current_service = Some(service.to_string());
            println!("{}", c.accent(service));
        }
        println!("  {}", c.accent(env));

        let items = list_service.execute(Some(&scope))?;
        if show_values {
            if items.is_empty() {
                println!(
                    "    {} {}",
                    c.prefix(),
                    c.muted(&format!("no secrets in {}", env))
                );
            } else {
                draw_key_table_with_indent(&items, true, c, "    ");
            }
        }
    }

    Ok(())
}

fn service_scopes_from_store(store: &FileStore, service: &str) -> anyhow::Result<Vec<String>> {
    let prefix = format!("{}/", service);
    let mut scopes: Vec<String> = store
        .list_services()?
        .into_iter()
        .filter(|name| name.starts_with(&prefix))
        .collect();
    scopes.sort();
    Ok(scopes)
}

fn env_file_name(scope: &str) -> anyhow::Result<String> {
    let env = scope.split_once('/').map_or(scope, |(_, env)| env);
    if env.is_empty() || env.contains('/') || env.contains('\\') {
        Err(anyhow::anyhow!("invalid environment name: {}", env))
    } else {
        Ok(format!(".env.{}", env))
    }
}

fn write_export_file(out_dir: &Path, scope: &str, content: &str) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(out_dir)?;
    let path = out_dir.join(env_file_name(scope)?);
    fs::write(&path, content)?;
    Ok(path)
}

fn scope_name(service: Option<&str>, env: &str) -> String {
    match service {
        Some(service) => format!("{}/{}", service, env),
        None => env.to_string(),
    }
}

fn service_from_scope(scope: &str) -> Option<&str> {
    scope.split_once('/').map(|(service, _)| service)
}

fn root_or_default_service_scope(default_envs: &[String], default_env: &str, name: &str) -> String {
    if default_envs.iter().any(|env| env == name) {
        name.to_string()
    } else {
        scope_name(Some(name), default_env)
    }
}

fn ensure_default_envs_for_scope(store: &FileStore, scope: &str) -> anyhow::Result<()> {
    if let Some(service) = service_from_scope(scope) {
        store
            .ensure_service_envs(service)
            .map_err(|e| anyhow::anyhow!("Failed to initialize default envs: {}", e))?;
    }
    Ok(())
}

struct TargetContext<'a> {
    default_envs: &'a [String],
    default_env: &'a str,
    inferred_service: Option<String>,
    service_flag: Option<String>,
}

struct SecretArgs {
    first: Option<String>,
    second: Option<String>,
    third: Option<String>,
    fourth: Option<String>,
}

fn parse_secret_target(
    ctx: TargetContext<'_>,
    args: SecretArgs,
    usage: &str,
) -> anyhow::Result<(String, String, String)> {
    match (
        ctx.service_flag,
        ctx.inferred_service,
        args.first,
        args.second,
        args.third,
        args.fourth,
    ) {
        (Some(service), _, Some(env), Some(key), Some(value), None) => {
            Ok((scope_name(Some(&service), &env), key, value))
        }
        (Some(service), _, Some(key), Some(value), None, None) => {
            Ok((scope_name(Some(&service), ctx.default_env), key, value))
        }
        (None, Some(service), Some(env_or_key), Some(key_or_value), Some(value), None) => {
            Ok((scope_name(Some(&service), &env_or_key), key_or_value, value))
        }
        (None, Some(service), Some(key), Some(value), None, None) => {
            Ok((scope_name(Some(&service), ctx.default_env), key, value))
        }
        (None, None, Some(service), Some(env), Some(key), Some(value)) => {
            Ok((scope_name(Some(&service), &env), key, value))
        }
        (None, None, Some(env), Some(key), Some(value), None) => Ok((
            root_or_default_service_scope(ctx.default_envs, ctx.default_env, &env),
            key,
            value,
        )),
        _ => Err(anyhow::anyhow!(usage.to_string())),
    }
}

fn parse_scope_args(
    default_envs: &[String],
    default_env: &str,
    inferred_service: Option<String>,
    service_flag: Option<String>,
    first: Option<String>,
    second: Option<String>,
) -> anyhow::Result<String> {
    match (service_flag, inferred_service, first, second) {
        (Some(service), _, Some(env), None) => Ok(scope_name(Some(&service), &env)),
        (Some(service), _, None, None) => Ok(scope_name(Some(&service), default_env)),
        (None, Some(service), Some(env), None) => Ok(scope_name(Some(&service), &env)),
        (None, Some(service), None, None) => Ok(scope_name(Some(&service), default_env)),
        (None, None, Some(service), Some(env)) => Ok(scope_name(Some(&service), &env)),
        (None, None, Some(name), None) => Ok(root_or_default_service_scope(
            default_envs,
            default_env,
            &name,
        )),
        _ => Err(anyhow::anyhow!(
            "No environment specified. Provide an environment name."
        )),
    }
}

enum ScopeSelection {
    One(String),
    Service(String),
}

enum GetSelection {
    All,
    Service(String),
    Scope(String),
    Key(String, String),
}

fn is_env_scope(
    services: &[String],
    default_envs: &[String],
    service: Option<&str>,
    env: &str,
) -> bool {
    default_envs.iter().any(|configured| configured == env)
        || service
            .map(|service| services.contains(&scope_name(Some(service), env)))
            .unwrap_or_else(|| services.contains(&env.to_string()))
}

fn parse_get_selection(
    services: &[String],
    ctx: TargetContext<'_>,
    first: Option<String>,
    second: Option<String>,
    third: Option<String>,
) -> anyhow::Result<GetSelection> {
    match (ctx.service_flag, ctx.inferred_service, first, second, third) {
        (Some(service), _, None, None, None) => Ok(GetSelection::Service(service)),
        (Some(service), _, Some(env_or_key), None, None) => {
            if is_env_scope(services, ctx.default_envs, Some(&service), &env_or_key) {
                Ok(GetSelection::Scope(scope_name(Some(&service), &env_or_key)))
            } else {
                Ok(GetSelection::Key(
                    scope_name(Some(&service), ctx.default_env),
                    env_or_key,
                ))
            }
        }
        (Some(service), _, Some(env), Some(key), None) => {
            Ok(GetSelection::Key(scope_name(Some(&service), &env), key))
        }
        (None, Some(service), None, None, None) => Ok(GetSelection::Service(service)),
        (None, Some(service), Some(env_or_key), None, None) => {
            if is_env_scope(services, ctx.default_envs, Some(&service), &env_or_key) {
                Ok(GetSelection::Scope(scope_name(Some(&service), &env_or_key)))
            } else {
                Ok(GetSelection::Key(
                    scope_name(Some(&service), ctx.default_env),
                    env_or_key,
                ))
            }
        }
        (None, Some(service), Some(env), Some(key), None) => {
            if is_env_scope(services, ctx.default_envs, Some(&service), &env) {
                Ok(GetSelection::Key(scope_name(Some(&service), &env), key))
            } else {
                Err(anyhow::anyhow!(
                    "Unknown environment '{}'. Use `kagi get {}` to list available environments.",
                    env,
                    service
                ))
            }
        }
        (None, None, None, None, None) => Ok(GetSelection::All),
        (None, None, Some(name), None, None) => {
            if is_env_scope(services, ctx.default_envs, None, &name) {
                Ok(GetSelection::Scope(name))
            } else {
                Ok(GetSelection::Service(name))
            }
        }
        (None, None, Some(name), Some(env_or_key), None) => {
            if is_env_scope(services, ctx.default_envs, None, &name) {
                Ok(GetSelection::Key(name, env_or_key))
            } else if is_env_scope(services, ctx.default_envs, Some(&name), &env_or_key) {
                Ok(GetSelection::Scope(scope_name(Some(&name), &env_or_key)))
            } else {
                Ok(GetSelection::Key(
                    scope_name(Some(&name), ctx.default_env),
                    env_or_key,
                ))
            }
        }
        (None, None, Some(service), Some(env), Some(key)) => {
            Ok(GetSelection::Key(scope_name(Some(&service), &env), key))
        }
        _ => Err(anyhow::anyhow!(
            "Usage: kagi get [--show-values] [--service <service>] [env|key] or kagi get <service> [env|key] [key]"
        )),
    }
}

fn parse_export_selection(
    default_envs: &[String],
    inferred_service: Option<String>,
    service_flag: Option<String>,
    first: Option<String>,
    second: Option<String>,
) -> anyhow::Result<ScopeSelection> {
    match (service_flag, inferred_service, first, second) {
        (Some(service), _, Some(env), None) => {
            Ok(ScopeSelection::One(scope_name(Some(&service), &env)))
        }
        (Some(service), _, None, None) => Ok(ScopeSelection::Service(service)),
        (None, Some(service), Some(env), None) => {
            Ok(ScopeSelection::One(scope_name(Some(&service), &env)))
        }
        (None, Some(service), None, None) => Ok(ScopeSelection::Service(service)),
        (None, None, Some(service), Some(env)) => {
            Ok(ScopeSelection::One(scope_name(Some(&service), &env)))
        }
        (None, None, Some(name), None) => {
            if default_envs.iter().any(|env| env == &name) {
                Ok(ScopeSelection::One(name))
            } else {
                Ok(ScopeSelection::Service(name))
            }
        }
        _ => Err(anyhow::anyhow!(
            "Usage: kagi export [--service <service>] [env] or kagi export <service> [env]"
        )),
    }
}

fn confirm_secret_output(tty: bool, operation: &str, c: &Palette) -> anyhow::Result<()> {
    if !tty || !io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "{} prints decrypted secrets and requires an interactive terminal. Use `kagi run` for scripts that need secrets injected into a child process.",
            operation
        ));
    }

    eprint!(
        "{} {} {} [y/N]: ",
        c.prefix(),
        c.warning("warning:"),
        c.info(&format!("{} will print decrypted secrets.", operation))
    );
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") {
        Ok(())
    } else {
        Err(anyhow::anyhow!("aborted"))
    }
}

fn confirm_env_delete(tty: bool, env: &str, c: &Palette) -> anyhow::Result<()> {
    if !tty || !io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "kagi env del deletes encrypted environment stores and requires an interactive terminal."
        ));
    }

    eprintln!(
        "{} {} {}",
        c.prefix(),
        c.warning("warning:"),
        c.info(&format!(
            "this will delete '{}' from every service. Type '{}' to confirm.",
            env, env
        ))
    );
    eprint!("{} {} ", c.prefix(), c.prompt("confirm:"));
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() == env {
        Ok(())
    } else {
        Err(anyhow::anyhow!("aborted"))
    }
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
            let service = InitService::with_nested_and_envs(local.clone(), nested, envs.clone());
            service.execute()?;

            if let Some(envs) = envs {
                let display_envs =
                    if envs.is_empty() || envs.iter().all(|env| env.trim().is_empty()) {
                        crate::domain::config::STANDARD_ENV_NAMES.join(", ")
                    } else {
                        envs.join(", ")
                    };
                println!(
                    "{} {} {} {}",
                    c.prefix(),
                    c.success("Initialized .kagi/"),
                    c.muted("with"),
                    c.accent(&display_envs)
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
            first,
            second,
            third,
            fourth,
        } => {
            let (store, inferred) = resolve_store()?;
            let default_envs = store
                .default_envs()
                .map_err(|e| anyhow::anyhow!("Failed to read default envs: {}", e))?;
            let default_env = store
                .default_env()
                .unwrap_or_else(|_| DEFAULT_ENV_NAME.to_string());
            let (scope, key, value) = parse_secret_target(
                TargetContext {
                    default_envs: &default_envs,
                    default_env: &default_env,
                    inferred_service: inferred,
                    service_flag: service_name,
                },
                SecretArgs {
                    first,
                    second,
                    third,
                    fourth,
                },
                "Usage: kagi set [--service <service>] [env] <key> <value> or kagi set <service> <env> <key> <value>",
            )?;
            ensure_default_envs_for_scope(&store, &scope)?;
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
            show_values,
            first,
            second,
            third,
        } => {
            let (store, inferred) = resolve_store()?;
            let default_envs = store
                .default_envs()
                .map_err(|e| anyhow::anyhow!("Failed to read default envs: {}", e))?;
            let default_env = store
                .default_env()
                .unwrap_or_else(|_| DEFAULT_ENV_NAME.to_string());
            let services = store
                .list_services()
                .map_err(|e| anyhow::anyhow!("Failed to list services: {}", e))?;
            let selection = parse_get_selection(
                &services,
                TargetContext {
                    default_envs: &default_envs,
                    default_env: &default_env,
                    inferred_service: inferred,
                    service_flag: service_name,
                },
                first,
                second,
                third,
            )?;
            match selection {
                GetSelection::All => {
                    if show_values {
                        confirm_secret_output(tty, "kagi get --show-values", &c)?;
                    }
                    let list_service = ListServicesService::new(store);
                    draw_all_service_envs(&list_service, show_values, &c)?;
                }
                GetSelection::Service(service) => {
                    if show_values {
                        confirm_secret_output(tty, "kagi get --show-values", &c)?;
                    }
                    let list_service = ListServicesService::new(store);
                    draw_service_envs(&list_service, &service, show_values, &c)?;
                }
                GetSelection::Scope(scope) => {
                    if show_values {
                        confirm_secret_output(tty, "kagi get --show-values", &c)?;
                    }
                    let list_service = ListServicesService::new(store);
                    let items = list_service.execute(Some(&scope))?;
                    if items.is_empty() {
                        draw_key_table(&[], show_values, &c);
                        println!(
                            "{} {}",
                            c.prefix(),
                            c.muted(&format!("no secrets in {}", scope))
                        );
                    } else {
                        draw_key_table(&items, show_values, &c);
                    }
                }
                GetSelection::Key(scope, key) => {
                    confirm_secret_output(tty, "kagi get", &c)?;
                    let get_service = GetSecretService::new(store);
                    let value = get_service.execute(&scope, &key)?;
                    println!("{}", value);
                }
            }
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
            let default_envs = store
                .default_envs()
                .map_err(|e| anyhow::anyhow!("Failed to read default envs: {}", e))?;
            let default_env = store
                .default_env()
                .unwrap_or_else(|_| DEFAULT_ENV_NAME.to_string());
            let (scope, cmd, run_args, allow_empty_inferred_scope) =
                if let Some(service) = service_name {
                    let env_scope = scope_name(Some(&service), &args[0]);
                    if services.contains(&env_scope) || default_envs.contains(&args[0]) {
                        if args.len() < 2 {
                            return Err(anyhow::anyhow!("No command provided"));
                        }
                        (env_scope, args[1].clone(), args[2..].to_vec(), false)
                    } else {
                        (
                            scope_name(Some(&service), &default_env),
                            args[0].clone(),
                            args[1..].to_vec(),
                            false,
                        )
                    }
                } else if let Some(service) = inferred {
                    let env_scope = scope_name(Some(&service), &args[0]);
                    if services.contains(&env_scope) || default_envs.contains(&args[0]) {
                        if args.len() < 2 {
                            return Err(anyhow::anyhow!("No command provided"));
                        }
                        (env_scope, args[1].clone(), args[2..].to_vec(), false)
                    } else {
                        (
                            scope_name(Some(&service), &default_env),
                            args[0].clone(),
                            args[1..].to_vec(),
                            true,
                        )
                    }
                } else if services.contains(&args[0]) {
                    if args.len() < 2 {
                        return Err(anyhow::anyhow!("No command provided"));
                    }
                    (args[0].clone(), args[1].clone(), args[2..].to_vec(), false)
                } else if args.len() >= 2
                    && (services.contains(&scope_name(Some(&args[0]), &args[1]))
                        || default_envs.contains(&args[1]))
                {
                    if args.len() < 3 {
                        return Err(anyhow::anyhow!("No command provided"));
                    }
                    (
                        scope_name(Some(&args[0]), &args[1]),
                        args[2].clone(),
                        args[3..].to_vec(),
                        false,
                    )
                } else if services.contains(&scope_name(Some(&args[0]), &default_env)) {
                    if args.len() < 2 {
                        return Err(anyhow::anyhow!("No command provided"));
                    }
                    (
                        scope_name(Some(&args[0]), &default_env),
                        args[1].clone(),
                        args[2..].to_vec(),
                        false,
                    )
                } else {
                    (String::new(), args[0].clone(), args[1..].to_vec(), true)
                };
            ensure_default_envs_for_scope(&store, &scope)?;
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
            out,
            first,
            second,
        } => {
            confirm_secret_output(tty, "kagi export", &c)?;
            let (store, inferred) = resolve_store()?;
            let default_envs = store
                .default_envs()
                .map_err(|e| anyhow::anyhow!("Failed to read default envs: {}", e))?;
            let selection =
                parse_export_selection(&default_envs, inferred, service_name, first, second)?;
            match selection {
                ScopeSelection::One(scope) => {
                    let export_service = ExportEnvService::new(store);
                    let output = export_service.execute(&scope)?;
                    if let Some(out) = out {
                        let path = write_export_file(Path::new(&out), &scope, &output)?;
                        println!(
                            "{} {} {}",
                            c.prefix(),
                            c.success("exported"),
                            c.accent(&path.display().to_string())
                        );
                    } else {
                        println!("{}", output);
                    }
                }
                ScopeSelection::Service(service) => {
                    let Some(out) = out else {
                        return Err(anyhow::anyhow!(
                            "Exporting all environments for a service requires --out <dir>. Use `kagi export {} <env>` for stdout.",
                            service
                        ));
                    };
                    let out_dir = Path::new(&out);
                    let scopes = service_scopes_from_store(&store, &service)?;
                    let export_service = ExportEnvService::new(store);
                    for scope in scopes {
                        let output = export_service.execute(&scope)?;
                        let path = write_export_file(out_dir, &scope, &output)?;
                        println!(
                            "{} {} {}",
                            c.prefix(),
                            c.success("exported"),
                            c.accent(&path.display().to_string())
                        );
                    }
                }
            }
        }
        Commands::Import {
            service: service_name,
            first,
            second,
            file,
            force,
        } => {
            let (store, inferred) = resolve_store()?;
            let default_envs = store
                .default_envs()
                .map_err(|e| anyhow::anyhow!("Failed to read default envs: {}", e))?;
            let default_env = store
                .default_env()
                .unwrap_or_else(|_| DEFAULT_ENV_NAME.to_string());
            let service_name = parse_scope_args(
                &default_envs,
                &default_env,
                inferred,
                service_name,
                first,
                second,
            )?;
            ensure_default_envs_for_scope(&store, &service_name)?;
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
        Commands::Sync {
            service: service_name,
            example,
            sources,
            envs,
        } => {
            let (store, inferred) = resolve_store()?;
            if let Some(service) = service_name.as_ref().or(inferred.as_ref()) {
                store
                    .ensure_service_envs(service)
                    .map_err(|e| anyhow::anyhow!("Failed to initialize default envs: {}", e))?;
            }
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
        Commands::Env { command } => {
            let (store, _) = resolve_store()?;
            match command {
                EnvCommands::List => {
                    for env in store.default_envs()? {
                        println!("{}", c.accent(&env));
                    }
                }
                EnvCommands::Add { env } => {
                    store.add_env(&env)?;
                    println!(
                        "{} {} {}",
                        c.prefix(),
                        c.success("added environment"),
                        c.accent(&env)
                    );
                }
                EnvCommands::Rename { old, new } => {
                    store.rename_env(&old, &new)?;
                    println!(
                        "{} {} {} {} {}",
                        c.prefix(),
                        c.success("renamed environment"),
                        c.accent(&old),
                        c.muted("to"),
                        c.accent(&new)
                    );
                }
                EnvCommands::Del { env } => {
                    confirm_env_delete(tty, &env, &c)?;
                    store.delete_env(&env)?;
                    println!(
                        "{} {} {}",
                        c.prefix(),
                        c.success("deleted environment"),
                        c.accent(&env)
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_file_name_uses_bun_style_defaults() {
        assert_eq!(
            env_file_name("api/development").unwrap(),
            ".env.development"
        );
        assert_eq!(env_file_name("api/production").unwrap(), ".env.production");
        assert_eq!(env_file_name("api/test").unwrap(), ".env.test");
        assert_eq!(env_file_name("api/staging").unwrap(), ".env.staging");
    }
}

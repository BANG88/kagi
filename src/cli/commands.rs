use std::io::{self, IsTerminal};
use std::path::PathBuf;
use crate::application::export_env::ExportEnvService;
use crate::application::sync_service::SyncService;
use crate::application::get_secret::GetSecretService;
use crate::application::init_service::InitService;
use crate::application::list_services::ListServicesService;
use crate::application::run_command::RunCommandService;
use crate::application::set_secret::SetSecretService;
use crate::cli::args::{Cli, Commands};
use crate::cli::style::Palette;
use crate::domain::config::KagiConfig;
use crate::domain::entity::service::Service;
use crate::domain::repository::secret_repo::SecretRepository;
use crate::infrastructure::aes_gcm_crypto::AesGcmEncryptor;
use crate::infrastructure::env_injector::SystemCommandRunner;
use crate::infrastructure::fs_store::FileStore;
use crate::infrastructure::key_manager::KeyManager;

fn draw_key_table(items: &[(String, String)], c: &Palette) {
    let max_key = items.iter().map(|(k, _)| k.len()).max().unwrap_or(0).max(3);
    let max_val = items.iter()
        .map(|(_, v)| if v.is_empty() { 7 } else { v.len() })
        .max().unwrap_or(0).max(5);

    let border = format!("┌─{:─<width1$}─┬─{:─<width2$}─┐", "", "", width1 = max_key, width2 = max_val);
    println!("{}", c.muted(&border));

    let header = format!("│ {: <width1$} │ {: <width2$} │", "Key", "Value", width1 = max_key, width2 = max_val);
    println!("{}", c.info(&header));

    let sep = format!("├─{:─<width1$}─┼─{:─<width2$}─┤", "", "", width1 = max_key, width2 = max_val);
    println!("{}", c.muted(&sep));

    for (key, value) in items {
        let left = format!("│ {: <width1$} │ ", key, width1 = max_key);
        print!("{}", c.muted(&left));
        if value.is_empty() {
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

    let bottom = format!("└─{:─<width1$}─┴─{:─<width2$}─┘", "", "", width1 = max_key, width2 = max_val);
    println!("{}", c.muted(&bottom));
}

fn resolve_kagi_base() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir()?;

    let local = cwd.join(".kagi");
    if local.is_dir() {
        return Ok(local);
    }

    let mut current = cwd.as_path();
    loop {
        let kagi = current.join(".kagi");
        if kagi.is_dir() {
            let config_path = kagi.join("config.json");
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                if let Ok(config) = serde_json::from_str::<KagiConfig>(&content) {
                    if !config.settings.nested {
                        return Err(anyhow::anyhow!(
                            "Found .kagi at {} but nested usage is disabled in settings. \
                             Run `kagi init` in this directory to create a local repository.",
                            current.display()
                        ));
                    }
                }
            }
            return Ok(kagi);
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }

    Err(anyhow::anyhow!(
        "No .kagi directory found. Run `kagi init` to create one."
    ))
}

pub fn run(cli: Cli) -> anyhow::Result<()> {
    let tty = io::stdout().is_terminal();
    let c = Palette::new(tty);
    match cli.command {
        Commands::Init => {
            let cwd = std::env::current_dir()?;
            let local = cwd.join(".kagi");
            if local.is_dir() {
                return Err(anyhow::anyhow!(".kagi/ already exists in this directory."));
            }
            let service = InitService::new(local.clone());
            service.execute()?;

            let key_manager = KeyManager::new(local.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(local, Box::new(encryptor));
            for env_name in &["dev", "test", "staging", "prod"] {
                let svc = Service::new(*env_name);
                store.save(&svc)?;
            }

            println!(
                "{} {} {} {} {} {} {}",
                c.success("Initialized .kagi/"),
                c.muted("with"),
                c.accent("dev"),
                c.accent("test"),
                c.accent("staging"),
                c.accent("prod"),
                c.success("environments")
            );
        }
        Commands::Set { service: service_name, key, value } => {
            let base_path = resolve_kagi_base()?;
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let set_service = SetSecretService::new(store);
            set_service.execute(&service_name, &key, &value)?;
            println!(
                "{} {}.{} = {}",
                c.info("Set"),
                c.accent(&service_name),
                c.key(&key),
                c.success(&value)
            );
        }
        Commands::Get { service: service_name, key } => {
            let base_path = resolve_kagi_base()?;
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let get_service = GetSecretService::new(store);
            let value = get_service.execute(&service_name, &key)?;
            println!("{}", value);
        }
        Commands::Run { service: service_name, command } => {
            if command.is_empty() {
                return Err(anyhow::anyhow!("No command provided"));
            }
            let base_path = resolve_kagi_base()?;
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let runner = SystemCommandRunner::new();
            let run_service = RunCommandService::new(store, runner);
            let cmd = command[0].clone();
            let args = command[1..].to_vec();
            let exit_code = run_service.execute(&service_name, &cmd, &args)?;
            std::process::exit(exit_code);
        }
        Commands::Export { service: service_name } => {
            let base_path = resolve_kagi_base()?;
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let export_service = ExportEnvService::new(store);
            let output = export_service.execute(&service_name)?;
            println!("{}", output);
        }
        Commands::Import { service: service_name, file, force } => {
            let base_path = resolve_kagi_base()?;
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let import_service = crate::application::import_env_file::ImportEnvFileService::new(store);

            let preview = import_service.execute(&service_name, &file, false)?;

            if !preview.overwritten.is_empty() && !force {
                eprintln!(
                    "{} the following keys already exist in {} and will be overwritten:",
                    c.warning("Warning:"),
                    c.accent(&service_name)
                );
                for key in &preview.overwritten {
                    eprintln!("  {} {}", c.error("-"), c.error(key));
                }
                eprint!("{} [y/N]: ", c.prompt("Continue?"));
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("{}", c.error("Aborted."));
                    return Ok(());
                }
            }

            let report = if preview.overwritten.is_empty() {
                preview
            } else {
                import_service.execute(&service_name, &file, true)?
            };

            println!(
                "{} {} keys from {}",
                c.success("Imported"),
                c.success(&report.imported.len().to_string()),
                c.accent(&file)
            );
            if !report.overwritten.is_empty() {
                println!(
                    "{} {} keys overwritten",
                    c.warning("Warning"),
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
        Commands::List { service: service_name } => {
            let base_path = resolve_kagi_base()?;
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let list_service = ListServicesService::new(store);
            let items = list_service.execute(service_name.as_deref())?;
            if let Some(name) = service_name {
                if items.is_empty() {
                    println!("{}", c.muted(&format!("No secrets in {}", name)));
                } else {
                    draw_key_table(&items, &c);
                }
            } else {
                for (name, _) in items {
                    println!("{}", c.accent(&name));
                }
            }
        }
        Commands::Sync { example, sources, envs } => {
            let base_path = resolve_kagi_base()?;
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let sync_service = SyncService::new(store);
            let report = sync_service.execute(&example, &sources, &envs)?;

            for (env_name, env_report) in &report.env_reports {
                println!("{} {}", c.success("Synced"), c.accent(env_name));
                if !env_report.added.is_empty() {
                    println!(
                        "  {} {} keys added",
                        c.success("+"),
                        c.success(&env_report.added.len().to_string())
                    );
                    for key in &env_report.added {
                        println!(
                            "    {} = {}",
                            c.key(key),
                            c.muted("(from example)")
                        );
                    }
                }
                if !env_report.commented.is_empty() {
                    println!(
                        "  {} {} keys added (commented)",
                        c.commented("#"),
                        c.commented(&env_report.commented.len().to_string())
                    );
                    for key in &env_report.commented {
                        println!(
                            "    {} {}",
                            c.key(key),
                            c.commented("(needs value)")
                        );
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

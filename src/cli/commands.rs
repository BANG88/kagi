use std::io::{self, IsTerminal};
use std::path::PathBuf;
use owo_colors::OwoColorize;
use crate::application::copy_service::CopyService;
use crate::application::export_env::ExportEnvService;
use crate::application::sync_service::SyncService;
use crate::application::get_secret::GetSecretService;
use crate::application::init_service::InitService;
use crate::application::list_services::ListServicesService;
use crate::application::run_command::RunCommandService;
use crate::application::set_secret::SetSecretService;
use crate::cli::args::{Cli, Commands};
use crate::domain::config::KagiConfig;
use crate::domain::entity::service::Service;
use crate::domain::repository::secret_repo::SecretRepository;
use crate::infrastructure::aes_gcm_crypto::AesGcmEncryptor;
use crate::infrastructure::env_injector::SystemCommandRunner;
use crate::infrastructure::fs_store::FileStore;
use crate::infrastructure::key_manager::KeyManager;

fn resolve_kagi_base() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir()?;

    // Check current directory first
    let local = cwd.join(".kagi");
    if local.is_dir() {
        return Ok(local);
    }

    // Search upwards for .kagi
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

            if tty {
                println!("{} {} {} {} {} {} {}",
                    "Initialized .kagi/".green(),
                    "with".green(),
                    "dev".cyan(),
                    "test".cyan(),
                    "staging".cyan(),
                    "prod".cyan(),
                    "environments".green()
                );
            } else {
                println!("Initialized .kagi/ with dev test staging prod environments");
            }
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
            if tty {
                println!("{} {}.{} = {}", "Set".bright_cyan(), service_name.cyan(), key.cyan(), value.green());
            } else {
                println!("Set {}.{} = {}", service_name, key, value);
            }
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

            // Dry run: check for conflicts without importing
            let preview = import_service.execute(&service_name, &file, false)?;

            if !preview.overwritten.is_empty() && !force {
                if tty {
                    eprintln!("{} the following keys already exist in {} and will be overwritten:", "Warning:".bright_yellow(), service_name.yellow());
                } else {
                    eprintln!("Warning: the following keys already exist in {} and will be overwritten:", service_name);
                }
                for key in &preview.overwritten {
                    if tty {
                        eprintln!("  {} {}", "-".bright_red(), key.red());
                    } else {
                        eprintln!("  - {}", key);
                    }
                }
                if tty {
                    eprint!("{} [y/N]: ", "Continue?".bright_magenta());
                } else {
                    eprint!("Continue? [y/N]: ");
                }
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    if tty {
                        println!("{}", "Aborted.".red());
                    } else {
                        println!("Aborted.");
                    }
                    return Ok(());
                }
            }

            // Perform actual import (with force if there were conflicts)
            let report = if preview.overwritten.is_empty() {
                preview
            } else {
                import_service.execute(&service_name, &file, true)?
            };

            if tty {
                println!("{} {} keys from {}", "Imported".green(), report.imported.len().to_string().bright_green(), file.cyan());
            } else {
                println!("Imported {} keys from {}", report.imported.len(), file);
            }
            if !report.overwritten.is_empty() {
                if tty {
                    println!("{} {} keys overwritten", "Warning".bright_yellow(), report.overwritten.len().to_string().yellow());
                } else {
                    println!("Warning: {} keys overwritten", report.overwritten.len());
                }
            }
            for key in report.imported {
                let overwritten_marker = if report.overwritten.contains(&key) { " (overwritten)" } else { "" };
                if tty {
                    println!("  {}.{}{}", service_name.bright_cyan(), key.cyan(), overwritten_marker.yellow());
                } else {
                    println!("  {}.{}{}", service_name, key, overwritten_marker);
                }
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
            for item in items {
                if tty {
                    println!("{}", item.bright_cyan());
                } else {
                    println!("{}", item);
                }
            }
        }
        Commands::Copy { source, target, only_missing } => {
            let base_path = resolve_kagi_base()?;
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let copy_service = CopyService::new(store);
            let report = copy_service.execute(&source, &target, only_missing)?;

            if tty {
                println!("{} {} keys from {} to {}",
                    "Copied".green(),
                    report.copied.len().to_string().bright_green(),
                    source.cyan(),
                    target.cyan()
                );
            } else {
                println!("Copied {} keys from {} to {}", report.copied.len(), source, target);
            }
            if !report.skipped.is_empty() {
                if tty {
                    println!("{} {} keys skipped (already exist in {})",
                        "Info".bright_magenta(),
                        report.skipped.len().to_string().magenta(),
                        target.cyan()
                    );
                } else {
                    println!("Info: {} keys skipped (already exist in {})", report.skipped.len(), target);
                }
            }
            for key in report.copied {
                if tty {
                    println!("  {}.{} → {}.{}", source.cyan(), key.cyan(), target.cyan(), key.cyan());
                } else {
                    println!("  {}.{} → {}.{}", source, key, target, key);
                }
            }
        }
        Commands::Sync { example, envs } => {
            let base_path = resolve_kagi_base()?;
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let sync_service = SyncService::new(store);
            let report = sync_service.execute(&example, &envs)?;

            for (env_name, env_report) in &report.env_reports {
                if tty {
                    println!("{} {}", "Synced".green(), env_name.cyan());
                } else {
                    println!("Synced {}", env_name);
                }
                if !env_report.added.is_empty() {
                    if tty {
                        println!("  {} {} keys added", "+".green(), env_report.added.len().to_string().green());
                    } else {
                        println!("  + {} keys added", env_report.added.len());
                    }
                    for key in &env_report.added {
                        if tty {
                            println!("    {} = {}", key.cyan(), "(from example)".green());
                        } else {
                            println!("    {} = (from example)", key);
                        }
                    }
                }
                if !env_report.commented.is_empty() {
                    if tty {
                        println!("  {} {} keys added (commented)", "#".magenta(), env_report.commented.len().to_string().magenta());
                    } else {
                        println!("  # {} keys added (commented)", env_report.commented.len());
                    }
                    for key in &env_report.commented {
                        if tty {
                            println!("    {} {}", key.cyan(), "(needs value)".magenta());
                        } else {
                            println!("    {} (needs value)", key);
                        }
                    }
                }
                if !env_report.skipped.is_empty() {
                    if tty {
                        println!("  {} {} keys skipped (already exist)", "-".yellow(), env_report.skipped.len().to_string().yellow());
                    } else {
                        println!("  - {} keys skipped (already exist)", env_report.skipped.len());
                    }
                }
            }
        }
    }
    Ok(())
}

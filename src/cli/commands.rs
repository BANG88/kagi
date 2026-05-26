use std::io::{self, IsTerminal};
use std::path::PathBuf;
use owo_colors::OwoColorize;
use crate::application::export_env::ExportEnvService;
use crate::application::get_secret::GetSecretService;
use crate::application::init_service::InitService;
use crate::application::list_services::ListServicesService;
use crate::application::run_command::RunCommandService;
use crate::application::set_secret::SetSecretService;
use crate::cli::args::{Cli, Commands};
use crate::infrastructure::aes_gcm_crypto::AesGcmEncryptor;
use crate::infrastructure::env_injector::SystemCommandRunner;
use crate::infrastructure::fs_store::FileStore;
use crate::infrastructure::key_manager::KeyManager;

pub fn run(cli: Cli) -> anyhow::Result<()> {
    let base_path = PathBuf::from(".kagi");
    let tty = io::stdout().is_terminal();
    match cli.command {
        Commands::Init => {
            let service = InitService::new(base_path);
            service.execute()?;
            if tty {
                println!("{}", "Initialized .kagi/".green());
            } else {
                println!("Initialized .kagi/");
            }
        }
        Commands::Set { service: service_name, key, value } => {
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let set_service = SetSecretService::new(store);
            set_service.execute(&service_name, &key, &value)?;
            if tty {
                println!("{} {}.{} = {}", "Set".cyan(), service_name, key, value);
            } else {
                println!("Set {}.{} = {}", service_name, key, value);
            }
        }
        Commands::Get { service: service_name, key } => {
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
        Commands::Import { service: service_name, file } => {
            let key_manager = KeyManager::new(base_path.clone());
            let master_key = key_manager.load()?;
            let key_array: [u8; 32] = master_key.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master key length"))?;
            let encryptor = AesGcmEncryptor::new(&key_array);
            let store = FileStore::new(base_path, Box::new(encryptor));
            let import_service = crate::application::import_env_file::ImportEnvFileService::new(store);
            let imported = import_service.execute(&service_name, &file)?;
            if tty {
                println!("{} {} keys from {}", "Imported".green(), imported.len(), file);
            } else {
                println!("Imported {} keys from {}", imported.len(), file);
            }
            for key in imported {
                println!("  {}.{} = <encrypted>", service_name, key);
            }
        }
        Commands::List { service: service_name } => {
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
    }
    Ok(())
}

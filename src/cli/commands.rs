use crate::application::export_env::ExportEnvService;
use crate::application::get_secret::GetSecretService;
use crate::application::init_service::InitService;
use crate::application::list_services::ListServicesService;
use crate::application::run_command::RunCommandService;
use crate::application::set_secret::SetSecretService;
use crate::application::sync_service::SyncService;
use crate::cli::args::{Cli, Commands, EnvCommands, MemberCommands};
#[cfg(feature = "server")]
use crate::cli::args::{ProjectCommands, RemoteCommands};
use crate::cli::style::Palette;
use crate::domain::config::{DEFAULT_ENV_NAME, KagiConfig};
use crate::domain::repository::secret_repo::SecretRepository;
use crate::domain::runner::CommandRunner;
#[cfg(feature = "server")]
use crate::domain::sync::project_token::base64_encode_url;
#[cfg(feature = "server")]
use crate::domain::sync::remote_config::RemoteMetadata;
use crate::infrastructure::env_injector::SystemCommandRunner;
use crate::infrastructure::fs_store::FileStore;
use crate::infrastructure::key_manager::KeyManager;
#[cfg(feature = "server")]
use crate::infrastructure::key_manager::MemberMetadata;
#[cfg(feature = "server")]
use crate::infrastructure::key_manager::default_member_name;
#[cfg(feature = "server")]
use crate::infrastructure::remote_client::MemberJoinRequest;
#[cfg(feature = "server")]
use crate::infrastructure::remote_client::TokenIssueResponse;
#[cfg(feature = "server")]
use crate::infrastructure::remote_local::RemoteLocalStore;
use crate::infrastructure::xchacha_crypto::XChaChaEncryptor;
use anyhow::Context;
#[cfg(feature = "server")]
use base64::Engine as _;
#[cfg(feature = "server")]
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(feature = "server")]
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
#[cfg(feature = "server")]
use std::str::FromStr;

const ROTATION_JOURNAL_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct RotationJournal {
    version: u8,
    project_id: String,
    access_json: String,
    files: BTreeMap<String, String>,
}

fn draw_key_table(items: &[(String, String, Option<String>)], show_values: bool, c: &Palette) {
    draw_key_table_with_indent(items, show_values, c, "");
}

fn draw_key_table_with_indent(
    items: &[(String, String, Option<String>)],
    show_values: bool,
    c: &Palette,
    indent: &str,
) {
    let max_key = items
        .iter()
        .map(|(k, _, _)| k.len())
        .max()
        .unwrap_or(0)
        .max(3);
    let max_val = items
        .iter()
        .map(|(_, v, _)| {
            if show_values {
                if v.is_empty() { 7 } else { v.len() }
            } else {
                8
            }
        })
        .max()
        .unwrap_or(0)
        .max(5);
    let has_desc = items.iter().any(|(_, _, d)| d.is_some());
    let max_desc = if has_desc {
        items
            .iter()
            .filter_map(|(_, _, d)| d.as_ref().map(|s| s.len()))
            .max()
            .unwrap_or(0)
            .max(4)
    } else {
        0
    };

    let border = if has_desc {
        format!(
            "┌─{:─<width1$}─┬─{:─<width2$}─┬─{:─<width3$}─┐",
            "",
            "",
            "",
            width1 = max_key,
            width2 = max_val,
            width3 = max_desc
        )
    } else {
        format!(
            "┌─{:─<width1$}─┬─{:─<width2$}─┐",
            "",
            "",
            width1 = max_key,
            width2 = max_val
        )
    };
    println!("{}{}", indent, c.accent(&border));

    print!("{}{}", indent, c.accent("│ "));
    print!("{}", c.prompt("Key"));
    print!("{}", " ".repeat(max_key.saturating_sub(3)));
    print!("{}", c.accent(" │ "));
    print!("{}", c.prompt("Value"));
    print!("{}", " ".repeat(max_val.saturating_sub(5)));
    if has_desc {
        print!("{}", c.accent(" │ "));
        print!("{}", c.prompt("Desc"));
        print!("{}", " ".repeat(max_desc.saturating_sub(4)));
    }
    println!("{}", c.accent(" │"));

    let sep = if has_desc {
        format!(
            "├─{:─<width1$}─┼─{:─<width2$}─┼─{:─<width3$}─┤",
            "",
            "",
            "",
            width1 = max_key,
            width2 = max_val,
            width3 = max_desc
        )
    } else {
        format!(
            "├─{:─<width1$}─┼─{:─<width2$}─┤",
            "",
            "",
            width1 = max_key,
            width2 = max_val
        )
    };
    println!("{}{}", indent, c.accent(&sep));

    for (key, value, desc) in items {
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
        } else if value.is_empty() {
            print!("{}", c.commented("(empty)"));
            let padding = max_val.saturating_sub(7);
            if padding > 0 {
                print!("{}", c.muted(&" ".repeat(padding)));
            }
        } else {
            print!("{}", c.success(value));
            let padding = max_val.saturating_sub(value.len());
            if padding > 0 {
                print!("{}", c.muted(&" ".repeat(padding)));
            }
        }
        if has_desc {
            print!("{}", c.accent(" │ "));
            if let Some(d) = desc {
                print!("{}", c.muted(d));
                let padding = max_desc.saturating_sub(d.len());
                if padding > 0 {
                    print!("{}", " ".repeat(padding));
                }
            } else {
                print!("{}", " ".repeat(max_desc));
            }
        }
        println!("{}", c.accent(" │"));
    }

    let bottom = if has_desc {
        format!(
            "└─{:─<width1$}─┴─{:─<width2$}─┴─{:─<width3$}─┘",
            "",
            "",
            "",
            width1 = max_key,
            width2 = max_val,
            width3 = max_desc
        )
    } else {
        format!(
            "└─{:─<width1$}─┴─{:─<width2$}─┘",
            "",
            "",
            width1 = max_key,
            width2 = max_val
        )
    };
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
        .map(|(name, _, _)| name)
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
        .map(|(name, _, _)| name)
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

fn has_encrypted_store(path: &Path) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if has_encrypted_store(&path)? {
                return Ok(true);
            }
        } else if path.extension().is_some_and(|ext| ext == "enc") {
            return Ok(true);
        }
    }
    Ok(false)
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
            "Usage: kagi get [--show] [--service <service>] [env|key] or kagi get <service> [env|key] [key]"
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

fn confirm_member_remove(tty: bool, member_id: &str, c: &Palette) -> anyhow::Result<()> {
    if !tty || !io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "kagi member remove changes project access and requires an interactive terminal."
        ));
    }

    eprintln!(
        "{} {} {}",
        c.prefix(),
        c.warning("warning:"),
        c.info(&format!(
            "this will remove member '{}' and rotate the project key. Type '{}' to confirm.",
            member_id, member_id
        ))
    );
    eprint!("{} {} ", c.prefix(), c.prompt("confirm:"));
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() == member_id {
        Ok(())
    } else {
        Err(anyhow::anyhow!("aborted"))
    }
}

fn print_member_approval_instruction(member_id: &str, c: &Palette) {
    println!("{} {}", c.prefix(), c.muted("Ask an active member to run:"));
    println!(
        "  {} {} {}",
        c.accent("kagi"),
        c.accent("member approve"),
        c.key(member_id)
    );
}

#[cfg(feature = "server")]
fn warn_join_request_cleanup_failed(member_id: &str, error: &dyn std::error::Error, c: &Palette) {
    eprintln!(
        "{} {} failed to clean up pending join request {} after server rejection: {}",
        c.prefix(),
        c.warning("warning:"),
        c.accent(member_id),
        error
    );
}

#[cfg(feature = "server")]
fn add_pending_remote_approval(
    mut meta: RemoteMetadata,
    member_id: &str,
    token_id: &str,
) -> RemoteMetadata {
    let mut accepted_member_ids = meta.pending_accepted_member_ids.unwrap_or_default();
    if !accepted_member_ids.iter().any(|id| id == member_id) {
        accepted_member_ids.push(member_id.to_string());
    }
    meta.pending_accepted_member_ids = Some(accepted_member_ids);

    let mut token_ids = meta.pending_token_ids.unwrap_or_default();
    if !token_ids.iter().any(|id| id == token_id) {
        token_ids.push(token_id.to_string());
    }
    meta.pending_token_ids = Some(token_ids);

    meta
}

#[cfg(feature = "server")]
fn apply_server_member_approval(
    key_manager: &KeyManager,
    remote_store: &RemoteLocalStore,
    meta: RemoteMetadata,
    member_id: &str,
    response: TokenIssueResponse,
) -> anyhow::Result<MemberMetadata> {
    let pending_member = key_manager
        .find_member(member_id)?
        .filter(|member| member.status == "pending")
        .ok_or_else(|| {
            anyhow::anyhow!(
                "server issued a token for `{}` but the local pending join request is missing. Recovery: run `kagi pull`; if the member is still pending, rerun `kagi member approve {}`.",
                member_id,
                member_id
            )
        })?;
    let recipient = age::x25519::Recipient::from_str(&pending_member.recipient)
        .map_err(|e| anyhow::anyhow!("invalid member recipient: {}", e))?;
    let encrypted = crate::infrastructure::remote_envelope::encrypt_bytes(
        response.project_token.as_bytes(),
        &recipient,
    )
    .map_err(|e| anyhow::anyhow!("failed to encrypt token: {}", e))?;
    let wrapped_token = base64::engine::general_purpose::STANDARD.encode(&encrypted);

    let remote_meta = add_pending_remote_approval(meta, member_id, &response.token_id);
    remote_store.save_remote_metadata(&remote_meta).with_context(|| {
        format!(
            "server issued a token for `{}` but kagi could not save pending remote approval metadata. Recovery: fix local kagi data directory permissions, then rerun `kagi member approve {}`.",
            member_id, member_id
        )
    })?;
    let member = key_manager
        .approve_join_request_with_wrapped_token(member_id, &wrapped_token)
        .with_context(|| {
            format!(
                "server issued a token for `{}` and pending remote approval metadata was saved, but kagi could not persist local access state. Recovery: fix .kagi/access.json or filesystem permissions, then rerun `kagi member approve {}`.",
                member_id, member_id
            )
        })?;

    Ok(member)
}

#[cfg(feature = "server")]
async fn member_join_server_mode(
    key_manager: &KeyManager,
    member: &MemberMetadata,
    config: &serde_json::Value,
    sync: &serde_json::Value,
    allow_insecure: bool,
    c: &Palette,
) -> anyhow::Result<()> {
    let project_id = config["project_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing project_id"))?
        .to_string();
    let remote_url = sync
        .get("remote")
        .and_then(|v| v.as_str())
        .or_else(|| config.get("kagi_url").and_then(|v| v.as_str()))
        .ok_or_else(|| anyhow::anyhow!("missing remote URL"))?
        .to_string();

    let remote_store = RemoteLocalStore::new(local_data_dir()?);
    let meta = remote_store
        .load_remote_metadata(&project_id)?
        .ok_or_else(|| anyhow::anyhow!("no remote metadata found"))?;

    let token = match remote_store.load_token(&project_id)? {
        Some(token) => token,
        None => {
            let claim_secret = remote_store
                .load_claim_secret(&project_id)?
                .ok_or_else(|| anyhow::anyhow!(
                    "Server token required to join project. Try 'kagi pull' first to obtain a token."
                ))?;
            let client = crate::infrastructure::remote_client::RemoteClient::new_pinned(
                remote_url.to_string(),
                &meta.server_fingerprint,
                allow_insecure,
            )
            .await?;
            let identity = key_manager.load_or_create_identity()?;
            let active_member_id = key_manager.member_id()?;
            client
                .get_token_from_claim_secret(
                    &project_id,
                    &active_member_id,
                    &claim_secret,
                    &identity,
                )
                .await?
        }
    };

    let client = crate::infrastructure::remote_client::RemoteClient::new_pinned(
        remote_url.to_string(),
        &meta.server_fingerprint,
        allow_insecure,
    )
    .await?;
    let identity = key_manager.load_or_create_identity()?;
    let join_request = MemberJoinRequest {
        member_id: member.member_id.clone(),
        name: member.name.clone(),
        recipient: member.recipient.clone(),
    };
    if let Err(e) = client
        .send_member_join_request(&project_id, &token, &join_request, &identity)
        .await
    {
        if let Err(cleanup_error) = key_manager.delete_join_request(&member.member_id) {
            warn_join_request_cleanup_failed(&member.member_id, &cleanup_error, c);
        }
        return Err(e.into());
    }
    println!(
        "{} {} {}",
        c.prefix(),
        c.success("Request sent to server"),
        c.accent(&member.member_id)
    );
    print_member_approval_instruction(&member.member_id, c);
    Ok(())
}

#[cfg(feature = "server")]
async fn fetch_server_join_requests(
    key_manager: &KeyManager,
    config: &serde_json::Value,
    allow_insecure: bool,
) -> anyhow::Result<Vec<MemberMetadata>> {
    let project_id = config["project_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing project_id"))?
        .to_string();
    let remote_url = config
        .get("settings")
        .and_then(|s| s.get("sync"))
        .and_then(|s| s.get("remote"))
        .and_then(|v| v.as_str())
        .or_else(|| config.get("kagi_url").and_then(|v| v.as_str()))
        .ok_or_else(|| anyhow::anyhow!("missing remote URL"))?
        .to_string();

    let local_data_dir = local_data_dir()?;
    let remote_store = crate::infrastructure::remote_local::RemoteLocalStore::new(local_data_dir);
    let token = remote_store
        .load_token(&project_id)?
        .ok_or_else(|| anyhow::anyhow!("no project token found"))?;
    let meta = remote_store
        .load_remote_metadata(&project_id)?
        .ok_or_else(|| anyhow::anyhow!("no remote metadata found"))?;

    let identity = key_manager.load_or_create_identity()?;
    let request_id = format!("kgr_{}", nanoid::nanoid!(12));
    let plaintext = crate::domain::sync::envelope::RequestPlaintext {
        version: 1,
        request_id: request_id.clone(),
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        operation: "status".into(),
        method: "POST".into(),
        path: format!("/v1/projects/{}/status", project_id),
        project_id: Some(project_id.to_string()),
        token: Some(token),
        claim_secret: None,
        payload: serde_json::json!({ "local_revision": meta.local_revision.unwrap_or(0) }),
    };

    let client = crate::infrastructure::remote_client::RemoteClient::new_pinned(
        remote_url.to_string(),
        &meta.server_fingerprint,
        allow_insecure,
    )
    .await?;
    let data = client.send_request(&plaintext, &identity).await?;
    let requests = data
        .get("join_requests")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut members = Vec::new();
    for req in requests {
        if let Some(member_id) = req.get("member_id").and_then(|v| v.as_str()) {
            let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let recipient = req.get("recipient").and_then(|v| v.as_str()).unwrap_or("");
            let signing_public_key: Option<String> = None; // server does not expose this in status response
            members.push(MemberMetadata {
                member_id: member_id.to_string(),
                name: name.to_string(),
                recipient: recipient.to_string(),
                status: "pending".to_string(),
                wrapped_key: None,
                wrapped_token: None,
                signing_public_key,
            });
        }
    }
    Ok(members)
}

#[cfg(feature = "server")]
async fn member_approve_server_mode(
    key_manager: &KeyManager,
    member_id: &str,
    config: &serde_json::Value,
    allow_insecure: bool,
    c: &Palette,
) -> anyhow::Result<()> {
    let project_id = config["project_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing project_id"))?
        .to_string();
    let remote_url = config
        .get("settings")
        .and_then(|s| s.get("sync"))
        .and_then(|s| s.get("remote"))
        .and_then(|v| v.as_str())
        .or_else(|| config.get("kagi_url").and_then(|v| v.as_str()))
        .ok_or_else(|| anyhow::anyhow!("missing remote URL"))?
        .to_string();

    let local_data_dir = local_data_dir()?;
    let remote_store = crate::infrastructure::remote_local::RemoteLocalStore::new(local_data_dir);
    let token = remote_store
        .load_token(&project_id)?
        .ok_or_else(|| anyhow::anyhow!("Server token required to approve member"))?;
    let meta = remote_store
        .load_remote_metadata(&project_id)?
        .ok_or_else(|| anyhow::anyhow!("no remote metadata found"))?;

    let client = crate::infrastructure::remote_client::RemoteClient::new_pinned(
        remote_url.to_string(),
        &meta.server_fingerprint,
        allow_insecure,
    )
    .await?;
    let identity = key_manager.load_or_create_identity()?;

    // If the local pending member is missing, try to create it from server data
    if key_manager
        .find_member(member_id)?
        .filter(|member| member.status == "pending")
        .is_none()
    {
        let server_requests =
            fetch_server_join_requests(key_manager, config, allow_insecure).await?;
        let server_request = server_requests
            .into_iter()
            .find(|r| r.member_id == member_id)
            .ok_or_else(|| anyhow::anyhow!("join request not found on server: {}", member_id))?;
        key_manager.create_pending_member_from_server(
            member_id,
            &server_request.name,
            &server_request.recipient,
            None,
        )?;
    }

    let response = client
        .send_member_token_issue(&project_id, &token, member_id, &identity)
        .await?;
    let member =
        apply_server_member_approval(key_manager, &remote_store, meta, member_id, response)?;

    println!(
        "{} {} {}",
        c.prefix(),
        c.success("Member approved. Token will be activated on next push."),
        c.accent(&member.member_id)
    );
    Ok(())
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
    validate_v2_config(&config_path)?;
    recover_pending_rotation(&base_path)?;

    let project_key = load_project_key(&base_path)?;
    let store = store_from_project_key(base_path, &project_key)?;
    Ok((store, inferred_service))
}

fn validate_v2_config(config_path: &Path) -> anyhow::Result<()> {
    let content = fs::read_to_string(config_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;
    let version = value.get("version").and_then(|v| v.as_str()).unwrap_or("");
    if (version != "2" && version != "3")
        || value
            .get("project_id")
            .and_then(|v| v.as_str())
            .is_none_or(|id| id.trim().is_empty())
    {
        return Err(anyhow::anyhow!(
            "Unsupported kagi repository format. This version requires a v2 team-ready .kagi/kagi.json with project_id. Run `kagi init --force` to create a new repository."
        ));
    }
    Ok(())
}

fn load_project_key(base_path: &Path) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let key_manager = KeyManager::new(base_path.to_path_buf());
    key_manager.load().context(
        "Failed to load project key. \
         Did you run `kagi init`? \
         If this is a shared repository, run `kagi join` and ask an active member to approve it, \
         or set KAGI_PROJECT_KEY / KAGI_PROJECT_KEY_FILE for CI.",
    )
}

fn store_from_project_key(base_path: PathBuf, project_key: &[u8]) -> anyhow::Result<FileStore> {
    let key_array: [u8; 32] = project_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid project key length"))?;
    let encryptor = XChaChaEncryptor::new(&key_array);
    Ok(FileStore::new(base_path, Box::new(encryptor)))
}

fn recover_pending_rotation(base_path: &Path) -> anyhow::Result<bool> {
    let key_manager = KeyManager::new(base_path.to_path_buf());
    recover_pending_rotation_with_key_manager(base_path, &key_manager)
}

fn recover_pending_rotation_with_key_manager(
    base_path: &Path,
    key_manager: &KeyManager,
) -> anyhow::Result<bool> {
    let journal_path = key_manager.rotation_journal_path()?;
    if !journal_path.exists() {
        return Ok(false);
    }

    let content = fs::read_to_string(&journal_path)?;
    let journal: RotationJournal = serde_json::from_str(&content)?;
    if journal.version != ROTATION_JOURNAL_VERSION {
        return Err(anyhow::anyhow!(
            "unsupported rotation journal version: {}",
            journal.version
        ));
    }
    if journal.project_id != key_manager.project_id()? {
        return Err(anyhow::anyhow!(
            "rotation journal belongs to another kagi project"
        ));
    }

    apply_rotation_journal(base_path, &journal)?;
    fs::remove_file(journal_path)?;
    Ok(true)
}

fn write_rotation_journal(path: &Path, journal: &RotationJournal) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_private_dir_permissions(parent)?;
    }
    atomic_write(path, &serde_json::to_string_pretty(journal)?)?;
    set_private_file_permissions(path)?;
    Ok(())
}

fn apply_rotation_journal(base_path: &Path, journal: &RotationJournal) -> anyhow::Result<()> {
    for (file, content) in &journal.files {
        if !is_valid_rotation_file(file) {
            return Err(anyhow::anyhow!(
                "invalid path in rotation journal: {}",
                file
            ));
        }
        atomic_write(&base_path.join(file), content)?;
    }
    atomic_write(&base_path.join("access.json"), &journal.access_json)?;
    Ok(())
}

fn is_valid_rotation_file(file: &str) -> bool {
    file.starts_with("secrets/")
        && !file.starts_with('/')
        && !file.contains('\\')
        && file
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn atomic_write(path: &Path, content: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("kagi")
    ));
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    set_private_file_permissions(path)?;
    Ok(())
}

fn set_private_file_permissions(_path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn set_private_dir_permissions(_path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn rotate_project_key(base_path: &Path, remove_member_id: Option<&str>) -> anyhow::Result<usize> {
    recover_pending_rotation(base_path)?;
    let key_manager = KeyManager::new(base_path.to_path_buf());
    let old_key = key_manager
        .load()
        .context("Failed to load current project key")?;
    let old_store = store_from_project_key(base_path.to_path_buf(), &old_key)?;
    let scopes = old_store
        .list_services()
        .map_err(|e| anyhow::anyhow!("Failed to list encrypted stores: {}", e))?;
    let mut services = Vec::new();
    for scope in scopes {
        services.push(
            old_store
                .load(&scope)
                .map_err(|e| anyhow::anyhow!("Failed to decrypt {}: {}", scope, e))?,
        );
    }

    let new_key = KeyManager::generate_project_key();
    let new_store = store_from_project_key(base_path.to_path_buf(), &new_key)?;
    let mut files = BTreeMap::new();
    for service in &services {
        let (file, content) = new_store
            .encrypted_service_content(service)
            .map_err(|e| anyhow::anyhow!("Failed to re-encrypt {}: {}", service.name, e))?;
        files.insert(file, content);
    }

    let journal = RotationJournal {
        version: ROTATION_JOURNAL_VERSION,
        project_id: key_manager.project_id()?,
        access_json: key_manager.rotated_access_json(&new_key, remove_member_id)?,
        files,
    };
    let journal_path = key_manager.rotation_journal_path()?;
    write_rotation_journal(&journal_path, &journal)?;
    apply_rotation_journal(base_path, &journal)?;
    key_manager.cache_project_key(&new_key)?;
    fs::remove_file(journal_path)?;

    Ok(services.len())
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let tty = io::stdout().is_terminal();
    let c = Palette::new(tty);
    #[cfg(feature = "server")]
    let allow_insecure = cli.allow_insecure_http
        || std::env::var("KAGI_ALLOW_INSECURE_HTTP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
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
                if has_encrypted_store(&local.join("secrets"))? {
                    eprintln!(
                        "{} {}",
                        c.prefix(),
                        c.warning(
                            "warning: overwriting existing .kagi/ will delete all stored secrets."
                        )
                    );
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
                c.muted(
                    "Commit .kagi/; local keys stay on this device. Do not commit real .env files."
                )
            );
        }
        Commands::Set {
            service: service_name,
            desc,
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
            set_service.execute(&scope, &key, &value, desc.as_deref())?;
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
                        confirm_secret_output(tty, "kagi get --show", &c)?;
                    }
                    let list_service = ListServicesService::new(store);
                    draw_all_service_envs(&list_service, show_values, &c)?;
                }
                GetSelection::Service(service) => {
                    if show_values {
                        confirm_secret_output(tty, "kagi get --show", &c)?;
                    }
                    let list_service = ListServicesService::new(store);
                    draw_service_envs(&list_service, &service, show_values, &c)?;
                }
                GetSelection::Scope(scope) => {
                    if show_values {
                        confirm_secret_output(tty, "kagi get --show", &c)?;
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
                    let secret_desc = store
                        .load(&scope)
                        .ok()
                        .and_then(|s| s.get_secret(&key).and_then(|sec| sec.description.clone()));
                    let get_service = GetSecretService::new(store);
                    let value = get_service.execute(&scope, &key)?;
                    if let Some(desc) = secret_desc {
                        println!("{} {} = {}", c.muted(&desc), c.key(&key), c.success(&value));
                    } else {
                        println!("{}", value);
                    }
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
        Commands::Member { command } => {
            let (base_path, _) = resolve_kagi_base()?;
            let key_manager = KeyManager::new(base_path.clone());
            match command {
                MemberCommands::List => {
                    let members = key_manager.list_members()?;
                    let requests = key_manager.list_join_requests()?;
                    #[cfg(feature = "server")]
                    let mut requests = requests;
                    let config_path = base_path.join(crate::domain::config::KAGI_CONFIG_FILE);
                    let config: serde_json::Value =
                        serde_json::from_str(&fs::read_to_string(&config_path)?)?;
                    let is_server_mode = config
                        .get("settings")
                        .and_then(|s| s.get("sync"))
                        .and_then(|s| s.get("mode"))
                        .and_then(|v| v.as_str())
                        == Some("server");
                    if is_server_mode {
                        #[cfg(feature = "server")]
                        match fetch_server_join_requests(&key_manager, &config, allow_insecure)
                            .await
                        {
                            Ok(server_requests) => {
                                // Merge: for each server request, add if not already present locally
                                for sr in server_requests {
                                    if !requests.iter().any(|r| r.member_id == sr.member_id) {
                                        requests.push(sr);
                                    }
                                }
                                requests.sort_by(|a, b| a.member_id.cmp(&b.member_id));
                            }
                            Err(e) => {
                                eprintln!(
                                    "{} warning: could not fetch server join requests: {}",
                                    c.prefix(),
                                    e
                                );
                            }
                        }
                    }
                    println!("{}", c.warning("Members"));
                    if members.is_empty() {
                        println!("  {}", c.muted("none"));
                    } else {
                        for member in members {
                            let status = if member.status == "active" {
                                c.success(&member.status)
                            } else {
                                c.muted(&member.status)
                            };
                            println!(
                                "  {}  {}  {}",
                                c.accent(&member.member_id),
                                c.key(&member.name),
                                status
                            );
                        }
                    }

                    println!("{}", c.warning("Join Requests"));
                    if requests.is_empty() {
                        println!("  {}", c.muted("none"));
                    } else {
                        for member in requests {
                            println!(
                                "  {}  {}  {}",
                                c.accent(&member.member_id),
                                c.key(&member.name),
                                c.warning(&member.status)
                            );
                        }
                    }
                }
                MemberCommands::Join { name } => {
                    let member = key_manager.create_join_request(name)?;
                    let config_path = base_path.join(crate::domain::config::KAGI_CONFIG_FILE);
                    let config: serde_json::Value =
                        serde_json::from_str(&fs::read_to_string(&config_path)?)?;
                    let sync = config.get("settings").and_then(|s| s.get("sync"));
                    let is_server_mode =
                        sync.and_then(|s| s.get("mode")).and_then(|v| v.as_str()) == Some("server");

                    if !is_server_mode {
                        println!(
                            "{} {} {}",
                            c.prefix(),
                            c.success("created join request"),
                            c.accent(&member.member_id)
                        );
                        print_member_approval_instruction(&member.member_id, &c);
                        return Ok(());
                    }
                    #[cfg(feature = "server")]
                    {
                        let sync = sync.ok_or_else(|| anyhow::anyhow!("missing sync settings"))?;
                        member_join_server_mode(
                            &key_manager,
                            &member,
                            &config,
                            sync,
                            allow_insecure,
                            &c,
                        )
                        .await?;
                    }
                    #[cfg(not(feature = "server"))]
                    {
                        return Err(anyhow::anyhow!("server mode not available"));
                    }
                }
                MemberCommands::Approve { member_id } => {
                    let config_path = base_path.join(crate::domain::config::KAGI_CONFIG_FILE);
                    let config: serde_json::Value =
                        serde_json::from_str(&fs::read_to_string(&config_path)?)?;
                    let is_server_mode = config
                        .get("settings")
                        .and_then(|s| s.get("sync"))
                        .and_then(|s| s.get("mode"))
                        .and_then(|v| v.as_str())
                        == Some("server");
                    if is_server_mode {
                        #[cfg(feature = "server")]
                        {
                            member_approve_server_mode(
                                &key_manager,
                                &member_id,
                                &config,
                                allow_insecure,
                                &c,
                            )
                            .await?;
                        }
                        #[cfg(not(feature = "server"))]
                        {
                            return Err(anyhow::anyhow!("server mode not available"));
                        }
                    } else {
                        let member = key_manager.approve_join_request(&member_id)?;
                        println!(
                            "{} {} {}",
                            c.prefix(),
                            c.success("approved member"),
                            c.accent(&member.member_id)
                        );
                    }
                }
                MemberCommands::Del { member_id } => {
                    confirm_member_remove(tty, &member_id, &c)?;
                    let count = rotate_project_key(&base_path, Some(&member_id))?;
                    println!(
                        "{} {} {} {}",
                        c.prefix(),
                        c.success("removed member and rotated project key"),
                        c.accent(&member_id),
                        c.muted(&format!("({} stores rewritten)", count))
                    );
                }
            }
        }
        #[cfg(feature = "server")]
        Commands::Serve {
            db,
            key_file,
            bind,
            max_body,
            allow_insecure_http,
        } => {
            let db_path = if db.is_empty() {
                std::env::current_dir()?.join("kagi.db")
            } else {
                PathBuf::from(db)
            };
            let key_file_path = if key_file.is_empty() {
                default_server_key_path()?
            } else {
                PathBuf::from(key_file)
            };
            let bind_addr: std::net::SocketAddr = bind
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid bind address: {}", e))?;
            let max_body_size = parse_max_body(&max_body);

            let env_override = std::env::var("KAGI_ALLOW_INSECURE_HTTP")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let allow_insecure = allow_insecure_http || env_override;

            if (bind_addr.ip().is_unspecified() || !bind_addr.ip().is_loopback()) && !allow_insecure
            {
                return Err(anyhow::anyhow!(
                    "Binding to non-localhost address {} requires HTTPS. Use a reverse proxy with TLS, or pass --allow-insecure-http for local testing only.",
                    bind_addr
                ));
            }

            println!("kagi: starting server on http://{}", bind_addr);
            println!("kagi: database: {}", db_path.display());
            println!("kagi: key file: {}", key_file_path.display());
            crate::server::serve(bind_addr, &db_path, &key_file_path, max_body_size).await?;
        }
        #[cfg(feature = "server")]
        Commands::Remote { command } => match command {
            RemoteCommands::Login { remote, token } => {
                remote_login(&remote, &token, &c, allow_insecure).await?;
            }
        },
        #[cfg(feature = "server")]
        Commands::Project { command } => match command {
            ProjectCommands::Join { remote } => {
                project_join_remote(std::env::current_dir()?, &remote, &c, allow_insecure).await?;
            }
            ProjectCommands::List { remote } => {
                let remote_url = resolve_admin_remote(remote).await?;
                project_list_remote(&remote_url, &c, allow_insecure).await?;
            }
            ProjectCommands::Approve { remote, project_id } => {
                let remote_url = resolve_admin_remote(remote).await?;
                project_approve_remote(&remote_url, &project_id, &c, allow_insecure).await?;
            }
            ProjectCommands::Del { remote, project_id } => {
                let remote_url = resolve_admin_remote(remote).await?;
                project_del_remote(&remote_url, &project_id, &c, allow_insecure).await?;
            }
        },
        #[cfg(feature = "server")]
        Commands::Push => {
            let (base_path, _) = resolve_kagi_base()?;
            let config_path = base_path.join(crate::domain::config::KAGI_CONFIG_FILE);
            let config: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&config_path)?)?;
            let project_id = config["project_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing project_id"))?;
            let remote_url = config["settings"]["sync"]["remote"]
                .as_str()
                .ok_or_else(|| {
                    anyhow::anyhow!("missing remote URL. Run kagi init --remote first.")
                })?;

            let local_data_dir = local_data_dir()?;
            let remote_store =
                crate::infrastructure::remote_local::RemoteLocalStore::new(local_data_dir);
            let token = remote_store
                .load_token(project_id)?
                .ok_or_else(|| anyhow::anyhow!("no project token found"))?;
            let meta = remote_store
                .load_remote_metadata(project_id)?
                .ok_or_else(|| anyhow::anyhow!("no remote metadata found"))?;

            let base_revision = meta.local_revision.unwrap_or(0);

            let key_manager = KeyManager::new(base_path.clone());
            let identity = key_manager.load_or_create_identity()?;
            let member_id = key_manager.member_id()?;
            let signing_key = key_manager.ensure_signing_key(&member_id)?;
            let signing_public_key = base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().to_bytes());

            let store = resolve_store()?.0;
            let kagi_json = fs::read_to_string(&config_path)?;
            let access_json = fs::read_to_string(base_path.join("access.json"))
                .unwrap_or_else(|_| "{}".to_string());

            let mut files = Vec::new();
            for scope in store.list_services()? {
                let (file_name, content) = store.raw_service_content(&scope)?;
                let content_hash = {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(content.as_bytes());
                    hex::encode(hasher.finalize())
                };
                files.push(crate::domain::sync::project_state::ProjectFile {
                    path: file_name,
                    content,
                    sha256: Some(content_hash),
                });
            }

            let project_state = crate::domain::sync::project_state::ProjectState {
                project_id: project_id.to_string(),
                revision: base_revision,
                kagi_json,
                access_json,
                files,
            };

            let previous_manifest_hash = if base_revision > 0 {
                Some(meta.last_manifest_hash.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "missing local manifest hash for revision {}; run kagi pull before pushing",
                        base_revision
                    )
                })?)
            } else {
                None
            };
            let manifest = crate::domain::sync::manifest::ProjectStateManifest {
                version: 1,
                project_id: project_id.to_string(),
                revision: base_revision + 1,
                previous_manifest_hash,
                kagi_json_hash: crate::domain::sync::manifest::hash_json(&project_state.kagi_json),
                access_json_hash: crate::domain::sync::manifest::hash_json(
                    &project_state.access_json,
                ),
                file_hashes: project_state
                    .files
                    .iter()
                    .map(|f| crate::domain::sync::manifest::FileHash {
                        path: f.path.clone(),
                        sha256: f.sha256.clone().unwrap_or_default(),
                    })
                    .collect(),
                timestamp: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap(),
                signer_member_id: member_id.clone(),
                signer_public_key: signing_public_key,
            };
            let manifest_json = serde_json::to_string(&manifest)?;
            let manifest_hash = manifest.compute_hash();
            let signature = signing_key.sign(manifest_hash.as_bytes());
            let signature_b64 =
                base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

            let mut payload = serde_json::json!({
                "base_revision": base_revision,
                "state": project_state,
                "manifest": manifest_json,
                "manifest_signature": signature_b64,
            });
            if let Some(ref token_ids) = meta.pending_token_ids {
                payload["activate_token_ids"] = serde_json::json!(token_ids);
            }
            if let Some(ref member_ids) = meta.pending_accepted_member_ids {
                payload["accepted_join_member_ids"] = serde_json::json!(member_ids);
            }

            let request_id = format!("kgr_{}", nanoid::nanoid!(12));
            let plaintext = crate::domain::sync::envelope::RequestPlaintext {
                version: 1,
                request_id: request_id.clone(),
                issued_at: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap(),
                operation: "push".into(),
                method: "POST".into(),
                path: format!("/v1/projects/{}/push", project_id),
                project_id: Some(project_id.to_string()),
                token: Some(token),
                claim_secret: None,
                payload,
            };

            let client = crate::infrastructure::remote_client::RemoteClient::new_pinned(
                remote_url.to_string(),
                &meta.server_fingerprint,
                allow_insecure,
            )
            .await?;
            let data = client.send_request(&plaintext, &identity).await?;
            let new_revision = data["revision"].as_i64().unwrap_or(base_revision + 1);

            remote_store.save_remote_metadata(
                &crate::domain::sync::remote_config::RemoteMetadata {
                    version: 1,
                    project_id: project_id.to_string(),
                    remote: remote_url.to_string(),
                    server_key_id: meta.server_key_id.clone(),
                    server_fingerprint: meta.server_fingerprint.clone(),
                    local_revision: Some(new_revision),
                    last_pulled_at: meta.last_pulled_at,
                    last_pushed_at: Some(
                        time::OffsetDateTime::now_utc()
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap(),
                    ),
                    last_manifest_hash: Some(manifest_hash),
                    pending_token_ids: None,
                    pending_accepted_member_ids: None,
                },
            )?;

            println!(
                "{} {} revision {}",
                c.prefix(),
                c.success("pushed"),
                c.accent(&new_revision.to_string())
            );
        }
        #[cfg(feature = "server")]
        Commands::Pull { token } => {
            if let Some(token_str) = token {
                pull_with_token(&token_str, &c, allow_insecure).await?;
            } else {
                let (base_path, _) = resolve_kagi_base()?;
                let config_path = base_path.join(crate::domain::config::KAGI_CONFIG_FILE);
                let config: serde_json::Value =
                    serde_json::from_str(&fs::read_to_string(&config_path)?)?;
                let project_id = config["project_id"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing project_id"))?;
                let remote_url = config["settings"]["sync"]["remote"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing remote URL"))?;

                let local_access_json = fs::read_to_string(base_path.join("access.json"))
                    .unwrap_or_else(|_| "{}".to_string());

                let local_data_dir = local_data_dir()?;
                let remote_store =
                    crate::infrastructure::remote_local::RemoteLocalStore::new(local_data_dir);
                let meta = remote_store
                    .load_remote_metadata(project_id)?
                    .ok_or_else(|| anyhow::anyhow!("no remote metadata found"))?;

                let key_manager = KeyManager::new(base_path.clone());
                let identity = key_manager.load_or_create_identity()?;
                let member_id = key_manager.member_id()?;
                let request_id = format!("kgr_{}", nanoid::nanoid!(12));

                let token = match remote_store.load_token(project_id)? {
                    Some(t) => t,
                    None => {
                        let claim_secret =
                            remote_store.load_claim_secret(project_id)?.ok_or_else(|| {
                                anyhow::anyhow!(
                                    "no claim secret found; run `kagi project join` first"
                                )
                            })?;
                        let claim_plaintext = crate::domain::sync::envelope::RequestPlaintext {
                            version: 1,
                            request_id: request_id.clone(),
                            issued_at: time::OffsetDateTime::now_utc()
                                .format(&time::format_description::well_known::Rfc3339)
                                .unwrap(),
                            operation: "pull".into(),
                            method: "POST".into(),
                            path: format!("/v1/projects/{}/pull", project_id),
                            project_id: Some(project_id.to_string()),
                            token: None,
                            claim_secret: Some(claim_secret.clone()),
                            payload: serde_json::json!({
                                "member_id": member_id,
                            }),
                        };
                        let client =
                            crate::infrastructure::remote_client::RemoteClient::new_pinned(
                                remote_url.to_string(),
                                &meta.server_fingerprint,
                                allow_insecure,
                            )
                            .await?;
                        let data = client.send_request(&claim_plaintext, &identity).await?;
                        if let Some(wrapped_b64) =
                            data.get("wrapped_project_token").and_then(|v| v.as_str())
                        {
                            let wrapped = base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(wrapped_b64)
                                .map_err(|e| anyhow::anyhow!("invalid wrapped token: {}", e))?;
                            let decrypted = crate::infrastructure::remote_envelope::decrypt_bytes(
                                &wrapped, &identity,
                            )
                            .map_err(|e| {
                                anyhow::anyhow!("failed to decrypt wrapped token: {}", e)
                            })?;
                            String::from_utf8(decrypted)
                                .map_err(|e| anyhow::anyhow!("invalid token: {}", e))?
                        } else {
                            return Err(anyhow::anyhow!(
                                "no project token available; run `kagi project join` first or ask admin to approve"
                            ));
                        }
                    }
                };
                let parsed_token = crate::domain::sync::project_token::ProjectToken::parse(&token)
                    .ok_or_else(|| anyhow::anyhow!("token from server is malformed"))?;

                let known_revision = meta.local_revision.unwrap_or(0);
                let plaintext = crate::domain::sync::envelope::RequestPlaintext {
                    version: 1,
                    request_id: request_id.clone(),
                    issued_at: time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap(),
                    operation: "pull".into(),
                    method: "POST".into(),
                    path: format!("/v1/projects/{}/pull", project_id),
                    project_id: Some(project_id.to_string()),
                    token: Some(token.clone()),
                    claim_secret: None,
                    payload: serde_json::json!({ "known_revision": known_revision }),
                };
                let client = crate::infrastructure::remote_client::RemoteClient::new_pinned(
                    remote_url.to_string(),
                    &meta.server_fingerprint,
                    allow_insecure,
                )
                .await?;
                let data = client.send_request(&plaintext, &identity).await?;
                let state = data["state"].clone();

                let _manifest_hash = verify_pulled_manifest(
                    &data,
                    &state,
                    project_id,
                    known_revision,
                    meta.last_manifest_hash.as_deref(),
                    &local_access_json,
                    parsed_token.payload.bootstrap_signer_public_key.as_deref(),
                )?;

                let remote_revision = data["revision"].as_i64().unwrap_or(0);
                let pulled_access_json = state
                    .get("access_json")
                    .and_then(|v| v.as_str())
                    .unwrap_or("{}");

                let has_pending = meta
                    .pending_token_ids
                    .as_ref()
                    .is_some_and(|v| !v.is_empty())
                    || meta
                        .pending_accepted_member_ids
                        .as_ref()
                        .is_some_and(|v| !v.is_empty());
                let would_change_state =
                    remote_revision != known_revision || pulled_access_json != local_access_json;

                if has_pending && would_change_state {
                    return Err(anyhow::anyhow!(
                        "Cannot pull while member approval metadata is pending. Run `kagi push` to publish the approval, or resolve the pending member approval before pulling."
                    ));
                }

                apply_pulled_state(&base_path, &state)?;

                // Only save token after authenticated pull succeeds
                remote_store.save_token(project_id, &token)?;
                remote_store.delete_claim_secret(project_id)?;

                remote_store.save_remote_metadata(
                    &crate::domain::sync::remote_config::RemoteMetadata {
                        version: 1,
                        project_id: project_id.to_string(),
                        remote: remote_url.to_string(),
                        server_key_id: meta.server_key_id.clone(),
                        server_fingerprint: meta.server_fingerprint.clone(),
                        local_revision: Some(remote_revision),
                        last_pulled_at: Some(
                            time::OffsetDateTime::now_utc()
                                .format(&time::format_description::well_known::Rfc3339)
                                .unwrap(),
                        ),
                        last_pushed_at: meta.last_pushed_at,
                        last_manifest_hash: data
                            .get("manifest_hash")
                            .and_then(|value| value.as_str())
                            .map(str::to_string)
                            .or(meta.last_manifest_hash),
                        pending_token_ids: meta.pending_token_ids,
                        pending_accepted_member_ids: meta.pending_accepted_member_ids,
                    },
                )?;

                println!(
                    "{} {} revision {}",
                    c.prefix(),
                    c.success("pulled"),
                    c.accent(&remote_revision.to_string())
                );
            }
        }
        #[cfg(feature = "server")]
        Commands::Status => {
            let (base_path, _) = resolve_kagi_base()?;
            let config_path = base_path.join(crate::domain::config::KAGI_CONFIG_FILE);
            let config: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&config_path)?)?;
            let project_id = config["project_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing project_id"))?;
            let remote_url = config["settings"]["sync"]["remote"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing remote URL"))?;

            let local_data_dir = local_data_dir()?;
            let remote_store =
                crate::infrastructure::remote_local::RemoteLocalStore::new(local_data_dir);
            let token = remote_store
                .load_token(project_id)?
                .ok_or_else(|| anyhow::anyhow!("no project token found"))?;
            let meta = remote_store
                .load_remote_metadata(project_id)?
                .ok_or_else(|| anyhow::anyhow!("no remote metadata found"))?;

            let local_revision = meta.local_revision.unwrap_or(0);

            let key_manager = KeyManager::new(base_path);
            let identity = key_manager.load_or_create_identity()?;
            let request_id = format!("kgr_{}", nanoid::nanoid!(12));
            let plaintext = crate::domain::sync::envelope::RequestPlaintext {
                version: 1,
                request_id: request_id.clone(),
                issued_at: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap(),
                operation: "status".into(),
                method: "POST".into(),
                path: format!("/v1/projects/{}/status", project_id),
                project_id: Some(project_id.to_string()),
                token: Some(token),
                claim_secret: None,
                payload: serde_json::json!({ "local_revision": local_revision }),
            };

            let client = crate::infrastructure::remote_client::RemoteClient::new_pinned(
                remote_url.to_string(),
                &meta.server_fingerprint,
                allow_insecure,
            )
            .await?;
            let data = client.send_request(&plaintext, &identity).await?;
            let remote_revision = data["remote_revision"].as_i64().unwrap_or(0);
            let state_str = data["state"].as_str().unwrap_or("unknown");
            let pending_joins = data["pending_join_count"].as_i64().unwrap_or(0);

            println!(
                "{} {} local={} remote={}",
                c.prefix(),
                c.info(state_str),
                c.accent(&local_revision.to_string()),
                c.accent(&remote_revision.to_string())
            );
            if pending_joins > 0 {
                println!(
                    "{} {} pending join request(s)",
                    c.prefix(),
                    c.warning(&pending_joins.to_string())
                );
            }
        }
    }
    Ok(())
}

#[cfg(feature = "server")]
fn parse_max_body(s: &str) -> usize {
    let s = s.to_lowercase();
    if s.ends_with("mb") {
        s.trim_end_matches("mb").parse::<usize>().unwrap_or(10) * 1024 * 1024
    } else if s.ends_with("kb") {
        s.trim_end_matches("kb").parse::<usize>().unwrap_or(10) * 1024
    } else {
        s.parse::<usize>().unwrap_or(10 * 1024 * 1024)
    }
}

#[cfg(feature = "server")]
fn default_server_key_path() -> anyhow::Result<PathBuf> {
    let base = local_data_dir()?;
    Ok(base.join("server/server.key.json"))
}

#[cfg(feature = "server")]
fn local_data_dir() -> anyhow::Result<PathBuf> {
    #[cfg(test)]
    {
        Ok(std::env::temp_dir().join("kagi-tests"))
    }
    #[cfg(not(test))]
    {
        if let Ok(path) = std::env::var("KAGI_HOME") {
            return Ok(PathBuf::from(path));
        }
        directories::ProjectDirs::from("dev", "kagi", "kagi")
            .map(|dirs| dirs.data_dir().to_path_buf())
            .ok_or_else(|| anyhow::anyhow!("failed to resolve local data directory"))
    }
}

#[cfg(feature = "server")]
fn apply_pulled_state(base_path: &Path, state: &serde_json::Value) -> anyhow::Result<()> {
    let project_state: crate::domain::sync::project_state::ProjectState =
        serde_json::from_value(state.clone())?;
    for file in &project_state.files {
        crate::domain::sync::project_state::validate_file_path(&file.path)
            .map_err(|err| anyhow::anyhow!("invalid remote file path {}: {}", file.path, err))?;
    }

    let kagi_json_empty = serde_json::from_str::<serde_json::Value>(&project_state.kagi_json)
        .map(|v| v.as_object().map(|o| o.is_empty()).unwrap_or(false))
        .unwrap_or(false);
    let access_json_empty = serde_json::from_str::<serde_json::Value>(&project_state.access_json)
        .map(|v| v.as_object().map(|o| o.is_empty()).unwrap_or(false))
        .unwrap_or(false);
    let is_empty_remote = project_state.revision == 0
        && kagi_json_empty
        && access_json_empty
        && project_state.files.is_empty();

    if is_empty_remote {
        let local_kagi = base_path.join("kagi.json");
        let local_access = base_path.join("access.json");
        if local_kagi.exists() && local_access.exists() {
            // Server has empty initial state; keep local files.
        } else {
            return Err(anyhow::anyhow!(
                "remote project is empty; run `kagi init` first, or ask the owner to push first"
            ));
        }
    } else {
        atomic_write(&base_path.join("kagi.json"), &project_state.kagi_json)?;
        atomic_write(&base_path.join("access.json"), &project_state.access_json)?;
    }

    for file in project_state.files {
        let file_path = base_path.join(&file.path);
        fs::create_dir_all(file_path.parent().unwrap())?;
        atomic_write(&file_path, &file.content)?;
    }
    Ok(())
}

#[cfg(feature = "server")]
fn is_empty_json_object(input: Option<&str>) -> bool {
    input
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
        .and_then(|value| value.as_object().map(|object| object.is_empty()))
        .unwrap_or(false)
}

#[cfg(feature = "server")]
fn is_empty_genesis_state(state: &serde_json::Value, project_id: &str) -> bool {
    state.get("project_id").and_then(|v| v.as_str()) == Some(project_id)
        && state.get("revision").and_then(|v| v.as_i64()) == Some(0)
        && is_empty_json_object(state.get("kagi_json").and_then(|v| v.as_str()))
        && is_empty_json_object(state.get("access_json").and_then(|v| v.as_str()))
        && state
            .get("files")
            .and_then(|v| v.as_array())
            .map(|files| files.is_empty())
            .unwrap_or(false)
}

#[cfg(feature = "server")]
fn verify_pulled_manifest(
    data: &serde_json::Value,
    state: &serde_json::Value,
    project_id: &str,
    known_revision: i64,
    last_manifest_hash: Option<&str>,
    access_json_str: &str,
    trusted_bootstrap_signer_public_key: Option<&str>,
) -> anyhow::Result<String> {
    let remote_revision = data
        .get("revision")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow::anyhow!("server response missing revision"))?;
    let manifest_str = match data.get("manifest").and_then(|v| v.as_str()) {
        Some(manifest_str) => manifest_str,
        None => {
            if data.get("manifest_hash").is_some() {
                return Err(anyhow::anyhow!(
                    "server returned manifest_hash but no manifest"
                ));
            }
            if remote_revision == 0
                && known_revision == 0
                && is_empty_genesis_state(state, project_id)
            {
                return Ok(String::new());
            }
            return Err(anyhow::anyhow!("server response missing manifest"));
        }
    };
    let manifest: crate::domain::sync::manifest::ProjectStateManifest =
        serde_json::from_str(manifest_str)
            .map_err(|e| anyhow::anyhow!("invalid manifest from server: {}", e))?;

    let expected_hash = manifest.compute_hash();
    let server_hash = data
        .get("manifest_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("server response missing manifest_hash"))?;
    if expected_hash != server_hash {
        return Err(anyhow::anyhow!(
            "manifest hash mismatch: computed {} vs server {}",
            expected_hash,
            server_hash
        ));
    }
    if manifest.project_id != project_id {
        return Err(anyhow::anyhow!(
            "manifest project_id mismatch: {} vs {}",
            manifest.project_id,
            project_id
        ));
    }
    if manifest.revision != remote_revision {
        return Err(anyhow::anyhow!(
            "manifest revision mismatch: {} vs {}",
            manifest.revision,
            remote_revision
        ));
    }
    // Replay protection: reject old or identical revisions
    if manifest.revision < known_revision {
        return Err(anyhow::anyhow!(
            "server rolled back revision: {} < local {}",
            manifest.revision,
            known_revision
        ));
    }
    if manifest.revision == known_revision {
        if let Some(last_hash) = last_manifest_hash {
            if expected_hash != last_hash {
                return Err(anyhow::anyhow!(
                    "manifest replay detected: revision {} hash changed but expected {}",
                    manifest.revision,
                    last_hash
                ));
            }
        } else {
            return Err(anyhow::anyhow!(
                "manifest replay detected: revision {} already known locally",
                manifest.revision
            ));
        }
    }
    if manifest.revision > known_revision && known_revision > 0 {
        let last_hash = last_manifest_hash.ok_or_else(|| {
            anyhow::anyhow!(
                "manifest chain missing local hash for revision {}",
                known_revision
            )
        })?;
        if manifest.previous_manifest_hash.as_deref() != Some(last_hash) {
            return Err(anyhow::anyhow!(
                "manifest chain mismatch: expected previous hash {} got {}",
                last_hash,
                manifest
                    .previous_manifest_hash
                    .as_deref()
                    .unwrap_or("<missing>")
            ));
        }
    }

    let kagi_json_str = state
        .get("kagi_json")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("state missing kagi_json"))?;
    let remote_access_json_str = state
        .get("access_json")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("state missing access_json"))?;
    let expected_kagi_hash = crate::domain::sync::manifest::hash_json(kagi_json_str);
    let expected_access_hash = crate::domain::sync::manifest::hash_json(remote_access_json_str);
    if manifest.kagi_json_hash != expected_kagi_hash {
        return Err(anyhow::anyhow!("manifest kagi_json hash mismatch"));
    }
    if manifest.access_json_hash != expected_access_hash {
        return Err(anyhow::anyhow!("manifest access_json hash mismatch"));
    }

    let files = state
        .get("files")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("state missing files"))?;
    let mut state_file_hashes = BTreeMap::new();
    for file_value in files {
        let path = file_value
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("state file missing path"))?;
        let content = file_value
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("state file {} missing content", path))?;
        let expected_file_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            hex::encode(hasher.finalize())
        };
        if state_file_hashes
            .insert(path.to_string(), expected_file_hash)
            .is_some()
        {
            return Err(anyhow::anyhow!(
                "state contains duplicate file path: {}",
                path
            ));
        }
    }

    let mut manifest_paths = BTreeSet::new();
    for manifest_file in &manifest.file_hashes {
        if !manifest_paths.insert(manifest_file.path.clone()) {
            return Err(anyhow::anyhow!(
                "manifest contains duplicate file path: {}",
                manifest_file.path
            ));
        }
        let expected_file_hash = state_file_hashes.get(&manifest_file.path).ok_or_else(|| {
            anyhow::anyhow!("manifest references missing file: {}", manifest_file.path)
        })?;
        if manifest_file.sha256 != *expected_file_hash {
            return Err(anyhow::anyhow!(
                "manifest file hash mismatch for {}: expected {} got {}",
                manifest_file.path,
                expected_file_hash,
                manifest_file.sha256
            ));
        }
    }

    let state_paths: BTreeSet<String> = state_file_hashes.keys().cloned().collect();
    if state_paths != manifest_paths {
        let missing_paths: Vec<String> = manifest_paths.difference(&state_paths).cloned().collect();
        if !missing_paths.is_empty() {
            return Err(anyhow::anyhow!(
                "manifest references missing files: {}",
                missing_paths.join(", ")
            ));
        }
        let extra_paths: Vec<String> = state_paths.difference(&manifest_paths).cloned().collect();
        if !extra_paths.is_empty() {
            return Err(anyhow::anyhow!(
                "state contains extra files not in manifest: {}",
                extra_paths.join(", ")
            ));
        }
    }

    // Verify signature against known member's public key
    let signature_b64 = data
        .get("manifest_signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("manifest present but manifest_signature missing"))?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| anyhow::anyhow!("invalid manifest signature: {}", e))?;
    if signature_bytes.len() != 64 {
        return Err(anyhow::anyhow!(
            "manifest signature must be 64 bytes, got {}",
            signature_bytes.len()
        ));
    }
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|e| anyhow::anyhow!("invalid signature: {}", e))?;
    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&manifest.signer_public_key)
        .map_err(|e| anyhow::anyhow!("invalid signer public key: {}", e))?;
    if public_key_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "signer public key must be 32 bytes, got {}",
            public_key_bytes.len()
        ));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&public_key_bytes);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| anyhow::anyhow!("invalid verifying key: {}", e))?;

    // Check that signer_public_key matches the known member's key in access.json
    let access: serde_json::Value =
        serde_json::from_str(access_json_str).unwrap_or(serde_json::Value::Null);
    let empty_members = vec![];
    let members = access
        .get("members")
        .and_then(|m| m.as_array())
        .unwrap_or(&empty_members);
    let known_public_key = members
        .iter()
        .find(|m| {
            m.get("member_id")
                .and_then(|v| v.as_str())
                .map(|id| id == manifest.signer_member_id)
                .unwrap_or(false)
        })
        .and_then(|m| m.get("signing_public_key"))
        .and_then(|v| v.as_str());

    let trusted_public_key = known_public_key.or(trusted_bootstrap_signer_public_key);
    let trusted_public_key = trusted_public_key.ok_or_else(|| {
        anyhow::anyhow!(
            "manifest signed by unknown member {} (no trusted signing key available)",
            manifest.signer_member_id
        )
    })?;
    if trusted_public_key != manifest.signer_public_key {
        return Err(anyhow::anyhow!(
            "manifest signer_public_key does not match trusted key for {}: expected {} got {}",
            manifest.signer_member_id,
            trusted_public_key,
            manifest.signer_public_key
        ));
    }

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(expected_hash.as_bytes(), &signature)
        .map_err(|e| anyhow::anyhow!("manifest signature verification failed: {}", e))?;

    Ok(expected_hash)
}

#[cfg(feature = "server")]
async fn pull_with_token(token_str: &str, c: &Palette, allow_insecure: bool) -> anyhow::Result<()> {
    let token = crate::domain::sync::project_token::ProjectToken::parse(token_str)
        .ok_or_else(|| anyhow::anyhow!("invalid project token"))?;
    let remote_url = token.payload.remote.clone();
    let project_id = token.payload.project_id.clone();

    let key_manager = KeyManager::new(std::env::current_dir()?.join(".kagi"));
    let identity = key_manager.load_or_create_identity()?;
    let base_path = std::env::current_dir()?.join(".kagi");
    let local_access_json =
        fs::read_to_string(base_path.join("access.json")).unwrap_or_else(|_| "{}".to_string());

    let local_data_dir = local_data_dir()?;
    let remote_store = crate::infrastructure::remote_local::RemoteLocalStore::new(local_data_dir);
    let existing_meta = remote_store
        .load_remote_metadata(&project_id)
        .ok()
        .flatten();
    let known_revision = existing_meta
        .as_ref()
        .and_then(|m| m.local_revision)
        .unwrap_or(0);
    let last_manifest_hash = existing_meta
        .as_ref()
        .and_then(|m| m.last_manifest_hash.as_deref());
    let pending_token_ids = existing_meta
        .as_ref()
        .and_then(|m| m.pending_token_ids.clone());
    let pending_accepted_member_ids = existing_meta
        .as_ref()
        .and_then(|m| m.pending_accepted_member_ids.clone());

    let request_id = format!("kgr_{}", nanoid::nanoid!(12));
    let plaintext = crate::domain::sync::envelope::RequestPlaintext {
        version: 1,
        request_id: request_id.clone(),
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        operation: "pull".into(),
        method: "POST".into(),
        path: format!("/v1/projects/{}/pull", project_id),
        project_id: Some(project_id.clone()),
        token: Some(token_str.to_string()),
        claim_secret: None,
        payload: serde_json::json!({ "known_revision": known_revision }),
    };

    let remote_client = crate::infrastructure::remote_client::RemoteClient::new_pinned(
        remote_url.to_string(),
        &token.payload.server_fingerprint,
        allow_insecure,
    )
    .await?;
    let data = remote_client.send_request(&plaintext, &identity).await?;
    let remote_revision = data["revision"].as_i64().unwrap_or(0);
    let state = data["state"].clone();

    let _manifest_hash = verify_pulled_manifest(
        &data,
        &state,
        &project_id,
        known_revision,
        last_manifest_hash,
        &local_access_json,
        token.payload.bootstrap_signer_public_key.as_deref(),
    )?;

    let pulled_access_json = state
        .get("access_json")
        .and_then(|v| v.as_str())
        .unwrap_or("{}");

    let has_pending = pending_token_ids.as_ref().is_some_and(|v| !v.is_empty())
        || pending_accepted_member_ids
            .as_ref()
            .is_some_and(|v| !v.is_empty());
    let would_change_state =
        remote_revision != known_revision || pulled_access_json != local_access_json;

    if has_pending && would_change_state {
        return Err(anyhow::anyhow!(
            "Cannot pull while member approval metadata is pending. Run `kagi push` to publish the approval, or resolve the pending member approval before pulling."
        ));
    }

    apply_pulled_state(&base_path, &state)?;

    remote_store.save_token(&project_id, token_str)?;
    remote_store.save_remote_metadata(&crate::domain::sync::remote_config::RemoteMetadata {
        version: 1,
        project_id: project_id.clone(),
        remote: remote_url.to_string(),
        server_key_id: remote_client.server_key_id().to_string(),
        server_fingerprint: remote_client.fingerprint().to_string(),
        local_revision: Some(remote_revision),
        last_pulled_at: Some(
            time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        ),
        last_pushed_at: None,
        last_manifest_hash: data
            .get("manifest_hash")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        pending_token_ids,
        pending_accepted_member_ids,
    })?;

    println!(
        "{} {} revision {}",
        c.prefix(),
        c.success("pulled"),
        c.accent(&remote_revision.to_string())
    );
    Ok(())
}

#[cfg(feature = "server")]
fn resolve_admin_token(fingerprint: &str) -> anyhow::Result<String> {
    if let Ok(token) = std::env::var("KAGI_ADMIN_TOKEN") {
        validate_admin_token_for_fingerprint(&token, fingerprint)?;
        return Ok(token);
    }
    let entry =
        crate::infrastructure::key_manager::keyring_admin_entry(fingerprint).map_err(|e| {
            anyhow::anyhow!(
                "keyring unavailable: {}. admin token requires OS keychain.",
                e
            )
        })?;
    match entry.get_password() {
        Ok(token) => {
            validate_admin_token_for_fingerprint(&token, fingerprint)?;
            Ok(token)
        }
        Err(_) => Err(anyhow::anyhow!(
            "admin token not found for server {}. Run `kagi remote login --remote <url> --token <token>` or set KAGI_ADMIN_TOKEN.",
            fingerprint
        )),
    }
}

#[cfg(feature = "server")]
fn validate_admin_token_for_fingerprint(token: &str, fingerprint: &str) -> anyhow::Result<()> {
    let parsed = crate::domain::sync::project_token::ProjectToken::parse(token)
        .ok_or_else(|| anyhow::anyhow!("invalid admin token"))?;
    if !token.starts_with("kagi_admin_v1_")
        || parsed.payload.project_id != "admin"
        || !parsed
            .payload
            .capabilities
            .iter()
            .any(|capability| capability == "admin")
    {
        return Err(anyhow::anyhow!("invalid admin token"));
    }
    if parsed.payload.server_fingerprint != fingerprint {
        return Err(anyhow::anyhow!(
            "admin token belongs to server {}, but remote fingerprint is {}",
            parsed.payload.server_fingerprint,
            fingerprint
        ));
    }
    Ok(())
}

#[cfg(feature = "server")]
async fn remote_login(
    remote_url: &str,
    token: &str,
    c: &Palette,
    allow_insecure: bool,
) -> anyhow::Result<()> {
    let remote_client = crate::infrastructure::remote_client::RemoteClient::new(
        remote_url.to_string(),
        allow_insecure,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to connect to remote: {}", e))?;
    let fingerprint = remote_client.fingerprint();
    validate_admin_token_for_fingerprint(token, fingerprint)?;
    let entry =
        crate::infrastructure::key_manager::keyring_admin_entry(fingerprint).map_err(|e| {
            anyhow::anyhow!(
                "keyring unavailable: {}. admin token requires OS keychain.",
                e
            )
        })?;
    entry
        .set_password(token)
        .map_err(|e| anyhow::anyhow!("failed to save admin token to keyring: {}", e))?;

    let local_data_dir = local_data_dir()?;
    let remote_store = crate::infrastructure::remote_local::RemoteLocalStore::new(local_data_dir);
    remote_store
        .save_admin_remote(fingerprint, remote_url)
        .map_err(|e| anyhow::anyhow!("failed to save admin remote config: {}", e))?;

    println!(
        "{} admin token saved for server {} ({})",
        c.success("ok"),
        c.accent(fingerprint),
        c.muted(remote_url)
    );
    Ok(())
}

#[cfg(feature = "server")]
async fn resolve_admin_remote(remote: Option<String>) -> anyhow::Result<String> {
    if let Some(url) = remote {
        return Ok(url);
    }
    let local_data_dir = local_data_dir()?;
    let admins_dir = local_data_dir.join("admins");
    let remote_store = crate::infrastructure::remote_local::RemoteLocalStore::new(local_data_dir);
    if !admins_dir.exists() {
        return Err(anyhow::anyhow!(
            "no saved admin remote found. Run `kagi remote login --remote <url> --token <token>` first, or pass --remote."
        ));
    }
    let mut found = None;
    for entry in fs::read_dir(&admins_dir)? {
        let entry = entry?;
        let fingerprint = entry.file_name().to_string_lossy().to_string();
        if let Some(remote) = remote_store.load_admin_remote(&fingerprint)? {
            found = Some(remote);
            break;
        }
    }
    found.ok_or_else(|| {
        anyhow::anyhow!(
            "no saved admin remote found. Run `kagi remote login --remote <url> --token <token>` first, or pass --remote."
        )
    })
}

#[cfg(feature = "server")]
async fn project_join_remote(
    cwd: PathBuf,
    remote_url: &str,
    c: &Palette,
    allow_insecure: bool,
) -> anyhow::Result<()> {
    let local = cwd.join(".kagi");
    if !local.is_dir() {
        return Err(anyhow::anyhow!(
            "no .kagi/ directory found. Run `kagi init` first."
        ));
    }

    let config_path = local.join(crate::domain::config::KAGI_CONFIG_FILE);
    let mut config: serde_json::Value = serde_json::from_str(&fs::read_to_string(&config_path)?)?;
    let existing_project_id = config["project_id"].as_str().map(|s| s.to_string());

    let key_manager = KeyManager::new(local.clone());
    let identity = key_manager.load_or_create_identity()?;
    let recipient = identity.to_public();
    let name = default_member_name();
    let member_id = key_manager.member_id()?;

    let remote_client = crate::infrastructure::remote_client::RemoteClient::new(
        remote_url.to_string(),
        allow_insecure,
    )
    .await?;

    let claim_secret = format!("kgs_{}", nanoid::nanoid!(24));
    let claim_secret_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(claim_secret.as_bytes());
        format!("cs:{}", base64_encode_url(&hasher.finalize()))
    };

    let request_id = format!("kgr_{}", nanoid::nanoid!(12));
    let plaintext = crate::domain::sync::envelope::RequestPlaintext {
        version: 1,
        request_id: request_id.clone(),
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        operation: "create_project_request".into(),
        method: "POST".into(),
        path: "/v1/projects/requests".into(),
        project_id: existing_project_id.clone(),
        token: None,
        claim_secret: None,
        payload: serde_json::json!({
            "requester_member_id": member_id,
            "requester_name": name,
            "requester_recipient": recipient.to_string(),
            "claim_secret_hash": claim_secret_hash,
        }),
    };

    let data = remote_client.send_request(&plaintext, &identity).await?;
    let project_id = data["project_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing project_id in response"))?;

    config["settings"]["sync"]["mode"] = serde_json::Value::String("server".to_string());
    config["settings"]["sync"]["remote"] = serde_json::Value::String(remote_url.to_string());
    if existing_project_id.is_none() {
        config["project_id"] = serde_json::Value::String(project_id.to_string());
    }
    fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

    let local_data_dir = local_data_dir()?;
    let remote_store = crate::infrastructure::remote_local::RemoteLocalStore::new(local_data_dir);

    remote_store.save_remote_metadata(&crate::domain::sync::remote_config::RemoteMetadata {
        version: 1,
        project_id: project_id.to_string(),
        remote: remote_url.to_string(),
        server_key_id: remote_client.server_key_id().to_string(),
        server_fingerprint: remote_client.fingerprint().to_string(),
        local_revision: Some(0),
        last_pulled_at: None,
        last_pushed_at: None,
        last_manifest_hash: None,
        pending_token_ids: None,
        pending_accepted_member_ids: None,
    })?;
    remote_store.save_claim_secret(project_id, &claim_secret)?;

    println!(
        "{} {} {}. {}",
        c.prefix(),
        c.success("Requested project"),
        c.accent(project_id),
        c.muted("Waiting for admin approval.")
    );
    Ok(())
}

#[cfg(feature = "server")]
async fn project_list_remote(
    remote_url: &str,
    c: &Palette,
    allow_insecure: bool,
) -> anyhow::Result<()> {
    let remote_client = crate::infrastructure::remote_client::RemoteClient::new(
        remote_url.to_string(),
        allow_insecure,
    )
    .await?;
    let token = resolve_admin_token(remote_client.fingerprint())?;

    let identity = {
        let key_manager = KeyManager::new(std::env::current_dir()?.join(".kagi"));
        key_manager.load_or_create_identity()?
    };

    // 1. Fetch pending requests
    let request_id = format!("kgr_{}", nanoid::nanoid!(12));
    let requests_plaintext = crate::domain::sync::envelope::RequestPlaintext {
        version: 1,
        request_id: request_id.clone(),
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        operation: "list_project_requests".into(),
        method: "POST".into(),
        path: "/v1/projects/requests/list".into(),
        project_id: Some("admin".into()),
        token: Some(token.clone()),
        claim_secret: None,
        payload: serde_json::json!({}),
    };
    let requests_data = remote_client
        .send_request(&requests_plaintext, &identity)
        .await?;
    let empty = Vec::new();
    let requests = requests_data["requests"].as_array().unwrap_or(&empty);

    // 2. Fetch active projects
    let request_id = format!("kgr_{}", nanoid::nanoid!(12));
    let projects_plaintext = crate::domain::sync::envelope::RequestPlaintext {
        version: 1,
        request_id: request_id.clone(),
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        operation: "list_projects".into(),
        method: "POST".into(),
        path: "/v1/projects/list".into(),
        project_id: Some("admin".into()),
        token: Some(token),
        claim_secret: None,
        payload: serde_json::json!({}),
    };
    let projects_data = remote_client
        .send_request(&projects_plaintext, &identity)
        .await?;
    let projects = projects_data["projects"].as_array().unwrap_or(&empty);

    if requests.is_empty() && projects.is_empty() {
        println!(
            "{} {}",
            c.prefix(),
            c.muted("No projects or pending requests found.")
        );
        return Ok(());
    }

    if !requests.is_empty() {
        println!("{} {}", c.prefix(), c.warning("Pending requests:"));
        for r in requests {
            let id = r["project_id"].as_str().unwrap_or("unknown");
            let name = r["requester_name"].as_str().unwrap_or("");
            let created_at = r["created_at"].as_str().unwrap_or("");
            println!(
                "  {}  {}  {}",
                c.accent(id),
                c.muted(&format!("by {}", name)),
                c.muted(created_at)
            );
        }
    }

    if !projects.is_empty() {
        println!("{} {}", c.prefix(), c.muted("Active projects:"));
        for p in projects {
            let id = p["project_id"].as_str().unwrap_or("unknown");
            let revision = p["revision"].as_i64().unwrap_or(0);
            let created_at = p["created_at"].as_str().unwrap_or("");
            println!(
                "  {}  rev={}  created={}",
                c.accent(id),
                revision,
                created_at
            );
        }
    }

    Ok(())
}

#[cfg(feature = "server")]
async fn project_approve_remote(
    remote_url: &str,
    project_id: &str,
    c: &Palette,
    allow_insecure: bool,
) -> anyhow::Result<()> {
    let remote_client = crate::infrastructure::remote_client::RemoteClient::new(
        remote_url.to_string(),
        allow_insecure,
    )
    .await?;
    let token = resolve_admin_token(remote_client.fingerprint())?;

    let request_id = format!("kgr_{}", nanoid::nanoid!(12));
    let plaintext = crate::domain::sync::envelope::RequestPlaintext {
        version: 1,
        request_id: request_id.clone(),
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        operation: "approve_project_request".into(),
        method: "POST".into(),
        path: format!("/v1/projects/requests/{}/approve", project_id),
        project_id: Some("admin".into()),
        token: Some(token),
        claim_secret: None,
        payload: serde_json::json!({ "remote": remote_url }),
    };

    let identity = {
        let key_manager = KeyManager::new(std::env::current_dir()?.join(".kagi"));
        key_manager.load_or_create_identity()?
    };

    let data = remote_client.send_request(&plaintext, &identity).await?;
    let approved_project_id = data["project_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing project_id in response"))?;

    println!(
        "{} {} {}",
        c.prefix(),
        c.success("Approved project"),
        c.accent(approved_project_id),
    );
    Ok(())
}

#[cfg(feature = "server")]
async fn project_del_remote(
    remote_url: &str,
    project_id: &str,
    c: &Palette,
    allow_insecure: bool,
) -> anyhow::Result<()> {
    let remote_client = crate::infrastructure::remote_client::RemoteClient::new(
        remote_url.to_string(),
        allow_insecure,
    )
    .await?;
    let token = resolve_admin_token(remote_client.fingerprint())?;

    let request_id = format!("kgr_{}", nanoid::nanoid!(12));
    let plaintext = crate::domain::sync::envelope::RequestPlaintext {
        version: 1,
        request_id: request_id.clone(),
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        operation: "delete_project".into(),
        method: "POST".into(),
        path: format!("/v1/projects/{}/delete", project_id),
        project_id: Some(project_id.into()),
        token: Some(token),
        claim_secret: None,
        payload: serde_json::json!({}),
    };

    let identity = {
        let key_manager = KeyManager::new(std::env::current_dir()?.join(".kagi"));
        key_manager.load_or_create_identity()?
    };

    remote_client.send_request(&plaintext, &identity).await?;

    println!(
        "{} {} {}",
        c.prefix(),
        c.success("Deleted project"),
        c.accent(project_id)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::config::KAGI_CONFIG_FILE;
    use crate::domain::entity::secret::Secret;
    use crate::domain::entity::service::Service;
    use crate::domain::repository::secret_repo::SecretRepository;
    use tempfile::TempDir;

    #[cfg(feature = "server")]
    fn fixed_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    #[cfg(feature = "server")]
    fn public_key_b64(signing_key: &ed25519_dalek::SigningKey) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    }

    #[cfg(feature = "server")]
    fn sha256_hex(value: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        hex::encode(hasher.finalize())
    }

    #[cfg(feature = "server")]
    fn signed_manifest_fixture(
        revision: i64,
        previous_manifest_hash: Option<String>,
        access_json: &str,
        files: &[(&str, &str)],
    ) -> (serde_json::Value, serde_json::Value, String, String) {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use ed25519_dalek::Signer as _;

        let signing_key = fixed_signing_key();
        let signer_public_key = public_key_b64(&signing_key);
        let file_hashes = files
            .iter()
            .map(|(path, content)| crate::domain::sync::manifest::FileHash {
                path: (*path).to_string(),
                sha256: sha256_hex(content),
            })
            .collect();
        let manifest = crate::domain::sync::manifest::ProjectStateManifest {
            version: 1,
            project_id: "kgp_test".into(),
            revision,
            previous_manifest_hash,
            kagi_json_hash: crate::domain::sync::manifest::hash_json("{}"),
            access_json_hash: crate::domain::sync::manifest::hash_json(access_json),
            file_hashes,
            timestamp: "2026-01-01T00:00:00Z".into(),
            signer_member_id: "kgm_test".into(),
            signer_public_key: signer_public_key.clone(),
        };
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let manifest_hash = manifest.compute_hash();
        let signature = signing_key.sign(manifest_hash.as_bytes());
        let signature_b64 = STANDARD.encode(signature.to_bytes());
        let state_files: Vec<serde_json::Value> = files
            .iter()
            .map(|(path, content)| serde_json::json!({"path": path, "content": content}))
            .collect();
        let state = serde_json::json!({
            "project_id": "kgp_test",
            "revision": revision,
            "kagi_json": "{}",
            "access_json": access_json,
            "files": state_files,
        });
        let data = serde_json::json!({
            "revision": revision,
            "manifest": manifest_json,
            "manifest_hash": manifest_hash,
            "manifest_signature": signature_b64,
        });
        (data, state, manifest_hash, signer_public_key)
    }

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

    #[test]
    #[cfg(feature = "server")]
    fn test_validate_admin_token_matches_server_fingerprint() {
        let token =
            crate::domain::sync::project_token::ProjectToken::generate_admin_token("kgs_ok".into());

        validate_admin_token_for_fingerprint(&token.full_token, "kgs_ok").unwrap();
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_validate_admin_token_rejects_wrong_server_fingerprint() {
        let token =
            crate::domain::sync::project_token::ProjectToken::generate_admin_token("kgs_ok".into());

        let err = validate_admin_token_for_fingerprint(&token.full_token, "kgs_other").unwrap_err();
        assert!(err.to_string().contains("admin token belongs to server"));
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_validate_admin_token_rejects_project_token() {
        let token = crate::domain::sync::project_token::ProjectToken::generate(
            "http://localhost:13816".into(),
            "kgp_test".into(),
            "kgs_ok".into(),
            vec!["pull".into()],
            None,
        );

        let err = validate_admin_token_for_fingerprint(&token.full_token, "kgs_ok").unwrap_err();
        assert!(err.to_string().contains("invalid admin token"));
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_verify_pulled_manifest_allows_empty_genesis_state() {
        let data = serde_json::json!({"revision": 0});
        let state = serde_json::json!({
            "project_id": "kgp_test",
            "revision": 0,
            "kagi_json": "{}",
            "access_json": "{}",
            "files": [],
        });

        let hash = verify_pulled_manifest(&data, &state, "kgp_test", 0, None, "{}", None).unwrap();

        assert_eq!(hash, "");
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_verify_pulled_manifest_rejects_missing_manifest_after_genesis() {
        let data = serde_json::json!({"revision": 1});
        let state = serde_json::json!({
            "project_id": "kgp_test",
            "revision": 1,
            "kagi_json": "{}",
            "access_json": "{}",
            "files": [],
        });

        let err =
            verify_pulled_manifest(&data, &state, "kgp_test", 0, None, "{}", None).unwrap_err();

        assert!(err.to_string().contains("server response missing manifest"));
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_verify_pulled_manifest_rejects_duplicate_state_paths() {
        let (data, mut state, _hash, signer_public_key) =
            signed_manifest_fixture(1, None, "{}", &[("services/api/development.env", "one")]);
        state["files"] = serde_json::json!([
            {"path": "services/api/development.env", "content": "one"},
            {"path": "services/api/development.env", "content": "two"},
        ]);

        let err = verify_pulled_manifest(
            &data,
            &state,
            "kgp_test",
            0,
            None,
            "{}",
            Some(&signer_public_key),
        )
        .unwrap_err();

        assert!(err.to_string().contains("duplicate file path"));
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_verify_pulled_manifest_requires_trusted_signer() {
        let (data, state, _hash, _signer_public_key) = signed_manifest_fixture(1, None, "{}", &[]);

        let err =
            verify_pulled_manifest(&data, &state, "kgp_test", 0, None, "{}", None).unwrap_err();

        assert!(err.to_string().contains("unknown member"));
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_verify_pulled_manifest_accepts_bootstrap_signer() {
        let (data, state, manifest_hash, signer_public_key) =
            signed_manifest_fixture(1, None, "{}", &[]);

        let verified_hash = verify_pulled_manifest(
            &data,
            &state,
            "kgp_test",
            0,
            None,
            "{}",
            Some(&signer_public_key),
        )
        .unwrap();

        assert_eq!(verified_hash, manifest_hash);
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_verify_pulled_manifest_rejects_broken_hash_chain() {
        let (data, state, _hash, signer_public_key) =
            signed_manifest_fixture(2, Some("wrong_previous_hash".into()), "{}", &[]);

        let err = verify_pulled_manifest(
            &data,
            &state,
            "kgp_test",
            1,
            Some("known_previous_hash"),
            "{}",
            Some(&signer_public_key),
        )
        .unwrap_err();

        assert!(err.to_string().contains("manifest chain mismatch"));
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_apply_pulled_state_rejects_path_escape() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join(".kagi");
        fs::create_dir(&base).unwrap();
        let state = serde_json::json!({
            "project_id": "kgp_test",
            "revision": 1,
            "kagi_json": "{}",
            "access_json": "{}",
            "files": [
                {
                    "path": "../outside.enc",
                    "content": "{}"
                }
            ]
        });

        let err = apply_pulled_state(&base, &state).unwrap_err();
        assert!(err.to_string().contains("invalid remote file path"));
        assert!(!dir.path().join("outside.enc").exists());
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_apply_pulled_state_preserves_local_on_empty_remote() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join(".kagi");
        fs::create_dir(&base).unwrap();
        fs::write(base.join("kagi.json"), "{\"project_id\":\"kgp_test\"}").unwrap();
        fs::write(base.join("access.json"), "{\"members\":[]}").unwrap();

        let state = serde_json::json!({
            "project_id": "kgp_test",
            "revision": 0,
            "kagi_json": "{}",
            "access_json": "{}",
            "files": []
        });

        apply_pulled_state(&base, &state).unwrap();
        assert_eq!(
            fs::read_to_string(base.join("kagi.json")).unwrap(),
            "{\"project_id\":\"kgp_test\"}"
        );
        assert_eq!(
            fs::read_to_string(base.join("access.json")).unwrap(),
            "{\"members\":[]}"
        );
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_apply_pulled_state_fails_when_local_missing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join(".kagi");
        fs::create_dir(&base).unwrap();

        let state = serde_json::json!({
            "project_id": "kgp_test",
            "revision": 0,
            "kagi_json": "{}",
            "access_json": "{}",
            "files": []
        });

        let err = apply_pulled_state(&base, &state).unwrap_err();
        assert!(
            err.to_string().contains("remote project is empty"),
            "expected error about empty remote, got: {}",
            err
        );
    }

    #[test]
    fn test_rotation_journal_is_local_and_recoverable() {
        let dir = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();

        let base = dir.path().join(".kagi");
        fs::create_dir(&base).unwrap();
        let config = KagiConfig {
            version: "2".into(),
            project_id: "kgp_test".into(),
            services: Default::default(),
            settings: Default::default(),
        };
        fs::write(
            base.join(KAGI_CONFIG_FILE),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let key_manager =
            KeyManager::new_with_local_data_dir(base.clone(), local.path().to_path_buf());
        key_manager
            .initialize_project("kgp_test", "kgm_test")
            .unwrap();
        let old_key = key_manager.load().unwrap();
        let old_store = store_from_project_key(base.clone(), &old_key).unwrap();
        let mut service = Service::new("api/development");
        service.set_secret(Secret::new("MESSAGE", "hello"));
        old_store.save(&service).unwrap();

        let new_key = KeyManager::generate_project_key();
        let new_store = store_from_project_key(base.clone(), &new_key).unwrap();
        let (file, content) = new_store.encrypted_service_content(&service).unwrap();
        let journal = RotationJournal {
            version: ROTATION_JOURNAL_VERSION,
            project_id: key_manager.project_id().unwrap(),
            access_json: key_manager.rotated_access_json(&new_key, None).unwrap(),
            files: BTreeMap::from([(file, content)]),
        };
        let journal_path = key_manager.rotation_journal_path().unwrap();
        write_rotation_journal(&journal_path, &journal).unwrap();

        assert!(journal_path.exists());
        assert!(!journal_path.starts_with(&base));
        assert!(!base.join("rotation.json").exists());

        recover_pending_rotation_with_key_manager(&base, &key_manager).unwrap();
        assert!(!journal_path.exists());

        let recovered_store = store_from_project_key(base, &new_key).unwrap();
        let recovered = recovered_store.load("api/development").unwrap();
        assert_eq!(recovered.get_secret("MESSAGE").unwrap().value, "hello");
    }
}

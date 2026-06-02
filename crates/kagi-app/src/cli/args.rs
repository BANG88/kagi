use clap::{ColorChoice, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "kagi",
    about = "Manage encrypted environment variables",
    version,
    color = ColorChoice::Auto
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Allow insecure HTTP remotes for non-localhost addresses
    #[arg(long, global = true)]
    pub allow_insecure_http: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new kagi repository in the current directory
    Init {
        /// Default environments for services (comma-separated, e.g., development,test)
        #[arg(short, long, value_delimiter = ',', num_args = 0..=1, default_missing_value = "")]
        envs: Option<Vec<String>>,

        /// Enable nested service inference from subdirectories
        #[arg(long)]
        nested: bool,

        /// Overwrite existing .kagi/ directory
        #[arg(long)]
        force: bool,

        /// Skip .env migration wizard
        #[arg(long)]
        no_migrate: bool,
    },

    /// Store an encrypted secret for an environment
    Set {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Description of the secret (shown in exports and lists)
        #[arg(short, long)]
        desc: Option<String>,

        /// Service or environment name
        first: Option<String>,

        /// Environment name or secret key
        second: Option<String>,

        /// Secret key or value
        third: Option<String>,

        /// Value to store (will be encrypted), when service and env are both provided positionally
        fourth: Option<String>,
    },

    /// Get service/env/key information or decrypt one secret value
    Get {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Show decrypted values when listing. Requires an interactive terminal.
        #[arg(long = "show")]
        show_values: bool,

        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,

        /// Service or environment name
        first: Option<String>,

        /// Environment name or secret key
        second: Option<String>,

        /// Secret key, when service and env are both provided positionally
        third: Option<String>,
    },

    /// Delete a single secret key from a scope
    Unset {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Service or environment name
        first: Option<String>,

        /// Environment name or secret key
        second: Option<String>,

        /// Secret key, when service and env are both provided positionally
        third: Option<String>,
    },

    /// Search secret keys across services
    Search {
        /// Search query (case-insensitive)
        query: String,

        /// Also search decrypted values (requires interactive terminal)
        #[arg(long)]
        values: bool,

        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,
    },

    /// Run a command with injected environment variables
    Run {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// <service> <command>... or <command>... when the scope is inferred from nested directory.
        #[arg(required = false, trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Diagnose local project health and check for common issues
    Doctor {
        /// Attempt to fix recoverable issues (e.g., pending rotation journal)
        #[arg(long)]
        fix: bool,

        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,
    },

    /// Recover local project metadata from device-local snapshots
    Recover {
        #[command(subcommand)]
        command: RecoverCommands,
    },

    /// Show current repository, inferred service, environments, and remote hints
    Status,

    /// Export secrets as KEY=value lines (suitable for shell sourcing)
    Export {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Directory to write one .env file per environment when exporting a service
        #[arg(short, long)]
        out: Option<String>,

        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,

        /// Service or environment name
        first: Option<String>,

        /// Environment name, when service is provided positionally
        second: Option<String>,
    },

    /// Import secrets from a .env file
    Import {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Service or environment name
        first: Option<String>,

        /// Environment name, when service is provided positionally
        second: Option<String>,

        /// Path to the env file to import
        #[arg(short, long, default_value = ".env")]
        file: String,

        /// Overwrite existing keys without prompting
        #[arg(long)]
        force: bool,

        /// Preview import changes without writing secrets
        #[arg(long)]
        dry_run: bool,

        /// Normalize imported keys to UPPER_SNAKE_CASE
        #[arg(long)]
        upper_snake: bool,
    },

    /// Synchronize keys from .env.example (and optional sources) across environments
    Sync {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory when present.
        #[arg(short, long)]
        service: Option<String>,

        /// Path to the .env.example template file
        #[arg(short, long, default_value = ".env.example")]
        example: String,

        /// Additional source files to merge (comma-separated, later overrides earlier)
        #[arg(long, value_delimiter = ',')]
        sources: Vec<String>,

        /// Environments to sync (comma-separated)
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "development,test,staging,production"
        )]
        envs: Vec<String>,

        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,
    },

    /// Manage encrypted files scoped like env secrets
    File {
        #[command(subcommand)]
        command: FileCommands,
    },

    /// Manage default environments
    Env {
        #[command(subcommand)]
        command: EnvCommands,
    },

    /// Manage project members
    Member {
        #[command(subcommand)]
        command: MemberCommands,
    },

    #[cfg(feature = "server")]
    /// Start the Kagi remote sync server
    Serve {
        /// Database file path
        #[arg(long, default_value = "")]
        db: String,

        /// Server key file path
        #[arg(long, default_value = "")]
        key_file: String,

        /// Bind address
        #[arg(long, default_value = "127.0.0.1:13816")]
        bind: String,

        /// Max body size (e.g. 10mb)
        #[arg(long, default_value = "10mb")]
        max_body: String,

        /// Allow serving HTTP on non-localhost addresses (unsafe for production)
        #[arg(long)]
        allow_insecure_http: bool,
    },

    #[cfg(feature = "server")]
    /// Manage remote server credentials and connections
    Remote {
        #[command(subcommand)]
        command: RemoteCommands,
    },

    /// Generate shell completions for kagi
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, elvish, powershell)
        shell: String,
    },

    /// Create a backup of the project and local credentials
    Backup {
        /// Output directory for the backup
        #[arg(short, long)]
        out: String,
    },

    /// Restore a project from a backup
    Restore {
        /// Backup directory to restore from
        #[arg(short, long)]
        from: String,

        /// Overwrite existing files without prompting
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum FileCommands {
    /// Add a small plaintext file to encrypted storage
    Add {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Logical file name to use inside kagi
        #[arg(long)]
        name: Option<String>,

        /// Replace an existing file with the same name in the selected scope
        #[arg(long)]
        force: bool,

        /// Allow files up to 5 MiB instead of the default 1 MiB
        #[arg(long)]
        allow_large: bool,

        /// Manage a file outside the repository, limited to the current user's home directory
        #[arg(long)]
        external: bool,

        /// [service] [env] <path>, or [env] <path> when service is inferred
        #[arg(required = true)]
        args: Vec<String>,
    },

    /// List encrypted files in a scope
    List {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// List files from every scope
        #[arg(long)]
        all: bool,

        /// [service] [env], or [env] when service is inferred
        args: Vec<String>,
    },

    /// Print one decrypted file to stdout. Requires an interactive terminal.
    Show {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// [service] [env] <name>, or [env] <name> when service is inferred
        #[arg(required = true)]
        args: Vec<String>,
    },

    /// Restore one decrypted file to its original path or --out path
    Restore {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Output path. Defaults to the path captured when the file was added.
        #[arg(short, long)]
        out: Option<String>,

        /// Overwrite an existing plaintext output file
        #[arg(long)]
        force: bool,

        /// Restore every encrypted file in the selected scope
        #[arg(long)]
        all: bool,

        /// Preview restore targets without writing files
        #[arg(long)]
        dry_run: bool,

        /// [service] [env] <name>, or [env] <name> when service is inferred
        args: Vec<String>,
    },

    /// Remove one encrypted file from the selected scope
    Remove {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Remove without an interactive confirmation prompt
        #[arg(long)]
        force: bool,

        /// [service] [env] <name>, or [env] <name> when service is inferred
        #[arg(required = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum EnvCommands {
    /// List configured default environments
    List {
        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,
    },

    /// Add an environment to every service
    Add {
        /// Environment name to add
        env: String,
    },

    /// Rename an environment across every service
    Rename {
        /// Existing environment name
        old: String,

        /// New environment name
        new: String,
    },

    /// Delete an environment from every service
    Remove {
        /// Environment name to delete
        env: String,

        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,
    },
}

#[derive(Subcommand)]
pub enum RecoverCommands {
    /// Restore .kagi/access.json from the local access snapshot
    Access {
        /// Overwrite an existing access.json
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum MemberCommands {
    /// List active members and pending member requests
    List {
        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,
    },

    /// Request to join this project from a new device
    Request {
        /// Display name for the member requesting access
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Approve a pending member request
    Approve {
        /// Member id from `kagi member list`.
        member_id: Option<String>,
    },

    /// Promote an active member to owner
    Promote {
        /// Member id from `kagi member list`.
        member_id: String,
    },

    /// Demote an owner to member
    Demote {
        /// Member id from `kagi member list`.
        member_id: String,
    },

    /// Remove a member's access wrapper
    Remove {
        /// Member id from `kagi member list`.
        member_id: Option<String>,
    },
}

#[cfg(feature = "server")]
#[derive(Subcommand)]
pub enum RemoteCommands {
    /// Save an admin token for a remote server (stored in OS keychain)
    Login {
        /// Remote server URL
        #[arg(long)]
        remote: String,

        /// Admin token from server first startup
        #[arg(long)]
        token: String,
    },

    /// Register this local project with a remote server
    Register {
        /// Remote server URL
        #[arg(long)]
        remote: String,
    },

    /// Upload local encrypted project state to the remote server
    Push,

    /// Download encrypted project state from the remote server
    Pull {
        /// Optional project token for pulling without local project
        token: Option<String>,
    },

    /// Compare local and remote revisions
    Status,

    /// List remote projects and pending registration requests (admin only)
    Projects {
        /// Remote server URL (optional if saved via `kagi remote login`)
        #[arg(long)]
        remote: Option<String>,

        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,
    },

    /// Approve a pending project registration request (admin only)
    Approve {
        /// Remote server URL (optional if saved via `kagi remote login`)
        #[arg(long)]
        remote: Option<String>,

        /// Project ID to approve
        project_id: String,
    },

    /// Delete a project from the remote server (admin or project admin)
    Remove {
        /// Remote server URL (optional if saved via `kagi remote login`)
        #[arg(long)]
        remote: Option<String>,

        /// Project ID to delete
        project_id: String,
    },

    /// List project tokens on the remote server
    Tokens {
        /// Remote server URL (optional if saved via `kagi remote login`)
        #[arg(long)]
        remote: Option<String>,

        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,
    },

    /// Revoke a project token
    RevokeToken {
        /// Remote server URL (optional if saved via `kagi remote login`)
        #[arg(long)]
        remote: Option<String>,

        /// Token ID to revoke
        token_id: String,
    },

    /// Query server audit logs (admin only)
    Audit {
        /// Remote server URL (optional if saved via `kagi remote login`)
        #[arg(long)]
        remote: Option<String>,

        /// Filter by project ID
        #[arg(long)]
        project_id: Option<String>,

        /// Maximum number of events to return (1-500)
        #[arg(long, default_value = "50")]
        limit: i64,

        /// Use plain text output
        #[arg(long)]
        #[cfg_attr(not(feature = "tui"), arg(hide = true))]
        plain: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    #[cfg(feature = "server")]
    fn test_server_commands_available_with_server_feature() {
        let cmd = Cli::command();
        let names: Vec<_> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        assert!(names.contains(&"serve"), "serve should be present");
        assert!(names.contains(&"remote"), "remote should be present");
        assert!(names.contains(&"status"), "status should be present");

        for removed in ["push", "pull", "project", "token"] {
            assert!(
                !names.contains(&removed),
                "{removed} should not be present as a top-level command"
            );
        }

        let remote = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "remote")
            .expect("remote command should be present");
        let remote_names: Vec<_> = remote.get_subcommands().map(|c| c.get_name()).collect();
        for expected in [
            "login",
            "register",
            "push",
            "pull",
            "status",
            "projects",
            "approve",
            "remove",
            "tokens",
            "revoke-token",
            "audit",
        ] {
            assert!(
                remote_names.contains(&expected),
                "remote {expected} should be present"
            );
        }
    }

    #[test]
    #[cfg(not(feature = "server"))]
    fn test_server_commands_not_available_without_server_feature() {
        let cmd = Cli::command();
        let names: Vec<_> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        assert!(
            !names.contains(&"serve"),
            "serve should NOT be present when server feature is disabled"
        );
        assert!(
            !names.contains(&"push"),
            "push should NOT be present when server feature is disabled"
        );
        assert!(
            !names.contains(&"pull"),
            "pull should NOT be present when server feature is disabled"
        );
        assert!(
            !names.contains(&"status"),
            "status should NOT be present when server feature is disabled"
        );
        assert!(
            !names.contains(&"project"),
            "project should NOT be present when server feature is disabled"
        );
        assert!(
            !names.contains(&"remote"),
            "remote should NOT be present when server feature is disabled"
        );
    }

    #[test]
    fn test_git_backed_command_names_stay_available() {
        let cmd = Cli::command();

        let env = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "env")
            .expect("env command should be present");
        let env_names: Vec<_> = env.get_subcommands().map(|c| c.get_name()).collect();
        assert!(env_names.contains(&"remove"));
        assert!(!env_names.contains(&"del"));

        let member = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "member")
            .expect("member command should be present");
        let member_names: Vec<_> = member.get_subcommands().map(|c| c.get_name()).collect();
        assert!(member_names.contains(&"request"));
        assert!(member_names.contains(&"approve"));
        assert!(member_names.contains(&"remove"));
        assert!(!member_names.contains(&"join"));
        assert!(!member_names.contains(&"del"));
    }

    #[test]
    fn test_completions_command_exists() {
        let cmd = Cli::command();
        let names: Vec<_> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        assert!(
            names.contains(&"completions"),
            "completions should be present"
        );
    }

    #[test]
    fn test_completions_accepts_supported_shells() {
        for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
            let args = vec!["kagi", "completions", shell];
            let result = Cli::try_parse_from(&args);
            assert!(result.is_ok(), "completions {shell} should parse");
        }
    }

    #[test]
    fn test_completions_rejects_unknown_shell() {
        let args = vec!["kagi", "completions", "unknown_shell"];
        let result = Cli::try_parse_from(&args);
        assert!(
            result.is_ok(),
            "unknown shell should parse at CLI level (error handled at runtime)"
        );
    }
}

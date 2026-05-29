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

        /// Force plain text output (disable TUI)
        #[arg(long)]
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

        /// Force plain text output (disable TUI)
        #[arg(long)]
        plain: bool,
    },

    /// Export secrets as KEY=value lines (suitable for shell sourcing)
    Export {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Directory to write one .env file per environment when exporting a service
        #[arg(short, long)]
        out: Option<String>,

        /// Force plain text output (disable TUI)
        #[arg(long)]
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
    /// Manage project tokens (list, revoke)
    Token {
        #[command(subcommand)]
        command: TokenCommands,
    },

    #[cfg(feature = "server")]
    /// Manage remote projects (join, list, approve, delete)
    Project {
        #[command(subcommand)]
        command: ProjectCommands,
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

    #[cfg(feature = "server")]
    /// Upload local encrypted project state to remote server
    Push,

    #[cfg(feature = "server")]
    /// Download encrypted project state from remote server
    Pull {
        /// Optional project token for pulling without local project
        token: Option<String>,
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

    #[cfg(feature = "server")]
    /// Compare local and remote revisions
    Status,
}

#[derive(Subcommand)]
pub enum EnvCommands {
    /// List configured default environments
    List,

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
    Del {
        /// Environment name to delete
        env: String,

        /// Force plain text output (disable TUI)
        #[arg(long)]
        plain: bool,
    },
}

#[derive(Subcommand)]
pub enum MemberCommands {
    /// List active members and pending join requests
    List {
        /// Force plain text output (disable TUI)
        #[arg(long)]
        plain: bool,
    },

    /// Request to join this project from a new device
    Join {
        /// Display name for the member requesting access
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Approve a pending join request
    Approve {
        /// Member id from `kagi member list`
        member_id: String,
    },

    /// Remove a member's access wrapper
    Del {
        /// Member id from `kagi member list`
        member_id: String,
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

        /// Force plain text output (disable TUI)
        #[arg(long)]
        plain: bool,
    },
}

#[cfg(feature = "server")]
#[derive(Subcommand)]
pub enum TokenCommands {
    /// List project tokens on the remote server
    List {
        /// Remote server URL (optional if saved via `kagi remote login`)
        #[arg(long)]
        remote: Option<String>,
    },

    /// Revoke a project token
    Revoke {
        /// Remote server URL (optional if saved via `kagi remote login`)
        #[arg(long)]
        remote: Option<String>,

        /// Token ID to revoke
        token_id: String,
    },
}

#[cfg(feature = "server")]
#[derive(Subcommand)]
pub enum ProjectCommands {
    /// Request to register this local project on a remote server
    Join {
        /// Remote server URL
        #[arg(long)]
        remote: String,
    },

    /// List projects on the remote server (admin only)
    List {
        /// Remote server URL (optional if saved via `kagi remote login`)
        #[arg(long)]
        remote: Option<String>,
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
    Del {
        /// Remote server URL (optional if saved via `kagi remote login`)
        #[arg(long)]
        remote: Option<String>,

        /// Project ID to delete
        project_id: String,
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
        assert!(names.contains(&"push"), "push should be present");
        assert!(names.contains(&"pull"), "pull should be present");
        assert!(names.contains(&"status"), "status should be present");
        assert!(names.contains(&"project"), "project should be present");
        assert!(names.contains(&"remote"), "remote should be present");
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
}

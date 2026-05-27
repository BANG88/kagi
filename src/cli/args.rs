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

        /// Service or environment name
        first: Option<String>,

        /// Environment name or secret key
        second: Option<String>,

        /// Secret key, when service and env are both provided positionally
        third: Option<String>,
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

    /// Export secrets as KEY=value lines (suitable for shell sourcing)
    Export {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Directory to write one .env file per environment when exporting a service
        #[arg(short, long)]
        out: Option<String>,

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

    /// Request access to this kagi project from a new device or member
    Join {
        /// Display name for the member requesting access
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Manage project members
    Member {
        #[command(subcommand)]
        command: MemberCommands,
    },
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
    },
}

#[derive(Subcommand)]
pub enum MemberCommands {
    /// List active members and pending join requests
    List,

    /// Approve a pending join request
    Approve {
        /// Member id from `kagi member list`
        member_id: String,
    },

    /// Remove a member's access wrapper
    Remove {
        /// Member id from `kagi member list`
        member_id: String,
    },
}

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
        /// Environments to create (comma-separated, e.g., dev,test)
        #[arg(short, long, value_delimiter = ',')]
        envs: Vec<String>,

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

        /// Environment name (e.g., dev, staging, prod). In nested mode, omit to use the inferred service without an environment.
        env: Option<String>,

        /// Name of the secret key
        key: Option<String>,

        /// Value to store (will be encrypted)
        value: Option<String>,
    },

    /// Retrieve and decrypt a secret value
    Get {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Allow printing the secret when stdout is not an interactive TTY
        #[arg(long)]
        allow_non_interactive: bool,

        /// Environment name. In nested mode, omit to use the inferred service without an environment.
        env: Option<String>,

        /// Name of the secret key
        key: Option<String>,
    },

    /// Run a command with injected environment variables
    Run {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// <env> <command>... or <command>... when the scope is inferred from nested directory.
        #[arg(required = false, trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Export secrets as KEY=value lines (suitable for shell sourcing)
    Export {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Allow non-interactive export. Required when stdout is not a TTY.
        #[arg(long)]
        allow_non_interactive: bool,

        /// Environment name. In nested mode, omit to use the inferred service without an environment.
        env: Option<String>,
    },

    /// Import secrets from a .env file
    Import {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Environment name. In nested mode, omit to use the inferred service without an environment.
        env: Option<String>,

        /// Path to the env file to import
        #[arg(short, long, default_value = ".env")]
        file: String,

        /// Overwrite existing keys without prompting
        #[arg(long)]
        force: bool,
    },

    /// List all services or secrets within a service
    List {
        /// Optional service scope (e.g., api, web). Defaults to the inferred nested directory.
        #[arg(short, long)]
        service: Option<String>,

        /// Show decrypted values. Requires an interactive TTY.
        #[arg(long)]
        show_values: bool,

        /// Optional environment name to list keys for
        #[arg(help = "Environment name to list keys for (omit to list all scopes)")]
        env: Option<String>,
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
        #[arg(long, value_delimiter = ',', default_value = "dev,test,staging,prod")]
        envs: Vec<String>,
    },
}

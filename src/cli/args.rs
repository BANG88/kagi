use clap::{Parser, Subcommand, ColorChoice};

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

        /// Overwrite existing .kagi/ directory
        #[arg(long)]
        force: bool,
    },

    /// Store an encrypted secret for a service
    Set {
        /// Name of the service (e.g., api, db, stripe). Omit to auto-detect from nested directory.
        service: Option<String>,

        /// Name of the secret key
        key: Option<String>,

        /// Value to store (will be encrypted)
        value: Option<String>,
    },

    /// Retrieve and decrypt a secret value
    Get {
        /// Name of the service. Omit to auto-detect from nested directory.
        service: Option<String>,

        /// Name of the secret key
        key: Option<String>,
    },

    /// Run a command with injected environment variables
    Run {
        /// [service] <command>... Omit service to auto-detect from nested directory.
        #[arg(required = false, trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Export secrets as KEY=value lines (suitable for shell sourcing)
    Export {
        /// Name of the service to export. Omit to auto-detect from nested directory.
        service: Option<String>,
    },

    /// Import secrets from a .env file
    Import {
        /// Name of the service to import into. Omit to auto-detect from nested directory.
        service: Option<String>,

        /// Path to the env file to import
        #[arg(short, long, default_value = ".env")]
        file: String,

        /// Overwrite existing keys without prompting
        #[arg(long)]
        force: bool,
    },

    /// List all services or secrets within a service
    List {
        /// Optional service name to list secrets for
        #[arg(help = "Service name to list secrets for (omit to list all services)")]
        service: Option<String>,
    },

    /// Synchronize keys from .env.example (and optional sources) across environments
    Sync {
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

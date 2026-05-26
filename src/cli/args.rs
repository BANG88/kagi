use clap::{Parser, Subcommand, ColorChoice};

#[derive(Parser)]
#[command(name = "kagi")]
#[command(about = "Manage encrypted environment variables")]
#[command(version)]
#[command(color = ColorChoice::Auto)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new kagi repository in the current directory
    Init,

    /// Store an encrypted secret for a service
    Set {
        /// Name of the service (e.g., api, db, stripe)
        service: String,

        /// Name of the secret key
        key: String,

        /// Value to store (will be encrypted)
        value: String,
    },

    /// Retrieve and decrypt a secret value
    Get {
        /// Name of the service
        service: String,

        /// Name of the secret key
        key: String,
    },

    /// Run a command with injected environment variables
    Run {
        /// Name of the service to load secrets from
        service: String,

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, help = "Command to run (e.g., bun dev, node server.js)")]
        command: Vec<String>,
    },

    /// Export secrets as KEY=value lines (suitable for shell sourcing)
    Export {
        /// Name of the service to export
        service: String,
    },

    /// Import secrets from a .env file
    Import {
        /// Name of the service to import into
        service: String,

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

    /// Copy secrets from one service to another
    Copy {
        /// Source service to copy from
        source: String,

        /// Target service to copy into
        target: String,

        /// Only copy keys that don't already exist in the target
        #[arg(long)]
        only_missing: bool,
    },

    /// Synchronize keys from .env.example across environments
    Sync {
        /// Path to the .env.example template file
        #[arg(short, long, default_value = ".env.example")]
        example: String,

        /// Environments to sync (comma-separated)
        #[arg(long, value_delimiter = ',', default_value = "dev,test,staging,prod")]
        envs: Vec<String>,
    },
}

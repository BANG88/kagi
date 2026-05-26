use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kagi")]
#[command(about = "Manage encrypted environment variables")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Init,
    Set {
        service: String,
        key: String,
        value: String,
    },
    Get {
        service: String,
        key: String,
    },
    Run {
        service: String,
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    Export {
        service: String,
    },
    List {
        service: Option<String>,
    },
}

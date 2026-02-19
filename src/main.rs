use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use color_eyre::eyre::{Context, OptionExt};

#[derive(Parser)]
#[command(name = "rahsia", version, about = "Runtime secret management")]
struct Cli {
    /// Path to the vault file
    #[arg(long, global = true, default_value_t = default_vault_path())]
    vault_path: Utf8PathBuf,

    #[command(subcommand)]
    command: Command,
}

fn default_vault_path() -> Utf8PathBuf {
    dirs::data_local_dir()
        .ok_or_eyre("Could not get local data directory")
        .unwrap()
        .join("rahsia")
        .try_into()
        .context("Local data directory is not a valid UTF-8 path")
        .unwrap()
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new encrypted vault
    Init,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => {
            unimplemented!();
        }
    }
}

use std::os::unix::process::CommandExt;

use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, Subcommand};
use color_eyre::{
    eyre::{bail, ensure, Context, OptionExt},
    owo_colors::OwoColorize,
    Result,
};
use dialoguer::Password;
use secrecy::ExposeSecret;
use zeroize::Zeroize;

use rahsia::command::{self, prompt_keys, prompt_tags, SharedCommand};
use rahsia::vault::Vault;

#[derive(Parser)]
#[command(name = "rahsia", version, about = "Runtime secret management", styles = rahsia::clap_styles())]
struct Cli {
    /// Path to the vault file [default: $XDG_DATA_HOME/rahsia/vault.db]
    #[arg(long, global = true)]
    vault_path: Option<Utf8PathBuf>,

    #[command(subcommand)]
    command: Command,
}

fn resolve_vault_path(explicit: Option<Utf8PathBuf>) -> Result<Utf8PathBuf> {
    match explicit {
        Some(p) => Ok(p),
        None => {
            let dir =
                dirs::data_local_dir().ok_or_eyre("Could not determine local data directory")?;
            dir.join("rahsia")
                .join("vault.db")
                .try_into()
                .context("Local data directory is not a valid UTF-8 path")
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new encrypted vault
    Init,

    /// Change the vault password
    UpdatePassword,

    /// Start an interactive REPL session
    Repl,

    /// Run the given command with the specified secrets
    Run {
        /// Load all secrets from this namespace.
        #[arg(long = "namespace", short = 'n')]
        namespace: Option<String>,

        /// These keys will be loaded.
        #[arg(long = "key", short = 'k', value_delimiter = ',')]
        keys: Vec<String>,

        /// Secrets with this tag will be loaded.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,

        /// The command to run.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    #[command(flatten)]
    Shared(SharedCommand),
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    let vault_path = resolve_vault_path(cli.vault_path)?;

    match cli.command {
        Command::Init => cmd_init(&vault_path),
        Command::UpdatePassword => {
            let mut vault = open_vault(&vault_path)?;
            cmd_update_password(&mut vault)
        }
        Command::Repl => {
            let mut vault = open_vault(&vault_path)?;
            rahsia::repl::run(&mut vault)
        }
        Command::Run {
            namespace,
            keys,
            tags,
            command: cmd,
        } => {
            let mut vault = open_vault(&vault_path)?;
            let tags = prompt_tags(tags)?;
            let keys = prompt_keys(keys)?;
            cmd_run(&mut vault, namespace, keys, tags, cmd)
        }
        Command::Shared(shared) => {
            let mut vault = open_vault(&vault_path)?;
            command::dispatch(&mut vault, shared)
        }
    }
}

/// Open an existing vault, prompting for the password.
fn open_vault(path: &Utf8Path) -> Result<Vault> {
    ensure!(
        path.exists(),
        "Vault not found at {}, run {} first",
        path.red(),
        "rahsia init".yellow()
    );
    let mut password = Password::new().with_prompt("Vault password").interact()?;
    let result = Vault::open(path, password.as_bytes());
    password.zeroize();
    Ok(result?)
}

// --- CLI-only commands ---

fn cmd_init(vault_path: &Utf8Path) -> Result<()> {
    let mut password = Password::new()
        .with_prompt("Vault password")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;

    ensure!(!password.is_empty(), "Password cannot be empty");

    let result = Vault::create(vault_path, password.as_bytes());
    password.zeroize();
    result?;
    eprintln!("Vault created at {vault_path}");
    Ok(())
}

fn cmd_update_password(vault: &mut Vault) -> Result<()> {
    let mut password = Password::new()
        .with_prompt("New vault password")
        .with_confirmation("Confirm new password", "Passwords do not match")
        .interact()?;

    ensure!(!password.is_empty(), "Password cannot be empty");

    vault.change_password(password.as_bytes())?;
    password.zeroize();
    eprintln!("Vault password updated");
    Ok(())
}

fn cmd_run(
    vault: &mut Vault,
    namespace: Option<String>,
    mut keys: Vec<String>,
    tags: Vec<String>,
    command: Vec<String>,
) -> Result<()> {
    ensure!(
        namespace.is_some() || !keys.is_empty() || !tags.is_empty(),
        "No namespace, keys, or tags specified. Use {}, {}, or {} to select secrets to inject.",
        "--namespace".yellow(),
        "--key".yellow(),
        "--tag".yellow()
    );

    let ns = namespace.as_deref().unwrap_or("");
    let entries = vault.list(ns, None);

    let mut secrets = vec![];

    if namespace.is_some() && keys.is_empty() && tags.is_empty() {
        // -n only: inject all secrets from namespace
        secrets = entries;
    } else {
        for entry in entries {
            if tags.iter().any(|t| entry.has_tag(t)) {
                if let Some(idx) = keys.iter().position(|k| k == &entry.key) {
                    keys.swap_remove(idx);
                }
                secrets.push(entry);
                continue;
            }

            if let Some(idx) = keys.iter().position(|k| k == &entry.key) {
                keys.swap_remove(idx);
                secrets.push(entry);
                continue;
            }
        }

        ensure!(
            keys.is_empty(),
            "One or more keys not found: {}",
            keys.join(",")
        );
    }

    ensure!(
        !secrets.is_empty(),
        "No secrets matched the specified filters"
    );

    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    for secret in secrets {
        cmd.env(&secret.key, secret.value.expose_secret());
    }

    let err = cmd.exec();
    bail!("Failed to exec command: {err}");
}

use std::os::unix::process::CommandExt;

use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, Subcommand};
use color_eyre::{
    eyre::{bail, ensure, Context, OptionExt},
    owo_colors::OwoColorize,
    Result,
};
use dialoguer::{Editor, Password};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

use rahsia::command::{self, prompt_keys, prompt_tags, SharedCommand};
use rahsia::vault::Vault;

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
        .join("vault.enc")
        .try_into()
        .context("Local data directory is not a valid UTF-8 path")
        .unwrap()
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new encrypted vault
    Init,

    /// Start an interactive REPL session
    Repl,

    /// Run the given command with the specified secrets
    Run {
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

    match cli.command {
        Command::Init => cmd_init(&cli.vault_path),
        Command::Repl => {
            let mut vault = open_vault(&cli.vault_path)?;
            rahsia::repl::run(&mut vault)
        }
        Command::Run {
            keys,
            tags,
            command: cmd,
        } => {
            let mut vault = open_vault(&cli.vault_path)?;
            let tags = prompt_tags(tags)?;
            let keys = prompt_keys(keys)?;
            cmd_run(&mut vault, keys, tags, cmd)
        }
        Command::Shared(shared) => {
            let mut vault = open_vault(&cli.vault_path)?;
            command::dispatch(&mut vault, shared)
        }
    }
}

// --- CLI-only prompts ---

fn prompt_secrets() -> Result<Vec<(String, SecretString)>> {
    let mut secret_string: String = Editor::new()
        .edit("Paste secrets in .env format")?
        .ok_or_eyre("No secrets to load")?;
    let secrets: Vec<(String, SecretString)> =
        dotenvy::from_read_iter(std::io::Cursor::new(&mut secret_string))
            .map(|s| s.map(|(k, v)| (k, v.into())))
            .collect::<Result<Vec<_>, dotenvy::Error>>()?;
    secret_string.zeroize();
    Ok(secrets)
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

fn cmd_run(
    vault: &mut Vault,
    mut keys: Vec<String>,
    tags: Vec<String>,
    command: Vec<String>,
) -> Result<()> {
    let entries = vault.list(None);

    let mut secrets = vec![];
    for entry in entries {
        if tags.iter().any(|t| entry.has_tag(t)) {
            secrets.push(entry);
            if let Some(idx) = keys.iter().position(|k| k == &entry.key) {
                keys.swap_remove(idx);
            }
            continue;
        }

        if let Some(idx) = keys.iter().position(|k| k == &entry.key) {
            secrets.push(entry);
            keys.swap_remove(idx);
            continue;
        }
    }

    ensure!(
        keys.is_empty(),
        "One or more keys not found: {}",
        keys.join(",")
    );

    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    for secret in secrets {
        cmd.env(&secret.key, secret.value.expose_secret());
    }

    let err = cmd.exec();
    bail!("Failed to exec command: {err}");
}

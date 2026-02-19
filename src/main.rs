use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, Subcommand};
use color_eyre::{
    eyre::{ensure, Context, OptionExt},
    owo_colors::OwoColorize,
    Result,
};
use dialoguer::{Input, Password};
use secrecy::ExposeSecret;

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

    /// Set a secret value (prompts for the value securely)
    Set {
        /// The secret key name (e.g. AWS_ACCESS_KEY_ID). Prompted if not provided.
        key: Option<String>,

        /// Tags to associate with this secret. Prompted if not provided.
        #[arg(long = "tag", short = 't')]
        tags: Vec<String>,
    },

    /// Get a secret value
    Get {
        /// The secret key name to retrieve. Prompted if not provided.
        key: Option<String>,
    },

    /// List secret keys in the vault
    List {
        /// Filter by tag
        #[arg(long = "tag", short = 't')]
        tag: Option<String>,
    },

    /// Remove a secret from the vault
    Remove {
        /// The secret key name to remove. Prompted if not provided.
        key: Option<String>,
    },
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    match cli.command {
        Command::Init => cmd_init(&cli.vault_path),

        Command::Set { key, tags } => {
            let mut vault = open_vault(&cli.vault_path)?;
            let key = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            let value = prompt_value(&key)?;
            cmd_set(&mut vault, key, value, tags)
        }

        Command::Get { key } => {
            let vault = open_vault(&cli.vault_path)?;
            let key = prompt_key(key)?;
            cmd_get(&vault, &key)
        }

        Command::List { tag } => {
            let vault = open_vault(&cli.vault_path)?;
            cmd_list(&vault, tag.as_deref())
        }

        Command::Remove { key } => {
            let mut vault = open_vault(&cli.vault_path)?;
            let key = prompt_key(key)?;
            cmd_remove(&mut vault, &key)
        }
    }
}

// --- Prompts ---

/// Resolve a key name: use the provided value, or prompt interactively.
fn prompt_key(key: Option<String>) -> Result<String> {
    match key {
        Some(k) => Ok(k),
        None => Ok(Input::new()
            .with_prompt("Secret key name")
            .interact_text()?),
    }
}

/// Resolve tags: use the provided values, or prompt interactively.
///
/// Accepts a comma-separated list. Empty input means no tags.
fn prompt_tags(tags: Vec<String>) -> Result<Vec<String>> {
    if !tags.is_empty() {
        return Ok(tags);
    }

    let input: String = Input::new()
        .with_prompt("Tags (comma-separated, empty to skip)")
        .allow_empty(true)
        .interact_text()?;

    Ok(input
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect())
}

/// Prompt for a secret value (no echo).
fn prompt_value(key: &str) -> Result<String> {
    let value: String = Password::new()
        .with_prompt(format!("Value for {}", key.green()))
        .interact()?;
    ensure!(!value.is_empty(), "Secret value cannot be empty");
    Ok(value)
}

/// Open an existing vault, prompting for the password.
fn open_vault(path: &Utf8Path) -> Result<Vault> {
    ensure!(
        path.exists(),
        "Vault not found at {}, run {} first",
        path.red(),
        "rahsia init".yellow()
    );
    let password = Password::new().with_prompt("Vault password").interact()?;
    Ok(Vault::open(path, password.as_bytes())?)
}

// --- Commands ---

fn cmd_init(vault_path: &Utf8Path) -> Result<()> {
    let password = Password::new()
        .with_prompt("Vault password")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;

    ensure!(!password.is_empty(), "Password cannot be empty");

    Vault::create(vault_path, password.as_bytes())?;
    eprintln!("Vault created at {vault_path}");
    Ok(())
}

fn cmd_set(vault: &mut Vault, key: String, value: String, tags: Vec<String>) -> Result<()> {
    vault.set(key.clone(), value, tags);
    vault.save()?;
    eprintln!("Secret '{}' saved", key.green());
    Ok(())
}

fn cmd_get(vault: &Vault, key: &str) -> Result<()> {
    let entry = vault.get(key)?;
    println!("{}", entry.value.expose_secret());
    Ok(())
}

fn cmd_list(vault: &Vault, tag: Option<&str>) -> Result<()> {
    let entries = vault.list(tag);

    if entries.is_empty() {
        eprintln!("No secrets found");
    } else {
        for entry in entries {
            if entry.tags.is_empty() {
                println!("{}", entry.key);
            } else {
                println!("{}  [{}]", entry.key, entry.tags.join(", "));
            }
        }
    }

    Ok(())
}

fn cmd_remove(vault: &mut Vault, key: &str) -> Result<()> {
    vault.remove(key)?;
    vault.save()?;
    eprintln!("Secret '{}' removed", key.green());
    Ok(())
}

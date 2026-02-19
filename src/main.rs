use std::os::unix::process::CommandExt;

use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, Subcommand};
use color_eyre::{
    eyre::{bail, ensure, Context, OptionExt},
    owo_colors::OwoColorize,
    Result,
};
use dialoguer::{Editor, Input, Password};
use secrecy::{ExposeSecret, SecretString};

use rahsia::vault::Vault;
use zeroize::Zeroize;

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

    /// Set a secret value
    Set {
        /// The secret key name (e.g. AWS_ACCESS_KEY_ID).
        key: Option<String>,

        /// Tags to associate with this secret.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Get a secret value
    Get {
        /// The secret key name to retrieve.
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
        /// The secret key name to remove.
        key: Option<String>,
    },

    /// Add a tag to an existing secret
    Tag {
        /// The secret key name.
        key: Option<String>,

        /// The tag(s) to add.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Remove a tag from a secret
    Untag {
        /// The secret key name.
        key: Option<String>,

        /// The tag(s) to remove.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Load secrets into the vault from KEY_1=VALUE_1\nKEY_2=VALUE_2 format.
    Load {
        /// The tag(s) to attach to all keys.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,
    },

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
        Command::Tag { key, tags } => {
            let mut vault = open_vault(&cli.vault_path)?;
            let key = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            cmd_tag(&mut vault, &key, tags)
        }
        Command::Untag { key, tags } => {
            let mut vault = open_vault(&cli.vault_path)?;
            let key = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            cmd_untag(&mut vault, &key, &tags)
        }
        Command::Load { tags } => {
            let mut vault = open_vault(&cli.vault_path)?;
            let tags = prompt_tags(tags)?;
            let secrets = prompt_secrets()?;
            cmd_load(&mut vault, secrets, tags)
        }
        Command::Run {
            keys,
            tags,
            command,
        } => {
            let mut vault = open_vault(&cli.vault_path)?;
            let tags = prompt_tags(tags)?;
            let keys = prompt_keys(keys)?;
            cmd_run(&mut vault, keys, tags, command)
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

fn prompt_keys(items: Vec<String>) -> Result<Vec<String>> {
    prompt_multi("Keys", items)
}

fn prompt_tags(items: Vec<String>) -> Result<Vec<String>> {
    prompt_multi("Tags", items)
}

/// Resolve items: use the provided values, or prompt interactively.
///
/// Accepts a comma-separated list. Empty input means no tags.
fn prompt_multi(name: &'static str, items: Vec<String>) -> Result<Vec<String>> {
    if !items.is_empty() {
        return Ok(items);
    }

    let input: String = Input::new()
        .with_prompt(format!("{name} (comma-separated, empty to skip)"))
        .allow_empty(true)
        .interact_text()?;

    Ok(input
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect())
}

/// Prompt for a secret value (no echo).
fn prompt_value(key: &str) -> Result<SecretString> {
    let value: String = Password::new()
        .with_prompt(format!("Value for {}", key.green()))
        .interact()?;
    ensure!(!value.is_empty(), "Secret value cannot be empty");
    Ok(value.into())
}

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

// --- Commands ---

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

fn cmd_set(vault: &mut Vault, key: String, value: SecretString, tags: Vec<String>) -> Result<()> {
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

fn cmd_tag(vault: &mut Vault, key: &str, tags: Vec<String>) -> Result<()> {
    vault.tag(key, tags)?;
    vault.save()?;
    eprintln!("Updated {}", key.green());
    Ok(())
}

fn cmd_untag(vault: &mut Vault, key: &str, tags: &[String]) -> Result<()> {
    vault.untag(key, tags)?;
    vault.save()?;
    eprintln!("Updated {}", key.green());
    Ok(())
}

fn cmd_load(
    vault: &mut Vault,
    secrets: Vec<(String, SecretString)>,
    tags: Vec<String>,
) -> Result<()> {
    let num_secrets = secrets.len();
    for (key, value) in secrets {
        vault.set(key.clone(), value, tags.clone());
    }
    vault.save()?;
    eprintln!("Saved {} secret(s)", num_secrets.green());
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

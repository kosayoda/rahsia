use clap::Subcommand;
use color_eyre::{
    eyre::{ensure, eyre, OptionExt},
    owo_colors::OwoColorize,
    Result,
};
use dialoguer::{Editor, Input, MultiSelect, Password};
use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

use crate::vault::Vault;

/// Commands shared between the CLI and the REPL.
#[derive(Subcommand)]
pub enum SharedCommand {
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
    #[command(alias = "ls")]
    List {
        /// Filter by tag
        #[arg(long = "tag", short = 't')]
        tag: Option<String>,
    },

    /// Remove secrets from the vault (supports regex patterns)
    #[command(alias = "rm")]
    Remove {
        /// Key name or regex pattern to match against key names.
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

    /// Load secrets into the vault from .env format (opens editor)
    Load {
        /// The tag(s) to attach to all loaded secrets.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,
    },
}

/// Dispatch a shared command against an open vault.
pub fn dispatch(vault: &mut Vault, cmd: SharedCommand) -> Result<()> {
    match cmd {
        SharedCommand::Set { key, tags } => {
            let key = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            let value = prompt_value(&key)?;
            cmd_set(vault, key, value, tags)
        }
        SharedCommand::Get { key } => {
            let key = prompt_key(key)?;
            cmd_get(vault, &key)
        }
        SharedCommand::List { tag } => cmd_list(vault, tag.as_deref()),
        SharedCommand::Remove { key } => {
            let pattern = prompt_key(key)?;
            cmd_remove(vault, &pattern)
        }
        SharedCommand::Tag { key, tags } => {
            let key = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            cmd_tag(vault, &key, tags)
        }
        SharedCommand::Untag { key, tags } => {
            let key = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            cmd_untag(vault, &key, &tags)
        }
        SharedCommand::Load { tags } => {
            let tags = prompt_tags(tags)?;
            let secrets = prompt_secrets()?;
            cmd_load(vault, secrets, tags)
        }
    }
}

// --- Prompts ---

/// Resolve a key name: use the provided value, or prompt interactively.
pub fn prompt_key(key: Option<String>) -> Result<String> {
    match key {
        Some(k) => Ok(k),
        None => Ok(Input::new()
            .with_prompt("Secret key name")
            .interact_text()?),
    }
}

pub fn prompt_keys(items: Vec<String>) -> Result<Vec<String>> {
    prompt_multi("Keys", items)
}

pub fn prompt_tags(items: Vec<String>) -> Result<Vec<String>> {
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

/// Open an editor and parse secrets in .env format.
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

/// Prompt for a secret value (no echo).
pub fn prompt_value(key: &str) -> Result<SecretString> {
    let value: String = Password::new()
        .with_prompt(format!("Value for {}", key.green()))
        .interact()?;
    ensure!(!value.is_empty(), "Secret value cannot be empty");
    Ok(value.into())
}

// --- Command implementations ---

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

fn cmd_remove(vault: &mut Vault, pattern: &str) -> Result<()> {
    let regex = full_match_regex(pattern)?;

    let mut matched_keys: Vec<String> = vault
        .list(None)
        .iter()
        .filter(|e| regex.is_match(&e.key))
        .map(|e| e.key.clone())
        .collect();
    matched_keys.sort();

    ensure!(!matched_keys.is_empty(), "No secrets match '{pattern}'");

    let to_remove = if matched_keys.len() == 1 {
        matched_keys
    } else {
        let defaults = vec![true; matched_keys.len()];
        let selections = MultiSelect::new()
            .with_prompt("Select secrets to remove")
            .items(&matched_keys)
            .defaults(&defaults)
            .interact()?;

        if selections.is_empty() {
            eprintln!("Nothing removed");
            return Ok(());
        }

        selections
            .iter()
            .map(|&i| matched_keys[i].clone())
            .collect()
    };

    let removed = vault.remove_many(&to_remove);
    vault.save()?;

    for entry in &removed {
        eprintln!("Removed '{}'", entry.key.green());
    }

    Ok(())
}

/// Compile a pattern into a regex anchored for full-match semantics.
fn full_match_regex(pattern: &str) -> Result<Regex> {
    let anchored = format!("^(?:{pattern})$");
    Regex::new(&anchored).map_err(|e| eyre!("Invalid pattern: {e}"))
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

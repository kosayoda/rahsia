use clap::Subcommand;
use color_eyre::{
    eyre::{bail, ensure, Context, OptionExt},
    owo_colors::OwoColorize,
    Result,
};
use dialoguer::{Confirm, Editor, Input, MultiSelect, Password};
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
        /// Filter by key name pattern (regex).
        pattern: Option<String>,

        /// Filter by tag.
        #[arg(long = "tag", short = 't')]
        tag: Option<String>,
    },

    /// Remove secrets from the vault (supports regex patterns)
    #[command(alias = "rm")]
    Remove {
        /// Key name or regex pattern to match against key names.
        key: Option<String>,
    },

    /// Add tags to secrets (supports regex patterns)
    Tag {
        /// Key name or regex pattern to match against key names.
        key: Option<String>,

        /// The tag(s) to add.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Remove tags from secrets (supports regex patterns)
    Untag {
        /// Key name or regex pattern to match against key names.
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

    /// Rename a secret key
    Rename {
        /// The current key name.
        old: Option<String>,

        /// The new key name.
        new: Option<String>,
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
        SharedCommand::List { pattern, tag } => cmd_list(vault, pattern.as_deref(), tag.as_deref()),
        SharedCommand::Remove { key } => {
            let pattern = prompt_key(key)?;
            cmd_remove(vault, &pattern)
        }
        SharedCommand::Tag { key, tags } => {
            let pattern = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            cmd_tag(vault, &pattern, tags)
        }
        SharedCommand::Untag { key, tags } => {
            let pattern = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            cmd_untag(vault, &pattern, &tags)
        }
        SharedCommand::Load { tags } => {
            let tags = prompt_tags(tags)?;
            let secrets = prompt_secrets()?;
            cmd_load(vault, secrets, tags)
        }
        SharedCommand::Rename { old, new } => {
            let old = prompt_key(old)?;
            let new = prompt_key(new)?;
            cmd_rename(vault, &old, new)
        }
    }
}

// --- Regex helpers ---

/// Compile a pattern into a regex anchored for full-match semantics.
fn full_match_regex(pattern: &str) -> Result<Regex> {
    let anchored = format!("^(?:{pattern})$");
    Regex::new(&anchored).context(format!("Invalid regex pattern: {pattern}"))
}

/// Find all key names matching a pattern, sorted alphabetically.
fn find_matching_keys(vault: &Vault, pattern: &str) -> Result<Vec<String>> {
    let regex = full_match_regex(pattern)?;
    let mut keys: Vec<String> = vault
        .list(None)
        .iter()
        .filter(|e| regex.is_match(&e.key))
        .map(|e| e.key.clone())
        .collect();
    keys.sort();
    Ok(keys)
}

/// Find matching keys and, if more than one match, let the user select with a multiselect.
/// Returns the selected keys. Errors if no keys match.
fn select_matching_keys(vault: &Vault, pattern: &str, prompt: &str) -> Result<Vec<String>> {
    let matched = find_matching_keys(vault, pattern)?;
    ensure!(!matched.is_empty(), "No secrets match '{pattern}'");

    if matched.len() == 1 {
        return Ok(matched);
    }

    let defaults = vec![true; matched.len()];
    let selections = MultiSelect::new()
        .with_prompt(prompt)
        .items(&matched)
        .defaults(&defaults)
        .interact()?;

    Ok(selections.iter().map(|&i| matched[i].clone()).collect())
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
    if vault.get(&key).is_ok() {
        let overwrite = Confirm::new()
            .with_prompt(format!("'{}' already exists. Overwrite?", key.yellow()))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Aborted");
            return Ok(());
        }
    }

    vault.set(key.clone(), value, tags)?;
    vault.save()?;
    eprintln!("Secret '{}' saved", key.green());
    Ok(())
}

fn cmd_get(vault: &Vault, key: &str) -> Result<()> {
    let entry = vault.get(key)?;
    println!("{}", entry.value.expose_secret());
    Ok(())
}

fn cmd_list(vault: &Vault, pattern: Option<&str>, tag: Option<&str>) -> Result<()> {
    let entries = vault.list(tag);

    let regex = pattern.map(full_match_regex).transpose()?;

    let filtered: Vec<_> = entries
        .into_iter()
        .filter(|e| match &regex {
            Some(r) => r.is_match(&e.key),
            None => true,
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("No secrets found");
    } else {
        for entry in filtered {
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
    let existing: Vec<String> = secrets
        .iter()
        .filter(|(k, _)| vault.get(k).is_ok())
        .map(|(k, _)| k.clone())
        .collect();

    if !existing.is_empty() {
        eprintln!(
            "The following keys already exist: {}",
            existing.join(", ").yellow()
        );
        let overwrite = Confirm::new()
            .with_prompt(format!("Overwrite {} existing secret(s)?", existing.len()))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Aborted");
            return Ok(());
        }
    }

    let num_secrets = secrets.len();
    let num_existing = existing.len();
    for (key, value) in secrets {
        vault.set(key.clone(), value, tags.clone())?;
    }
    vault.save()?;

    if num_existing > 0 {
        eprintln!(
            "Saved {} secret(s) ({} overwritten)",
            num_secrets.green(),
            num_existing.yellow()
        );
    } else {
        eprintln!("Saved {} secret(s)", num_secrets.green());
    }
    Ok(())
}

fn cmd_remove(vault: &mut Vault, pattern: &str) -> Result<()> {
    let selected = select_matching_keys(vault, pattern, "Select secrets to remove")?;

    if selected.is_empty() {
        eprintln!("Nothing removed");
        return Ok(());
    }

    let removed = vault.remove_many(&selected);
    vault.save()?;

    for entry in &removed {
        eprintln!("Removed '{}'", entry.key.green());
    }

    Ok(())
}

fn cmd_tag(vault: &mut Vault, pattern: &str, tags: Vec<String>) -> Result<()> {
    let selected = select_matching_keys(vault, pattern, "Select secrets to tag")?;

    if selected.is_empty() {
        eprintln!("Nothing updated");
        return Ok(());
    }

    for key in &selected {
        vault.tag(key, tags.clone())?;
    }
    vault.save()?;

    for key in &selected {
        eprintln!("Updated {}", key.green());
    }

    Ok(())
}

fn cmd_untag(vault: &mut Vault, pattern: &str, tags: &[String]) -> Result<()> {
    let selected = select_matching_keys(vault, pattern, "Select secrets to untag")?;

    if selected.is_empty() {
        eprintln!("Nothing updated");
        return Ok(());
    }

    for key in &selected {
        vault.untag(key, tags)?;
    }
    vault.save()?;

    for key in &selected {
        eprintln!("Updated {}", key.green());
    }

    Ok(())
}

fn cmd_rename(vault: &mut Vault, old: &str, new: String) -> Result<()> {
    if vault.get(old).is_err() {
        bail!("Secret '{}' not found", old.red());
    }

    if vault.get(&new).is_ok() {
        let overwrite = Confirm::new()
            .with_prompt(format!("'{}' already exists. Overwrite?", new.yellow()))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Aborted");
            return Ok(());
        }
    }

    vault.rename(old, new.clone())?;
    vault.save()?;
    eprintln!("Renamed '{}' to '{}'", old.green(), new.green());
    Ok(())
}

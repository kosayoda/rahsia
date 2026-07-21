use clap::Subcommand;
use color_eyre::{
    eyre::{bail, ensure, Context, OptionExt},
    owo_colors::OwoColorize,
    Result,
};
use dialoguer::{Confirm, Editor, Input, MultiSelect, Password, Select};
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

        /// Namespace for this secret.
        #[arg(long = "namespace", short = 'n')]
        namespace: Option<String>,

        /// Tags to associate with this secret.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Get a secret value
    Get {
        /// The secret key name to retrieve.
        key: Option<String>,

        /// Namespace for this secret.
        #[arg(long = "namespace", short = 'n')]
        namespace: Option<String>,

        /// Copy value to clipboard instead of printing.
        #[arg(long = "copy", short = 'c')]
        copy: bool,
    },

    /// List secret keys in the vault
    #[command(alias = "ls")]
    List {
        /// Filter by key name pattern (regex).
        pattern: Option<String>,

        /// Only show secrets in this namespace.
        #[arg(long = "namespace", short = 'n')]
        namespace: Option<String>,

        /// Filter by tag.
        #[arg(long = "tag", short = 't')]
        tag: Option<String>,
    },

    /// Remove secrets from the vault (supports regex patterns)
    #[command(alias = "rm")]
    Remove {
        /// Key name or regex pattern to match against key names.
        key: Option<String>,

        /// Namespace for this secret.
        #[arg(long = "namespace", short = 'n')]
        namespace: Option<String>,
    },

    /// Add tags to secrets (supports regex patterns)
    Tag {
        /// Key name or regex pattern to match against key names.
        key: Option<String>,

        /// Namespace for this secret.
        #[arg(long = "namespace", short = 'n')]
        namespace: Option<String>,

        /// The tag(s) to add.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Remove tags from secrets (supports regex patterns)
    Untag {
        /// Key name or regex pattern to match against key names.
        key: Option<String>,

        /// Namespace for this secret.
        #[arg(long = "namespace", short = 'n')]
        namespace: Option<String>,

        /// The tag(s) to remove.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Load secrets into the vault from .env format (opens editor)
    Load {
        /// Namespace for loaded secrets.
        #[arg(long = "namespace", short = 'n')]
        namespace: Option<String>,

        /// The tag(s) to attach to all loaded secrets.
        #[arg(long = "tag", short = 't', value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Export secrets in .env format
    Export {
        /// Only export secrets from this namespace.
        #[arg(long = "namespace", short = 'n')]
        namespace: Option<String>,

        /// Filter by tag.
        #[arg(long = "tag", short = 't')]
        tag: Option<String>,
    },

    /// Rename a secret key
    Rename {
        /// The current key name.
        old: Option<String>,

        /// The new key name.
        new: Option<String>,

        /// Namespace for this secret.
        #[arg(long = "namespace", short = 'n')]
        namespace: Option<String>,
    },

    /// Move a secret to a different namespace
    #[command(alias = "mv")]
    Move {
        /// The secret key name to move.
        key: Option<String>,

        /// Source namespace.
        #[arg(long = "from", short = 'f')]
        from: Option<String>,

        /// Destination namespace.
        #[arg(long = "to", short = 't')]
        to: Option<String>,
    },

    /// Rename a namespace
    RenameNamespace {
        /// The current namespace name.
        old: Option<String>,

        /// The new namespace name.
        new: Option<String>,
    },
}

/// Dispatch a shared command against an open vault.
pub fn dispatch(vault: &mut Vault, cmd: SharedCommand) -> Result<()> {
    match cmd {
        SharedCommand::Set {
            key,
            namespace,
            tags,
        } => {
            let ns = prompt_namespace(vault, namespace)?;
            let key = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            let value = prompt_value(&key)?;
            cmd_set(vault, &ns, key, value, tags)
        }
        SharedCommand::Get {
            key,
            namespace,
            copy,
        } => {
            let ns = prompt_namespace(vault, namespace)?;
            let key = prompt_key(key)?;
            let copy = if copy { Some(true) } else { None };
            cmd_get(vault, &ns, &key, copy)
        }
        SharedCommand::List {
            pattern,
            namespace,
            tag,
        } => cmd_list(
            vault,
            namespace.as_deref(),
            pattern.as_deref(),
            tag.as_deref(),
        ),
        SharedCommand::Export { namespace, tag } => {
            cmd_export(vault, namespace.as_deref(), tag.as_deref())
        }
        SharedCommand::Remove { key, namespace } => {
            let ns = prompt_namespace(vault, namespace)?;
            let pattern = prompt_key(key)?;
            cmd_remove(vault, &ns, &pattern)
        }
        SharedCommand::Tag {
            key,
            namespace,
            tags,
        } => {
            let ns = prompt_namespace(vault, namespace)?;
            let pattern = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            cmd_tag(vault, &ns, &pattern, tags)
        }
        SharedCommand::Untag {
            key,
            namespace,
            tags,
        } => {
            let ns = prompt_namespace(vault, namespace)?;
            let pattern = prompt_key(key)?;
            let tags = prompt_tags(tags)?;
            cmd_untag(vault, &ns, &pattern, &tags)
        }
        SharedCommand::Load { namespace, tags } => {
            let ns = prompt_namespace(vault, namespace)?;
            let tags = prompt_tags(tags)?;
            let secrets = prompt_secrets()?;
            cmd_load(vault, &ns, secrets, tags)
        }
        SharedCommand::Rename {
            old,
            new,
            namespace,
        } => {
            let ns = prompt_namespace(vault, namespace)?;
            let old = prompt_key(old)?;
            let new = prompt_key(new)?;
            cmd_rename(vault, &ns, &old, new)
        }
        SharedCommand::Move { key, from, to } => {
            let from_ns = prompt_namespace(vault, from)?;
            let key = prompt_key(key)?;
            let to_ns = prompt_namespace(vault, to)?;
            cmd_move(vault, &from_ns, &key, &to_ns)
        }
        SharedCommand::RenameNamespace { old, new } => {
            let old = prompt_namespace(vault, old)?;
            ensure!(!old.is_empty(), "Cannot rename the default namespace");
            let new: String = match new {
                Some(n) => n,
                None => Input::new()
                    .with_prompt("New namespace name")
                    .interact_text()?,
            };
            ensure!(!new.is_empty(), "Namespace name cannot be empty");
            cmd_rename_namespace(vault, &old, &new)
        }
    }
}

/// Resolve the namespace: use the provided value, or prompt interactively.
///
/// Shows existing namespaces plus "(none)" for the default namespace
/// and "New namespace..." to create one.
fn prompt_namespace(vault: &Vault, ns: Option<String>) -> Result<String> {
    if let Some(n) = ns {
        return Ok(n);
    }

    let existing = vault.namespaces();
    if existing.is_empty() {
        let input: String = Input::new()
            .with_prompt("Namespace (empty for none)")
            .allow_empty(true)
            .interact_text()?;
        return Ok(input);
    }

    let mut items: Vec<String> = vec!["(none)".to_string()];
    items.extend(existing);
    items.push("+ New namespace".to_string());

    let selection = Select::new()
        .with_prompt("Namespace")
        .items(&items)
        .default(0)
        .interact()?;

    if selection == 0 {
        Ok(String::new())
    } else if selection == items.len() - 1 {
        let input: String = Input::new()
            .with_prompt("New namespace name")
            .interact_text()?;
        Ok(input)
    } else {
        Ok(items[selection].clone())
    }
}

// --- Regex helpers ---

/// Compile a pattern into a regex anchored for full-match semantics.
fn full_match_regex(pattern: &str) -> Result<Regex> {
    let anchored = format!("^(?:{pattern})$");
    Regex::new(&anchored).context(format!("Invalid regex pattern: {pattern}"))
}

/// Find all key names matching a pattern within a namespace.
fn find_matching_keys(vault: &Vault, ns: &str, pattern: &str) -> Result<Vec<String>> {
    let regex = full_match_regex(pattern)?;
    let mut keys: Vec<String> = vault
        .list(ns, None)
        .iter()
        .filter(|e| regex.is_match(&e.key))
        .map(|e| e.key.clone())
        .collect();
    keys.sort();
    Ok(keys)
}

/// Find matching keys and, if more than one match, let the user select with a multiselect.
fn select_matching_keys(
    vault: &Vault,
    ns: &str,
    pattern: &str,
    prompt: &str,
) -> Result<Vec<String>> {
    let matched = find_matching_keys(vault, ns, pattern)?;
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

fn cmd_set(
    vault: &mut Vault,
    ns: &str,
    key: String,
    value: SecretString,
    tags: Vec<String>,
) -> Result<()> {
    if vault.get(ns, &key).is_ok() {
        let overwrite = Confirm::new()
            .with_prompt(format!("'{}' already exists. Overwrite?", key.yellow()))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Aborted");
            return Ok(());
        }
    }

    vault.set(ns, key.clone(), value, tags)?;
    vault.save()?;
    eprintln!("Secret '{}' saved", key.green());
    Ok(())
}

fn cmd_get(vault: &Vault, ns: &str, key: &str, copy: Option<bool>) -> Result<()> {
    let entry = vault.get(ns, key)?;

    let copy = match copy {
        Some(v) => v,
        None => {
            let selection = Select::new()
                .with_prompt("Output")
                .items(["Print to stdout", "Copy to clipboard"])
                .default(0)
                .interact()?;
            selection == 1
        }
    };

    if copy {
        let mut clipboard = arboard::Clipboard::new()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to access clipboard: {e}"))?;
        clipboard
            .set_text(entry.value.expose_secret())
            .map_err(|e| color_eyre::eyre::eyre!("Failed to copy to clipboard: {e}"))?;
        eprintln!("Copied '{}' to clipboard", key.green());
    } else {
        println!("{}", entry.value.expose_secret());
    }
    Ok(())
}

fn cmd_list(
    vault: &Vault,
    namespace: Option<&str>,
    pattern: Option<&str>,
    tag: Option<&str>,
) -> Result<()> {
    let regex = pattern.map(full_match_regex).transpose()?;

    match namespace {
        Some(ns) => {
            let entries = vault.list(ns, tag);
            let filtered = apply_regex_filter(entries, &regex);
            if filtered.is_empty() {
                eprintln!("No secrets found");
            } else {
                for entry in filtered {
                    print_entry(&entry);
                }
            }
        }
        None => {
            let entries = vault.list_all(tag);
            let filtered = apply_regex_filter(entries, &regex);
            if filtered.is_empty() {
                eprintln!("No secrets found");
            } else {
                print_grouped(&filtered);
            }
        }
    }

    Ok(())
}

fn apply_regex_filter(
    entries: Vec<crate::secret::SecretEntry>,
    regex: &Option<Regex>,
) -> Vec<crate::secret::SecretEntry> {
    entries
        .into_iter()
        .filter(|e| match regex {
            Some(r) => r.is_match(&e.key),
            None => true,
        })
        .collect()
}

fn print_entry(entry: &crate::secret::SecretEntry) {
    if entry.tags.is_empty() {
        println!("{}", entry.key.green());
    } else {
        println!(
            "{}  {}",
            entry.key.green(),
            format!("[{}]", entry.tags.join(", ")).dimmed()
        );
    }
}

fn print_grouped(entries: &[crate::secret::SecretEntry]) {
    let mut current_ns: Option<&str> = None;
    let mut first = true;

    for entry in entries {
        let ns = entry.namespace.as_str();

        if current_ns != Some(ns) {
            if !first {
                println!();
            }
            if !ns.is_empty() {
                println!("{}", ns.cyan().bold());
            }
            current_ns = Some(ns);
            first = false;
        }

        let indent = if ns.is_empty() { "" } else { "  " };
        if entry.tags.is_empty() {
            println!("{indent}{}", entry.key.green());
        } else {
            println!(
                "{indent}{}  {}",
                entry.key.green(),
                format!("[{}]", entry.tags.join(", ")).dimmed()
            );
        }
    }
}

fn cmd_export(vault: &Vault, namespace: Option<&str>, tag: Option<&str>) -> Result<()> {
    let entries = match namespace {
        Some(ns) => vault.list(ns, tag),
        None => vault.list_all(tag),
    };

    ensure!(!entries.is_empty(), "No secrets to export");

    for entry in entries {
        let value = entry.value.expose_secret();
        let needs_quoting = value.contains(|c: char| c.is_whitespace() || c == '#' || c == '"');
        if needs_quoting {
            println!(
                "{}=\"{}\"",
                entry.key,
                value.replace('\\', "\\\\").replace('"', "\\\"")
            );
        } else {
            println!("{}={}", entry.key, value);
        }
    }

    Ok(())
}

fn cmd_load(
    vault: &mut Vault,
    ns: &str,
    secrets: Vec<(String, SecretString)>,
    tags: Vec<String>,
) -> Result<()> {
    let existing: Vec<String> = secrets
        .iter()
        .filter(|(k, _)| vault.get(ns, k).is_ok())
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
        vault.set(ns, key.clone(), value, tags.clone())?;
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

fn cmd_remove(vault: &mut Vault, ns: &str, pattern: &str) -> Result<()> {
    let selected = select_matching_keys(vault, ns, pattern, "Select secrets to remove")?;

    if selected.is_empty() {
        eprintln!("Nothing removed");
        return Ok(());
    }

    let removed = vault.remove_many(ns, &selected);
    vault.save()?;

    for entry in &removed {
        eprintln!("Removed '{}'", entry.key.green());
    }

    Ok(())
}

fn cmd_tag(vault: &mut Vault, ns: &str, pattern: &str, tags: Vec<String>) -> Result<()> {
    let selected = select_matching_keys(vault, ns, pattern, "Select secrets to tag")?;

    if selected.is_empty() {
        eprintln!("Nothing updated");
        return Ok(());
    }

    for key in &selected {
        vault.tag(ns, key, tags.clone())?;
    }
    vault.save()?;

    for key in &selected {
        eprintln!("Updated {}", key.green());
    }

    Ok(())
}

fn cmd_untag(vault: &mut Vault, ns: &str, pattern: &str, tags: &[String]) -> Result<()> {
    let selected = select_matching_keys(vault, ns, pattern, "Select secrets to untag")?;

    if selected.is_empty() {
        eprintln!("Nothing updated");
        return Ok(());
    }

    for key in &selected {
        vault.untag(ns, key, tags)?;
    }
    vault.save()?;

    for key in &selected {
        eprintln!("Updated {}", key.green());
    }

    Ok(())
}

fn cmd_rename(vault: &mut Vault, ns: &str, old: &str, new: String) -> Result<()> {
    if vault.get(ns, old).is_err() {
        bail!("Secret '{}' not found", old.red());
    }

    if vault.get(ns, &new).is_ok() {
        let overwrite = Confirm::new()
            .with_prompt(format!("'{}' already exists. Overwrite?", new.yellow()))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Aborted");
            return Ok(());
        }
    }

    vault.rename(ns, old, new.clone())?;
    vault.save()?;
    eprintln!("Renamed '{}' to '{}'", old.green(), new.green());
    Ok(())
}

fn cmd_move(vault: &mut Vault, from_ns: &str, key: &str, to_ns: &str) -> Result<()> {
    if vault.get(from_ns, key).is_err() {
        bail!("Secret '{}' not found", key.red());
    }

    if vault.get(to_ns, key).is_ok() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "'{}' already exists in namespace '{}'. Overwrite?",
                key.yellow(),
                to_ns.yellow()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Aborted");
            return Ok(());
        }
    }

    vault.move_secret(from_ns, key, to_ns)?;
    vault.save()?;

    let from_label = if from_ns.is_empty() {
        "(none)"
    } else {
        from_ns
    };
    let to_label = if to_ns.is_empty() { "(none)" } else { to_ns };
    eprintln!(
        "Moved '{}' from {} to {}",
        key.green(),
        from_label.cyan(),
        to_label.cyan()
    );
    Ok(())
}

fn cmd_rename_namespace(vault: &mut Vault, old: &str, new: &str) -> Result<()> {
    let count = vault.rename_namespace(old, new)?;
    ensure!(count > 0, "Namespace '{}' not found", old.red());
    vault.save()?;
    eprintln!(
        "Renamed namespace {} to {} ({} secret(s))",
        old.cyan(),
        new.cyan(),
        count.to_string().green()
    );
    Ok(())
}

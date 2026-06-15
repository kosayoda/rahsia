use clap::{CommandFactory, Parser, Subcommand};
use color_eyre::{eyre::ensure, owo_colors::OwoColorize, Result};
use dialoguer::Password;
use rustyline::completion::Completer;
use rustyline::error::ReadlineError;
use rustyline::{Context, Editor};
use zeroize::Zeroize;

use crate::command::{self, SharedCommand};
use crate::vault::Vault;

/// REPL-only wrapper parsed with `try_parse_from`.
#[derive(Parser)]
#[command(
    name = "",
    no_binary_name = true,
    disable_help_subcommand = true,
    disable_version_flag = true,
    styles = crate::clap_styles()
)]
struct ReplCli {
    #[command(subcommand)]
    command: ReplCommand,
}

/// Commands available inside the REPL.
#[derive(Subcommand)]
enum ReplCommand {
    /// Show available commands
    #[command(alias = "?")]
    Help,

    /// List all unique tags in the vault
    Tags,

    /// List all namespaces in the vault
    Namespaces,

    /// Change the vault password
    UpdatePassword,

    /// Exit the REPL
    #[command(alias = "quit")]
    Exit,

    #[command(flatten)]
    Shared(SharedCommand),
}

// --- Tab completion ---

const COMMANDS: &[&str] = &[
    "exit",
    "get",
    "help",
    "list",
    "load",
    "ls",
    "move",
    "mv",
    "namespaces",
    "quit",
    "remove",
    "rename",
    "rm",
    "set",
    "tag",
    "tags",
    "untag",
    "update-password",
];

#[derive(rustyline::Helper, rustyline::Hinter, rustyline::Highlighter, rustyline::Validator)]
struct ReplHelper {
    keys: Vec<String>,
}

impl Completer for ReplHelper {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<String>)> {
        let line_up_to_cursor = &line[..pos];

        // Find the start of the current word.
        let word_start = line_up_to_cursor.rfind(' ').map_or(0, |i| i + 1);
        let word = &line_up_to_cursor[word_start..];

        // Determine if we're completing the first word (command) or a later word (key name).
        let is_command = !line_up_to_cursor[..word_start].contains(' ');
        let candidates = if is_command { COMMANDS } else { &[] };

        // For key completion, only complete after commands that take a key argument.
        let key_candidates = if !is_command {
            let first_word = line_up_to_cursor.split_whitespace().next().unwrap_or("");
            match first_word {
                "get" | "remove" | "rm" | "rename" | "set" | "tag" | "untag" => &self.keys,
                _ => &vec![],
            }
        } else {
            &vec![]
        };

        let mut matches: Vec<String> = candidates
            .iter()
            .filter(|c| c.starts_with(word))
            .map(|c| c.to_string())
            .collect();

        matches.extend(
            key_candidates
                .iter()
                .filter(|k| k.starts_with(word))
                .cloned(),
        );

        Ok((word_start, matches))
    }
}

/// Run an interactive REPL session with an already-open vault.
pub fn run(vault: &mut Vault) -> Result<()> {
    let mut rl = Editor::new()?;
    rl.set_helper(Some(ReplHelper { keys: Vec::new() }));

    eprintln!(
        "Entering REPL. Type {} for commands, {} to exit.",
        "help".green(),
        "exit".yellow()
    );

    loop {
        // Update key list for tab completion (all keys across all namespaces).
        if let Some(helper) = rl.helper_mut() {
            let mut keys: Vec<String> =
                vault.list_all(None).iter().map(|e| e.key.clone()).collect();
            keys.sort();
            keys.dedup();
            helper.keys = keys;
        }

        match rl.readline(&format!("{} ", "rahsia >".yellow())) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let _ = rl.add_history_entry(line);

                let args = match shell_words::split(line) {
                    Ok(args) => args,
                    Err(e) => {
                        eprintln!("{}: {e}", "Parse error".red());
                        continue;
                    }
                };

                match ReplCli::try_parse_from(&args) {
                    Ok(cli) => match cli.command {
                        ReplCommand::Help => {
                            ReplCli::command().print_help().ok();
                            eprintln!();
                        }
                        ReplCommand::Tags => {
                            let tags = vault.tags("");
                            if tags.is_empty() {
                                eprintln!("No tags found");
                            } else {
                                for tag in tags {
                                    println!("{tag}");
                                }
                            }
                        }
                        ReplCommand::Namespaces => {
                            let namespaces = vault.namespaces();
                            if namespaces.is_empty() {
                                eprintln!("No namespaces found");
                            } else {
                                for ns in namespaces {
                                    println!("{ns}");
                                }
                            }
                        }
                        ReplCommand::UpdatePassword => match cmd_update_password(vault) {
                            Ok(()) => {}
                            Err(e) => eprintln!("{}: {e}", "Error".red()),
                        },
                        ReplCommand::Exit => break,
                        ReplCommand::Shared(shared) => {
                            if let Err(e) = command::dispatch(vault, shared) {
                                eprintln!("{}: {e}", "Error".red());
                            }
                        }
                    },
                    Err(e) => {
                        eprint!("{e}");
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                continue;
            }
            Err(ReadlineError::Eof) => {
                break;
            }
            Err(e) => {
                eprintln!("{}: {e}", "Readline error".red());
                break;
            }
        }
    }

    eprintln!("Bye!");
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

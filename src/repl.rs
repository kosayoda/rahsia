use clap::{CommandFactory, Parser, Subcommand};
use color_eyre::{owo_colors::OwoColorize, Result};
use rustyline::completion::Completer;
use rustyline::error::ReadlineError;
use rustyline::{Context, Editor};

use crate::command::{self, SharedCommand};
use crate::vault::Vault;

/// REPL-only wrapper parsed with `try_parse_from`.
#[derive(Parser)]
#[command(
    name = "",
    no_binary_name = true,
    disable_help_subcommand = true,
    disable_version_flag = true
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

    /// Exit the REPL
    #[command(alias = "quit")]
    Exit,

    #[command(flatten)]
    Shared(SharedCommand),
}

// --- Tab completion ---

const COMMANDS: &[&str] = &[
    "exit", "get", "help", "list", "load", "ls", "quit", "remove", "rename", "rm", "set", "tag",
    "tags", "untag",
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
        // Update key list for tab completion.
        if let Some(helper) = rl.helper_mut() {
            let mut keys: Vec<String> = vault.list(None).iter().map(|e| e.key.clone()).collect();
            keys.sort();
            helper.keys = keys;
        }

        match rl.readline("rahsia> ") {
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
                            let tags = vault.tags();
                            if tags.is_empty() {
                                eprintln!("No tags found");
                            } else {
                                for tag in tags {
                                    println!("{tag}");
                                }
                            }
                        }
                        ReplCommand::Exit => break,
                        ReplCommand::Shared(shared) => {
                            if let Err(e) = command::dispatch(vault, shared) {
                                eprintln!("{}: {e}", "Error".red());
                            }
                        }
                    },
                    Err(e) => {
                        // Clap errors include --help output, version, etc.
                        // Print them without the "Error:" prefix for help.
                        eprint!("{e}");
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C: continue the loop
                continue;
            }
            Err(ReadlineError::Eof) => {
                // Ctrl-D: exit
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

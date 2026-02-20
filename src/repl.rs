use clap::{CommandFactory, Parser, Subcommand};
use color_eyre::{owo_colors::OwoColorize, Result};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::command::{self, SharedCommand};
use crate::vault::Vault;

/// Runtime secret management
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

/// Run an interactive REPL session with an already-open vault.
pub fn run(vault: &mut Vault) -> Result<()> {
    let mut rl = DefaultEditor::new()?;

    eprintln!(
        "Entering REPL. Type {} for commands, {} to exit.",
        "help".green(),
        "exit".yellow()
    );

    loop {
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

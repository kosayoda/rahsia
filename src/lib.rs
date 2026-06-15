pub mod command;
pub mod error;
pub mod repl;
pub mod secret;
pub mod vault;

pub fn clap_styles() -> clap::builder::Styles {
    use clap::builder::styling;
    clap::builder::Styles::styled()
        .header(styling::AnsiColor::Yellow.on_default().bold())
        .usage(styling::AnsiColor::Cyan.on_default().bold())
        .literal(styling::AnsiColor::White.on_default())
        .placeholder(styling::AnsiColor::Green.on_default())
        .invalid(styling::AnsiColor::Red.on_default())
        .error(styling::AnsiColor::Red.on_default())
}

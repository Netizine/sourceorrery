//! `sourceorrery completions <shell>`

use clap::CommandFactory;

use crate::cli::{Cli, CompletionsArgs};

#[allow(clippy::unnecessary_wraps)] // uniform command signature
pub fn run(args: &CompletionsArgs) -> anyhow::Result<()> {
    let mut command = Cli::command();
    let name = command.get_name().to_owned();
    clap_complete::generate(args.shell, &mut command, name, &mut std::io::stdout());
    Ok(())
}

//! `sourceorrery` — secrets belong to the runtime, not the repository.

#![forbid(unsafe_code)]

mod banner;
mod cli;
mod commands;
mod context;
mod dotenv;
mod integrations;
mod output;
mod prompt;
mod qr;
mod strength;
#[cfg(feature = "ui")]
mod ui;

use std::process::ExitCode;

use clap::Parser;
use sourceorrery_core::SecretError;

use crate::cli::{Cli, Command};
use crate::context::Ctx;

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let Some(command) = &cli.command else {
        return match banner::print() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => report(&err.into(), cli.output),
        };
    };

    let ctx = match Ctx::from_cli(&cli) {
        Ok(ctx) => ctx,
        Err(err) => return report(&err, cli.output),
    };

    let result = match command {
        Command::Vault(cmd) => commands::vault::run(&ctx, cmd),
        Command::Secret(cmd) => commands::secret::run(&ctx, cmd),
        Command::Audit(args) => commands::audit::run(&ctx, args),
        Command::Init(args) => commands::project::init(&ctx, args),
        Command::Import(args) => commands::import::run(&ctx, args),
        Command::Check(args) => commands::project::check(&ctx, args),
        Command::Run(args) => return commands::project::run(&ctx, args),
        Command::Backup(args) => commands::backup::backup(&ctx, args),
        Command::Restore(args) => commands::backup::restore(&ctx, args),
        #[cfg(feature = "ui")]
        Command::Ui(args) => ui::run(&ctx, args),
        Command::Completions(args) => commands::completions::run(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => report(&err, cli.output),
    }
}

fn report(err: &anyhow::Error, format: cli::OutputFormat) -> ExitCode {
    let code = err
        .downcast_ref::<SecretError>()
        .map_or("cli", SecretError::code);
    output::print_error(format, code, &format!("{err:#}"));
    ExitCode::from(1)
}

fn init_tracing(verbosity: u8) {
    use tracing_subscriber::EnvFilter;
    let default = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_env("SOURCEORRERY_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

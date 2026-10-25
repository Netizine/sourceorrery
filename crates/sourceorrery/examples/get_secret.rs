//! Read one secret and report its size, never its value.
//!
//! ```bash
//! export SOURCEORRERY_RECOVERY_KEY=...   # or rely on this machine's key
//! cargo run -p sourceorrery --example get_secret -- development database-password
//! ```

use std::process::ExitCode;

use sourceorrery::SecretReader;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let vault = args.next().unwrap_or_else(|| "development".to_owned());
    let name = args
        .next()
        .unwrap_or_else(|| "database-password".to_owned());

    let outcome = SecretReader::open(&vault).and_then(|reader| reader.get(&name));
    match outcome {
        Ok(secret) => {
            // `secret.value` is zeroised when it goes out of scope.
            println!(
                "{name} version {} from vault {vault}: {} bytes",
                secret.properties.version,
                secret.value.len()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            // The error carries the stable code and a hint; neither holds a value.
            eprintln!("error [{}]: {err}", err.code());
            ExitCode::FAILURE
        }
    }
}

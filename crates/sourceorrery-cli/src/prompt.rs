//! Interactive input that never echoes secrets and never touches stdout.

use std::io::{IsTerminal, Read, Write};

use anyhow::{Context as _, anyhow};
use sourceorrery_core::SecretBytes;

use crate::cli::SecretSetArgs;

/// Prompt on stderr and read a line without echo.
pub fn read_hidden(prompt: &str) -> anyhow::Result<SecretBytes> {
    let mut stderr = std::io::stderr();
    stderr.write_all(prompt.as_bytes())?;
    stderr.flush()?;
    let text = rpassword::read_password().context("failed to read hidden input")?;
    Ok(SecretBytes::from_string(text))
}

/// Ask a yes/no question on stderr. Non-interactive sessions answer "no".
pub fn confirm(question: &str) -> anyhow::Result<bool> {
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    let mut stderr = std::io::stderr();
    write!(stderr, "{question} [y/N] ")?;
    stderr.flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

/// Obtain the value for `secret set` from a file, stdin or a hidden prompt.
pub fn read_secret_value(args: &SecretSetArgs) -> anyhow::Result<SecretBytes> {
    let value = if let Some(path) = &args.from_file {
        let bytes =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        SecretBytes::new(bytes)
    } else if args.stdin || !std::io::stdin().is_terminal() {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .context("failed to read secret value from stdin")?;
        if !args.keep_trailing_newline {
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        SecretBytes::new(bytes)
    } else {
        let first = read_hidden("Enter secret value: ")?;
        if args.confirm {
            let second = read_hidden("Confirm secret value: ")?;
            if first != second {
                return Err(anyhow!("values do not match"));
            }
        }
        first
    };

    if value.is_empty() && !args.allow_empty {
        return Err(anyhow!(
            "refusing to store an empty value (pass --allow-empty to override)"
        ));
    }
    Ok(value)
}

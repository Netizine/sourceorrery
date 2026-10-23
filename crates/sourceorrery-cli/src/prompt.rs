//! Interactive input that never echoes secrets and never touches stdout.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;

use anyhow::{Context as _, anyhow};
use sourceorrery_core::SecretBytes;

use crate::cli::SecretSetArgs;
use crate::output;

/// Prompt on stderr and read a line without echo. The prompt may name the
/// vault as its file reports it, before anything in the file is verified,
/// so it is sanitised like every other line of output.
pub fn read_hidden(prompt: &str) -> anyhow::Result<SecretBytes> {
    let mut stderr = std::io::stderr();
    stderr.write_all(output::sanitize(prompt).as_bytes())?;
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
    write!(stderr, "{} [y/N] ", output::sanitize(question))?;
    stderr.flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

/// Where a new value comes from: a file, stdin, or a hidden prompt.
#[derive(Debug, Clone, Copy)]
pub struct ValueSource<'a> {
    /// Read the whole file (binary allowed).
    pub from_file: Option<&'a Path>,
    /// Read stdin even when it is a terminal.
    pub stdin: bool,
    /// Keep one trailing newline read from stdin.
    pub keep_trailing_newline: bool,
    /// Ask twice when prompting.
    pub confirm: bool,
    /// Accept an empty value.
    pub allow_empty: bool,
}

/// Remove one trailing newline (`\n` or `\r\n`) from bytes read from a pipe.
pub fn strip_trailing_newline(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
}

/// Obtain the value for `secret set` from a file, stdin or a hidden prompt.
pub fn read_secret_value(args: &SecretSetArgs) -> anyhow::Result<SecretBytes> {
    read_value(&ValueSource {
        from_file: args.from_file.as_deref(),
        stdin: args.stdin,
        keep_trailing_newline: args.keep_trailing_newline,
        confirm: args.confirm,
        allow_empty: args.allow_empty,
    })
}

/// Obtain a value from `source`: the file, else stdin when asked for or
/// piped, else a hidden prompt.
pub fn read_value(source: &ValueSource<'_>) -> anyhow::Result<SecretBytes> {
    let value = if let Some(path) = source.from_file {
        let bytes =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        SecretBytes::new(bytes)
    } else if source.stdin || !std::io::stdin().is_terminal() {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .context("failed to read secret value from stdin")?;
        if !source.keep_trailing_newline {
            strip_trailing_newline(&mut bytes);
        }
        SecretBytes::new(bytes)
    } else {
        let first = read_hidden("Enter secret value: ")?;
        if source.confirm {
            let second = read_hidden("Confirm secret value: ")?;
            if first != second {
                return Err(anyhow!("values do not match"));
            }
        }
        first
    };

    if value.is_empty() && !source.allow_empty {
        return Err(anyhow!(
            "refusing to store an empty value (pass --allow-empty to override)"
        ));
    }
    Ok(value)
}

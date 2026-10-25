//! Conformance runner for the Rust SDK: executes one scenario from
//! `tests/conformance/sdk/scenarios.json` and prints what it observed as
//! `key<TAB>value` lines (protocol: `tests/conformance/sdk/README.md`).
//!
//! ```text
//! conformance <op> [key=value ...]
//! ```

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use sourceorrery::{
    Error, OpenOptions, Project, Secret, SecretError, SecretProperties, SecretReader,
};

type Lines = Vec<(String, String)>;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(op) = args.next() else {
        eprintln!("usage: conformance <op> [key=value ...]");
        return ExitCode::from(2);
    };
    let kv: BTreeMap<String, String> = args
        .filter_map(|arg| {
            arg.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect();
    let vault = kv
        .get("vault")
        .cloned()
        .or_else(|| std::env::var("SOURCEORRERY_TEST_VAULT").ok())
        .unwrap_or_else(|| "development".to_owned());

    let mut options = OpenOptions::new();
    if let Some(home) = kv.get("home") {
        options = options.home(home);
    }
    if let Some(key) = kv.get("recovery_key") {
        options = options.recovery_key(key.as_str());
    }
    if let Some(file) = kv.get("recovery_key_file") {
        options = options.recovery_key_file(file);
    }
    if kv.get("environment").is_some_and(|v| v == "false") {
        options = options.environment(false);
    }

    match run(&op, &kv, &vault, &options) {
        Ok(lines) => {
            println!("outcome\tok");
            for (key, value) in lines {
                println!("{key}\t{value}");
            }
        }
        Err(err) => {
            println!("outcome\terror");
            println!("code\t{}", err.code());
            println!("message\t{}", err.message());
            println!("hint\t{}", err.hint());
            println!("transient\t{}", err.is_transient());
            println!("type\t{:?}", err.kind());
        }
    }
    ExitCode::SUCCESS
}

fn missing(key: &str) -> Error {
    Error::from(SecretError::InvalidArgument(format!(
        "scenario argument {key}= is required"
    )))
}

fn properties_lines(props: &SecretProperties) -> Lines {
    let mut lines = vec![
        ("version".to_owned(), props.version.clone()),
        ("enabled".to_owned(), props.enabled.to_string()),
        (
            "content_type".to_owned(),
            props.content_type.clone().unwrap_or_default(),
        ),
        ("reference".to_owned(), props.reference().to_string()),
    ];
    for (key, value) in &props.tags {
        lines.push((format!("tag.{key}"), value.clone()));
    }
    lines
}

fn secret_lines(secret: &Secret) -> Lines {
    let value = secret
        .value
        .expose_utf8()
        .map_or_else(|| hex(secret.value.expose()), str::to_owned);
    let mut lines = vec![("value".to_owned(), value)];
    lines.extend(properties_lines(&secret.properties));
    lines
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn run(
    op: &str,
    kv: &BTreeMap<String, String>,
    vault: &str,
    options: &OpenOptions,
) -> sourceorrery::Result<Lines> {
    let arg = |key: &str| kv.get(key).ok_or_else(|| missing(key));
    match op {
        "open" => {
            let reader = SecretReader::open_with(vault, options)?;
            let descriptor = reader.descriptor()?;
            Ok(vec![
                ("descriptor.name".to_owned(), descriptor.name),
                (
                    "descriptor.protectors".to_owned(),
                    descriptor.protectors.join(","),
                ),
            ])
        }
        "get" => {
            let reader = SecretReader::open_with(vault, options)?;
            let secret = match kv.get("version") {
                Some(version) => reader.get_version(arg("name")?, version)?,
                None => reader.get(arg("name")?)?,
            };
            Ok(secret_lines(&secret))
        }
        "get-newest-explicit" => {
            let reader = SecretReader::open_with(vault, options)?;
            let newest = reader.properties(arg("name")?, None)?.version;
            Ok(secret_lines(&reader.get_version(arg("name")?, &newest)?))
        }
        "properties" => {
            let reader = SecretReader::open_with(vault, options)?;
            let props = reader.properties(arg("name")?, kv.get("version").map(String::as_str))?;
            Ok(properties_lines(&props))
        }
        "resolve" => {
            let reader = SecretReader::open_with(vault, options)?;
            Ok(secret_lines(&reader.resolve(arg("reference")?)?))
        }
        "load" => {
            let project = Project::load(Some(Path::new(arg("manifest")?)), options)?;
            let mut names: Vec<&str> = project.secrets().iter().map(|s| s.name.as_str()).collect();
            names.sort_unstable();
            let mut lines = vec![
                ("project.name".to_owned(), project.name().to_owned()),
                (
                    "project.count".to_owned(),
                    project.secrets().len().to_string(),
                ),
                ("project.names".to_owned(), names.join(",")),
            ];
            for secret in project.secrets() {
                let value = secret
                    .value
                    .expose_utf8()
                    .map_or_else(|| hex(secret.value.expose()), str::to_owned);
                lines.push((format!("secret.{}", secret.env), value));
            }
            Ok(lines)
        }
        other => Err(Error::from(SecretError::InvalidArgument(format!(
            "unknown scenario op '{other}'"
        )))),
    }
}

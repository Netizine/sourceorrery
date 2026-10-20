//! Command-line surface (clap derive).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

/// Secrets belong to the runtime, not the repository.
#[derive(Debug, Parser)]
#[command(
    name = "sourceorrery",
    version,
    about = "SourceOrrery — secrets belong to the runtime, not the repository.",
    long_about = "SourceOrrery keeps secrets in an encrypted local vault and delivers them to \
                  your application at run time, so no .env file ever needs to exist.\n\n\
                  Metadata commands (list, versions, get) never print secret values. \
                  Use `secret get --reveal` to disclose a value on purpose."
)]
pub struct Cli {
    /// Vault to operate on (default: the project vault named in sourceorrery.toml).
    #[arg(long, global = true, env = "SOURCEORRERY_VAULT", value_name = "NAME")]
    pub vault: Option<String>,

    /// SourceOrrery home directory holding vault files.
    #[arg(long, global = true, env = "SOURCEORRERY_HOME", value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// Output format.
    #[arg(short, long, global = true, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,

    /// Read the vault passphrase from this file instead of prompting (automation).
    #[arg(
        long,
        global = true,
        env = "SOURCEORRERY_PASSPHRASE_FILE",
        value_name = "FILE"
    )]
    pub passphrase_file: Option<PathBuf>,

    /// Increase diagnostic output (-v, -vv, -vvv). Never prints secret values.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// With no subcommand, `sourceorrery` prints its banner and a quick start.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable tables.
    Table,
    /// Machine-readable JSON.
    Json,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create, inspect and manage vaults.
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Create, read, update, delete and recover secrets.
    #[command(subcommand)]
    Secret(SecretCommand),
    /// Show the metadata-only audit log of a vault.
    Audit(AuditArgs),
    /// Write a sourceorrery.toml manifest for the current project.
    Init(InitArgs),
    /// Verify every secret in the manifest is present and accessible (no values read).
    Check(CheckArgs),
    /// Run a command with the manifest's secrets injected as environment variables.
    Run(RunArgs),
    /// Generate shell completions.
    Completions(CompletionsArgs),
}

// ---------------------------------------------------------------------------
// vault
// ---------------------------------------------------------------------------

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Create a new encrypted vault.
    Create(VaultCreateArgs),
    /// List vaults in the home directory.
    List,
    /// Show a vault's metadata and key protectors.
    Info,
    /// Manage the key protectors that can unlock a vault.
    #[command(subcommand)]
    Protector(ProtectorCommand),
    /// Permanently delete a vault file and its OS-keyring entries.
    Destroy(VaultDestroyArgs),
    /// Upgrade a vault written by an older release to the current on-disk format.
    ///
    /// Older vaults carry no integrity tags, so this is an explicit trust decision:
    /// only migrate a file you know is genuine. A file that was already in the
    /// current format (a downgraded copy) is refused.
    Migrate(VaultMigrateArgs),
}

#[derive(Debug, Args)]
pub struct VaultMigrateArgs {
    /// Vault name.
    pub name: String,
}

#[derive(Debug, Args)]
pub struct VaultCreateArgs {
    /// Vault name (lowercase letters, digits, hyphens).
    pub name: String,
    /// How the vault key is protected. Default: os-keyring when available, else passphrase.
    #[arg(long, value_enum)]
    pub protector: Option<ProtectorChoice>,
    /// Days a deleted secret stays recoverable (7-90).
    #[arg(long, default_value_t = 90, value_name = "DAYS")]
    pub retention_days: u32,
    /// Disable soft delete: deletions are immediate and permanent.
    #[arg(long)]
    pub purgeable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ProtectorChoice {
    /// Random key stored in the OS credential store (Credential Manager, Keychain, Secret Service).
    OsKeyring,
    /// Key derived from a passphrase with Argon2id.
    Passphrase,
}

#[derive(Debug, Subcommand)]
pub enum ProtectorCommand {
    /// List key protectors.
    List,
    /// Add a key protector (e.g. a passphrase for use inside WSL, Docker or CI).
    Add(ProtectorAddArgs),
    /// Remove a key protector by id or label. The last one cannot be removed.
    Remove(ProtectorRemoveArgs),
}

#[derive(Debug, Args)]
pub struct ProtectorAddArgs {
    /// Kind of protector to add.
    #[arg(long, value_enum)]
    pub kind: ProtectorChoice,
    /// Unique label (default: the kind).
    #[arg(long)]
    pub label: Option<String>,
}

#[derive(Debug, Args)]
pub struct ProtectorRemoveArgs {
    /// Protector id or label.
    pub protector: String,
}

#[derive(Debug, Args)]
pub struct VaultDestroyArgs {
    /// Vault name.
    pub name: String,
    /// Confirm permanent deletion without prompting.
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Leave the vault's OS-keyring entries in place (for example when the
    /// same vault file also lives elsewhere).
    #[arg(long)]
    pub keep_os_key: bool,
}

// ---------------------------------------------------------------------------
// secret
// ---------------------------------------------------------------------------

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Store a new version of a secret. The value is read interactively, from stdin or a file;
    /// it is never accepted as a command-line argument.
    Set(SecretSetArgs),
    /// Show a secret's metadata, or its value with --reveal.
    Get(SecretGetArgs),
    /// List secrets (metadata only).
    List(SecretListArgs),
    /// List all versions of a secret (metadata only).
    Versions(SecretNameArgs),
    /// Change a version's metadata (enabled, content type, tags, time window).
    Update(SecretUpdateArgs),
    /// Soft-delete a secret (all versions). Recoverable until retention ends.
    Delete(SecretNameArgs),
    /// Recover a soft-deleted secret.
    Recover(SecretNameArgs),
    /// Permanently remove a soft-deleted secret.
    Purge(SecretPurgeArgs),
}

#[derive(Debug, Args)]
pub struct SecretNameArgs {
    /// Secret name.
    pub name: String,
}

#[derive(Debug, Args)]
pub struct SecretSetArgs {
    /// Secret name (letters, digits, hyphens; Azure Key Vault compatible).
    pub name: String,
    /// Read the value from standard input (automatic when stdin is not a terminal).
    #[arg(long)]
    pub stdin: bool,
    /// Read the value from a file (binary allowed).
    #[arg(long, value_name = "FILE", conflicts_with = "stdin")]
    pub from_file: Option<PathBuf>,
    /// Keep a trailing newline read from stdin (stripped by default).
    #[arg(long)]
    pub keep_trailing_newline: bool,
    /// Ask for the value twice when prompting interactively.
    #[arg(long)]
    pub confirm: bool,
    /// Allow an empty value.
    #[arg(long)]
    pub allow_empty: bool,
    /// Content type hint (e.g. text/plain, application/json).
    #[arg(long, value_name = "TYPE")]
    pub content_type: Option<String>,
    /// Non-sensitive tag, repeatable (key=value).
    #[arg(long = "tag", value_name = "KEY=VALUE")]
    pub tags: Vec<String>,
    /// Activation time (RFC 3339, e.g. 2026-12-01T00:00:00Z).
    #[arg(long, value_name = "TIME")]
    pub not_before: Option<String>,
    /// Expiry time (RFC 3339).
    #[arg(long, value_name = "TIME")]
    pub expires: Option<String>,
    /// Create the version disabled.
    #[arg(long)]
    pub disabled: bool,
}

#[derive(Debug, Args)]
pub struct SecretGetArgs {
    /// Secret name.
    pub name: String,
    /// Specific version (default: newest accessible version).
    #[arg(long, value_name = "ID")]
    pub version: Option<String>,
    /// Print the secret value. Without this flag only metadata is shown.
    #[arg(long)]
    pub reveal: bool,
    /// With --reveal: write the raw value with no trailing newline.
    #[arg(long, requires = "reveal")]
    pub raw: bool,
}

#[derive(Debug, Args)]
pub struct SecretListArgs {
    /// List soft-deleted secrets instead of live ones.
    #[arg(long)]
    pub deleted: bool,
}

#[derive(Debug, Args)]
pub struct SecretUpdateArgs {
    /// Secret name.
    pub name: String,
    /// Version to update (default: newest).
    #[arg(long, value_name = "ID")]
    pub version: Option<String>,
    /// Enable the version.
    #[arg(long, conflicts_with = "disable")]
    pub enable: bool,
    /// Disable the version.
    #[arg(long)]
    pub disable: bool,
    /// Set the content type.
    #[arg(long, value_name = "TYPE", conflicts_with = "clear_content_type")]
    pub content_type: Option<String>,
    /// Remove the content type.
    #[arg(long)]
    pub clear_content_type: bool,
    /// Replace all tags with these (key=value, repeatable).
    #[arg(long = "tag", value_name = "KEY=VALUE", conflicts_with = "clear_tags")]
    pub tags: Vec<String>,
    /// Remove all tags.
    #[arg(long)]
    pub clear_tags: bool,
    /// Set the activation time (RFC 3339).
    #[arg(long, value_name = "TIME", conflicts_with = "clear_not_before")]
    pub not_before: Option<String>,
    /// Remove the activation time.
    #[arg(long)]
    pub clear_not_before: bool,
    /// Set the expiry time (RFC 3339).
    #[arg(long, value_name = "TIME", conflicts_with = "clear_expires")]
    pub expires: Option<String>,
    /// Remove the expiry time.
    #[arg(long)]
    pub clear_expires: bool,
}

#[derive(Debug, Args)]
pub struct SecretPurgeArgs {
    /// Secret name.
    pub name: String,
    /// Confirm permanent deletion without prompting.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

// ---------------------------------------------------------------------------
// audit / project / completions
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Only events about this secret.
    #[arg(long, value_name = "NAME")]
    pub secret: Option<String>,
    /// Only this operation (e.g. secret_get, vault_open).
    #[arg(long, value_name = "OP")]
    pub operation: Option<String>,
    /// Only events at or after this time (RFC 3339).
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,
    /// Maximum number of events, newest first.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// Verify the audit log's hash chain instead of listing events. Exits 1 if it is not intact.
    #[arg(long, conflicts_with_all = ["secret", "operation", "since", "limit"])]
    pub verify: bool,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Project name (default: current directory name).
    #[arg(long, value_name = "NAME")]
    pub project_name: Option<String>,
    /// Default vault for the project (default: development).
    #[arg(long, value_name = "NAME")]
    pub vault_name: Option<String>,
    /// Where to write the manifest (default: ./sourceorrery.toml).
    #[arg(long, value_name = "FILE")]
    pub path: Option<PathBuf>,
    /// Overwrite an existing manifest.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Manifest path (default: discovered upwards from the current directory).
    #[arg(long, value_name = "FILE")]
    pub manifest: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Manifest path (default: discovered upwards from the current directory).
    #[arg(long, value_name = "FILE")]
    pub manifest: Option<PathBuf>,
    /// Command to run, with its arguments. Separate from sourceorrery flags with `--`.
    #[arg(
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND"
    )]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: Shell,
}

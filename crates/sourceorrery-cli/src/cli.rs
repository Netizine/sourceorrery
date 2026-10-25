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

    /// Read the vault's recovery key from this file when this machine cannot open the vault by
    /// itself (WSL, containers, CI) instead of prompting.
    #[arg(
        long,
        global = true,
        env = "SOURCEORRERY_RECOVERY_KEY_FILE",
        value_name = "FILE"
    )]
    pub recovery_key_file: Option<PathBuf>,

    /// Read the view check's password from this file (scripts) instead of prompting.
    #[arg(
        long,
        global = true,
        env = "SOURCEORRERY_PASSWORD_FILE",
        value_name = "FILE"
    )]
    pub password_file: Option<PathBuf>,

    /// Increase diagnostic output (-v, -vv, -vvv). Never prints secret values.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,
    /// Authenticator code for the vault's view check (scripts; otherwise it is asked for).
    /// Codes are valid for about a minute and never reused.
    #[arg(
        long,
        global = true,
        env = "SOURCEORRERY_TOTP",
        value_name = "CODE",
        hide_env_values = true
    )]
    pub code: Option<crate::context::Code>,

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
    /// Set up a vault on screens: create one, or change a vault's view check, recovery key and
    /// storage. With --guide, or without a terminal, it prints the one command that does it.
    Setup(SetupArgs),
    /// Create, inspect and manage vaults.
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Create, read, update, delete and recover secrets.
    #[command(subcommand)]
    Secret(SecretCommand),
    /// Show the metadata-only audit log of a vault.
    Audit(AuditArgs),
    /// Write the project's sourceorrery.toml from the secrets of a vault (by name only), or add
    /// to it, and record the folder in the vault; install the skills for AI coding agents.
    Init(InitArgs),
    /// Move a .env file into a vault: store every value (never printed) and
    /// declare each key in sourceorrery.toml.
    Import(ImportArgs),
    /// Verify every secret in the manifest is present and accessible (no values read).
    Check(CheckArgs),
    /// Run a command with the manifest's secrets injected as environment variables.
    Run(RunArgs),
    /// Browse a vault interactively (metadata only; values are never shown).
    #[cfg(feature = "ui")]
    Ui(UiArgs),
    /// Generate shell completions.
    Completions(CompletionsArgs),
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct SetupArgs {
    /// Print the one `vault create` command that sets a vault up without the screens (as it is
    /// printed without a terminal).
    #[arg(long)]
    pub guide: bool,
    /// Colours of the screens.
    #[cfg(feature = "ui")]
    #[arg(long, value_enum, env = "SOURCEORRERY_THEME", default_value_t = UiTheme::Dark)]
    pub theme: UiTheme,
}

// ---------------------------------------------------------------------------
// vault
// ---------------------------------------------------------------------------

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Create a vault, or change one (its view check, recovery key and storage), on the setup
    /// screens (in a terminal, without the flags of a non-interactive create). With flags, or
    /// without a terminal, it creates NAME at once: its recovery key is printed once (or written
    /// to --recovery-key-out), and --password-file sets its view check's password.
    Create(VaultCreateArgs),
    /// List vaults in the home directory.
    List,
    /// Write a copy of a vault for another machine. The copy opens with its recovery key only:
    /// this machine's key and the view check stay behind.
    Export(VaultExportArgs),
    /// Bring a vault exported elsewhere onto this machine, opened with its recovery key; this
    /// machine then opens it without asking. Its view check is set again from --password-file.
    Import(VaultImportArgs),
    /// Permanently delete a vault file and its OS-keyring entries.
    Destroy(VaultDestroyArgs),
}

#[derive(Debug, Args)]
pub struct VaultCreateArgs {
    /// Vault name (letters, digits, hyphens and underscores; not starting with a hyphen). On
    /// the screens, an existing vault's name opens it for changes.
    pub name: Option<String>,
    /// Days a deleted secret stays recoverable (7-90).
    #[arg(long, default_value_t = 90, value_name = "DAYS")]
    pub retention_days: u32,
    /// Disable soft delete: deletions are immediate and permanent.
    #[arg(long)]
    pub purgeable: bool,
    /// Keep no key for this machine in the OS credential store: the vault then opens with its
    /// recovery key only.
    #[arg(long)]
    pub no_keyring: bool,
    /// Write the recovery key to this file (readable by the current user only) instead of
    /// printing it.
    #[arg(long, value_name = "FILE")]
    pub recovery_key_out: Option<PathBuf>,
    #[command(flatten)]
    pub connections: Box<ConnectionArgs>,
    /// Colours of the setup screens.
    #[cfg(feature = "ui")]
    #[arg(long, value_enum, env = "SOURCEORRERY_THEME", default_value_t = UiTheme::Dark)]
    pub theme: UiTheme,
}

#[derive(Debug, Args)]
pub struct VaultExportArgs {
    /// Vault to export (default: --vault, else the project's).
    pub name: Option<String>,
    /// File to write. It must not exist: an export never replaces a file.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct VaultImportArgs {
    /// The exported vault file. It is only read.
    pub file: PathBuf,
    /// Register the vault under this name instead of the one it was exported with.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
}

/// The connections `vault create` gives the vault: one flag set per provider, each named by
/// the provider. A credential is only ever read from a file; without one, the connection uses
/// the provider's own sign-in (its environment variables, CLI login, workload or managed
/// identity).
#[derive(Debug, Default, Args)]
pub struct ConnectionArgs {
    /// Connect to a HashiCorp Vault server at this address (https://, or http:// to this machine).
    #[arg(
        long,
        value_name = "ADDRESS",
        help_heading = "HashiCorp Vault connection"
    )]
    pub hashicorp_vault: Option<String>,
    /// The KV version 2 engine's mount path [default: secret].
    #[arg(
        long,
        value_name = "MOUNT",
        requires = "hashicorp_vault",
        help_heading = "HashiCorp Vault connection"
    )]
    pub hashicorp_vault_mount: Option<String>,
    /// Vault Enterprise namespace.
    #[arg(
        long,
        value_name = "NAMESPACE",
        requires = "hashicorp_vault",
        help_heading = "HashiCorp Vault connection"
    )]
    pub hashicorp_vault_namespace: Option<String>,
    /// Store the token in this file in the vault, sealed, instead of using VAULT_TOKEN and
    /// Vault's other sign-in sources.
    #[arg(
        long,
        value_name = "FILE",
        requires = "hashicorp_vault",
        help_heading = "HashiCorp Vault connection"
    )]
    pub hashicorp_vault_token_file: Option<PathBuf>,

    /// Connect to AWS Secrets Manager in this region.
    #[arg(
        long,
        value_name = "REGION",
        help_heading = "AWS Secrets Manager connection"
    )]
    pub aws_secrets_manager: Option<String>,
    /// Keep every secret under this name prefix (for example myapp/).
    #[arg(
        long,
        value_name = "PREFIX",
        requires = "aws_secrets_manager",
        help_heading = "AWS Secrets Manager connection"
    )]
    pub aws_secrets_manager_prefix: Option<String>,
    /// The service endpoint, for a private endpoint or an emulator (default: the region's).
    #[arg(
        long,
        value_name = "URL",
        requires = "aws_secrets_manager",
        help_heading = "AWS Secrets Manager connection"
    )]
    pub aws_secrets_manager_endpoint: Option<String>,
    /// Store an access key in the vault, sealed: this access key id, with the secret access
    /// key from --aws-secret-access-key-file.
    #[arg(
        long,
        value_name = "ID",
        requires_all = ["aws_secrets_manager", "aws_secret_access_key_file"],
        help_heading = "AWS Secrets Manager connection"
    )]
    pub aws_access_key_id: Option<String>,
    /// The file holding the secret access key of --aws-access-key-id.
    #[arg(
        long,
        value_name = "FILE",
        requires_all = ["aws_secrets_manager", "aws_access_key_id"],
        help_heading = "AWS Secrets Manager connection"
    )]
    pub aws_secret_access_key_file: Option<PathBuf>,

    /// Connect to the Azure Key Vault at this URL (https://<name>.vault.azure.net).
    #[arg(long, value_name = "URL", help_heading = "Azure Key Vault connection")]
    pub azure_key_vault: Option<String>,
    /// Store a service principal in the vault, sealed: its directory (tenant) id, with
    /// --azure-client-id and --azure-client-secret-file.
    #[arg(
        long,
        value_name = "ID",
        requires_all = ["azure_key_vault", "azure_client_id", "azure_client_secret_file"],
        help_heading = "Azure Key Vault connection"
    )]
    pub azure_tenant_id: Option<String>,
    /// The service principal's application (client) id.
    #[arg(
        long,
        value_name = "ID",
        requires_all = ["azure_key_vault", "azure_tenant_id", "azure_client_secret_file"],
        help_heading = "Azure Key Vault connection"
    )]
    pub azure_client_id: Option<String>,
    /// The file holding the service principal's client secret.
    #[arg(
        long,
        value_name = "FILE",
        requires_all = ["azure_key_vault", "azure_tenant_id", "azure_client_id"],
        help_heading = "Azure Key Vault connection"
    )]
    pub azure_client_secret_file: Option<PathBuf>,
}

impl ConnectionArgs {
    /// No connection is asked for (each provider's other flags require its first).
    #[cfg(feature = "ui")]
    pub fn is_empty(&self) -> bool {
        self.hashicorp_vault.is_none()
            && self.aws_secrets_manager.is_none()
            && self.azure_key_vault.is_none()
    }
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
    /// Rotate a secret: issue a new value (from the manifest's issue command, stdin or a prompt),
    /// validate it, activate it, and retire the previous version after the grace period.
    Rotate(SecretRotateArgs),
}

/// What `secret rotate` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RotationStep {
    /// Issue, validate and activate a new version; retire the previous one at once unless a grace
    /// period is set.
    Rotate,
    /// Activate the validated candidate a `--no-activate` run left behind.
    Activate,
    /// Retire the previous version once the grace period has ended (or now, with --now).
    Retire,
    /// Show where the secret's rotation stands.
    Status,
}

#[derive(Debug, Args)]
pub struct SecretRotateArgs {
    /// Secret name.
    pub name: String,
    /// Manifest path (default: found upwards from the current directory, within the
    /// repository and your home directory). The manifest's
    /// `[rotation.NAME]` table supplies the issue, validate and retire commands and the grace period.
    #[arg(long, value_name = "FILE")]
    pub manifest: Option<PathBuf>,
    /// The step to run.
    #[arg(long, value_enum, default_value_t = RotationStep::Rotate)]
    pub step: RotationStep,
    /// Stop after validation: the candidate stays disabled until `--step activate`.
    #[arg(long)]
    pub no_activate: bool,
    /// Retire the previous version this long after activation (7d, 12h, 30m). Overrides the
    /// manifest; without either, the previous version is retired in the same run.
    #[arg(long, value_name = "DURATION")]
    pub retire_after: Option<String>,
    /// With --step retire: retire before the grace period has ended.
    #[arg(long)]
    pub now: bool,
    /// Read the new value from standard input (automatic when stdin is not a terminal and the
    /// manifest has no issue command).
    #[arg(long)]
    pub stdin: bool,
    /// Read the new value from a file.
    #[arg(long, value_name = "FILE", conflicts_with = "stdin")]
    pub from_file: Option<PathBuf>,
    /// Keep a trailing newline read from stdin or the issue command (stripped by default).
    #[arg(long)]
    pub keep_trailing_newline: bool,
    /// Allow an empty value.
    #[arg(long)]
    pub allow_empty: bool,
}

#[derive(Debug, Args)]
pub struct SecretNameArgs {
    /// Secret name.
    pub name: String,
}

#[derive(Debug, Args)]
pub struct SecretSetArgs {
    /// Secret name (letters, digits, hyphens; at most 127 characters).
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
    /// Where a new secret is kept: sourceorrery (the vault file, the default), or a provider
    /// the vault has a connection to (hashicorp-vault, aws-secrets-manager, azure-key-vault).
    /// A new version of an existing secret goes where the secret is.
    #[arg(long, value_name = "STORAGE")]
    pub storage: Option<String>,
    /// What the secret is for, in one line: kept in the vault's catalog, and written into a
    /// project's manifest as `purpose` by `init`. Replaces the description the secret has.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
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
    /// Show at most N secrets, then how to continue (names are listed in order).
    #[arg(long, value_name = "N")]
    pub limit: Option<usize>,
    /// Continue after this name, as printed by the previous page.
    #[arg(long, value_name = "NAME")]
    pub after: Option<String>,
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
#[command(args_conflicts_with_subcommands = true)]
pub struct AuditArgs {
    /// `audit export`: the whole log for a collector.
    #[command(subcommand)]
    pub command: Option<AuditSubcommand>,
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
    /// Acknowledge every detected audit-log truncation and unblock the vault. Prints the
    /// truncation events first and asks for confirmation; only do this after comparing the
    /// surviving history with an exported copy of the vault.
    #[arg(long, conflicts_with_all = ["secret", "operation", "since", "limit", "verify"])]
    pub acknowledge: bool,
    /// With --acknowledge: confirm without prompting (automation).
    #[arg(long, short = 'y', requires = "acknowledge")]
    pub yes: bool,
}

#[derive(Debug, Subcommand)]
pub enum AuditSubcommand {
    /// Write the audit log, oldest first, as JSON Lines on stdout or as OTLP logs to a collector,
    /// ending with the chain verification so a collector can tell a complete export from a
    /// truncated log. --follow keeps going as new events are recorded.
    Export(AuditExportArgs),
}

/// How `audit export` writes events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuditFormat {
    /// One JSON object per line on stdout; the last line is the verification trailer.
    Jsonl,
    /// OTLP/HTTP log records (JSON encoding) posted to --endpoint; the verification is the last record.
    Otlp,
}

#[derive(Debug, Args)]
pub struct AuditExportArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = AuditFormat::Jsonl)]
    pub format: AuditFormat,
    /// Only events at or after this time (RFC 3339).
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,
    /// After the existing log, keep exporting new events as they are recorded, until stdout
    /// closes or the process is stopped.
    #[arg(long)]
    pub follow: bool,
    /// With --follow: seconds between looks at the log.
    #[arg(long, value_name = "SECONDS", default_value_t = 2)]
    pub interval: u64,
    /// With --format otlp: the collector's logs endpoint (default: OTEL_EXPORTER_OTLP_LOGS_ENDPOINT,
    /// else OTEL_EXPORTER_OTLP_ENDPOINT with /v1/logs appended).
    #[arg(long, value_name = "URL")]
    pub endpoint: Option<String>,
    /// With --format otlp: an HTTP header to send, repeatable (KEY=VALUE; also read from
    /// OTEL_EXPORTER_OTLP_HEADERS).
    #[arg(long = "header", value_name = "KEY=VALUE")]
    pub headers: Vec<String>,
    /// With --format otlp: log records per request.
    #[arg(long, value_name = "N", default_value_t = 500)]
    pub batch: usize,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// The vault the project's secrets come from (default: the one an existing manifest names,
    /// else --vault, else the only vault on this machine).
    #[arg(value_name = "VAULT")]
    pub target_vault: Option<String>,
    /// Project name (default: the folder's name; an existing manifest keeps its own).
    #[arg(long, value_name = "NAME")]
    pub project_name: Option<String>,
    /// Declare every secret the vault holds.
    #[arg(long, conflicts_with = "secrets")]
    pub all: bool,
    /// Declare this secret, which the vault must hold (repeatable). Store a new one first with
    /// `sourceorrery secret set NAME --stdin`.
    #[arg(long = "secret", value_name = "NAME")]
    pub secrets: Vec<String>,
    /// The manifest (default: ./sourceorrery.toml). An existing one is added to, in place.
    #[arg(long, value_name = "FILE")]
    pub path: Option<PathBuf>,
    /// Colours of the screens init shows on a terminal when no secret is picked with a flag.
    #[cfg(feature = "ui")]
    #[arg(long, value_enum, env = "SOURCEORRERY_THEME", default_value_t = UiTheme::Dark)]
    pub theme: UiTheme,
    /// Install the SourceOrrery skills for an AI coding agent (repeatable or
    /// comma-separated; `all` for every one). The manifest is written too when
    /// --all or --secret picks secrets.
    #[arg(
        long = "integration",
        value_enum,
        value_delimiter = ',',
        value_name = "AGENT"
    )]
    pub integrations: Vec<IntegrationChoice>,
    /// Where the skills go: this project (shared through the repository) or
    /// your user profile (every project on this machine; no manifest is written).
    #[arg(long, value_enum, default_value_t = SkillScope::Project, requires = "integrations")]
    pub scope: SkillScope,
    /// Write the skill folders into this directory instead, for example an
    /// organisation's managed skills directory (no manifest is written).
    #[arg(
        long,
        value_name = "DIR",
        requires = "integrations",
        conflicts_with = "scope"
    )]
    pub skills_dir: Option<PathBuf>,
}

/// An AI coding agent `init --integration` installs the skills for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum IntegrationChoice {
    /// Claude Code: .claude/skills, plus a migration subagent in .claude/agents.
    Claude,
    /// Gemini CLI: .gemini/skills.
    Gemini,
    /// GitHub Copilot (VS Code agent mode, Copilot CLI, cloud agent): .github/skills.
    Copilot,
    /// Google Antigravity: .agents/skills.
    Antigravity,
    /// Cline: .cline/skills.
    Cline,
    /// OpenAI Codex: .agents/skills, with agents/openai.yaml per skill.
    Codex,
    /// Cursor: .cursor/skills.
    Cursor,
    /// Hermes Agent: .hermes/skills (run `hermes skills trust` once).
    Hermes,
    /// Kilo Code: .kilo/skills.
    Kilocode,
    /// Kimi Code CLI: .kimi-code/skills.
    Kimi,
    /// Kiro: .kiro/skills.
    Kiro,
    /// OpenCode: .opencode/skills.
    Opencode,
    /// Every agent above.
    All,
}

/// Where `init --integration` puts the skills.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SkillScope {
    /// The project: committed and shared with everyone who clones it.
    Project,
    /// Your user profile: available in every project on this machine.
    User,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// The .env file to import (for example .env, .env.local, .env.production).
    pub file: PathBuf,
    /// Show what would happen, by key name only, and change nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// Declare the keys in sourceorrery.toml without storing any value
    /// (for .env.example files, or when the values will be set by hand).
    #[arg(long, conflicts_with = "overwrite")]
    pub manifest_only: bool,
    /// Import only this key (repeatable).
    #[arg(long = "only", value_name = "KEY")]
    pub only: Vec<String>,
    /// Leave this key out (repeatable).
    #[arg(long = "exclude", value_name = "KEY")]
    pub exclude: Vec<String>,
    /// Store a new version even when the vault already holds the secret
    /// (by default an existing secret is left as it is).
    #[arg(long)]
    pub overwrite: bool,
    /// Manifest to update (default: the nearest sourceorrery.toml, or a new
    /// one in the current directory).
    #[arg(long, value_name = "FILE", conflicts_with = "no_manifest")]
    pub manifest: Option<PathBuf>,
    /// Do not create or change sourceorrery.toml.
    #[arg(long, conflicts_with = "manifest_only")]
    pub no_manifest: bool,
    /// Where the new secrets are kept: sourceorrery (the vault file, the default), or a
    /// provider the vault has a connection to (hashicorp-vault, aws-secrets-manager,
    /// azure-key-vault).
    #[arg(long, value_name = "STORAGE", conflicts_with = "manifest_only")]
    pub storage: Option<String>,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Manifest path (default: found upwards from the current directory, within the
    /// repository and your home directory).
    #[arg(long, value_name = "FILE")]
    pub manifest: Option<PathBuf>,
    /// Also read each value and discard it, so the status says whether this
    /// identity may read the secret, not only inspect it. A remote provider
    /// can allow metadata and deny values; on a local vault this is an
    /// audited read.
    #[arg(long)]
    pub access: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Manifest path (default: found upwards from the current directory, within the
    /// repository and your home directory).
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

#[cfg(feature = "ui")]
#[derive(Debug, Args)]
pub struct UiArgs {
    /// Colours: the documentation site's dark or light palette, or the terminal's own.
    #[arg(long, value_enum, env = "SOURCEORRERY_THEME", default_value_t = UiTheme::Dark)]
    pub theme: UiTheme,
    /// Lock the open vault after this many minutes without a key press,
    /// wiping its key from memory (0: never).
    #[arg(
        long,
        env = "SOURCEORRERY_UI_LOCK_AFTER",
        default_value_t = 10,
        value_name = "MINUTES"
    )]
    pub lock_after: u32,
    /// Browse only: refuse every change.
    #[arg(long)]
    pub read_only: bool,
}

#[cfg(feature = "ui")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum UiTheme {
    /// The docs' dark palette: warm charcoal and navy ink, painted over the whole screen.
    Dark,
    /// The docs' light palette: paper and navy ink, painted over the whole screen.
    Light,
    /// The terminal's own background and named colours.
    Terminal,
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: Shell,
}

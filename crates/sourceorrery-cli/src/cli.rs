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
    /// Second-factor code for an operation the vault's reveal guard protects (automation;
    /// otherwise it is asked for). Codes are valid for about a minute and never reused.
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
    /// Guided first run: a vault, a first secret, recovery, a second factor, the
    /// reveal guard and the project manifest, step by step on the terminal.
    Setup(SetupArgs),
    /// Create, inspect and manage vaults.
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Create, read, update, delete and recover secrets.
    #[command(subcommand)]
    Secret(SecretCommand),
    /// Show the metadata-only audit log of a vault.
    Audit(AuditArgs),
    /// Write a sourceorrery.toml manifest for the current project, and install
    /// the SourceOrrery skills for AI coding agents.
    Init(InitArgs),
    /// Move a .env file into a vault: store every value (never printed) and
    /// declare each key in sourceorrery.toml.
    Import(ImportArgs),
    /// Verify every secret in the manifest is present and accessible (no values read).
    Check(CheckArgs),
    /// Run a command with the manifest's secrets injected as environment variables.
    Run(RunArgs),
    /// Write an encrypted backup of the vault's secrets (every version, values included).
    Backup(BackupArgs),
    /// Restore the secrets of an encrypted backup into the vault as new versions.
    Restore(RestoreArgs),
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
    /// Name of the first secret.
    #[arg(long, default_value = "database-password", value_name = "NAME")]
    pub secret: String,
    /// Project name for the manifest (default: current directory name).
    #[arg(long, value_name = "NAME")]
    pub project_name: Option<String>,
    /// Where to write the manifest (default: ./sourceorrery.toml).
    #[arg(long, value_name = "FILE")]
    pub path: Option<PathBuf>,
    /// Print the steps as commands on stderr instead of the guided screens.
    #[arg(long)]
    pub guide: bool,
    /// Colours: the documentation site's dark or light palette, or the terminal's own.
    #[cfg(feature = "ui")]
    #[arg(long, value_enum, env = "SOURCEORRERY_THEME", default_value_t = UiTheme::Dark)]
    pub theme: UiTheme,
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
    /// The vault passphrase: generate a strong one, estimate one's strength, change it, or set
    /// the hint shown at the prompt.
    #[command(subcommand)]
    Passphrase(PassphraseCommand),
    /// The second factor (an authenticator app, TOTP): enable with a QR code, verify, disable,
    /// status.
    #[command(name = "2fa", subcommand)]
    TwoFactor(TwoFactorCommand),
    /// What revealing a secret or exporting the vault must present again: the passphrase, a
    /// second-factor code, both or nothing. Without --reveal, show the current guard.
    Guard(GuardArgs),
    /// Recovery codes: one-time passphrases that unlock the vault when the passphrase is lost.
    #[command(subcommand)]
    Recovery(RecoveryCommand),
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
    /// Accept a passphrase the strength estimate rates below "good" when it is typed at the
    /// prompt. (A passphrase from SOURCEORRERY_PASSPHRASE or --passphrase-file is only warned about.)
    #[arg(long)]
    pub allow_weak: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ProtectorChoice {
    /// Random key stored in the OS credential store (Credential Manager, Keychain, Secret Service).
    OsKeyring,
    /// Key derived from a passphrase with Argon2id.
    Passphrase,
}

#[derive(Debug, Subcommand)]
pub enum PassphraseCommand {
    /// Print a random passphrase (letters, digits and symbols) to stdout, once. Pipe it where it
    /// is needed, or write it down: it is not stored anywhere.
    Generate(PassphraseGenerateArgs),
    /// Read a passphrase from stdin or a hidden prompt and print its strength estimate: the
    /// score, the estimated bits of guessing work and what weakened it. Nothing is stored.
    Check,
    /// Change the vault passphrase: the current one is asked for (or taken from
    /// SOURCEORRERY_PASSPHRASE), the new one typed twice and strength-checked.
    Set(PassphraseSetArgs),
    /// Set, show or clear the hint shown at the passphrase prompt. Stored in clear in the vault
    /// file and readable by anyone who has it; a hint that unlocks the vault is refused.
    Hint(PassphraseHintArgs),
}

#[derive(Debug, Args)]
pub struct PassphraseSetArgs {
    /// Read the new passphrase from a file (automation) instead of prompting.
    #[arg(long, value_name = "FILE")]
    pub new_from_file: Option<PathBuf>,
    /// Accept a new passphrase the strength estimate rates below "good".
    #[arg(long)]
    pub allow_weak: bool,
}

#[derive(Debug, Args)]
pub struct PassphraseHintArgs {
    /// The hint (at most 120 characters). Without it, the current hint is shown.
    pub text: Option<String>,
    /// Remove the hint.
    #[arg(long, conflicts_with = "text")]
    pub clear: bool,
}

#[derive(Debug, Subcommand)]
pub enum TwoFactorCommand {
    /// Enrol an authenticator: draws a QR code, then asks for one code to prove the enrolment.
    Enable(TwoFactorEnableArgs),
    /// Prove an enrolment made with --no-verify by entering one code.
    Verify,
    /// Remove the second factor (a code is asked for while the enrolment is verified).
    Disable,
    /// Whether a second factor is enrolled and verified, and what the guard asks for.
    Status,
}

#[derive(Debug, Args)]
pub struct TwoFactorEnableArgs {
    /// Also print the otpauth:// URI and the key, for an authenticator that cannot scan.
    #[arg(long)]
    pub show_uri: bool,
    /// Leave the enrolment unverified instead of asking for a code now (`vault 2fa verify`
    /// completes it). With -o json the key is printed, for automation.
    #[arg(long)]
    pub no_verify: bool,
}

#[derive(Debug, Args)]
pub struct GuardArgs {
    /// What a reveal or export must present: `passphrase`, `second-factor`,
    /// `passphrase,second-factor` or `none`.
    #[arg(long, value_name = "WHAT")]
    pub reveal: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum RecoveryCommand {
    /// Generate recovery codes (replacing any earlier ones) and print them once.
    Codes(RecoveryCodesArgs),
}

#[derive(Debug, Args)]
pub struct RecoveryCodesArgs {
    /// How many codes (1 to 7; they count against the eight passphrase protectors a vault holds).
    #[arg(long, default_value_t = 5, value_name = "N")]
    pub count: usize,
}

#[derive(Debug, Args)]
pub struct PassphraseGenerateArgs {
    /// Characters to generate (at least 12; the default is about 125 bits of entropy).
    #[arg(long, default_value_t = 20, value_name = "N")]
    pub length: usize,
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
    /// Accept a passphrase the strength estimate rates below "good" when it is typed at the
    /// prompt.
    #[arg(long)]
    pub allow_weak: bool,
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
    /// surviving history with a backup.
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
    /// Install the SourceOrrery skills for an AI coding agent (repeatable or
    /// comma-separated; `all` for every one). An existing manifest is kept.
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
}

#[derive(Debug, Args)]
pub struct BackupArgs {
    /// File to write (conventionally *.sobackup). Readable by the current user only.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    /// Back up only this secret (repeatable; default: every live secret).
    #[arg(long = "secret", value_name = "NAME")]
    pub secret: Vec<String>,
    /// Include soft-deleted secrets, with their deleted state.
    #[arg(long)]
    pub include_deleted: bool,
    /// Replace an existing file.
    #[arg(long)]
    pub force: bool,
    /// Accept a typed backup passphrase that rates below "good".
    #[arg(long)]
    pub allow_weak: bool,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// The backup file to restore from.
    pub file: PathBuf,
    /// Restore only this secret (repeatable; default: every secret in the backup).
    #[arg(long = "only", value_name = "NAME")]
    pub only: Vec<String>,
    /// Add the backup's versions to a secret that already exists
    /// (by default an existing secret is skipped).
    #[arg(long)]
    pub overwrite: bool,
    /// Soft-delete again a secret the backup holds as deleted (by default it comes back live).
    #[arg(long)]
    pub keep_deleted: bool,
    /// Show what would happen, by name, and change nothing.
    #[arg(long)]
    pub dry_run: bool,
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

/**
 * Read secrets from a SourceOrrery vault.
 *
 * ```ts
 * import { SecretReader } from '@sourceorreryai/sdk';
 *
 * using reader = new SecretReader('development');
 * using secret = reader.get('database-password');
 * connect({ password: secret.value.exposeText() });
 * ```
 *
 * The package only reads: no set, update, delete, recover or purge, and no
 * key, check, connection or audit management. Administration is the CLI's job.
 */

/** Options accepted when opening a vault or loading a project. */
export interface OpenOptions {
  /** Directory holding the `vaults/` folder. Default: `SOURCEORRERY_HOME` or the platform data directory. */
  home?: string;
  /** A recovery key tried before the environment sources. Prefer `recoveryKeyFile` or the environment in production. */
  recoveryKey?: string | Buffer;
  /** A file holding the recovery key (trailing newlines ignored); replaces `SOURCEORRERY_RECOVERY_KEY_FILE`. */
  recoveryKeyFile?: string;
  /** Consult `SOURCEORRERY_RECOVERY_KEY` and `SOURCEORRERY_RECOVERY_KEY_FILE` (default `true`). */
  environment?: boolean;
}

/** Metadata of one version. Never contains the value. */
export interface SecretProperties {
  readonly vault: string;
  readonly name: string;
  readonly version: string;
  readonly enabled: boolean;
  readonly contentType: string | null;
  readonly tags: Readonly<Record<string, string>>;
  readonly notBefore: Date | null;
  readonly expiresOn: Date | null;
  readonly createdOn: Date;
  readonly updatedOn: Date;
  readonly recoveryLevel: 'recoverable' | 'purgeable';
  /** `sourceorrery://vault/name/version` for exactly this version. */
  readonly reference: string;
}

/**
 * A secret value held on the native side until `close()` (or `using`)
 * zeroises it. `expose()` returns a copy the application owns.
 * `toString()`, `toJSON()` and `util.inspect` all print `[REDACTED]`.
 */
export class SecretValue {
  private constructor();
  /** A copy of the bytes. */
  expose(): Buffer;
  /** The value decoded as UTF-8. */
  exposeText(): string;
  /** Zeroise the bytes. Idempotent. */
  close(): void;
  readonly closed: boolean;
  readonly length: number;
  toString(): string;
  toJSON(): string;
  [Symbol.dispose](): void;
}

/** A version's metadata and its value. */
export class Secret {
  readonly properties: SecretProperties;
  readonly value: SecretValue;
  /** Zeroise the value. */
  close(): void;
  [Symbol.dispose](): void;
}

/** Non-sensitive description of a vault. */
export interface VaultDescriptor {
  name: string;
  id: string;
  backend: string;
  path?: string;
  created_on: string;
  recovery_level: 'recoverable' | 'purgeable';
  retention_days: number;
  protectors: string[];
}

/**
 * A read-only, thread-safe handle on one vault, unlocked the way the CLI
 * unlocks it: OS credential store, then `options.recoveryKey`,
 * `SOURCEORRERY_RECOVERY_KEY`, then `options.recoveryKeyFile` /
 * `SOURCEORRERY_RECOVERY_KEY_FILE`. Never prompts.
 */
export class SecretReader {
  constructor(vault: string, options?: OpenOptions);
  static open(vault: string, options?: OpenOptions): SecretReader;
  readonly vaultName: string;
  readonly closed: boolean;
  /** The newest accessible version of `name` (enabled, inside its time window), or exactly `version`. */
  get(name: string, version?: string): Secret;
  /** Metadata only; policy is not applied, so disabled and expired versions can be inspected. */
  properties(name: string, version?: string): SecretProperties;
  /** Resolve `sourceorrery://vault/name[/version]`; the vault must be this reader's. */
  resolve(reference: string): Secret;
  descriptor(): VaultDescriptor;
  /** Release the vault; the key held in memory is zeroised. */
  close(): void;
  [Symbol.dispose](): void;
}

/** One secret resolved from `sourceorrery.toml`. */
export interface ProjectSecret {
  readonly name: string;
  readonly env: string;
  readonly reference: string;
  readonly required: boolean;
  readonly properties: SecretProperties;
  readonly value: SecretValue;
}

/**
 * The secrets a `sourceorrery.toml` declares, resolved like `sourceorrery run`:
 * every required secret must resolve or `load` throws that secret's error;
 * optional secrets that are missing, refused by policy or whose vault does
 * not exist are left out.
 */
export class Project implements Iterable<ProjectSecret> {
  private constructor();
  /** Load `manifest` (default: the nearest `sourceorrery.toml` above the current directory). */
  static load(manifest?: string, options?: OpenOptions): Project;
  readonly name: string;
  readonly manifestPath: string;
  readonly secrets: ProjectSecret[];
  readonly size: number;
  get(name: string): ProjectSecret | undefined;
  env(variable: string): SecretValue | undefined;
  /** Zeroise every value. */
  close(): void;
  [Symbol.dispose](): void;
  [Symbol.iterator](): Iterator<ProjectSecret>;
}

export function loadProject(manifest?: string, options?: OpenOptions): Project;

/** Contract version of the core this package was built with. */
export function contractVersion(): string;

/** Base class: a failed read with the core's stable code and a hint. */
export class SourceOrreryError extends Error {
  constructor(message: string, code?: string, hint?: string);
  /** Stable, append-only code (`not_found`, `locked`, ...). */
  readonly code: string;
  /** What went wrong, without the hint. */
  readonly detail: string;
  /** What to do about it; empty when nothing specific applies. */
  readonly hint: string;
  /** True when retrying later could succeed without administrative action. */
  readonly transient: boolean;
}
export class VaultNotFoundError extends SourceOrreryError {}
export class VaultLockedError extends SourceOrreryError {}
export class MigrationRequiredError extends SourceOrreryError {}
export class VaultMismatchError extends SourceOrreryError {}
export class SecretNotFoundError extends SourceOrreryError {}
export class VersionNotFoundError extends SecretNotFoundError {}
export class SecretDeletedError extends SourceOrreryError {}
export class PolicyError extends SourceOrreryError {}
export class SecretDisabledError extends PolicyError {}
export class SecretNotYetValidError extends PolicyError {}
export class SecretExpiredError extends PolicyError {}
export class IntegrityError extends SourceOrreryError {}
export class UnsupportedError extends SourceOrreryError {}
export class InvalidArgumentError extends SourceOrreryError {}
export class InvalidNameError extends InvalidArgumentError {}
export class ManifestError extends SourceOrreryError {}
export class PermissionDeniedError extends SourceOrreryError {}
export class StorageError extends SourceOrreryError {}
/** `unauthenticated`: the remote provider has no credentials for this process, or they expired. */
export class UnauthenticatedError extends SourceOrreryError {}
/** `provider_unavailable`: the remote provider could not be reached. `transient` is true. */
export class ProviderUnavailableError extends SourceOrreryError {}

/** The error instance for a stable code; unknown codes keep their code. */
export function errorFor(code: string, message: string, hint?: string): SourceOrreryError;

'use strict';
// Public API of @sourceorrery/sdk. The native addon (../index.js, generated
// by napi-rs) does the work; this file parses metadata JSON into plain
// objects and turns native failures into typed errors by stable code.

const util = require('node:util');
const native = require('../index.js');

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Base class: a failed read with the core's stable code and a hint. */
class SourceOrreryError extends Error {
  constructor(message, code = 'internal', hint = '') {
    super(hint ? `${message}. ${hint}` : message);
    this.name = new.target.name;
    /** What went wrong, without the hint. */
    this.detail = message;
    /** Stable, append-only code (`not_found`, `locked`, ...). */
    this.code = code;
    /** What to do about it; empty when nothing specific applies. */
    this.hint = hint;
  }

  /** True when retrying later could succeed without administrative action. */
  get transient() {
    return this.code === 'not_yet_valid';
  }
}

class VaultNotFoundError extends SourceOrreryError {}
class VaultLockedError extends SourceOrreryError {}
class MigrationRequiredError extends SourceOrreryError {}
class SecretNotFoundError extends SourceOrreryError {}
class VersionNotFoundError extends SecretNotFoundError {}
class SecretDeletedError extends SourceOrreryError {}
class PolicyError extends SourceOrreryError {}
class SecretDisabledError extends PolicyError {}
class SecretNotYetValidError extends PolicyError {}
class SecretExpiredError extends PolicyError {}
class IntegrityError extends SourceOrreryError {}
class UnsupportedError extends SourceOrreryError {}
class InvalidArgumentError extends SourceOrreryError {}
class InvalidNameError extends InvalidArgumentError {}
class ManifestError extends SourceOrreryError {}
class PermissionDeniedError extends SourceOrreryError {}
class StorageError extends SourceOrreryError {}

const ERRORS_BY_CODE = {
  vault_not_found: VaultNotFoundError,
  locked: VaultLockedError,
  migration_required: MigrationRequiredError,
  not_found: SecretNotFoundError,
  version_not_found: VersionNotFoundError,
  deleted: SecretDeletedError,
  disabled: SecretDisabledError,
  not_yet_valid: SecretNotYetValidError,
  expired: SecretExpiredError,
  crypto: IntegrityError,
  unsupported: UnsupportedError,
  invalid_argument: InvalidArgumentError,
  invalid_name: InvalidNameError,
  manifest: ManifestError,
  permission_denied: PermissionDeniedError,
  storage: StorageError,
  io: StorageError,
};

/** The error instance for a stable code; unknown codes keep their code. */
function errorFor(code, message, hint = '') {
  const Cls = ERRORS_BY_CODE[code] ?? SourceOrreryError;
  return new Cls(message, code, hint);
}

/** Native failures carry `{"sourceorrery":{code,message,hint}}` as their message. */
function translate(error) {
  if (error instanceof Error && typeof error.message === 'string' && error.message.startsWith('{"sourceorrery"')) {
    try {
      const parts = JSON.parse(error.message).sourceorrery;
      return errorFor(parts.code, parts.message, parts.hint);
    } catch {
      return error;
    }
  }
  return error;
}

function guarded(fn) {
  try {
    return fn();
  } catch (error) {
    throw translate(error);
  }
}

// ---------------------------------------------------------------------------
// Values and metadata
// ---------------------------------------------------------------------------

const { SecretValue } = native;
const REDACTED = 'SecretValue([REDACTED])';
Object.defineProperty(SecretValue.prototype, util.inspect.custom, { value: () => REDACTED });
if (typeof Symbol.dispose === 'symbol') {
  Object.defineProperty(SecretValue.prototype, Symbol.dispose, {
    value() {
      this.close();
    },
  });
}

function timestamp(text) {
  return text == null ? null : new Date(text);
}

/** `SecretProperties` from the core's JSON shape. */
function propertiesFrom(raw) {
  return Object.freeze({
    vault: raw.vault,
    name: raw.name,
    version: raw.version,
    enabled: raw.enabled,
    contentType: raw.content_type ?? null,
    tags: Object.freeze({ ...(raw.tags ?? {}) }),
    notBefore: timestamp(raw.not_before),
    expiresOn: timestamp(raw.expires_on),
    createdOn: timestamp(raw.created_on),
    updatedOn: timestamp(raw.updated_on),
    recoveryLevel: raw.recovery_level ?? 'recoverable',
    reference: `sourceorrery://${raw.vault}/${raw.name}/${raw.version}`,
  });
}

/** A version's metadata and its value. `close()` zeroises the value. */
class Secret {
  constructor(value) {
    this.properties = propertiesFrom(JSON.parse(value.metadataJson));
    this.value = value;
  }

  close() {
    this.value.close();
  }

  [Symbol.dispose]() {
    this.close();
  }
}

function passphraseBytes(passphrase) {
  if (passphrase == null) return null;
  return Buffer.isBuffer(passphrase) ? passphrase : Buffer.from(String(passphrase), 'utf8');
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/**
 * A read-only handle on one vault, unlocked the way the CLI unlocks it: OS
 * credential store, then `options.passphrase`, `SOURCEORRERY_PASSPHRASE`,
 * then `options.passphraseFile` / `SOURCEORRERY_PASSPHRASE_FILE`. Never
 * prompts.
 */
class SecretReader {
  constructor(vault, options = {}) {
    const { home, passphrase, passphraseFile, environment } = options;
    this._native = guarded(
      () => new native.NativeReader(vault, home ?? null, passphraseBytes(passphrase), passphraseFile ?? null, environment ?? true),
    );
    this._vault = vault;
  }

  /** Open a vault; same as `new SecretReader(vault, options)`. */
  static open(vault, options = {}) {
    return new SecretReader(vault, options);
  }

  get vaultName() {
    return this._vault;
  }

  get closed() {
    return this._native.closed;
  }

  /** The newest accessible version of `name`, or exactly `version`. */
  get(name, version) {
    return new Secret(guarded(() => this._native.get(name, version ?? null)));
  }

  /** Metadata only; policy is not applied. */
  properties(name, version) {
    return propertiesFrom(JSON.parse(guarded(() => this._native.properties(name, version ?? null))));
  }

  /** Resolve `sourceorrery://vault/name[/version]`; the vault must be this reader's. */
  resolve(reference) {
    return new Secret(guarded(() => this._native.resolve(reference)));
  }

  /** Non-sensitive description of the vault. */
  descriptor() {
    return JSON.parse(guarded(() => this._native.descriptor()));
  }

  /** Release the vault; the key held in memory is zeroised. */
  close() {
    this._native.close();
  }

  [Symbol.dispose]() {
    this.close();
  }

  [util.inspect.custom]() {
    return `SecretReader(vault='${this._vault}')`;
  }
}

// ---------------------------------------------------------------------------
// Project manifests
// ---------------------------------------------------------------------------

/** The secrets a sourceorrery.toml declares, resolved like `sourceorrery run`. */
class Project {
  constructor(info, secrets) {
    this.name = info.name;
    this.manifestPath = info.manifest_path;
    this._secrets = secrets;
  }

  static load(manifest, options = {}) {
    const { home, passphrase, passphraseFile, environment } = options;
    const loaded = guarded(() =>
      native.loadProject(manifest ?? null, home ?? null, passphraseBytes(passphrase), passphraseFile ?? null, environment ?? true),
    );
    const secrets = loaded.takeEntries().map((value) => {
      const entry = JSON.parse(value.metadataJson);
      return Object.freeze({
        name: entry.name,
        env: entry.env,
        reference: entry.reference,
        required: entry.required,
        properties: propertiesFrom(entry.properties),
        value,
      });
    });
    return new Project(JSON.parse(loaded.infoJson), secrets);
  }

  /** Every secret that resolved, in manifest order. */
  get secrets() {
    return [...this._secrets];
  }

  get size() {
    return this._secrets.length;
  }

  /** The entry declared as `[secrets.<name>]`, if it resolved. */
  get(name) {
    return this._secrets.find((s) => s.name === name);
  }

  /** The value delivered in environment variable `variable`, if any. */
  env(variable) {
    return this._secrets.find((s) => s.env === variable)?.value;
  }

  /** Zeroise every value. */
  close() {
    for (const secret of this._secrets) secret.value.close();
  }

  [Symbol.dispose]() {
    this.close();
  }

  [Symbol.iterator]() {
    return this._secrets[Symbol.iterator]();
  }
}

function loadProject(manifest, options) {
  return Project.load(manifest, options);
}

/** Contract version of the core this package was built with. */
function contractVersion() {
  return native.contractVersion();
}

// Identifiers only: Node's CommonJS export detection stops at the first
// non-identifier value, which would hide the names after it from ESM
// `import { ... }` statements.
module.exports = {
  SecretReader,
  Secret,
  SecretValue,
  Project,
  loadProject,
  contractVersion,
  errorFor,
  SourceOrreryError,
  VaultNotFoundError,
  VaultLockedError,
  MigrationRequiredError,
  SecretNotFoundError,
  VersionNotFoundError,
  SecretDeletedError,
  PolicyError,
  SecretDisabledError,
  SecretNotYetValidError,
  SecretExpiredError,
  IntegrityError,
  UnsupportedError,
  InvalidArgumentError,
  InvalidNameError,
  ManifestError,
  PermissionDeniedError,
  StorageError,
};

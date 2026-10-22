<?php

declare(strict_types=1);

namespace SourceOrrery;

use RuntimeException;

/**
 * A failed read. `$code` is the core's stable, append-only code, `$detail`
 * says what went wrong and `$hint` what to do about it; `getMessage()` is
 * both joined. None of them ever contains a secret value. Subclasses exist
 * for every code this version knows; a code added later maps to this class
 * and keeps its code.
 */
class SourceOrreryException extends RuntimeException
{
    public function __construct(
        public readonly string $detail,
        public readonly string $code_,
        public readonly string $hint = '',
    ) {
        parent::__construct($hint === '' ? $detail : "$detail. $hint");
    }

    /** Stable code (`not_found`, `locked`, ...). */
    public function code(): string
    {
        return $this->code_;
    }

    /** True when retrying later could succeed without administrative action. */
    public function isTransient(): bool
    {
        return $this->code_ === 'not_yet_valid';
    }

    /** The exception for a stable code. */
    public static function forCode(string $code, string $message, string $hint = ''): self
    {
        return match ($code) {
            'vault_not_found' => new VaultNotFoundException($message, $code, $hint),
            'locked' => new VaultLockedException($message, $code, $hint),
            'migration_required' => new MigrationRequiredException($message, $code, $hint),
            'vault_mismatch' => new VaultMismatchException($message, $code, $hint),
            'not_found' => new SecretNotFoundException($message, $code, $hint),
            'version_not_found' => new VersionNotFoundException($message, $code, $hint),
            'deleted' => new SecretDeletedException($message, $code, $hint),
            'disabled' => new SecretDisabledException($message, $code, $hint),
            'not_yet_valid' => new SecretNotYetValidException($message, $code, $hint),
            'expired' => new SecretExpiredException($message, $code, $hint),
            'crypto' => new IntegrityException($message, $code, $hint),
            'unsupported' => new UnsupportedException($message, $code, $hint),
            'invalid_argument' => new InvalidArgumentException($message, $code, $hint),
            'invalid_name' => new InvalidNameException($message, $code, $hint),
            'manifest' => new ManifestException($message, $code, $hint),
            'permission_denied' => new PermissionDeniedException($message, $code, $hint),
            'storage', 'io' => new StorageException($message, $code, $hint),
            default => new self($message, $code, $hint),
        };
    }
}

/** `vault_not_found`: no vault file with that name in the home directory. */
class VaultNotFoundException extends SourceOrreryException {}
/** `locked`: no protector or passphrase source could unlock the vault. */
class VaultLockedException extends SourceOrreryException {}
/** `migration_required`: run `sourceorrery vault migrate <name>` first. */
class MigrationRequiredException extends SourceOrreryException {}
/** `vault_mismatch`: the file found for the vault holds another vault (renamed, copied or swapped in). */
class VaultMismatchException extends SourceOrreryException {}
/** `not_found`: no secret with that name. */
class SecretNotFoundException extends SourceOrreryException {}
/** `version_not_found`: the secret exists but the version does not. */
class VersionNotFoundException extends SecretNotFoundException {}
/** `deleted`: the secret is soft-deleted; recover it before use. */
class SecretDeletedException extends SourceOrreryException {}
/** A version refused by policy: disabled, not yet valid or expired. */
class PolicyException extends SourceOrreryException {}
/** `disabled`: the version is disabled. */
class SecretDisabledException extends PolicyException {}
/** `not_yet_valid`: the version's activation time has not been reached. */
class SecretNotYetValidException extends PolicyException {}
/** `expired`: the version's expiry time has passed. */
class SecretExpiredException extends PolicyException {}
/** `crypto`: the vault file failed an integrity check. */
class IntegrityException extends SourceOrreryException {}
/** `unsupported`: no OS credential store here; use a passphrase. */
class UnsupportedException extends SourceOrreryException {}
/** `invalid_argument`: a malformed reference, version or option. */
class InvalidArgumentException extends SourceOrreryException {}
/** `invalid_name`: a secret or vault name breaks the naming rules. */
class InvalidNameException extends InvalidArgumentException {}
/** `manifest`: sourceorrery.toml is missing or invalid. */
class ManifestException extends SourceOrreryException {}
/** `permission_denied`: authenticated but not authorised. */
class PermissionDeniedException extends SourceOrreryException {}
/** `storage` / `io`: the vault file could not be read. */
class StorageException extends SourceOrreryException {}

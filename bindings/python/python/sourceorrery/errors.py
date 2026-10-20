"""Typed exceptions for every stable SourceOrrery error code.

Every exception carries the stable ``code`` (``not_found``, ``locked``, ...),
the ``message`` and a ``hint`` saying what to do about it, all produced by
the Rust core. None of them ever contains a secret value.
"""

from __future__ import annotations

__all__ = [
    "SourceOrreryError",
    "VaultNotFoundError",
    "VaultLockedError",
    "MigrationRequiredError",
    "SecretNotFoundError",
    "VersionNotFoundError",
    "SecretDeletedError",
    "PolicyError",
    "SecretDisabledError",
    "SecretNotYetValidError",
    "SecretExpiredError",
    "IntegrityError",
    "UnsupportedError",
    "InvalidArgumentError",
    "InvalidNameError",
    "ManifestError",
    "PermissionDeniedError",
    "StorageError",
    "error_for",
]


class SourceOrreryError(Exception):
    """Base class: a failed read, with the core's stable code and a hint."""

    #: Code used when the constructor is not given one.
    default_code: str = "internal"

    def __init__(self, message: str, code: str | None = None, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.hint = hint

    def __str__(self) -> str:
        return f"{self.message}. {self.hint}" if self.hint else self.message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"

    def __reduce__(self):  # keep code and hint through pickling
        return (type(self), (self.message, self.code, self.hint))

    @property
    def transient(self) -> bool:
        """True when retrying later could succeed without administrative action."""
        return self.code == "not_yet_valid"


class VaultNotFoundError(SourceOrreryError):
    """``vault_not_found``: no vault file with that name in the home directory."""

    default_code = "vault_not_found"


class VaultLockedError(SourceOrreryError):
    """``locked``: no protector or passphrase source could unlock the vault."""

    default_code = "locked"


class MigrationRequiredError(SourceOrreryError):
    """``migration_required``: run ``sourceorrery vault migrate <name>`` first."""

    default_code = "migration_required"


class SecretNotFoundError(SourceOrreryError):
    """``not_found``: no secret with that name."""

    default_code = "not_found"


class VersionNotFoundError(SecretNotFoundError):
    """``version_not_found``: the secret exists but the version does not."""

    default_code = "version_not_found"


class SecretDeletedError(SourceOrreryError):
    """``deleted``: the secret is soft-deleted; recover it before use."""

    default_code = "deleted"


class PolicyError(SourceOrreryError):
    """A version refused by policy: disabled, not yet valid or expired."""


class SecretDisabledError(PolicyError):
    """``disabled``: the version is disabled."""

    default_code = "disabled"


class SecretNotYetValidError(PolicyError):
    """``not_yet_valid``: the version's activation time has not been reached."""

    default_code = "not_yet_valid"


class SecretExpiredError(PolicyError):
    """``expired``: the version's expiry time has passed."""

    default_code = "expired"


class IntegrityError(SourceOrreryError):
    """``crypto``: the vault file failed an integrity check."""

    default_code = "crypto"


class UnsupportedError(SourceOrreryError):
    """``unsupported``: no OS credential store here; use a passphrase."""

    default_code = "unsupported"


class InvalidArgumentError(SourceOrreryError):
    """``invalid_argument``: a malformed reference, version or option."""

    default_code = "invalid_argument"


class InvalidNameError(InvalidArgumentError):
    """``invalid_name``: a secret or vault name breaks the naming rules."""

    default_code = "invalid_name"


class ManifestError(SourceOrreryError):
    """``manifest``: ``sourceorrery.toml`` is missing or invalid."""

    default_code = "manifest"


class PermissionDeniedError(SourceOrreryError):
    """``permission_denied``: authenticated but not authorised."""

    default_code = "permission_denied"


class StorageError(SourceOrreryError):
    """``storage`` / ``io``: the vault file could not be read."""

    default_code = "storage"


_BY_CODE: dict[str, type[SourceOrreryError]] = {
    "vault_not_found": VaultNotFoundError,
    "locked": VaultLockedError,
    "migration_required": MigrationRequiredError,
    "not_found": SecretNotFoundError,
    "version_not_found": VersionNotFoundError,
    "deleted": SecretDeletedError,
    "disabled": SecretDisabledError,
    "not_yet_valid": SecretNotYetValidError,
    "expired": SecretExpiredError,
    "crypto": IntegrityError,
    "unsupported": UnsupportedError,
    "invalid_argument": InvalidArgumentError,
    "invalid_name": InvalidNameError,
    "manifest": ManifestError,
    "permission_denied": PermissionDeniedError,
    "storage": StorageError,
    "io": StorageError,
}


def error_for(code: str, message: str, hint: str = "") -> SourceOrreryError:
    """The exception instance for a stable code. Unknown codes (added after
    this package was written) map to :class:`SourceOrreryError` and keep
    their code."""
    cls = _BY_CODE.get(code, SourceOrreryError)
    return cls(message, code, hint)

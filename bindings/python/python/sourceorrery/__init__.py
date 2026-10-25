"""Read secrets from a SourceOrrery vault.

    from sourceorrery import SecretReader

    with SecretReader("development") as reader:
        with reader.get("database-password") as secret:
            connect(password=secret.value.expose_text())

The package only reads: there is no way to create, change or delete a
secret, and no key, check, connection or audit management. Administration
is the CLI's job. All semantics live in the Rust core; this package converts types and
raises the typed exceptions in :mod:`sourceorrery.errors`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping

from . import _native
from ._native import SecretValue, contract_version
from .errors import (
    IntegrityError,
    InvalidArgumentError,
    InvalidNameError,
    ManifestError,
    MigrationRequiredError,
    PermissionDeniedError,
    PolicyError,
    ProviderUnavailableError,
    SecretDeletedError,
    SecretDisabledError,
    SecretExpiredError,
    SecretNotFoundError,
    SecretNotYetValidError,
    SourceOrreryError,
    StorageError,
    UnauthenticatedError,
    UnsupportedError,
    VaultLockedError,
    VaultMismatchError,
    VaultNotFoundError,
    VersionNotFoundError,
)

__all__ = [
    "SecretReader",
    "Secret",
    "SecretProperties",
    "SecretValue",
    "Project",
    "ProjectSecret",
    "load_project",
    "contract_version",
    "SourceOrreryError",
    "VaultNotFoundError",
    "VaultLockedError",
    "MigrationRequiredError",
    "VaultMismatchError",
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
    "UnauthenticatedError",
    "ProviderUnavailableError",
]

__version__ = "0.3.0"

PathLike = str | os.PathLike[str]


def _timestamp(text: str | None) -> datetime | None:
    return None if text is None else datetime.fromisoformat(text)


def _recovery_key_bytes(recovery_key: str | bytes | None) -> bytes | None:
    if recovery_key is None:
        return None
    return recovery_key.encode("utf-8") if isinstance(recovery_key, str) else bytes(recovery_key)


@dataclass(frozen=True)
class SecretProperties:
    """Metadata of one version. Never contains the value."""

    vault: str
    name: str
    version: str
    enabled: bool
    created_on: datetime
    updated_on: datetime
    recovery_level: str
    content_type: str | None = None
    tags: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    not_before: datetime | None = None
    expires_on: datetime | None = None

    @property
    def reference(self) -> str:
        """``sourceorrery://vault/name/version`` for exactly this version."""
        return f"sourceorrery://{self.vault}/{self.name}/{self.version}"

    @classmethod
    def _from_json(cls, text: str) -> SecretProperties:
        raw: dict[str, Any] = json.loads(text)
        return cls(
            vault=raw["vault"],
            name=raw["name"],
            version=raw["version"],
            enabled=raw["enabled"],
            created_on=_timestamp(raw["created_on"]),  # type: ignore[arg-type]
            updated_on=_timestamp(raw["updated_on"]),  # type: ignore[arg-type]
            recovery_level=raw.get("recovery_level", "recoverable"),
            content_type=raw.get("content_type"),
            tags=MappingProxyType(dict(raw.get("tags", {}))),
            not_before=_timestamp(raw.get("not_before")),
            expires_on=_timestamp(raw.get("expires_on")),
        )


@dataclass(frozen=True)
class Secret:
    """A version's metadata and its value.

    Use it as a context manager (or call :meth:`close`) to zeroise the value
    once it has been used.
    """

    properties: SecretProperties
    value: SecretValue

    def close(self) -> None:
        self.value.close()

    def __enter__(self) -> Secret:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class SecretReader:
    """A read-only, thread-safe handle on one vault.

    ``vault`` is the vault name. The vault is looked up under ``home`` (or
    ``SOURCEORRERY_HOME``, or the platform data directory) and unlocked, in
    order, by the OS credential store, ``recovery_key``,
    ``SOURCEORRERY_RECOVERY_KEY`` and ``recovery_key_file`` /
    ``SOURCEORRERY_RECOVERY_KEY_FILE``. Pass ``environment=False`` to ignore
    the two recovery-key variables. There is never an interactive prompt.

    A secret one of the vault's connections stores is read at that
    provider, with the credentials the connection stores or the ones the
    provider's own tools find in the environment.
    """

    def __init__(
        self,
        vault: str,
        *,
        home: PathLike | None = None,
        recovery_key: str | bytes | None = None,
        recovery_key_file: PathLike | None = None,
        environment: bool = True,
    ) -> None:
        self._native = _native.Reader(
            vault,
            home=None if home is None else os.fspath(home),
            recovery_key=_recovery_key_bytes(recovery_key),
            recovery_key_file=None if recovery_key_file is None else os.fspath(recovery_key_file),
            environment=environment,
        )
        self._vault = vault

    @property
    def vault_name(self) -> str:
        return self._vault

    @property
    def closed(self) -> bool:
        return self._native.closed

    def get(self, name: str, version: str | None = None) -> Secret:
        """The newest accessible version of ``name`` (enabled, inside its
        time window), or exactly ``version``. Policy refusals raise
        :class:`PolicyError` subclasses."""
        properties, value = self._native.get(name, version)
        return Secret(SecretProperties._from_json(properties), value)

    def properties(self, name: str, version: str | None = None) -> SecretProperties:
        """Metadata only; policy is not applied, so disabled and expired
        versions can be inspected."""
        return SecretProperties._from_json(self._native.properties(name, version))

    def resolve(self, reference: str) -> Secret:
        """Resolve ``sourceorrery://vault/name[/version]``; the vault must be
        this reader's."""
        properties, value = self._native.resolve(reference)
        return Secret(SecretProperties._from_json(properties), value)

    def descriptor(self) -> dict[str, Any]:
        """Non-sensitive description of the vault (name, id, path, protectors)."""
        return json.loads(self._native.descriptor())

    def close(self) -> None:
        """Release the vault; the key held in memory is zeroised."""
        self._native.close()

    def __enter__(self) -> SecretReader:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"SecretReader(vault={self._vault!r})"


@dataclass(frozen=True)
class ProjectSecret:
    """One secret resolved from ``sourceorrery.toml``."""

    name: str
    env: str
    reference: str
    required: bool
    properties: SecretProperties
    value: SecretValue


class Project:
    """The secrets a ``sourceorrery.toml`` declares, resolved like
    ``sourceorrery run``: every required secret must resolve or
    :meth:`load` raises that secret's error; optional secrets that are
    missing, refused by policy or in a vault that does not exist are left
    out."""

    def __init__(self, name: str, manifest_path: str, secrets: list[ProjectSecret]) -> None:
        self._name = name
        self._manifest_path = manifest_path
        self._secrets = secrets

    @classmethod
    def load(
        cls,
        manifest: PathLike | None = None,
        *,
        home: PathLike | None = None,
        recovery_key: str | bytes | None = None,
        recovery_key_file: PathLike | None = None,
        environment: bool = True,
    ) -> Project:
        """Load ``manifest`` (default: the nearest ``sourceorrery.toml``
        above the current directory). Unlock options as for
        :class:`SecretReader`, for the vault the manifest names."""
        info_text, entries = _native.load_project(
            manifest=None if manifest is None else os.fspath(manifest),
            home=None if home is None else os.fspath(home),
            recovery_key=_recovery_key_bytes(recovery_key),
            recovery_key_file=None if recovery_key_file is None else os.fspath(recovery_key_file),
            environment=environment,
        )
        info = json.loads(info_text)
        secrets = []
        for entry_text, value in entries:
            entry = json.loads(entry_text)
            secrets.append(
                ProjectSecret(
                    name=entry["name"],
                    env=entry["env"],
                    reference=entry["reference"],
                    required=entry["required"],
                    properties=SecretProperties._from_json(json.dumps(entry["properties"])),
                    value=value,
                )
            )
        return cls(info["name"], info["manifest_path"], secrets)

    @property
    def name(self) -> str:
        return self._name

    @property
    def manifest_path(self) -> str:
        return self._manifest_path

    @property
    def secrets(self) -> list[ProjectSecret]:
        return list(self._secrets)

    def get(self, name: str) -> ProjectSecret | None:
        """The entry declared as ``[secrets.<name>]``, if it resolved."""
        return next((s for s in self._secrets if s.name == name), None)

    def env(self, variable: str) -> SecretValue | None:
        """The value delivered in environment variable ``variable``, if any."""
        return next((s.value for s in self._secrets if s.env == variable), None)

    def close(self) -> None:
        """Zeroise every value."""
        for secret in self._secrets:
            secret.value.close()

    def __enter__(self) -> Project:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __len__(self) -> int:
        return len(self._secrets)

    def __iter__(self):
        return iter(self._secrets)

    def __repr__(self) -> str:
        return f"Project(name={self._name!r}, secrets={[s.name for s in self._secrets]!r})"


def load_project(
    manifest: PathLike | None = None,
    *,
    home: PathLike | None = None,
    recovery_key: str | bytes | None = None,
    recovery_key_file: PathLike | None = None,
    environment: bool = True,
) -> Project:
    """Shorthand for :meth:`Project.load`."""
    return Project.load(
        manifest,
        home=home,
        recovery_key=recovery_key,
        recovery_key_file=recovery_key_file,
        environment=environment,
    )

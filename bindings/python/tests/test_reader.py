"""The Python SDK against the CI fixture vault (read-only semantics)."""

from __future__ import annotations

import copy
import json
import pickle
import threading
from datetime import datetime, timezone

import pytest

import sourceorrery
from sourceorrery import (
    InvalidArgumentError,
    InvalidNameError,
    ManifestError,
    PolicyError,
    Project,
    ProviderUnavailableError,
    SecretDeletedError,
    SecretDisabledError,
    SecretExpiredError,
    SecretNotFoundError,
    SecretNotYetValidError,
    SecretReader,
    SecretValue,
    SourceOrreryError,
    UnauthenticatedError,
    VaultLockedError,
    VaultNotFoundError,
    VersionNotFoundError,
)


@pytest.fixture
def reader(fixture):
    # Unlocks through SOURCEORRERY_PASSPHRASE from the environment, like the CLI.
    with SecretReader(fixture.vault) as reader:
        yield reader


def test_contract_version():
    assert sourceorrery.contract_version() == "1"


def test_get_returns_the_newest_accessible_version(reader, fixture):
    with reader.get("database-password") as secret:
        assert secret.value.expose() == fixture.LATEST
        assert secret.value.expose_text() == fixture.LATEST.decode()
        assert len(secret.value) == len(fixture.LATEST)
        assert secret.properties.name == "database-password"
        assert secret.properties.vault == fixture.vault
        assert secret.properties.enabled is True
        assert secret.properties.content_type == "text/plain"
        assert dict(secret.properties.tags) == {"env": "ci"}
        assert secret.properties.created_on.tzinfo is not None
        assert secret.properties.created_on <= datetime.now(timezone.utc)
        assert secret.properties.reference == (
            f"sourceorrery://{fixture.vault}/database-password/{secret.properties.version}"
        )
    assert secret.value.closed


def test_explicit_version_and_properties(reader, fixture):
    old = reader.get("database-password", fixture.old_version)
    assert old.value.expose() == fixture.FIRST
    assert old.properties.version == fixture.old_version
    assert reader.properties("database-password", fixture.old_version).version == fixture.old_version
    newest = reader.properties("database-password")
    assert newest.version != fixture.old_version


def test_references_resolve_within_the_vault(reader, fixture):
    latest = reader.resolve(f"sourceorrery://{fixture.vault}/database-password")
    assert latest.value.expose() == fixture.LATEST
    pinned = reader.resolve(f"sourceorrery://{fixture.vault}/database-password/{fixture.old_version}")
    assert pinned.value.expose() == fixture.FIRST
    with pytest.raises(InvalidArgumentError) as info:
        reader.resolve("sourceorrery://other-vault/database-password")
    assert info.value.code == "invalid_argument"
    with pytest.raises(InvalidArgumentError):
        reader.resolve("not-a-reference")


def test_disabled_newest_version_falls_back(reader):
    current = reader.get("rotated-key")
    assert current.value.expose() == b"old"
    newest = reader.properties("rotated-key")
    assert newest.enabled is False
    with pytest.raises(SecretDisabledError) as info:
        reader.get("rotated-key", newest.version)
    assert isinstance(info.value, PolicyError)
    assert info.value.code == "disabled"
    assert "--enable" in info.value.hint


def test_policy_errors_explain_themselves(reader):
    with pytest.raises(SecretExpiredError) as expired:
        reader.get("expired-token")
    assert expired.value.hint.startswith("Policy")
    assert not expired.value.transient
    with pytest.raises(SecretNotYetValidError) as pending:
        reader.get("future-token")
    assert pending.value.transient
    with pytest.raises(SecretDeletedError) as deleted:
        reader.get("deleted-secret")
    assert "secret recover deleted-secret" in deleted.value.hint


def test_missing_secrets_say_how_to_store_them(reader, fixture):
    with pytest.raises(SecretNotFoundError) as info:
        reader.get("missing")
    err = info.value
    assert err.code == "not_found"
    assert err.message == "secret 'missing' was not found"
    assert f"sourceorrery secret set missing --vault {fixture.vault}" in err.hint
    assert str(err).startswith(err.message + ". ")
    assert repr(err) == "SecretNotFoundError(code='not_found', message=\"secret 'missing' was not found\")"
    with pytest.raises(VersionNotFoundError) as version:
        reader.get("database-password", "deadbeef")
    assert isinstance(version.value, SecretNotFoundError)
    with pytest.raises(InvalidNameError):
        reader.get("bad_name")
    restored = pickle.loads(pickle.dumps(err))
    assert restored.code == "not_found" and restored.hint == err.hint


def test_vault_errors_say_how_to_fix_them(fixture):
    with pytest.raises(VaultNotFoundError) as missing:
        SecretReader("no-such-vault")
    assert "sourceorrery vault create no-such-vault" in missing.value.hint
    assert fixture.home in missing.value.hint

    with pytest.raises(VaultLockedError) as locked:
        SecretReader(fixture.vault, passphrase="wrong-passphrase", environment=False)
    hint = locked.value.hint
    assert "passphrase option: tried" in hint
    assert "SOURCEORRERY_PASSPHRASE: not set" in hint
    assert f"--vault {fixture.vault}" in hint
    assert "wrong-passphrase" not in str(locked.value)

    # An explicit passphrase and an explicit home work without the environment.
    with SecretReader(
        fixture.vault, home=fixture.home, passphrase=fixture.passphrase, environment=False
    ) as reader:
        assert reader.vault_name == fixture.vault
        assert reader.descriptor()["name"] == fixture.vault
        assert "passphrase" in reader.descriptor()["protectors"]


def test_secret_values_do_not_leak(reader, fixture):
    secret = reader.get("database-password")
    value = secret.value
    assert isinstance(value, SecretValue)
    assert repr(value) == "SecretValue([REDACTED])"
    assert str(value) == "[REDACTED]"
    assert fixture.LATEST.decode() not in repr(secret)
    assert fixture.LATEST.decode() not in repr(secret.properties)
    with pytest.raises(TypeError):
        pickle.dumps(value)
    with pytest.raises(TypeError):
        copy.copy(value)
    with pytest.raises(TypeError):
        json.dumps(value)
    with pytest.raises(TypeError):
        json.dumps({"secret": secret.value})
    value.close()
    assert value.closed
    assert len(value) == 0
    with pytest.raises(ValueError):
        value.expose()
    value.close()  # idempotent


def test_reader_is_closed_explicitly(fixture):
    reader = SecretReader(fixture.vault)
    reader.close()
    assert reader.closed
    with pytest.raises(ValueError):
        reader.get("database-password")
    reader.close()


def test_reader_is_thread_safe(reader, fixture):
    failures: list[BaseException] = []

    def work() -> None:
        try:
            for _ in range(5):
                # Recorded, not asserted: an assert here would be caught below.
                if reader.get("database-password").value.expose() != fixture.LATEST:
                    failures.append(RuntimeError("a thread read another value"))
            with pytest.raises(SecretNotFoundError):
                reader.get("missing")
        except BaseException as exc:  # noqa: BLE001 - reported below
            failures.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not failures


def test_project_load_mirrors_run(fixture):
    with Project.load(fixture.manifest) as project:
        assert project.name == "ci-project"
        assert project.manifest_path.endswith("sourceorrery.toml")
        assert sorted(s.name for s in project) == ["database-password", "rotated-key"]
        assert project.env("DATABASE_PASSWORD").expose() == fixture.LATEST
        assert project.env("ROTATED").expose() == b"old"
        assert project.get("missing-optional") is None, "optional misses are skipped"
        assert project.get("expired-token") is None, "optional policy refusals are skipped"
        entry = project.get("rotated-key")
        assert entry.required and entry.env == "ROTATED"
        assert entry.reference == f"sourceorrery://{fixture.vault}/rotated-key"
        assert len(project) == 2
    assert project.env("ROTATED").closed

    assert sourceorrery.load_project(fixture.manifest).name == "ci-project"
    with pytest.raises(ManifestError):
        Project.load(fixture.manifest + ".missing")
    with pytest.raises(VaultLockedError):
        Project.load(fixture.manifest, passphrase="wrong", environment=False)


def test_unknown_codes_keep_their_code():
    err = sourceorrery.errors.error_for("brand_new_code", "m", "h")
    assert type(err) is SourceOrreryError
    assert err.code == "brand_new_code"


def test_provider_codes_map_to_typed_errors():
    unauthenticated = sourceorrery.errors.error_for("unauthenticated", "m", "h")
    assert type(unauthenticated) is UnauthenticatedError
    assert unauthenticated.code == "unauthenticated"
    assert not unauthenticated.transient
    unavailable = sourceorrery.errors.error_for("provider_unavailable", "m", "h")
    assert type(unavailable) is ProviderUnavailableError
    assert unavailable.code == "provider_unavailable"
    assert unavailable.transient
    assert UnauthenticatedError("m").code == "unauthenticated"
    assert ProviderUnavailableError("m").code == "provider_unavailable"


def test_a_remote_vault_in_the_manifest_is_opened_at_its_provider(fixture, tmp_path, monkeypatch):
    manifest = tmp_path / "sourceorrery.toml"
    manifest.write_text(
        "[project]\n"
        'name = "demo"\n'
        f'vault = "{fixture.vault}"\n'
        "\n"
        "[vaults.remote-x]\n"
        'provider = "hashicorp-vault"\n'
        'address = "http://127.0.0.1:1"\n'  # nothing listens here
        'mount = "secret"\n'
    )
    options = dict(home=fixture.home, passphrase=fixture.passphrase, environment=False)

    # With a credential, the remote vault is opened at its provider, which is not there.
    monkeypatch.setenv("VAULT_TOKEN", "dummy-token-for-tests")
    with pytest.raises(ProviderUnavailableError) as info:
        SecretReader("remote-x", manifest=manifest, **options)
    assert info.value.code == "provider_unavailable"
    assert info.value.transient
    assert "hashicorp-vault is unavailable" in info.value.message
    assert "[vaults.remote-x]" in info.value.hint

    # Without one, the provider refuses before any request, unless the developer
    # running the tests has a ~/.vault-token or another Vault credential around.
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with pytest.raises((UnauthenticatedError, ProviderUnavailableError)) as info:
        SecretReader("remote-x", manifest=manifest, **options)
    if isinstance(info.value, UnauthenticatedError):
        assert info.value.code == "unauthenticated"
        assert not info.value.transient
        assert "not authenticated to hashicorp-vault" in info.value.message
        assert "VAULT_TOKEN" in info.value.hint
    else:
        assert info.value.code == "provider_unavailable"

    # A vault without a `[vaults.<name>]` table is still the local file.
    with SecretReader(fixture.vault, manifest=manifest, **options) as reader:
        assert reader.get("database-password").value.expose() == fixture.LATEST

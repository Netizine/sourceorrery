"""Shared fixture: the vault created by scripts/ci/fixture-vault.sh.

The suite never creates vaults itself (the package cannot write); CI runs
the script first and exports the variables below. Locally:

    eval "$(bash scripts/ci/fixture-vault.sh)"
    pytest bindings/python
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import pytest


@dataclass(frozen=True)
class Fixture:
    home: str
    passphrase: str
    vault: str
    manifest: str
    old_version: str

    # Values the fixture script stores; see its header.
    LATEST = b"ci-secret-value"
    FIRST = b"first-version"


@pytest.fixture(scope="session")
def fixture() -> Fixture:
    try:
        return Fixture(
            home=os.environ["SOURCEORRERY_HOME"],
            passphrase=os.environ["SOURCEORRERY_PASSPHRASE"],
            vault=os.environ["SOURCEORRERY_TEST_VAULT"],
            manifest=os.environ["SOURCEORRERY_TEST_MANIFEST"],
            old_version=os.environ["SOURCEORRERY_TEST_OLD_VERSION"],
        )
    except KeyError as missing:
        pytest.skip(f"{missing} is not set; run scripts/ci/fixture-vault.sh first")

#!/usr/bin/env python3
"""Create a Key Vault on an Azure emulator and print its URL.

    python3 scripts/ci/azure-vault.py <vault-name>

For the CI jobs that run the Azure Key Vault provider against LocalStack for
Azure (scripts/ci/localstack.sh). The emulator's endpoint comes from
SOURCEORRERY_AZURE_TEST_ENDPOINT and the identity from AZURE_TENANT_ID,
AZURE_CLIENT_ID and AZURE_CLIENT_SECRET, placeholders the emulator accepts;
the vault is created through its Resource Manager with role-based access
and a 7-day soft-delete retention. The identity that creates the vault can
use it; any other is refused while LS_AZURE_ENFORCE_RBAC is on. Never point
this at Azure itself.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse
import urllib.request

SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
RESOURCE_GROUP = "rg-sourceorrery-ci"
NAME = re.compile(r"^[a-z][a-z0-9-]{1,22}[a-z0-9]$")


def request(method: str, url: str, body: dict | None = None, token: str | None = None,
            form: dict | None = None) -> dict:
    headers = {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, data=data, method=method, headers=headers),
                                timeout=60) as response:
        return json.loads(response.read() or b"{}")


def create_vault(endpoint: str, name: str, env: dict[str, str]) -> str:
    """The URL of a new vault called `name` on the emulator at `endpoint`."""
    if not NAME.match(name):
        raise ValueError("a vault name is 3-24 lowercase letters, digits and hyphens, starting with a letter")
    if not endpoint.startswith("https://"):
        raise ValueError("the emulator endpoint must be an https:// URL")
    tenant = env["AZURE_TENANT_ID"]
    token = request("POST", f"{endpoint}/{tenant}/oauth2/v2.0/token", form={
        "grant_type": "client_credentials",
        "client_id": env["AZURE_CLIENT_ID"],
        "client_secret": env["AZURE_CLIENT_SECRET"],
        "scope": "https://management.azure.com/.default",
    })["access_token"]
    group = f"{endpoint}/subscriptions/{SUBSCRIPTION}/resourcegroups/{RESOURCE_GROUP}"
    request("PUT", f"{group}?api-version=2021-04-01", {"location": "westeurope"}, token)
    vault = request("PUT", f"{group}/providers/Microsoft.KeyVault/vaults/{name}?api-version=2023-07-01", {
        "location": "westeurope",
        "properties": {
            "tenantId": tenant,
            "sku": {"family": "A", "name": "standard"},
            "accessPolicies": [],
            "enableRbacAuthorization": True,
            "enableSoftDelete": True,
            "softDeleteRetentionInDays": 7,
        },
    }, token)
    return vault["properties"]["vaultUri"]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    endpoint = os.environ.get("SOURCEORRERY_AZURE_TEST_ENDPOINT", "").rstrip("/")
    try:
        print(create_vault(endpoint, argv[1], dict(os.environ)))
    except (KeyError, ValueError, OSError) as error:
        print(f"azure-vault: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

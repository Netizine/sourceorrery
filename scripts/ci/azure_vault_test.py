"""azure-vault.py creates emulator vaults only, with the settings the tests rely on."""

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("azure_vault", HERE / "azure-vault.py")
azure_vault = importlib.util.module_from_spec(spec)
spec.loader.exec_module(azure_vault)

ENV = {"AZURE_TENANT_ID": "00000000-0000-0000-0000-000000000000",
       "AZURE_CLIENT_ID": "ci", "AZURE_CLIENT_SECRET": "placeholder"}


class AzureVaultTests(unittest.TestCase):
    def test_creates_a_role_based_vault_with_a_short_retention(self):
        calls = []

        def fake(method, url, body=None, token=None, form=None):
            calls.append((method, url, body, token, form))
            if url.endswith("/oauth2/v2.0/token"):
                return {"access_token": "t"}
            if "/vaults/" in url:
                return {"properties": {"vaultUri": "https://kv1.vault.example:4566/"}}
            return {}

        with mock.patch.object(azure_vault, "request", fake):
            url = azure_vault.create_vault("https://emulator.example:4566", "kv1", ENV)
        self.assertEqual(url, "https://kv1.vault.example:4566/")
        token, group, vault = calls
        self.assertEqual(token[4]["scope"], "https://management.azure.com/.default")
        self.assertTrue(group[1].endswith("/resourcegroups/rg-sourceorrery-ci?api-version=2021-04-01"))
        properties = vault[2]["properties"]
        self.assertTrue(properties["enableRbacAuthorization"])
        self.assertEqual(properties["softDeleteRetentionInDays"], 7)
        self.assertEqual(vault[3], "t")

    def test_names_and_endpoints_are_checked_before_any_request(self):
        with mock.patch.object(azure_vault, "request", side_effect=AssertionError("no request")):
            for name in ["kv", "Upper", "9starts-with-digit", "ends-", "x" * 25]:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    azure_vault.create_vault("https://emulator.example", name, ENV)
            with self.assertRaises(ValueError):
                azure_vault.create_vault("http://emulator.example", "kv1", ENV)

    def test_missing_settings_fail_without_a_traceback(self):
        with mock.patch.dict("os.environ", {"SOURCEORRERY_AZURE_TEST_ENDPOINT": ""}, clear=True):
            self.assertEqual(azure_vault.main(["azure-vault.py", "kv1"]), 1)
        self.assertEqual(azure_vault.main(["azure-vault.py"]), 2)


if __name__ == "__main__":
    unittest.main()

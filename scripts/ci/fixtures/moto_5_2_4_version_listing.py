"""Moto 5.2.4's original listing method, with neighbouring fields to preserve.

Source: https://github.com/getmoto/moto/blob/5.2.4/moto/secretsmanager/models.py#L940-L960
Moto is licensed under Apache-2.0.
"""

import json
import time


class SecretsManagerBackend:
    def another_operation(self):
        return {"CreatedDate": int(time.time())}

    def list_secret_version_ids(self, secret_id: str) -> str:
        secret = self.secrets[secret_id]

        version_list = []
        for version_id, version in secret.versions.items():
            version_list.append(
                {
                    "CreatedDate": int(time.time()),
                    "LastAccessedDate": int(time.time()),
                    "VersionId": version_id,
                    "VersionStages": version["version_stages"],
                }
            )
        return json.dumps(
            {
                "ARN": secret.secret_id,
                "Name": secret.name,
                "NextToken": "",
                "Versions": version_list,
            }
        )

    def a_later_operation(self):
        return {"CreatedDate": int(time.time())}

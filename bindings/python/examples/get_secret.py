"""Read one secret and report its size, never its value.

    pip install sourceorrery
    export SOURCEORRERY_PASSPHRASE=...   # or rely on the OS credential store
    python get_secret.py development database-password
"""

import sys

from sourceorrery import SecretReader, SourceOrreryError


def main(vault: str, name: str) -> int:
    try:
        with SecretReader(vault) as reader, reader.get(name) as secret:
            # secret.value is zeroised when the `with` block ends.
            print(f"{name} version {secret.properties.version} from vault {vault}: "
                  f"{len(secret.value)} bytes")
            return 0
    except SourceOrreryError as err:
        # err.code is stable; str(err) is the message plus a hint. No values.
        print(f"error [{err.code}]: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    args = sys.argv[1:]
    sys.exit(main(args[0] if args else "development", args[1] if len(args) > 1 else "database-password"))

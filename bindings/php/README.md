# sourceorrery/sourceorrery (PHP)

**Read secrets from [SourceOrrery](https://sourceorrery.ai) vaults in
PHP.** Secrets belong to the runtime, not the repository.

```php
use SourceOrrery\SecretReader;

$reader = SecretReader::open('development');
$secret = $reader->get('database-password');
connect(password: $secret->value->expose());
$secret->close();   // zeroises the value
```

SourceOrrery replaces the plaintext `.env` file with an encrypted local
vault. This package is its read-only PHP SDK: it opens a vault, reads the
newest accessible version of a secret (or an exact version), its
properties and `sourceorrery://` references, and loads every secret a
project's `sourceorrery.toml` declares. It cannot create, change or delete
a secret through its public API; reads still append audit events.

Documentation: [the PHP guide](https://sourceorrery.ai/sdks/php/) ·
[Getting started](https://sourceorrery.ai/getting-started/) ·
[Threat model](https://sourceorrery.ai/security/threat-model/)

## Before you start: the CLI

### Option 1: Set up with the CLI

This SDK is read-only. Use the separately installed `sourceorrery` CLI to
create vaults and set secret values. Composer does not install the CLI. Follow
the [CLI installation guide](https://sourceorrery.ai/getting-started/#install), then:

```bash
sourceorrery vault create development
sourceorrery secret set database-password --vault development   # typed at a hidden prompt
```

The CLI does not have to be installed where your application runs: this
package opens the vault file itself, through the native library below.

### Option 2: Set up with an AI coding agent

```bash
sourceorrery init --integration all
```

Use your existing coding agent and ask: "Set up SourceOrrery for this
project without showing secret values." Replace `all` with your agent's
name to install only its skills. The agent handles the manifest, code and
launch commands; you create vaults and enter values privately.
The [agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
also covers updating skills from the repository independently of the CLI.

## Install

```bash
composer require sourceorrery/sourceorrery
```

Requires PHP 8.2+ with the `ffi` extension (`ffi.enable=true`, or the
default `preload` setting for CLI scripts) and the native library
(`libsourceorrery_ffi.so` / `.dylib` / `sourceorrery_ffi.dll`), which
Composer does not install: it is in the
`sourceorrery-ffi-<version>-<target>` archive on the
[GitHub release](https://github.com/Netizine/sourceorrery/releases/latest),
matching the package's version. Put it in the directory named by
`SOURCEORRERY_NATIVE_DIR`, or under `bindings/php/native/<os>-<arch>/`
inside this package, or on the loader's search path. Step by step per
platform: [the PHP guide](https://sourceorrery.ai/sdks/php/#install).

## Errors and values

Every failure is a `SourceOrreryException` subclass
(`SecretNotFoundException`, `VaultLockedException`,
`SecretExpiredException`, …) with a stable `code()` and a `$hint` that
says what to do. A value is a `SecretValue`: it prints, encodes and dumps
as `[REDACTED]`, refuses `serialize()` and `clone`, gives its bytes only
through `expose()`, and `close()` zeroises them.

## Secrets at a provider

A secret that one of the vault's connections stores (HashiCorp Vault, AWS
Secrets Manager or Azure Key Vault) is read at that provider by the same
calls, with the credentials the connection stores or the ones the
provider's own tools find in the environment
([providers](https://sourceorrery.ai/providers/)); `UnauthenticatedException` /
`ProviderUnavailableException` (transient) report a provider's failures.

## How the package is published

The Composer manifest is `composer.json` at the repository root, because
Packagist reads only that file: the package it serves is the repository at
the release tag, with this directory's `src/` autoloaded (PSR-4, plus a
classmap for `SourceOrreryException.php` and `Project.php`, which hold more
than one class). `scripts/ci/php-package-install.sh` proves the install
from a tag; see *The PHP package and Packagist* in `docs/release.md`.

## Tests

```bash
cargo build --release -p sourceorrery-ffi -p sourceorrery-cli
eval "$(bash scripts/ci/fixture-vault.sh)"
php bindings/php/tests/run.php
```

Every step, with the prerequisites for each platform:
<https://sourceorrery.ai/sdks/php/#building-from-source>.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/bindings/php>.

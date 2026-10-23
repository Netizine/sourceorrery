# PHP

Requires PHP 8.2+ with the `ffi` extension. The default `ffi.enable=preload`
allows FFI in CLI scripts and preloaded files; set `ffi.enable=true` for
web SAPIs.

## Install

Two parts: the package, from Packagist, and the native library it loads,
from the release (or [built from source](#building-from-source)).

### The package, from Packagist

```bash
composer require sourceorrery/sourceorrery
```

[`sourceorrery/sourceorrery` on Packagist](https://packagist.org/packages/sourceorrery/sourceorrery)
has every release as a version named by its tag. The package is the
repository: Packagist reads `composer.json` at the repository root, so
what Composer installs into `vendor/sourceorrery/sourceorrery` is the tree
at that tag, with the SDK autoloaded from `bindings/php/src/`, and
`composer.lock` records the exact commit
([Supply chain](../supply-chain.md#composer)). To try an unreleased
revision, add `https://github.com/Netizine/sourceorrery` as a `vcs`
repository and require `dev-main`.

### The native library, from the release

The native library (`libsourceorrery_ffi.so` / `.dylib` /
`sourceorrery_ffi.dll`) is in the `sourceorrery-ffi-0.1.4-<target>` archive
on the
[v0.1.4 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.4).
Download the one for your platform, unpack it, and name the directory in
`SOURCEORRERY_NATIVE_DIR`:

<!-- tabs: os -->

#### Windows

```powershell
$release = "https://github.com/Netizine/sourceorrery/releases/download/v0.1.4"
$dir = "$env:LOCALAPPDATA\sourceorrery-ffi"
Invoke-WebRequest "$release/sourceorrery-ffi-0.1.4-x86_64-pc-windows-msvc.zip" -OutFile sourceorrery-ffi.zip   # aarch64-pc-windows-msvc on Arm
Expand-Archive sourceorrery-ffi.zip -DestinationPath $dir -Force
[Environment]::SetEnvironmentVariable("SOURCEORRERY_NATIVE_DIR", $dir, "User")
```

#### macOS

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.1.4
archive=sourceorrery-ffi-0.1.4-aarch64-apple-darwin        # x86_64-apple-darwin on Intel
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1
export SOURCEORRERY_NATIVE_DIR=/opt/sourceorrery
```

#### Linux

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.1.4
archive=sourceorrery-ffi-0.1.4-x86_64-unknown-linux-gnu    # aarch64-unknown-linux-gnu on arm64
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1
export SOURCEORRERY_NATIVE_DIR=/opt/sourceorrery
```

<!-- /tabs -->

Verify a download against the release's `SHA256SUMS` before unpacking it.
Instead of the variable, the library can also sit under
`bindings/php/native/<os>-<arch>/` inside the installed package, or on the
loader's search path.

## Get a secret

```php
use SourceOrrery\SecretReader;

$reader = SecretReader::open('development');
$secret = $reader->get('database-password');
connect(password: $secret->value->expose());
$secret->close();   // zeroises the value
$reader->close();
```

`SecretReader::open($vault)` behaves like the CLI: `SOURCEORRERY_HOME`
locates the vault; the OS credential store, then `SOURCEORRERY_PASSPHRASE`,
then `SOURCEORRERY_PASSPHRASE_FILE` unlock it.
`SecretReader::open($vault, new OpenOptions(home: .., passphrase: .., passphraseFile: .., environment: false, manifest: ..))`
overrides any of that. `manifest` names the `sourceorrery.toml` whose
`[vaults.<name>]` tables say which vaults are remote and at which provider
(default: the nearest one above the current directory); a vault with such
a table is opened at its provider instead of as a local file. Credentials
come from the provider's own environment, never from the manifest: [HashiCorp
Vault](../providers/hashicorp-vault.md) takes `VAULT_TOKEN` or the other
sources it documents, [AWS Secrets Manager](../providers/aws-secrets-manager.md)
the AWS default credential chain.

| Call | Returns |
|------|---------|
| `$reader->get($name)` | `Secret` for the newest accessible version |
| `$reader->get($name, $version)` | `Secret` for exactly that version |
| `$reader->properties($name, $version = null)` | `SecretProperties` (policy not applied) |
| `$reader->resolve('sourceorrery://development/database-password')` | `Secret` |
| `$reader->descriptor()` | array describing the vault (no values) |
| `$reader->close()` | releases the vault; the destructor does the same |

`$secret->properties` (`vault`, `name`, `version`, `enabled`,
`contentType`, `tags`, `notBefore`, `expiresOn`, `createdOn`, `updatedOn`
as `DateTimeImmutable`, `recoveryLevel`, `reference()`) and
`$secret->value`, a `SecretValue`:

```php
$value->expose();      // string (a copy)
$value->length();
$value->close();       // zeroise; expose() throws LogicException afterwards
(string) $value;       // "[REDACTED]"; json_encode and var_dump redact too; serialize() and clone refuse
```

## Errors

Every failure is a `SourceOrrery\SourceOrreryException` or a subclass with
`code()`, `$detail`, `$hint` and `getMessage()` (detail plus hint):

```php
use SourceOrrery\{SecretReader, SecretNotFoundException, VaultLockedException, SourceOrreryException};

try {
    $reader = SecretReader::open('development');
    $secret = $reader->get('database-password');
} catch (VaultLockedException $e) {
    error_log($e->hint);        // which passphrase sources were tried
} catch (SecretNotFoundException $e) {
    error_log($e->hint);        // "Store it with `sourceorrery secret set ...`"
} catch (SourceOrreryException $e) {
    error_log("{$e->code()}: {$e->getMessage()}");
}
```

Classes: `VaultNotFoundException`, `VaultLockedException`,
`MigrationRequiredException`, `VaultMismatchException`,
`SecretNotFoundException`, `VersionNotFoundException`,
`SecretDeletedException`, `PolicyException` with
`SecretDisabledException`, `SecretNotYetValidException` (`isTransient()`),
`SecretExpiredException`, `IntegrityException`, `UnsupportedException`,
`InvalidArgumentException`, `InvalidNameException`, `ManifestException`,
`PermissionDeniedException`, `StorageException`,
`UnauthenticatedException` (the remote provider has no credentials for
this process), `ProviderUnavailableException` (it could not be reached;
`isTransient()`). See [the SDK overview](index.md#errors).

## Load a project

```php
use SourceOrrery\Project;

$project = Project::load('sourceorrery.toml');   // or Project::load() to discover it
foreach ($project->secrets as $secret) {
    putenv("{$secret->env}={$secret->value->expose()}");
}
$project->close();
```

`Project::load` resolves every `[secrets.*]` entry the way `sourceorrery run`
does and throws the first required secret's exception if one cannot be read.

## Building from source

You need Git, Rust 1.91.1 or newer installed with rustup, and a C compiler
(on Linux also `pkg-config` and `libdbus-1-dev`);
[Building from source](../building.md#what-you-need) has the commands for
each platform. For this SDK, also PHP 8.2 or newer with the `ffi`
extension (on Windows, enable `extension=ffi` in `php.ini`) and Composer.

The PHP code needs no build; what you build is the native library it
loads:

```bash
git clone https://github.com/Netizine/sourceorrery
cd sourceorrery
git checkout v0.1.4              # or stay on main for the newest changes
cargo build --release -p sourceorrery-ffi
export SOURCEORRERY_NATIVE_DIR=/path/to/sourceorrery/target/release
# PowerShell: $env:SOURCEORRERY_NATIVE_DIR = "C:\path\to\sourceorrery\target\release"
```

With `SOURCEORRERY_NATIVE_DIR` naming `target/release`, the package from
Packagist (or the `vcs` repository above) uses the library you built.

To run the tests, the example and the conformance harness, build the CLI
too, which creates the test vault, and run the rest in Bash (Git Bash on
Windows) from the repository root:

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"       # a throwaway vault, the variables the tests read, SOURCEORRERY_NATIVE_DIR
composer validate --strict composer.json         # the manifest Packagist reads
php bindings/php/tests/run.php
php bindings/php/examples/get_secret.php "$SOURCEORRERY_TEST_VAULT" database-password
python tests/conformance/sdk/harness.py --runner php
```

The tests run from the command line, where PHP's default
`ffi.enable=preload` already allows FFI. What the fixture script creates:
[The SDK test vault](../building.md#the-sdk-test-vault).
Source: [`bindings/php`](../../bindings/php/README.md).

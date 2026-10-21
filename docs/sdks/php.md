# PHP

Requires PHP 8.2+ with the `ffi` extension. The default `ffi.enable=preload`
allows FFI in CLI scripts and preloaded files; set `ffi.enable=true` for
web SAPIs.

## Install

Two parts: the native library from the release, and the package from Packagist.

### The native library, from the release

The native library (`libsourceorrery_ffi.so` / `.dylib` /
`sourceorrery_ffi.dll`) is in the `sourceorrery-ffi-0.1.3-<target>` archive
on the
[v0.1.3 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.3).
Download the one for your platform, unpack it, and name the directory in
`SOURCEORRERY_NATIVE_DIR`:

<!-- tabs: os -->

#### Windows

```powershell
$release = "https://github.com/Netizine/sourceorrery/releases/download/v0.1.3"
$dir = "$env:LOCALAPPDATA\sourceorrery-ffi"
Invoke-WebRequest "$release/sourceorrery-ffi-0.1.3-x86_64-pc-windows-msvc.zip" -OutFile sourceorrery-ffi.zip   # aarch64-pc-windows-msvc on Arm
Expand-Archive sourceorrery-ffi.zip -DestinationPath $dir -Force
[Environment]::SetEnvironmentVariable("SOURCEORRERY_NATIVE_DIR", $dir, "User")
```

#### macOS

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.1.3
archive=sourceorrery-ffi-0.1.3-aarch64-apple-darwin        # x86_64-apple-darwin on Intel
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1
export SOURCEORRERY_NATIVE_DIR=/opt/sourceorrery
```

#### Linux

```bash
release=https://github.com/Netizine/sourceorrery/releases/download/v0.1.3
archive=sourceorrery-ffi-0.1.3-x86_64-unknown-linux-gnu    # aarch64-unknown-linux-gnu on arm64
curl -LO "$release/$archive.tar.gz"
sudo mkdir -p /opt/sourceorrery && sudo tar xzf "$archive.tar.gz" -C /opt/sourceorrery --strip-components=1
export SOURCEORRERY_NATIVE_DIR=/opt/sourceorrery
```

<!-- /tabs -->

Verify a download against the release's `SHA256SUMS` before unpacking it.
Instead of the variable, the library can also sit under `native/<os>-<arch>/`
next to the SDK's `src/` directory or on the loader's search path.

### The package, from Packagist

```bash
composer require sourceorrery/sourceorrery
```

Every release is a version on Packagist, named by its tag.

The package is the repository: Packagist reads `composer.json` at the
repository root, so what Composer installs into
`vendor/sourceorrery/sourceorrery` is the tree at that tag, with the SDK
autoloaded from `bindings/php/src/`. The native library still comes from
the release archive as above; `SOURCEORRERY_NATIVE_DIR` names its
directory, or put it under `bindings/php/native/<os>-<arch>/` inside the
installed package. To try an unreleased revision, add
`https://github.com/Netizine/sourceorrery` as a `vcs` repository and
require `dev-main`.

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
`SecretReader::open($vault, new OpenOptions(home: .., passphrase: .., passphraseFile: .., environment: false))`
overrides any of that.

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
`MigrationRequiredException`, `SecretNotFoundException`,
`VersionNotFoundException`, `SecretDeletedException`, `PolicyException`
with `SecretDisabledException`, `SecretNotYetValidException`
(`isTransient()`), `SecretExpiredException`, `IntegrityException`,
`UnsupportedException`, `InvalidArgumentException`, `InvalidNameException`,
`ManifestException`, `PermissionDeniedException`, `StorageException`. See
[the SDK overview](index.md#errors).

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

```bash
cargo build --release -p sourceorrery-ffi -p sourceorrery-cli
eval "$(bash scripts/ci/fixture-vault.sh)"
php bindings/php/tests/run.php
```

Source: [`bindings/php`](../../bindings/php/README.md).

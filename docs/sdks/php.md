# PHP

```bash
composer require sourceorrery/sourceorrery
```

Requires PHP 8.2+ with the `ffi` extension. The default `ffi.enable=preload`
allows FFI in CLI scripts and preloaded files; set `ffi.enable=true` for
web SAPIs. The native library (`libsourceorrery_ffi.so` / `.dylib` /
`sourceorrery_ffi.dll`) comes from the `sourceorrery-ffi-<version>-<target>`
release archive: put it in the directory named by `SOURCEORRERY_NATIVE_DIR`,
under `native/<os>-<arch>/` inside the package, or on the loader's search
path.

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

<?php
// The PHP SDK against the vault created by scripts/ci/fixture-vault.sh.
// Dependency-free: `php tests/run.php` exits non-zero on the first failure.

declare(strict_types=1);

require __DIR__ . '/../autoload.php';

use SourceOrrery\InvalidArgumentException;
use SourceOrrery\InvalidNameException;
use SourceOrrery\ManifestException;
use SourceOrrery\Native;
use SourceOrrery\OpenOptions;
use SourceOrrery\PolicyException;
use SourceOrrery\Project;
use SourceOrrery\ProviderUnavailableException;
use SourceOrrery\SecretDeletedException;
use SourceOrrery\SecretDisabledException;
use SourceOrrery\SecretExpiredException;
use SourceOrrery\SecretNotFoundException;
use SourceOrrery\SecretNotYetValidException;
use SourceOrrery\SecretReader;
use SourceOrrery\SourceOrrery;
use SourceOrrery\SourceOrreryException;
use SourceOrrery\UnauthenticatedException;
use SourceOrrery\UnsupportedException;
use SourceOrrery\VaultLockedException;
use SourceOrrery\VaultNotFoundException;
use SourceOrrery\VersionNotFoundException;

$env = static function (string $name): string {
    $value = getenv($name);
    if (!is_string($value) || $value === '') {
        fwrite(STDERR, "$name is not set; run scripts/ci/fixture-vault.sh first\n");
        exit(2);
    }
    return $value;
};
$home = $env('SOURCEORRERY_HOME');
$passphrase = $env('SOURCEORRERY_PASSPHRASE');
$vault = $env('SOURCEORRERY_TEST_VAULT');
$manifest = $env('SOURCEORRERY_TEST_MANIFEST');
$oldVersion = $env('SOURCEORRERY_TEST_OLD_VERSION');
const LATEST = 'ci-secret-value';
const FIRST = 'first-version';

$failures = 0;
function check(bool $condition, string $what): void
{
    global $failures;
    if (!$condition) {
        fwrite(STDERR, "CHECK failed: $what\n");
        $failures++;
    }
}
/** @param class-string<SourceOrreryException> $class */
function expectThrow(callable $f, string $class, string $code, string $hintContains = ''): ?SourceOrreryException
{
    try {
        $f();
        check(false, "expected $code to be thrown");
        return null;
    } catch (SourceOrreryException $e) {
        check($e instanceof $class, "expected $class for $code, got " . $e::class);
        check($e->code() === $code, "expected code $code, got {$e->code()}");
        if ($hintContains !== '') {
            check(str_contains($e->hint, $hintContains), "hint '{$e->hint}' does not contain '$hintContains'");
        }
        return $e;
    }
}

check(SourceOrrery::contractVersion() === '1', 'contract version');
check(SourceOrrery::abiVersion() === 1, 'abi version');

// Unlocked through SOURCEORRERY_PASSPHRASE from the environment, like the CLI.
$reader = SecretReader::open($vault);
check($reader->vaultName() === $vault, 'vault name');

$secret = $reader->get('database-password');
check($secret->value->expose() === LATEST, 'latest value');
check($secret->value->length() === strlen(LATEST), 'length');
check($secret->properties->name === 'database-password', 'name');
check($secret->properties->vault === $vault, 'vault');
check($secret->properties->enabled, 'enabled');
check($secret->properties->contentType === 'text/plain', 'content type');
check($secret->properties->tags === ['env' => 'ci'], 'tags');
check($secret->properties->createdOn <= new DateTimeImmutable(), 'created_on');
check($secret->properties->reference() === "sourceorrery://$vault/database-password/{$secret->properties->version}", 'reference');
check((string) $secret->value === '[REDACTED]', 'string cast');
check(json_encode(['v' => $secret->value]) === '{"v":"[REDACTED]"}', 'json_encode');
check(!str_contains(print_r($secret, true), LATEST), 'print_r');
ob_start();
var_dump($secret->value);
check(!str_contains((string) ob_get_clean(), LATEST), 'var_dump');
try {
    $serialized = serialize($secret->value);
    check(false, 'serialize must refuse, it returned ' . strlen($serialized) . ' bytes');
} catch (LogicException) {
}
try {
    $copy = clone $secret->value;
    check(false, 'clone must refuse');
} catch (LogicException) {
}
$secret->close();
check($secret->value->isClosed() && $secret->value->length() === 0, 'closed');
try {
    $secret->value->expose();
    check(false, 'expose after close must refuse');
} catch (LogicException) {
}
$secret->close(); // idempotent

$old = $reader->get('database-password', $oldVersion);
check($old->value->expose() === FIRST, 'old value');
check($old->properties->version === $oldVersion, 'old version');
check($reader->properties('database-password', $oldVersion)->version === $oldVersion, 'properties pinned');
check($reader->properties('database-password')->version !== $oldVersion, 'properties newest');

check($reader->resolve("sourceorrery://$vault/database-password")->value->expose() === LATEST, 'resolve latest');
check($reader->resolve("sourceorrery://$vault/database-password/$oldVersion")->value->expose() === FIRST, 'resolve pinned');
expectThrow(fn() => $reader->resolve('sourceorrery://other-vault/database-password'), InvalidArgumentException::class, 'invalid_argument');
expectThrow(fn() => $reader->resolve('not-a-reference'), InvalidArgumentException::class, 'invalid_argument', 'sourceorrery://vault/name');

check($reader->get('rotated-key')->value->expose() === 'old', 'fallback');
$newest = $reader->properties('rotated-key');
check(!$newest->enabled, 'newest disabled');
$disabled = expectThrow(fn() => $reader->get('rotated-key', $newest->version), SecretDisabledException::class, 'disabled', '--enable');
check($disabled instanceof PolicyException, 'disabled is a policy error');

$expired = expectThrow(fn() => $reader->get('expired-token'), SecretExpiredException::class, 'expired', 'Policy');
check($expired !== null && !$expired->isTransient(), 'expired not transient');
$pending = expectThrow(fn() => $reader->get('future-token'), SecretNotYetValidException::class, 'not_yet_valid');
check($pending !== null && $pending->isTransient(), 'not_yet_valid transient');
expectThrow(fn() => $reader->get('deleted-secret'), SecretDeletedException::class, 'deleted', 'secret recover deleted-secret');

$missing = expectThrow(fn() => $reader->get('missing'), SecretNotFoundException::class, 'not_found', "sourceorrery secret set missing --vault $vault");
check($missing !== null && $missing->detail === "secret 'missing' was not found", 'detail');
check($missing !== null && str_starts_with($missing->getMessage(), $missing->detail . '. '), 'message');
$version = expectThrow(fn() => $reader->get('database-password', 'deadbeef'), VersionNotFoundException::class, 'version_not_found', 'secret versions database-password');
check($version instanceof SecretNotFoundException, 'version_not_found extends not_found');
expectThrow(fn() => $reader->get('bad_name'), InvalidNameException::class, 'invalid_name');

$vaultMissing = expectThrow(fn() => SecretReader::open('no-such-vault'), VaultNotFoundException::class, 'vault_not_found', 'sourceorrery vault create no-such-vault');
check($vaultMissing !== null && str_contains($vaultMissing->hint, $home), 'vault hint names home');
$locked = expectThrow(
    fn() => SecretReader::open($vault, new OpenOptions(passphrase: 'wrong-passphrase', environment: false)),
    VaultLockedException::class,
    'locked',
    'passphrase option: tried',
);
check($locked !== null && str_contains($locked->hint, 'SOURCEORRERY_PASSPHRASE: not set'), 'locked hint sources');
check($locked !== null && str_contains($locked->hint, "--vault $vault"), 'locked hint vault');
check($locked !== null && !str_contains($locked->getMessage(), 'wrong-passphrase'), 'locked never echoes the passphrase');

$explicit = SecretReader::open($vault, new OpenOptions(home: $home, passphrase: $passphrase, environment: false));
$descriptor = $explicit->descriptor();
check($descriptor['name'] === $vault && in_array('passphrase', $descriptor['protectors'], true), 'descriptor');
$explicit->close();
check($explicit->isClosed(), 'reader closed');
try {
    $explicit->get('database-password');
    check(false, 'closed reader must refuse');
} catch (LogicException) {
}
$explicit->close();

$project = Project::load($manifest);
check($project->name === 'ci-project', 'project name');
check(str_ends_with($project->manifestPath, 'sourceorrery.toml'), 'manifest path');
$names = array_map(fn($s) => $s->name, $project->secrets);
sort($names);
check($names === ['database-password', 'rotated-key'], 'project secrets');
check($project->env('DATABASE_PASSWORD')?->expose() === LATEST, 'project env');
check($project->env('ROTATED')?->expose() === 'old', 'project env custom');
check($project->get('missing-optional') === null, 'optional miss skipped');
check($project->get('expired-token') === null, 'optional policy refusal skipped');
$entry = $project->get('rotated-key');
check($entry !== null && $entry->required && $entry->env === 'ROTATED' && $entry->reference === "sourceorrery://$vault/rotated-key", 'entry');
$project->close();
check($project->env('ROTATED')?->isClosed() === true, 'project closed');
expectThrow(fn() => Project::load($manifest . '.missing'), ManifestException::class, 'manifest');
expectThrow(fn() => Project::load($manifest, new OpenOptions(passphrase: 'wrong', environment: false)), VaultLockedException::class, 'locked');

// A vault the manifest declares in [vaults.<name>] is opened at its remote
// provider (HashiCorp Vault, at an address where nothing listens); a vault
// without a table is still the local file.
$remoteDir = sys_get_temp_dir() . '/sourceorrery-php-remote-' . getmypid();
mkdir($remoteDir, 0700, true);
$remoteManifest = "$remoteDir/sourceorrery.toml";
file_put_contents(
    $remoteManifest,
    "[project]\nname = \"demo\"\nvault = \"$vault\"\n\n"
    . "[vaults.remote-x]\nprovider = \"hashicorp-vault\"\n"
    . "address = \"http://127.0.0.1:1\"\nmount = \"secret\"\n",
);
$withManifest = new OpenOptions(manifest: $remoteManifest);
check(str_contains($withManifest->toJson(), '"manifest":'), 'manifest reaches the options document');
// With a credential the provider connects to the manifest's address: the
// failure is transient and names the vault's table.
$previousToken = getenv('VAULT_TOKEN');
putenv('VAULT_TOKEN=test-token');
$remote = expectThrow(fn() => SecretReader::open('remote-x', $withManifest), ProviderUnavailableException::class, 'provider_unavailable', '[vaults.remote-x]');
check($remote !== null && str_contains($remote->detail, 'hashicorp-vault is unavailable'), 'remote detail names the provider');
check($remote !== null && $remote->isTransient(), 'provider_unavailable is transient');
// Without VAULT_TOKEN the process is unauthenticated before any request is
// made, unless the developer has another Vault credential (such as
// ~/.vault-token), in which case the address is still unreachable.
putenv('VAULT_TOKEN');
try {
    SecretReader::open('remote-x', $withManifest);
    check(false, 'expected a remote error without VAULT_TOKEN');
} catch (SourceOrreryException $e) {
    if ($e->code() === 'unauthenticated') {
        check($e instanceof UnauthenticatedException, 'unauthenticated is typed');
        check(str_contains($e->detail, 'not authenticated to hashicorp-vault'), 'unauthenticated detail names the provider');
        check(str_contains($e->hint, 'VAULT_TOKEN'), 'unauthenticated hint names VAULT_TOKEN');
        check(!$e->isTransient(), 'unauthenticated is not transient');
    } else {
        check($e->code() === 'provider_unavailable', "expected unauthenticated or provider_unavailable, got {$e->code()}");
        check($e instanceof ProviderUnavailableException && $e->isTransient(), 'provider_unavailable is typed and transient');
    }
}
putenv(is_string($previousToken) ? "VAULT_TOKEN=$previousToken" : 'VAULT_TOKEN');
$local = SecretReader::open($vault, $withManifest);
check($local->get('database-password')->value->expose() === LATEST, 'a vault without a table stays local');
$local->close();
unlink($remoteManifest);
rmdir($remoteDir);

$unauthenticated = SourceOrreryException::forCode('unauthenticated', 'm', 'h');
check($unauthenticated instanceof UnauthenticatedException && !$unauthenticated->isTransient(), 'unauthenticated is typed and not transient');
$unavailable = SourceOrreryException::forCode('provider_unavailable', 'm', 'h');
check($unavailable instanceof ProviderUnavailableException && $unavailable->isTransient(), 'provider_unavailable is typed and transient');
check(!($unavailable instanceof PolicyException), 'provider_unavailable is not a policy error');

$unknown = SourceOrreryException::forCode('brand_new_code', 'm', 'h');
check($unknown::class === SourceOrreryException::class && $unknown->code() === 'brand_new_code' && $unknown->getMessage() === 'm. h', 'unknown code');

$reader->close();
// An SDK refuses a library built for another C ABI version with a typed
// exception (ADR 0007); the installed library matches.
check(SourceOrrery::abiVersion() === Native::ABI_VERSION, 'the installed library matches the ABI version');
check(Native::abiMismatch(Native::ABI_VERSION) === null, 'no mismatch for the built version');
$mismatch = Native::abiMismatch(Native::ABI_VERSION + 1);
check($mismatch instanceof SourceOrreryException && $mismatch->code() === 'abi_mismatch', 'abi_mismatch is typed');
check($mismatch !== null && str_contains($mismatch->getMessage(), (string) (Native::ABI_VERSION + 1)), 'the message names the versions');

if ($failures > 0) {
    fwrite(STDERR, "$failures check(s) failed\n");
    exit(1);
}
echo "PHP SDK: all checks passed\n";

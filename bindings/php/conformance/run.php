<?php
// Conformance runner for the PHP SDK (tests/conformance/sdk/README.md).
//
//   php run.php <op> [key=value ...]

declare(strict_types=1);

require file_exists(__DIR__ . '/../vendor/autoload.php') ? __DIR__ . '/../vendor/autoload.php' : __DIR__ . '/../autoload.php';

use SourceOrrery\OpenOptions;
use SourceOrrery\Project;
use SourceOrrery\Secret;
use SourceOrrery\SecretProperties;
use SourceOrrery\SecretReader;
use SourceOrrery\SourceOrreryException;

$op = $argv[1] ?? '';
$kv = [];
foreach (array_slice($argv, 2) as $arg) {
    [$key, $value] = explode('=', $arg, 2) + [1 => ''];
    $kv[$key] = $value;
}

function propertiesLines(SecretProperties $p): array
{
    $lines = [
        ['version', $p->version],
        ['enabled', $p->enabled ? 'true' : 'false'],
        ['content_type', $p->contentType ?? ''],
        ['reference', $p->reference()],
    ];
    foreach ($p->tags as $key => $value) {
        $lines[] = ["tag.$key", $value];
    }
    return $lines;
}

function secretLines(Secret $secret): array
{
    return array_merge([['value', $secret->value->expose()]], propertiesLines($secret->properties));
}

function run(string $op, array $kv): array
{
    $vault = $kv['vault'] ?? (getenv('SOURCEORRERY_TEST_VAULT') ?: 'development');
    $options = new OpenOptions(
        home: $kv['home'] ?? null,
        passphrase: $kv['passphrase'] ?? null,
        passphraseFile: $kv['passphrase_file'] ?? null,
        environment: ($kv['environment'] ?? 'true') !== 'false',
    );
    if ($op === 'load') {
        $project = Project::load($kv['manifest'], $options);
        $names = array_map(fn($s) => $s->name, $project->secrets);
        sort($names);
        $lines = [
            ['project.name', $project->name],
            ['project.count', (string) count($project->secrets)],
            ['project.names', implode(',', $names)],
        ];
        foreach ($project->secrets as $secret) {
            $lines[] = ["secret.{$secret->env}", $secret->value->expose()];
        }
        return $lines;
    }
    $reader = SecretReader::open($vault, $options);
    switch ($op) {
        case 'open':
            $d = $reader->descriptor();
            return [['descriptor.name', $d['name']], ['descriptor.protectors', implode(',', $d['protectors'])]];
        case 'get':
            return secretLines($reader->get($kv['name'], $kv['version'] ?? null));
        case 'get-newest-explicit':
            return secretLines($reader->get($kv['name'], $reader->properties($kv['name'])->version));
        case 'properties':
            return propertiesLines($reader->properties($kv['name'], $kv['version'] ?? null));
        case 'resolve':
            return secretLines($reader->resolve($kv['reference']));
        default:
            throw new RuntimeException("unknown scenario op '$op'");
    }
}

try {
    $lines = array_merge([['outcome', 'ok']], run($op, $kv));
} catch (SourceOrreryException $e) {
    $lines = [
        ['outcome', 'error'],
        ['code', $e->code()],
        ['message', $e->detail],
        ['hint', $e->hint],
        ['transient', $e->isTransient() ? 'true' : 'false'],
        ['type', (new ReflectionClass($e))->getShortName()],
    ];
}
foreach ($lines as [$key, $value]) {
    echo "$key\t$value\n";
}

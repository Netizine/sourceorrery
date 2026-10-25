<?php

declare(strict_types=1);

namespace SourceOrrery;

use FFI;

/** One secret resolved from `sourceorrery.toml`. */
final class ProjectSecret
{
    public function __construct(
        public readonly string $name,
        public readonly string $env,
        public readonly string $reference,
        public readonly bool $required,
        public readonly SecretProperties $properties,
        public readonly SecretValue $value,
    ) {
    }
}

/**
 * The secrets a `sourceorrery.toml` declares, resolved like
 * `sourceorrery run`: every required secret must resolve or `load()` throws
 * that secret's exception; optional secrets that are missing, refused by
 * policy or whose vault does not exist are left out.
 */
final class Project
{
    /**
     * @param list<ProjectSecret> $secrets
     */
    private function __construct(
        public readonly string $name,
        public readonly string $manifestPath,
        public readonly array $secrets,
    ) {
    }

    /**
     * Load `$manifest` (null: the nearest `sourceorrery.toml` above the current
     * directory). `$options` apply to every vault the manifest names.
     */
    public static function load(?string $manifest = null, ?OpenOptions $options = null): self
    {
        $options ??= new OpenOptions();
        Native::requireAbi();
        $ffi = Native::ffi();
        [$manifestPtr, $manifestLen] = Native::arg($manifest);
        [$jsonPtr, $jsonLen] = Native::arg($options->toJson());
        [$keyPtr, $keyLen] = Native::arg($options->recoveryKey);
        $handle = $ffi->new('so_project*');
        try {
            Native::check($ffi->so_project_load($manifestPtr, $manifestLen, $jsonPtr, $jsonLen, $keyPtr, $keyLen, FFI::addr($handle)));
        } finally {
            Native::release($keyPtr, $keyLen);
            Native::release($jsonPtr, $jsonLen);
            Native::release($manifestPtr, $manifestLen);
        }
        try {
            $infoSlot = Native::bytesSlot();
            Native::check($ffi->so_project_info($handle, FFI::addr($infoSlot)));
            /** @var array<string, mixed> $info */
            $info = json_decode(Native::takeString($infoSlot), true, 512, JSON_THROW_ON_ERROR);
            $count = $ffi->so_project_count($handle);
            $secrets = [];
            for ($index = 0; $index < $count; $index++) {
                $entrySlot = Native::bytesSlot();
                $valueSlot = Native::bytesSlot();
                Native::check($ffi->so_project_entry($handle, $index, FFI::addr($entrySlot), FFI::addr($valueSlot)));
                /** @var array<string, mixed> $entry */
                $entry = json_decode(Native::takeString($entrySlot), true, 512, JSON_THROW_ON_ERROR);
                $secrets[] = new ProjectSecret(
                    (string) $entry['name'],
                    (string) $entry['env'],
                    (string) $entry['reference'],
                    (bool) $entry['required'],
                    SecretProperties::fromArray((array) $entry['properties']),
                    new SecretValue($valueSlot),
                );
            }
            return new self((string) $info['name'], (string) $info['manifest_path'], $secrets);
        } finally {
            $ffi->so_project_free($handle);
        }
    }

    /** The entry declared as `[secrets.<name>]`, if it resolved. */
    public function get(string $name): ?ProjectSecret
    {
        foreach ($this->secrets as $secret) {
            if ($secret->name === $name) {
                return $secret;
            }
        }
        return null;
    }

    /** The value delivered in environment variable `$env`, if any. */
    public function env(string $env): ?SecretValue
    {
        foreach ($this->secrets as $secret) {
            if ($secret->env === $env) {
                return $secret->value;
            }
        }
        return null;
    }

    /** Zeroise every value. */
    public function close(): void
    {
        foreach ($this->secrets as $secret) {
            $secret->value->close();
        }
    }
}

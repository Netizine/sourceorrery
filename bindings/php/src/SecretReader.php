<?php

declare(strict_types=1);

namespace SourceOrrery;

use FFI;
use FFI\CData;

/**
 * A read-only handle on one vault, unlocked the way the CLI unlocks it: OS
 * credential store, then `OpenOptions::$passphrase`, SOURCEORRERY_PASSPHRASE,
 * then `OpenOptions::$passphraseFile` / SOURCEORRERY_PASSPHRASE_FILE. Never
 * prompts.
 *
 * ```php
 * $reader = SecretReader::open('development');
 * $secret = $reader->get('database-password');
 * connect(password: $secret->value->expose());
 * $secret->close();   // zeroises the value
 * ```
 */
final class SecretReader
{
    private ?CData $handle;

    private function __construct(CData $handle, private readonly string $vaultName)
    {
        $this->handle = $handle;
    }

    /** Open `$vault`; see the class description for the unlock order. */
    public static function open(string $vault, ?OpenOptions $options = null): self
    {
        $options ??= new OpenOptions();
        Native::requireAbi();
        $ffi = Native::ffi();
        [$namePtr, $nameLen] = Native::arg($vault);
        [$jsonPtr, $jsonLen] = Native::arg($options->toJson());
        [$passPtr, $passLen] = Native::arg($options->passphrase);
        $out = $ffi->new('so_reader*');
        try {
            Native::check($ffi->so_reader_open($namePtr, $nameLen, $jsonPtr, $jsonLen, $passPtr, $passLen, FFI::addr($out)));
        } finally {
            Native::release($passPtr, $passLen);
            Native::release($jsonPtr, $jsonLen);
            Native::release($namePtr, $nameLen);
        }
        return new self($out, $vault);
    }

    /** Name of the vault this reader is bound to. */
    public function vaultName(): string
    {
        return $this->vaultName;
    }

    /** True once closed. */
    public function isClosed(): bool
    {
        return $this->handle === null;
    }

    /**
     * The newest accessible version of `$name` (enabled, inside its time
     * window), or exactly `$version`. Policy refusals throw PolicyException
     * subclasses.
     */
    public function get(string $name, ?string $version = null): Secret
    {
        $ffi = Native::ffi();
        [$namePtr, $nameLen] = Native::arg($name);
        [$versionPtr, $versionLen] = Native::arg($version);
        $props = Native::bytesSlot();
        $value = Native::bytesSlot();
        try {
            Native::check($ffi->so_reader_get($this->require(), $namePtr, $nameLen, $versionPtr, $versionLen, FFI::addr($props), FFI::addr($value)));
        } finally {
            Native::release($versionPtr, $versionLen);
            Native::release($namePtr, $nameLen);
        }
        return new Secret(SecretProperties::fromJson(Native::takeString($props)), new SecretValue($value));
    }

    /** Metadata only; policy is not applied, so disabled and expired versions can be inspected. */
    public function properties(string $name, ?string $version = null): SecretProperties
    {
        $ffi = Native::ffi();
        [$namePtr, $nameLen] = Native::arg($name);
        [$versionPtr, $versionLen] = Native::arg($version);
        $props = Native::bytesSlot();
        try {
            Native::check($ffi->so_reader_properties($this->require(), $namePtr, $nameLen, $versionPtr, $versionLen, FFI::addr($props)));
        } finally {
            Native::release($versionPtr, $versionLen);
            Native::release($namePtr, $nameLen);
        }
        return SecretProperties::fromJson(Native::takeString($props));
    }

    /** Resolve `sourceorrery://vault/name[/version]`; the vault must be this reader's. */
    public function resolve(string $reference): Secret
    {
        $ffi = Native::ffi();
        [$refPtr, $refLen] = Native::arg($reference);
        $props = Native::bytesSlot();
        $value = Native::bytesSlot();
        try {
            Native::check($ffi->so_reader_resolve($this->require(), $refPtr, $refLen, FFI::addr($props), FFI::addr($value)));
        } finally {
            Native::release($refPtr, $refLen);
        }
        return new Secret(SecretProperties::fromJson(Native::takeString($props)), new SecretValue($value));
    }

    /**
     * Non-sensitive description of the vault (name, id, path, protectors).
     *
     * @return array<string, mixed>
     */
    public function descriptor(): array
    {
        $out = Native::bytesSlot();
        Native::check(Native::ffi()->so_reader_descriptor($this->require(), FFI::addr($out)));
        /** @var array<string, mixed> $descriptor */
        $descriptor = json_decode(Native::takeString($out), true, 512, JSON_THROW_ON_ERROR);
        return $descriptor;
    }

    /** Release the vault; the key held in memory is zeroised. Idempotent. */
    public function close(): void
    {
        if ($this->handle !== null) {
            Native::ffi()->so_reader_close($this->handle);
            $this->handle = null;
        }
    }

    public function __destruct()
    {
        $this->close();
    }

    private function require(): CData
    {
        if ($this->handle === null) {
            throw new \LogicException('SecretReader is closed');
        }
        return $this->handle;
    }
}

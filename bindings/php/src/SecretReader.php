<?php

declare(strict_types=1);

namespace SourceOrrery;

use FFI;
use FFI\CData;

/**
 * A read-only handle on one vault, unlocked the way the CLI unlocks it: OS
 * credential store, then `OpenOptions::$recoveryKey`, SOURCEORRERY_RECOVERY_KEY,
 * then `OpenOptions::$recoveryKeyFile` / SOURCEORRERY_RECOVERY_KEY_FILE. Never
 * prompts.
 * Use the separately installed CLI to create vaults and set secret values:
 * https://sourceorrery.ai/getting-started/#install. Installing this SDK does
 * not install the CLI; applications do not need a CLI process alongside them.
 *
 * ```php
 * $reader = SecretReader::open('development');
 * $secret = $reader->get('database-password');
 * connect(password: $secret->value->expose());
 * $secret->close();   // zeroises the value
 * ```
 *
 * A reader is the one owner of its native handle: it cannot be cloned or
 * serialised, and `close()` frees the handle once. Share the one object.
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
        [$keyPtr, $keyLen] = Native::arg($options->recoveryKey);
        $out = $ffi->new('so_reader*');
        try {
            Native::check($ffi->so_reader_open($namePtr, $nameLen, $jsonPtr, $jsonLen, $keyPtr, $keyLen, FFI::addr($out)));
        } finally {
            Native::release($keyPtr, $keyLen);
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

    /**
     * Refused: two objects would own one native handle, and the first to
     * close it would leave the other holding a freed one.
     */
    public function __clone()
    {
        // The copy owns nothing, even if PHP destroys it after this throws.
        $this->handle = null;
        throw new \LogicException('SecretReader cannot be cloned; share the one reader instead');
    }

    public function __serialize(): array
    {
        throw new \LogicException('SecretReader cannot be serialised; open the vault where it is needed');
    }

    public function __unserialize(array $data): void
    {
        throw new \LogicException('SecretReader cannot be unserialised');
    }

    private function require(): CData
    {
        if ($this->handle === null) {
            throw new \LogicException('SecretReader is closed');
        }
        return $this->handle;
    }
}

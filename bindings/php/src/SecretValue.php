<?php

declare(strict_types=1);

namespace SourceOrrery;

use FFI;
use FFI\CData;
use JsonSerializable;

/**
 * A secret value kept in native memory until `close()` zeroises it.
 * `expose()` returns a copy the application owns (a PHP string cannot be
 * wiped: keep it short-lived). Printing, `var_dump`, `json_encode` and
 * `serialize` all give `[REDACTED]` or refuse.
 */
final class SecretValue implements JsonSerializable
{
    private ?CData $bytes;

    /** @internal */
    public function __construct(CData $bytes)
    {
        $this->bytes = $bytes;
    }

    /** A copy of the bytes. */
    public function expose(): string
    {
        if ($this->bytes === null || $this->bytes->ptr === null) {
            throw new \LogicException('SecretValue is closed; its bytes were zeroised');
        }
        return FFI::string($this->bytes->ptr, $this->bytes->len);
    }

    /** Length in bytes; 0 once closed. */
    public function length(): int
    {
        return $this->bytes === null || $this->bytes->ptr === null ? 0 : $this->bytes->len;
    }

    /** True once `close()` has run. */
    public function isClosed(): bool
    {
        return $this->bytes === null || $this->bytes->ptr === null;
    }

    /** Zeroise and free the native bytes. Idempotent. */
    public function close(): void
    {
        if ($this->bytes !== null) {
            Native::ffi()->so_bytes_free(FFI::addr($this->bytes));
            $this->bytes = null;
        }
    }

    public function __destruct()
    {
        $this->close();
    }

    public function __toString(): string
    {
        return '[REDACTED]';
    }

    public function jsonSerialize(): string
    {
        return '[REDACTED]';
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['value' => '[REDACTED]'];
    }

    public function __serialize(): array
    {
        throw new \LogicException('SecretValue cannot be serialised; call expose() deliberately');
    }

    public function __unserialize(array $data): void
    {
        throw new \LogicException('SecretValue cannot be unserialised');
    }

    public function __clone()
    {
        // The copy owns nothing, even if PHP destroys it after this throws:
        // closing it must not free the original's bytes.
        $this->bytes = null;
        throw new \LogicException('SecretValue cannot be cloned; call expose() deliberately');
    }
}

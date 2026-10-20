<?php

declare(strict_types=1);

namespace SourceOrrery;

/** A version's metadata and its value. `close()` zeroises the value. */
final class Secret
{
    public function __construct(
        public readonly SecretProperties $properties,
        public readonly SecretValue $value,
    ) {
    }

    public function close(): void
    {
        $this->value->close();
    }
}

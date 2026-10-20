<?php

declare(strict_types=1);

namespace SourceOrrery;

use DateTimeImmutable;

/** Metadata of one version. Never contains the value. */
final class SecretProperties
{
    /**
     * @param array<string, string> $tags
     */
    public function __construct(
        public readonly string $vault,
        public readonly string $name,
        public readonly string $version,
        public readonly bool $enabled,
        public readonly ?string $contentType,
        public readonly array $tags,
        public readonly ?DateTimeImmutable $notBefore,
        public readonly ?DateTimeImmutable $expiresOn,
        public readonly DateTimeImmutable $createdOn,
        public readonly DateTimeImmutable $updatedOn,
        public readonly string $recoveryLevel,
    ) {
    }

    /** `sourceorrery://vault/name/version` for exactly this version. */
    public function reference(): string
    {
        return "sourceorrery://{$this->vault}/{$this->name}/{$this->version}";
    }

    /** @internal */
    public static function fromJson(string $json): self
    {
        /** @var array<string, mixed> $raw */
        $raw = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        return self::fromArray($raw);
    }

    /**
     * @internal
     * @param array<string, mixed> $raw
     */
    public static function fromArray(array $raw): self
    {
        return new self(
            (string) $raw['vault'],
            (string) $raw['name'],
            (string) $raw['version'],
            (bool) $raw['enabled'],
            isset($raw['content_type']) ? (string) $raw['content_type'] : null,
            array_map('strval', (array) ($raw['tags'] ?? [])),
            self::timestamp($raw['not_before'] ?? null),
            self::timestamp($raw['expires_on'] ?? null),
            self::timestamp($raw['created_on']) ?? new DateTimeImmutable('@0'),
            self::timestamp($raw['updated_on']) ?? new DateTimeImmutable('@0'),
            (string) ($raw['recovery_level'] ?? 'recoverable'),
        );
    }

    private static function timestamp(mixed $text): ?DateTimeImmutable
    {
        return is_string($text) ? new DateTimeImmutable($text) : null;
    }
}

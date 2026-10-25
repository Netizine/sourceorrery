<?php

declare(strict_types=1);

namespace SourceOrrery;

/**
 * How to find and unlock a vault. The defaults reproduce the CLI: vaults
 * under SOURCEORRERY_HOME, unlocked by the OS credential store, then
 * SOURCEORRERY_RECOVERY_KEY, then SOURCEORRERY_RECOVERY_KEY_FILE. A secret
 * one of the vault's connections stores is read at that provider.
 */
final class OpenOptions
{
    public function __construct(
        /** Directory holding the `vaults/` folder; null honours SOURCEORRERY_HOME. */
        public readonly ?string $home = null,
        /** A recovery key tried before the environment sources. */
        public readonly ?string $recoveryKey = null,
        /** A file holding the recovery key; replaces SOURCEORRERY_RECOVERY_KEY_FILE. */
        public readonly ?string $recoveryKeyFile = null,
        /** Consult SOURCEORRERY_RECOVERY_KEY and SOURCEORRERY_RECOVERY_KEY_FILE. */
        public readonly bool $environment = true,
    ) {
    }

    /** @internal */
    public function toJson(): string
    {
        $options = ['environment' => $this->environment];
        if ($this->home !== null && $this->home !== '') {
            $options['home'] = $this->home;
        }
        if ($this->recoveryKeyFile !== null && $this->recoveryKeyFile !== '') {
            $options['recovery_key_file'] = $this->recoveryKeyFile;
        }
        return json_encode($options, JSON_THROW_ON_ERROR);
    }
}

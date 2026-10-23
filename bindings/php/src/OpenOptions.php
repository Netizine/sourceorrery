<?php

declare(strict_types=1);

namespace SourceOrrery;

/**
 * How to find and unlock a vault. The defaults reproduce the CLI: vaults
 * under SOURCEORRERY_HOME, unlocked by the OS credential store, then
 * SOURCEORRERY_PASSPHRASE, then SOURCEORRERY_PASSPHRASE_FILE.
 */
final class OpenOptions
{
    public function __construct(
        /** Directory holding the `vaults/` folder; null honours SOURCEORRERY_HOME. */
        public readonly ?string $home = null,
        /** A passphrase tried before the environment sources. */
        public readonly ?string $passphrase = null,
        /** A file holding the passphrase; replaces SOURCEORRERY_PASSPHRASE_FILE. */
        public readonly ?string $passphraseFile = null,
        /** Consult SOURCEORRERY_PASSPHRASE and SOURCEORRERY_PASSPHRASE_FILE. */
        public readonly bool $environment = true,
        /**
         * The sourceorrery.toml whose `[vaults.<name>]` tables say which vaults
         * are remote and where; null uses the nearest one above the current
         * directory. A vault with a table is opened at its provider instead of
         * as a local file. Credentials come from the provider's own
         * environment, never from the manifest.
         */
        public readonly ?string $manifest = null,
    ) {
    }

    /** @internal */
    public function toJson(): string
    {
        $options = ['environment' => $this->environment];
        if ($this->home !== null && $this->home !== '') {
            $options['home'] = $this->home;
        }
        if ($this->passphraseFile !== null && $this->passphraseFile !== '') {
            $options['passphrase_file'] = $this->passphraseFile;
        }
        if ($this->manifest !== null && $this->manifest !== '') {
            $options['manifest'] = $this->manifest;
        }
        return json_encode($options, JSON_THROW_ON_ERROR);
    }
}

package ai.sourceorrery;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Optional;

import ai.sourceorrery.internal.Json;

/**
 * How to find and unlock a vault. {@link #defaults()} reproduces the CLI:
 * vaults under {@code SOURCEORRERY_HOME}, unlocked by the OS credential
 * store, then {@code SOURCEORRERY_PASSPHRASE}, then
 * {@code SOURCEORRERY_PASSPHRASE_FILE}; a vault that {@code sourceorrery.toml}
 * declares in a {@code [vaults.<name>]} table is opened at its remote provider.
 *
 * @param home directory holding the {@code vaults/} folder; empty honours {@code SOURCEORRERY_HOME}
 * @param passphrase a passphrase tried before the environment sources
 * @param passphraseFile a file holding the passphrase; replaces {@code SOURCEORRERY_PASSPHRASE_FILE}
 * @param environment whether {@code SOURCEORRERY_PASSPHRASE} and {@code SOURCEORRERY_PASSPHRASE_FILE} are consulted
 * @param manifest the {@code sourceorrery.toml} whose {@code [vaults.<name>]} tables say which vaults
 *     are remote and where; empty uses the nearest manifest above the current directory
 */
public record OpenOptions(
        Optional<String> home,
        Optional<String> passphrase,
        Optional<String> passphraseFile,
        boolean environment,
        Optional<String> manifest) {

    /** The CLI's defaults. */
    public static OpenOptions defaults() {
        return new OpenOptions(Optional.empty(), Optional.empty(), Optional.empty(), true, Optional.empty());
    }

    public OpenOptions withHome(String home) {
        return new OpenOptions(Optional.ofNullable(home), passphrase, passphraseFile, environment, manifest);
    }

    public OpenOptions withPassphrase(String passphrase) {
        return new OpenOptions(home, Optional.ofNullable(passphrase), passphraseFile, environment, manifest);
    }

    public OpenOptions withPassphraseFile(String passphraseFile) {
        return new OpenOptions(home, passphrase, Optional.ofNullable(passphraseFile), environment, manifest);
    }

    public OpenOptions withEnvironment(boolean environment) {
        return new OpenOptions(home, passphrase, passphraseFile, environment, manifest);
    }

    /**
     * Resolve remote vaults through this {@code sourceorrery.toml} instead of
     * the nearest one. Credentials for a remote provider come from the
     * provider's own environment, never from the manifest.
     */
    public OpenOptions withManifest(String manifest) {
        return new OpenOptions(home, passphrase, passphraseFile, environment, Optional.ofNullable(manifest));
    }

    /** {@link #withManifest(String)} for a {@link Path}. */
    public OpenOptions withManifest(Path manifest) {
        return withManifest(manifest == null ? null : manifest.toString());
    }

    String toJson() {
        StringBuilder json = new StringBuilder("{");
        home.ifPresent(h -> json.append("\"home\":").append(Json.quote(h)).append(','));
        passphraseFile.ifPresent(f -> json.append("\"passphrase_file\":").append(Json.quote(f)).append(','));
        manifest.ifPresent(m -> json.append("\"manifest\":").append(Json.quote(m)).append(','));
        json.append("\"environment\":").append(environment).append('}');
        return json.toString();
    }

    byte[] passphraseBytes() {
        return passphrase.map(p -> p.getBytes(StandardCharsets.UTF_8)).orElse(null);
    }
}

package ai.sourceorrery;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import ai.sourceorrery.internal.Json;

/**
 * How to find and unlock a vault. {@link #defaults()} reproduces the CLI:
 * vaults under {@code SOURCEORRERY_HOME}, unlocked by the OS credential
 * store, then {@code SOURCEORRERY_PASSPHRASE}, then
 * {@code SOURCEORRERY_PASSPHRASE_FILE}.
 *
 * @param home directory holding the {@code vaults/} folder; empty honours {@code SOURCEORRERY_HOME}
 * @param passphrase a passphrase tried before the environment sources
 * @param passphraseFile a file holding the passphrase; replaces {@code SOURCEORRERY_PASSPHRASE_FILE}
 * @param environment whether {@code SOURCEORRERY_PASSPHRASE} and {@code SOURCEORRERY_PASSPHRASE_FILE} are consulted
 */
public record OpenOptions(
        Optional<String> home,
        Optional<String> passphrase,
        Optional<String> passphraseFile,
        boolean environment) {

    /** The CLI's defaults. */
    public static OpenOptions defaults() {
        return new OpenOptions(Optional.empty(), Optional.empty(), Optional.empty(), true);
    }

    public OpenOptions withHome(String home) {
        return new OpenOptions(Optional.ofNullable(home), passphrase, passphraseFile, environment);
    }

    public OpenOptions withPassphrase(String passphrase) {
        return new OpenOptions(home, Optional.ofNullable(passphrase), passphraseFile, environment);
    }

    public OpenOptions withPassphraseFile(String passphraseFile) {
        return new OpenOptions(home, passphrase, Optional.ofNullable(passphraseFile), environment);
    }

    public OpenOptions withEnvironment(boolean environment) {
        return new OpenOptions(home, passphrase, passphraseFile, environment);
    }

    String toJson() {
        StringBuilder json = new StringBuilder("{");
        home.ifPresent(h -> json.append("\"home\":").append(Json.quote(h)).append(','));
        passphraseFile.ifPresent(f -> json.append("\"passphrase_file\":").append(Json.quote(f)).append(','));
        json.append("\"environment\":").append(environment).append('}');
        return json.toString();
    }

    byte[] passphraseBytes() {
        return passphrase.map(p -> p.getBytes(StandardCharsets.UTF_8)).orElse(null);
    }
}

package ai.sourceorrery;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import ai.sourceorrery.internal.Json;

/**
 * How to find and unlock a vault. {@link #defaults()} reproduces the CLI:
 * vaults under {@code SOURCEORRERY_HOME}, unlocked by the OS credential
 * store, then {@code SOURCEORRERY_RECOVERY_KEY}, then
 * {@code SOURCEORRERY_RECOVERY_KEY_FILE}. A secret one of the vault's
 * connections stores is read at that provider.
 *
 * @param home directory holding the {@code vaults/} folder; empty honours {@code SOURCEORRERY_HOME}
 * @param recoveryKey a recovery key tried before the environment sources
 * @param recoveryKeyFile a file holding the recovery key; replaces {@code SOURCEORRERY_RECOVERY_KEY_FILE}
 * @param environment whether {@code SOURCEORRERY_RECOVERY_KEY} and {@code SOURCEORRERY_RECOVERY_KEY_FILE} are consulted
 */
public record OpenOptions(
        Optional<String> home,
        Optional<String> recoveryKey,
        Optional<String> recoveryKeyFile,
        boolean environment) {

    /** The CLI's defaults. */
    public static OpenOptions defaults() {
        return new OpenOptions(Optional.empty(), Optional.empty(), Optional.empty(), true);
    }

    public OpenOptions withHome(String home) {
        return new OpenOptions(Optional.ofNullable(home), recoveryKey, recoveryKeyFile, environment);
    }

    public OpenOptions withRecoveryKey(String recoveryKey) {
        return new OpenOptions(home, Optional.ofNullable(recoveryKey), recoveryKeyFile, environment);
    }

    public OpenOptions withRecoveryKeyFile(String recoveryKeyFile) {
        return new OpenOptions(home, recoveryKey, Optional.ofNullable(recoveryKeyFile), environment);
    }

    public OpenOptions withEnvironment(boolean environment) {
        return new OpenOptions(home, recoveryKey, recoveryKeyFile, environment);
    }

    String toJson() {
        StringBuilder json = new StringBuilder("{");
        home.ifPresent(h -> json.append("\"home\":").append(Json.quote(h)).append(','));
        recoveryKeyFile.ifPresent(f -> json.append("\"recovery_key_file\":").append(Json.quote(f)).append(','));
        json.append("\"environment\":").append(environment).append('}');
        return json.toString();
    }

    byte[] recoveryKeyBytes() {
        return recoveryKey.map(p -> p.getBytes(StandardCharsets.UTF_8)).orElse(null);
    }
}

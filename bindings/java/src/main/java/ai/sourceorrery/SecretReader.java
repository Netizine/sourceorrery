package ai.sourceorrery;

import java.lang.foreign.MemorySegment;
import java.util.Objects;
import java.util.Optional;

import ai.sourceorrery.internal.Guarded;
import ai.sourceorrery.internal.Native;

/**
 * A read-only, thread-safe handle on one vault, unlocked the way the CLI
 * unlocks it: OS credential store, then {@link OpenOptions#recoveryKey()},
 * {@code SOURCEORRERY_RECOVERY_KEY}, then {@link OpenOptions#recoveryKeyFile()}
 * / {@code SOURCEORRERY_RECOVERY_KEY_FILE}. Never prompts.
 *
 * <pre>{@code
 * try (SecretReader reader = SecretReader.open("development");
 *      Secret secret = reader.get("database-password")) {
 *     connect(secret.value().exposeText());
 * }
 * }</pre>
 *
 * <p>One reader can be shared by any number of platform or virtual threads.
 * {@link #close()} waits for the calls already running, then frees the
 * native reader once; a call made after {@code close()} was called throws
 * {@link IllegalStateException}.
 */
public final class SecretReader implements AutoCloseable {
    private final Guarded<MemorySegment> handle;
    private final String vaultName;

    private SecretReader(MemorySegment handle, String vaultName) {
        this.handle = new Guarded<>(handle, Native::readerClose, "SecretReader is closed");
        this.vaultName = vaultName;
    }

    /** Open {@code vault} with the CLI's defaults. */
    public static SecretReader open(String vault) {
        return open(vault, OpenOptions.defaults());
    }

    /** Open {@code vault} with explicit options. */
    public static SecretReader open(String vault, OpenOptions options) {
        Native.requireAbi();
        Objects.requireNonNull(vault, "vault");
        Objects.requireNonNull(options, "options");
        MemorySegment opened = Native.readerOpen(vault, options.toJson(), options.recoveryKeyBytes());
        return new SecretReader(opened, vault);
    }

    /** Name of the vault this reader is bound to. */
    public String vaultName() {
        return vaultName;
    }

    /** True once {@link #close()} has been called. */
    public boolean isClosed() {
        return handle.isClosed();
    }

    /** The newest accessible version of {@code name}: enabled and inside its time window. */
    public Secret get(String name) {
        return get(name, Optional.empty());
    }

    /** Exactly {@code version} of {@code name}, or a policy error if that version is refused. */
    public Secret get(String name, String version) {
        return get(name, Optional.ofNullable(version));
    }

    /** {@link #get(String)} or {@link #get(String, String)} depending on {@code version}. */
    public Secret get(String name, Optional<String> version) {
        Objects.requireNonNull(name, "name");
        Native.SecretParts parts = handle.call(h -> Native.readerGet(h, name, version.orElse(null)));
        return new Secret(SecretProperties.fromJson(parts.propertiesJson()), new SecretValue(parts.value()));
    }

    /** Metadata of the newest version; policy is not applied. */
    public SecretProperties properties(String name) {
        return properties(name, Optional.empty());
    }

    /** Metadata of one version; policy is not applied, so disabled and expired versions can be inspected. */
    public SecretProperties properties(String name, Optional<String> version) {
        Objects.requireNonNull(name, "name");
        return SecretProperties.fromJson(
                handle.call(h -> Native.readerProperties(h, name, version.orElse(null))));
    }

    /** Resolve {@code sourceorrery://vault/name[/version]}; the vault must be this reader's. */
    public Secret resolve(String reference) {
        Objects.requireNonNull(reference, "reference");
        Native.SecretParts parts = handle.call(h -> Native.readerResolve(h, reference));
        return new Secret(SecretProperties.fromJson(parts.propertiesJson()), new SecretValue(parts.value()));
    }

    /** Non-sensitive description of the vault. */
    public VaultDescriptor descriptor() {
        return VaultDescriptor.fromJson(handle.call(Native::readerDescriptor));
    }

    /**
     * Release the vault once the calls already running have returned; the
     * key held in memory is zeroised. Idempotent.
     */
    @Override
    public void close() {
        handle.close();
    }

    @Override
    public String toString() {
        return "SecretReader(vault='" + vaultName + "')";
    }
}

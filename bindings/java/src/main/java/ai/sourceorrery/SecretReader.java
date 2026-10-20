package ai.sourceorrery;

import java.lang.foreign.MemorySegment;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import ai.sourceorrery.internal.Native;

/**
 * A read-only, thread-safe handle on one vault, unlocked the way the CLI
 * unlocks it: OS credential store, then {@link OpenOptions#passphrase()},
 * {@code SOURCEORRERY_PASSPHRASE}, then {@link OpenOptions#passphraseFile()}
 * / {@code SOURCEORRERY_PASSPHRASE_FILE}. Never prompts.
 *
 * <pre>{@code
 * try (SecretReader reader = SecretReader.open("development");
 *      Secret secret = reader.get("database-password")) {
 *     connect(secret.value().exposeText());
 * }
 * }</pre>
 */
public final class SecretReader implements AutoCloseable {
    private final AtomicReference<MemorySegment> handle;
    private final String vaultName;

    private SecretReader(MemorySegment handle, String vaultName) {
        this.handle = new AtomicReference<>(handle);
        this.vaultName = vaultName;
    }

    /** Open {@code vault} with the CLI's defaults. */
    public static SecretReader open(String vault) {
        return open(vault, OpenOptions.defaults());
    }

    /** Open {@code vault} with explicit options. */
    public static SecretReader open(String vault, OpenOptions options) {
        Objects.requireNonNull(vault, "vault");
        Objects.requireNonNull(options, "options");
        MemorySegment opened = Native.readerOpen(vault, options.toJson(), options.passphraseBytes());
        return new SecretReader(opened, vault);
    }

    /** Name of the vault this reader is bound to. */
    public String vaultName() {
        return vaultName;
    }

    /** True once closed. */
    public boolean isClosed() {
        return handle.get() == null;
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
        Native.SecretParts parts = Native.readerGet(require(), name, version.orElse(null));
        return new Secret(SecretProperties.fromJson(parts.propertiesJson()), new SecretValue(parts.value()));
    }

    /** Metadata of the newest version; policy is not applied. */
    public SecretProperties properties(String name) {
        return properties(name, Optional.empty());
    }

    /** Metadata of one version; policy is not applied, so disabled and expired versions can be inspected. */
    public SecretProperties properties(String name, Optional<String> version) {
        Objects.requireNonNull(name, "name");
        return SecretProperties.fromJson(Native.readerProperties(require(), name, version.orElse(null)));
    }

    /** Resolve {@code sourceorrery://vault/name[/version]}; the vault must be this reader's. */
    public Secret resolve(String reference) {
        Objects.requireNonNull(reference, "reference");
        Native.SecretParts parts = Native.readerResolve(require(), reference);
        return new Secret(SecretProperties.fromJson(parts.propertiesJson()), new SecretValue(parts.value()));
    }

    /** Non-sensitive description of the vault. */
    public VaultDescriptor descriptor() {
        return VaultDescriptor.fromJson(Native.readerDescriptor(require()));
    }

    /** Release the vault; the key held in memory is zeroised. Idempotent. */
    @Override
    public void close() {
        MemorySegment current = handle.getAndSet(null);
        if (current != null) {
            Native.readerClose(current);
        }
    }

    @Override
    public String toString() {
        return "SecretReader(vault='" + vaultName + "')";
    }

    private MemorySegment require() {
        MemorySegment current = handle.get();
        if (current == null) {
            throw new IllegalStateException("SecretReader is closed");
        }
        return current;
    }
}
